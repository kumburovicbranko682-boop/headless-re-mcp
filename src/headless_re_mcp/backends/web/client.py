"""Chrome DevTools Protocol driving via Playwright's sync API.

One browser per web session, driven through a CDP session so network, console,
scripts and WASM modules can be inspected with DevTools fidelity. Playwright is
optional and its browsers must be installed; a missing dependency degrades to
``capability_unavailable``. There is deliberately no arbitrary-JS ``evaluate``
tool, mirroring the debugger surface's refusal to offer ``dynamic.command``.

The sync API is used because tool handlers run on worker threads with no running
event loop (the MCP adapter offloads blocking work), which is exactly where the
sync API is supported. It is greenlet-based and thread-affine, so every call for
a session is funnelled onto that session's own thread -- see ``_Runner``.
"""

from __future__ import annotations

import contextlib
import queue
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit
from uuid import uuid4

from headless_re_mcp.backends.common.json_budget import fit_json_list, fit_json_text
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES, capped_file_size
from headless_re_mcp.core.process_tree import process_image_path, terminate_pid_tree

JsonObject = dict[str, Any]
T = TypeVar("T")

_MAX_REQUESTS = 3000
_MAX_CONSOLE = 2000
_MAX_SCRIPTS = 2000
_MAX_INLINE_BODY = 200_000
_MAX_CONSOLE_TEXT = 8 * 1024
_MAX_URL_BYTES = 16 * 1024
_MAX_METADATA_BYTES = 1024
# Response headers are server-controlled: a hostile or misbehaving origin can
# send many large headers. Cap each value, then bound the whole map by its
# JSON-encoded size so network_get's header capture cannot push the reply past
# the result budget (mirrors the proxy.flow_get header discipline).
_MAX_HEADER_VALUE_BYTES = 4 * 1024
_MAX_HEADERS_ENCODED = 16 * 1024
# DOM storage is page-controlled and can hold megabytes (a cache blob, a big
# token). Cap each value generously enough for a JWT/session token to survive
# intact, then bound each of the two maps (local + session) by encoded size so
# two storage reads together cannot overrun the result budget.
_MAX_STORAGE_VALUE_BYTES = 8 * 1024
_MAX_STORAGE_ENCODED = 96 * 1024
# Headroom fit_json_text leaves for a web result's other fields when it bounds an
# inline body/source/html by encoded size: the largest is a url capped at
# _MAX_URL_BYTES (16 KiB); the rest are small scalars. Smaller than the shared
# default because there is no bulky stderr field here.
_WEB_FIELD_RESERVE = 32 * 1024
# Headroom for a list result's scalar siblings (count/total/offset/has_more/
# dropped) when the window (requests/scripts/console rows) is bounded by encoded
# size; the window itself gets the rest of the budget.
_LIST_FIELD_RESERVE = 16 * 1024
# Playwright enforces its own timeouts inside the driver process, so they stop
# existing the moment the driver does. This is the outer bound that keeps a call
# from parking a worker thread forever when that happens.
_CALL_TIMEOUT = 60.0
_OPENING = object()


class WebError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    payload = text.encode("utf-8", errors="replace")
    if len(payload) <= max_bytes:
        return text, False
    return payload[:max_bytes].decode("utf-8", errors="ignore"), True


def _coerce_header(value: object) -> str:
    """A JSON-safe str for a CDP header key or value, whatever type it arrives as."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return "" if value is None else str(value)


def _normalize_cookie(raw: JsonObject) -> JsonObject:
    """A JSON-safe, size-bounded cookie record from a CDP ``Network.Cookie``.

    The security-relevant part of a cookie for a web/auth review is its flags, not
    its value: ``http_only`` false on a session cookie means script-reachable (an
    XSS can exfiltrate it), ``secure`` false means it rides plaintext HTTP, and
    ``same_site`` "None"/unset is the CSRF surface. The value is still returned --
    auth analysis often needs the token itself -- but capped like a header value
    and flagged when cut so one oversized cookie cannot bloat the reply.
    Name/domain/path are bounded too; ``expires`` is kept only when numeric (CDP
    uses -1 for a session cookie), and ``same_site`` is empty when the site did
    not set the attribute.
    """
    name, name_cut = _bounded_metadata(raw.get("name"), _MAX_METADATA_BYTES)
    value, value_cut = _bounded_metadata(raw.get("value"), _MAX_HEADER_VALUE_BYTES)
    domain, _domain_cut = _bounded_metadata(raw.get("domain"), _MAX_METADATA_BYTES)
    path, _path_cut = _bounded_metadata(raw.get("path"), _MAX_METADATA_BYTES)
    same_site, _same_site_cut = _bounded_metadata(raw.get("sameSite"), _MAX_METADATA_BYTES)
    expires = raw.get("expires")
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        expires = None
    elif expires < 0:
        # CDP uses -1 for a session cookie (no persistent expiry); report that as
        # null rather than a bogus pre-epoch timestamp -- the session flag carries
        # the same fact, and a negative "expires" would read as long expired.
        expires = None
    cookie: JsonObject = {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "secure": bool(raw.get("secure")),
        "http_only": bool(raw.get("httpOnly")),
        "session": bool(raw.get("session")),
        "same_site": same_site,
        "expires": expires,
    }
    if name_cut or value_cut:
        cookie["value_truncated"] = True
    return cookie


def _security_origin(url: object) -> str | None:
    """``scheme://host[:port]`` for a real web origin, or ``None`` for an opaque one.

    DOM storage is keyed by security origin, which CDP wants as this exact string.
    A page on ``about:blank`` or a ``data:`` URL has an opaque origin with no
    storage to read, so returning ``None`` lets the caller answer "empty" instead
    of sending CDP an origin it will reject.
    """
    text = url if isinstance(url, str) else ""
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _bounded_storage(entries: object) -> tuple[dict[str, str], bool]:
    """Coerce CDP ``DOMStorage`` entries to a JSON-safe, size-bounded ``str->str`` map.

    ``getDOMStorageItems`` returns ``entries`` as ``[key, value]`` pairs whose
    contents are page-controlled. Cap each value at ``_MAX_STORAGE_VALUE_BYTES``
    and bound the whole map by its JSON-encoded size, the same discipline the
    response-header map uses, so one storage read cannot push the reply past the
    result budget. Returns ``(items, truncated)``; ``truncated`` covers both a
    capped value and a map trimmed to fit.
    """
    pairs: list[list[str]] = []
    truncated = False
    seq = entries if isinstance(entries, list) else []
    for pair in seq:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        key = _coerce_header(pair[0])
        value, value_cut = _bounded_metadata(_coerce_header(pair[1]), _MAX_STORAGE_VALUE_BYTES)
        truncated = truncated or value_cut
        pairs.append([key, value])
    kept, _dropped, list_cut = fit_json_list(pairs, budget=_MAX_STORAGE_ENCODED, reserve=0)
    return {k: v for k, v in kept}, truncated or list_cut


def _bounded_headers(raw: object) -> tuple[dict[str, str], bool]:
    """Coerce a CDP header map to a JSON-safe, size-bounded ``str -> str`` dict.

    CDP's ``Network.responseReceived`` hands back ``response.headers`` whose keys
    and values are server-controlled. Capturing them verbatim would let a hostile
    origin push megabytes of headers into a network_get reply -- enough to overrun
    the result budget and get the whole reply discarded for a ~16 KiB summary --
    and any non-str value would break JSON serialization. Coerce every field to
    ``str``, cap each value at ``_MAX_HEADER_VALUE_BYTES``, and bound the whole map
    by its JSON-encoded size. Returns ``(headers, truncated)``.
    """
    try:
        base = dict(raw)  # type: ignore[call-overload]
    except Exception:  # noqa: BLE001 - header container shape varies
        return {}, False
    pairs: list[list[str]] = []
    truncated = False
    for key, value in base.items():
        bounded_value, value_cut = _bounded_metadata(
            _coerce_header(value), _MAX_HEADER_VALUE_BYTES
        )
        truncated = truncated or value_cut
        pairs.append([_coerce_header(key), bounded_value])
    kept, _dropped, list_cut = fit_json_list(pairs, budget=_MAX_HEADERS_ENCODED, reserve=0)
    return {k: v for k, v in kept}, truncated or list_cut


def _norm_str_filter(value: str | None) -> str | None:
    """A stripped filter string, or None when absent or only whitespace.

    Treating an empty/whitespace value as "no filter" keeps network_list
    forgiving: an empty ``url_contains`` would match every row (the empty
    substring is in everything) and an empty ``method`` would match none, both
    surprising. It also lets network_list decide honestly whether a filter is
    active when it sets the ``filtered`` flag. Mirrors the proxy.flows filter
    normalization so the two capture surfaces behave the same.
    """
    if value is None:
        return None
    text = value.strip()
    return text or None


def _request_matches(
    entry: JsonObject,
    *,
    method: str | None,
    url_contains: str | None,
    resource_type: str | None,
    status_min: int | None,
    status_max: int | None,
) -> bool:
    """True when a captured request passes every active filter (filters are ANDed).

    ``method`` and ``resource_type`` are exact case-insensitive matches (the CDP
    resourceType is a fixed vocabulary -- Document, Script, XHR, Fetch, Image
    ...); ``url_contains`` is a case-insensitive substring. A status bound only
    matches a request that actually has an integer status, so one whose response
    was not seen yet (status None) is excluded whenever any status bound is set --
    you asked for a status range and it has none.
    """
    if method is not None and str(entry.get("method") or "").casefold() != method.casefold():
        return False
    if url_contains is not None and url_contains.casefold() not in str(
        entry.get("url") or ""
    ).casefold():
        return False
    if resource_type is not None and str(
        entry.get("resourceType") or ""
    ).casefold() != resource_type.casefold():
        return False
    if status_min is not None or status_max is not None:
        status = entry.get("status")
        if not isinstance(status, int) or isinstance(status, bool):
            return False
        if status_min is not None and status < status_min:
            return False
        if status_max is not None and status > status_max:
            return False
    return True


def _console_matches(
    entry: JsonObject, *, level: str | None, text_contains: str | None
) -> bool:
    """True when a console message passes every active filter (filters are ANDed).

    ``level`` is an exact case-insensitive match on the message ``type`` field
    (the CDP consoleAPICalled vocabulary -- log, info, warning, error, debug,
    trace ...), so ``error`` selects only errors, not warnings. ``text_contains``
    is a case-insensitive substring of the joined message text; that text was
    already clipped to the per-message cap on capture, so the substring is tested
    against the clipped form, not the page's original argument. Mirrors the
    proxy.flows / network_list filter shape so the capture surfaces read the same.
    """
    if level is not None and str(entry.get("type") or "").casefold() != level.casefold():
        return False
    if text_contains is None:
        return True
    return text_contains.casefold() in str(entry.get("text") or "").casefold()


def _accumulate_headers(
    store: OrderedDict[str, dict[str, str]], request_id: str, raw: object
) -> None:
    """Merge coerced, per-value-capped request headers for ``request_id``.

    A request's headers arrive across two CDP events: ``requestWillBeSent`` (the
    headers the page/fetch set) and ``requestWillBeSentExtraInfo`` (the ones the
    network stack adds, notably Cookie). Capturing only the first would tell an
    analyst "no Cookie was sent" when there was one, so both feed the same bucket
    keyed by requestId; a dict dedupes by name, so redirects reusing the id do
    not grow it without bound. Values are coerced and capped here so a giant
    Authorization/Cookie cannot sit in the buffer; the encoded-size bound is
    applied once at read time by ``_bounded_headers``. The store evicts oldest
    past ``_MAX_REQUESTS`` in lockstep with the request ring.
    """
    try:
        base = dict(raw)  # type: ignore[call-overload]
    except Exception:  # noqa: BLE001 - header container shape varies
        return
    if not base:
        return
    bucket = store.get(request_id)
    if bucket is None:
        bucket = {}
        store[request_id] = bucket
    for key, value in base.items():
        capped_value, _cut = _bounded_metadata(_coerce_header(value), _MAX_HEADER_VALUE_BYTES)
        bucket[_coerce_header(key)] = capped_value
    store.move_to_end(request_id)
    while len(store) > _MAX_REQUESTS:
        store.popitem(last=False)


def _clip_console_text(params: JsonObject) -> tuple[str, bool]:
    """Join console args, stopping at ``_MAX_CONSOLE_TEXT``.

    A page that ``console.log``s a whole document would otherwise store that
    string in the ring for as long as the session lives. Slice each argument
    before joining so the huge original is not copied into the buffer.
    """
    parts: list[str] = []
    remaining = _MAX_CONSOLE_TEXT
    truncated = False
    for argument in params.get("args") or []:
        if remaining <= 0:
            truncated = True
            break
        if not isinstance(argument, dict):
            continue
        if "value" in argument:
            raw = argument["value"]
        elif argument.get("description"):
            raw = argument["description"]
        else:
            raw = argument.get("type", "")
        piece = raw if isinstance(raw, str) else str(raw)
        if parts:
            if remaining <= 1:
                truncated = True
                break
            remaining -= 1
        if len(piece) > remaining:
            piece = piece[:remaining]
            remaining = 0
            truncated = True
        else:
            remaining -= len(piece)
        parts.append(piece)
        if truncated:
            break
    return " ".join(parts), truncated


def _spill_text(
    text: str,
    *,
    artifact_dir: Path,
    filename: str,
    kind: str,
) -> tuple[str, Path | None, bool]:
    """Inline a prefix, spill the rest, or refuse when the capture cap is hit.

    CDP already delivered the whole payload. Writing it to the session artifact
    dir still fills the disk before retention runs: a single media response is
    enough. Returns ``(inline, spill_path_or_none, truncated)``.

    The inline text is bounded by its JSON-encoded size, not just its raw byte
    count: the transport discards the whole reply -- the spill path included --
    for a ~16 KiB summary once the encoded envelope outruns the result budget,
    and a page controls this body, so an escape-heavy 200 KB response could take
    the pointer to its own spilled copy down with it. Whenever the inline is cut
    (by the raw preview cap or the encoded bound) the full bytes are written to
    disk, so a ``truncated`` reply always carries a spill path to the rest.
    """
    payload = text.encode("utf-8", errors="replace")
    size = len(payload)
    if size > UNREGISTERED_CAPTURE_MAX_BYTES:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=size,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    spilled = size > _MAX_INLINE_BODY
    candidate = (
        text if not spilled else payload[:_MAX_INLINE_BODY].decode("utf-8", errors="ignore")
    )
    inline, _original_bytes, encoded_cut = fit_json_text(candidate, reserve=_WEB_FIELD_RESERVE)
    if not spilled and not encoded_cut:
        return text, None, False
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise WebError("invalid_params", f"invalid {kind} artifact filename")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    out = artifact_dir / filename
    out.write_bytes(payload)
    written, over = capped_file_size(out, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
    if over:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=written,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    return inline, out, True


class _Runner:
    """Own one thread and run every Playwright call for one session on it.

    The sync API is greenlet-based and its objects cannot be touched from a
    thread other than the one that created them: doing so raises "Cannot switch
    to a different thread" from deep inside playwright. Tool calls arrive on a
    shared worker pool, so which thread services ``web.dom_snapshot`` has
    nothing to do with which one serviced ``web.open`` -- the pool reuses an
    idle worker, so it appears to work until concurrency spreads the calls out.

    Waits are bounded here too. Playwright's own timeouts live in the driver
    process, so a driver that dies takes them with it and the caller blocks for
    good; a wedged runner is marked and refuses further work rather than
    queueing the whole session behind a call that will never return.
    """

    def __init__(self, name: str) -> None:
        self._queue: queue.SimpleQueue[tuple[Callable[[], Any], Future[Any]] | None] = (
            queue.SimpleQueue()
        )
        self._wedged = False
        self._closed = False
        self._thread = threading.Thread(target=self._loop, name=name, daemon=True)
        self._thread.start()

    @property
    def wedged(self) -> bool:
        return self._wedged

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            work, future = item
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(work())
            except BaseException as exc:  # noqa: BLE001 - handed to the caller
                future.set_exception(exc)

    def call(self, work: Callable[[], T], *, timeout: float = _CALL_TIMEOUT) -> T:
        if self._closed:
            raise WebError("invalid_state", "web session is closed")
        if self._wedged:
            raise WebError(
                "backend_error",
                "browser is unresponsive and this session cannot be used; call web.close",
            )
        future: Future[T] = Future()
        self._queue.put((work, future))
        try:
            return future.result(timeout=timeout)
        except FutureTimeout as exc:
            # The thread stays blocked in playwright and cannot be interrupted.
            # It is a daemon, so it costs the process a thread and nothing else,
            # and the session it belongs to is now unusable by definition.
            self._wedged = True
            raise WebError("timeout", f"browser did not respond within {timeout:g}s") from exc

    def shutdown(self) -> None:
        self._closed = True
        with contextlib.suppress(Exception):
            self._queue.put(None)
        self._thread.join(timeout=2.0)


class _WebSession:
    """Live browser objects plus bounded telemetry buffers for one session."""

    def __init__(self, playwright: Any, browser: Any, context: Any, page: Any, cdp: Any) -> None:
        self.playwright = playwright
        self.browser = browser
        self.context = context
        self.page = page
        self.cdp = cdp
        self.requests: OrderedDict[str, JsonObject] = OrderedDict()
        # Response headers live in their own bounded map keyed by requestId, not
        # on the request entry, so network_list stays lean (its rows are already
        # bounded by url size) while network_get can still return them per-request.
        self.response_headers: OrderedDict[str, JsonObject] = OrderedDict()
        # Request headers accumulate across requestWillBeSent (+ExtraInfo) into
        # their own bounded map, same rationale as response_headers above.
        self.request_headers: OrderedDict[str, dict[str, str]] = OrderedDict()
        self.console: deque[JsonObject] = deque(maxlen=_MAX_CONSOLE)
        self.requests_dropped = 0
        self.console_dropped = 0
        # Bounded like the other two: scriptParsed fires for every script a page
        # parses, so a long-lived tab (or one that eval()s) would otherwise grow
        # this dictionary for as long as the session is open.
        self.scripts: OrderedDict[str, JsonObject] = OrderedDict()
        self.scripts_dropped = 0
        self.lock = threading.RLock()
        # Set right after construction: the runner is what built these objects,
        # and it is the only thread allowed to touch them again.
        self.runner: _Runner | None = None
        # Node driver that owns Chromium. Playwright does not expose a PID;
        # close from another thread cannot talk to the objects, so this is
        # what a wedged session has to kill.
        self.driver_pid: int | None = None

    def close(self) -> None:
        for closer in (self.context.close, self.browser.close, self.playwright.stop):
            with contextlib.suppress(Exception):  # teardown is best-effort
                closer()


class WebBackend:
    """Manages one browser per session id (process-lifetime state)."""

    def __init__(self) -> None:
        self._sessions: dict[str, _WebSession] = {}
        self._lock = threading.RLock()
        self._available: bool | None = None

    def _check_available(self) -> None:
        if self._available is None:
            try:
                import playwright.sync_api  # noqa: F401

                self._available = True
            except Exception:
                self._available = False
        if not self._available:
            raise WebError("capability_unavailable", "playwright is not installed")

    def status(self, session_id: str) -> JsonObject:
        """Cheap page identity; never launches a browser."""
        with self._lock:
            handle = self._sessions.get(session_id)
        if handle is None:
            return {"open": False}
        if type(handle) is object:
            return {"open": False, "opening": True}
        if not isinstance(handle, _WebSession):
            return {"open": False}

        def work() -> JsonObject:
            return {
                "open": True,
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
            }

        return self._runner(handle).call(work)

    def _get(self, session_id: str) -> _WebSession:
        with self._lock:
            handle = self._sessions.get(session_id)
        if not isinstance(handle, _WebSession):
            raise WebError(
                "invalid_state", "web session not open; call web.open first", session_id=session_id
            )
        return handle

    def _runner(self, handle: _WebSession) -> _Runner:
        runner = handle.runner
        if runner is None:
            raise WebError("invalid_state", "web session has no browser thread")
        return runner

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        self._check_available()

        with self._lock:
            if session_id in self._sessions:
                raise WebError("invalid_state", "web session already open", session_id=session_id)
            # Per-open token, not the shared _OPENING sentinel: close() pops
            # the reservation, and a second open() must not look like the
            # first launch still owns the slot.
            opening = object()
            self._sessions[session_id] = opening  # type: ignore[assignment]

        from playwright.sync_api import sync_playwright

        runner = _Runner(f"playwright-{session_id[:8]}")
        # Filled as soon as the node driver exists, so a timeout in launch or
        # goto can still kill the tree from this thread.
        pid_box: list[int] = []

        def build() -> tuple[_WebSession, JsonObject]:
            pw = sync_playwright().start()
            pid = _playwright_driver_pid(pw)
            if isinstance(pid, int) and pid > 0:
                pid_box.append(pid)
            try:
                browser = pw.chromium.launch(headless=headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                cdp = context.new_cdp_session(page)
                handle = _WebSession(pw, browser, context, page, cdp)
                handle.driver_pid = pid
                self._wire_events(handle)
                if url:
                    page.goto(url, timeout=timeout * 1000.0, wait_until="domcontentloaded")
                # Summarised here rather than by a second call: between the two,
                # a browser exists that no session yet refers to, and a failure
                # in that window would leave it with nothing able to close it.
                summary = {
                    "opened": True,
                    "url": _bounded_metadata(page.url, _MAX_URL_BYTES)[0],
                    "title": _safe_title(page),
                    "headless": headless,
                }
            except Exception as exc:  # noqa: BLE001
                with contextlib.suppress(Exception):
                    pw.stop()
                raise WebError("backend_error", f"failed to open browser: {exc}", url=url) from exc
            return handle, summary

        try:
            # Launching a browser is the slowest thing here, so it gets the
            # caller's navigation budget plus room for the launch itself.
            handle, summary = runner.call(build, timeout=timeout + 30.0)
        except BaseException:
            runner.shutdown()
            for pid in pid_box:
                _reap_driver_pid(pid)
            with self._lock:
                if self._sessions.get(session_id) is opening:
                    self._sessions.pop(session_id, None)
            raise
        handle.runner = runner
        with self._lock:
            if self._sessions.get(session_id) is not opening:
                runner.shutdown()
                _reap_web_session(handle)
                raise WebError("invalid_state", "web session was closed while opening")
            self._sessions[session_id] = handle
        return summary

    def _wire_events(self, handle: _WebSession) -> None:
        cdp = handle.cdp
        cdp.send("Network.enable")
        cdp.send("Runtime.enable")
        cdp.send("Debugger.enable")
        cdp.send("Page.enable")

        def on_request(params: JsonObject) -> None:
            req = params.get("request") or {}
            url, url_truncated = _bounded_metadata(req.get("url"), _MAX_URL_BYTES)
            method, method_truncated = _bounded_metadata(
                req.get("method"), _MAX_METADATA_BYTES
            )
            resource_type, type_truncated = _bounded_metadata(
                params.get("type"), _MAX_METADATA_BYTES
            )
            entry: JsonObject = {
                "requestId": params.get("requestId"),
                "url": url,
                "method": method,
                "resourceType": resource_type,
                "status": None,
                "mimeType": None,
                # The request body is fetched on demand in network_get (like the
                # response body) rather than buffered per request; this flag is
                # what tells network_get whether that fetch is worth attempting.
                "has_post_data": bool(req.get("hasPostData") or req.get("postData")),
            }
            if url_truncated or method_truncated or type_truncated:
                entry["metadata_truncated"] = True
            request_id = str(params.get("requestId"))
            with handle.lock:
                handle.requests[request_id] = entry
                while len(handle.requests) > _MAX_REQUESTS:
                    handle.requests.popitem(last=False)
                    handle.requests_dropped += 1
                _accumulate_headers(handle.request_headers, request_id, req.get("headers"))

        def on_request_extra(params: JsonObject) -> None:
            # requestWillBeSentExtraInfo carries the headers the network stack
            # adds after the page's own (Cookie, sec-* ...); merge them into the
            # same per-request bucket so the captured request headers are whole.
            request_id = str(params.get("requestId"))
            with handle.lock:
                _accumulate_headers(handle.request_headers, request_id, params.get("headers"))

        def on_response(params: JsonObject) -> None:
            resp = params.get("response") or {}
            mime_type, mime_truncated = _bounded_metadata(
                resp.get("mimeType"), _MAX_METADATA_BYTES
            )
            headers, headers_truncated = _bounded_headers(resp.get("headers"))
            request_id = str(params.get("requestId"))
            with handle.lock:
                entry = handle.requests.get(request_id)
                if entry is not None:
                    entry["status"] = resp.get("status")
                    entry["mimeType"] = mime_type
                    if mime_truncated:
                        entry["metadata_truncated"] = True
                    handle.response_headers[request_id] = {
                        "response_headers": headers,
                        "headers_truncated": headers_truncated,
                    }
                    handle.response_headers.move_to_end(request_id)
                    while len(handle.response_headers) > _MAX_REQUESTS:
                        handle.response_headers.popitem(last=False)

        def on_script(params: JsonObject) -> None:
            url, url_truncated = _bounded_metadata(params.get("url"), _MAX_URL_BYTES)
            language, language_truncated = _bounded_metadata(
                params.get("scriptLanguage", "JavaScript"), _MAX_METADATA_BYTES
            )
            entry: JsonObject = {
                "scriptId": params.get("scriptId"),
                "url": url,
                "language": language,
            }
            if url_truncated or language_truncated:
                entry["metadata_truncated"] = True
            with handle.lock:
                handle.scripts[str(params.get("scriptId"))] = entry
                while len(handle.scripts) > _MAX_SCRIPTS:
                    handle.scripts.popitem(last=False)
                    handle.scripts_dropped += 1

        def on_console(params: JsonObject) -> None:
            text, text_truncated = _clip_console_text(params)
            entry: JsonObject = {
                "type": str(params.get("type") or "log"),
                "text": text,
            }
            if text_truncated:
                entry["text_truncated"] = True
            with handle.lock:
                if (
                    handle.console.maxlen is not None
                    and len(handle.console) == handle.console.maxlen
                ):
                    handle.console_dropped += 1
                handle.console.append(entry)

        cdp.on("Network.requestWillBeSent", on_request)
        cdp.on("Network.requestWillBeSentExtraInfo", on_request_extra)
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Debugger.scriptParsed", on_script)
        # Over CDP like the rest, not page.on("console"). The high-level event
        # hands over a ConsoleMessage whose args are remote JSHandle wrappers,
        # and nothing disposes them: measured at 120 OS handles per navigation
        # on a page logging 60 lines, growing for as long as the session lived.
        # The same information arrives here as plain data.
        cdp.on("Runtime.consoleAPICalled", on_console)

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                handle.page.goto(url, timeout=timeout * 1000.0, wait_until="domcontentloaded")
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"navigation failed: {exc}", url=url) from exc
            return {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
            }

        return self._runner(handle).call(work, timeout=timeout + 10.0)

    def close(self, session_id: str) -> JsonObject:
        with self._lock:
            handle = self._sessions.pop(session_id, None)
        if handle is None:
            return {"closed": False, "note": "no web session was open"}
        # Opening reservations are bare object() tokens. Anything else is a
        # live handle (or a test double) and must be torn down.
        if type(handle) is object:
            return {"closed": True, "note": "open was aborted"}
        runner = handle.runner
        if runner is None:
            handle.close()
            return {"closed": True}
        clean = True
        if not runner.wedged:
            # Teardown talks to the browser, so it belongs on the same thread as
            # everything else. Bounded, because close is the recovery path: it
            # has to reclaim the session even when the browser is beyond saving.
            with contextlib.suppress(WebError):
                runner.call(handle.close, timeout=20.0)
        if runner.wedged:
            clean = False
            # Playwright objects cannot be touched from this thread, and a
            # wedged runner will never run handle.close. The node driver is
            # what still holds Chromium; killing it is the only close that
            # works from here.
            _reap_web_session(handle)
        runner.shutdown()
        return {"closed": True, "clean": clean}

    def network_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        method: str | None = None,
        url_contains: str | None = None,
        resource_type: str | None = None,
        status_min: int | None = None,
        status_max: int | None = None,
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        method_f = _norm_str_filter(method)
        url_f = _norm_str_filter(url_contains)
        type_f = _norm_str_filter(resource_type)
        filtered = (
            method_f is not None
            or url_f is not None
            or type_f is not None
            or status_min is not None
            or status_max is not None
        )
        # Filter the whole capture first, then paginate the matches, so total and
        # has_more describe the filtered view the caller is actually paging.
        # dropped stays a property of the capture ring (what it already evicted),
        # not of the filter, and captured reports how many were in the ring before
        # the filter -- mirroring proxy.flows so the two surfaces read the same.
        matched = (
            [
                row
                for row in items
                if _request_matches(
                    row,
                    method=method_f,
                    url_contains=url_f,
                    resource_type=type_f,
                    status_min=status_min,
                    status_max=status_max,
                )
            ]
            if filtered
            else items
        )
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = matched[start : start + cap]
        # Bound the page by its JSON-encoded size, not just the row count: each
        # entry carries a url of up to 16 KiB, so a 1000-row window can run to
        # megabytes and be discarded whole by the transport for a ~16 KiB
        # summary. Trimming before has_more is computed keeps it honest -- a
        # budget-cut page still reports more to fetch, so the caller pages past
        # it.
        window = fit_json_list(window, reserve=_LIST_FIELD_RESERVE)[0]
        result: JsonObject = {
            "requests": window,
            "count": len(window),
            "total": len(matched),
            "offset": start,
            "has_more": start + len(window) < len(matched),
            "dropped": dropped,
        }
        if filtered:
            # total now counts only matches, so surface both the flag and the
            # pre-filter ring size to keep the narrowing visible and honest.
            result["filtered"] = True
            result["captured"] = len(items)
        return result

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entry = handle.requests.get(request_id)
            captured_headers = handle.response_headers.get(request_id)
            captured_request_headers = dict(handle.request_headers.get(request_id) or {})
        if entry is None:
            raise WebError("not_found", "unknown request id", request_id=request_id)
        # Response headers captured at Network.responseReceived (Set-Cookie, CSP,
        # CORS, redirect Location, HSTS ...) -- the security-relevant metadata a
        # body alone cannot answer. Absent when no response was seen for this id.
        header_fields: JsonObject = {"response_headers": {}, "headers_truncated": False}
        if captured_headers is not None:
            header_fields = dict(captured_headers)
        # Request headers accumulated across requestWillBeSent(+ExtraInfo): what
        # the client sent (Cookie, Authorization, custom X- headers, User-Agent).
        # Bound by encoded size once here, the same discipline as the response map.
        request_headers, request_headers_truncated = _bounded_headers(captured_request_headers)
        header_fields["request_headers"] = request_headers
        header_fields["request_headers_truncated"] = request_headers_truncated
        body = ""
        base64_encoded = False
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Network.getResponseBody", {"requestId": request_id})
            )
            body = resp.get("body", "")
            base64_encoded = bool(resp.get("base64Encoded"))
        except Exception as exc:  # noqa: BLE001
            return {**entry, **header_fields, "body_error": str(exc)}
        if not isinstance(body, str):
            body = str(body)
        inline, spill, cut = _spill_text(
            body,
            artifact_dir=artifact_dir,
            filename=f"body-{uuid4().hex}.bin",
            kind="response body",
        )
        result = dict(entry)
        result.update(header_fields)
        result["body"] = inline
        result["body_truncated"] = cut
        if spill is not None:
            result["body_path"] = str(spill)
        result["base64_encoded"] = base64_encoded
        # Request body (POST/PUT payload: the JSON/form an API call sent). Fetched
        # on demand like the response body, not buffered per request, so it does
        # not bloat the ring. Only attempted when the request carried a body; a
        # browser that has already discarded it answers with request_body_error
        # rather than failing the whole read.
        if entry.get("has_post_data"):
            try:
                post = self._runner(handle).call(
                    lambda: handle.cdp.send(
                        "Network.getRequestPostData", {"requestId": request_id}
                    )
                )
                post_data = post.get("postData", "")
                if not isinstance(post_data, str):
                    post_data = str(post_data)
                req_inline, req_spill, req_cut = _spill_text(
                    post_data,
                    artifact_dir=artifact_dir,
                    filename=f"reqbody-{uuid4().hex}.bin",
                    kind="request body",
                )
                result["request_body"] = req_inline
                result["request_body_truncated"] = req_cut
                if req_spill is not None:
                    result["request_body_path"] = str(req_spill)
            except WebError:
                raise
            except Exception as exc:  # noqa: BLE001 - post data may be discarded
                result["request_body_error"] = str(exc)
        return result

    def cookies(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)
        # Network.getAllCookies returns every cookie the browser holds for the
        # session -- not only the current document's -- so a redirect chain or a
        # third-party auth hop that set a cookie is visible, which document.cookie
        # (httpOnly-blind, current-origin-only) could never show.
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Network.getAllCookies")
            )
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001 - CDP transport may drop
            raise WebError("backend_error", f"could not read cookies: {exc}") from exc
        raw_list = resp.get("cookies") if isinstance(resp, dict) else None
        items: list[JsonObject] = []
        if isinstance(raw_list, list):
            for entry in raw_list:
                if isinstance(entry, dict):
                    items.append(_normalize_cookie(entry))
        total = len(items)
        # Bound the set by JSON-encoded size like the other list surfaces: a
        # session can hold many cookies each with a multi-KiB value, so a raw
        # dump could overrun the result budget and be discarded whole.
        window = fit_json_list(items, reserve=_LIST_FIELD_RESERVE)[0]
        return {
            "cookies": window,
            "count": len(window),
            "total": total,
            "has_more": len(window) < total,
        }

    def storage(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)
        try:
            url = self._runner(handle).call(lambda: handle.page.url)
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001 - reading page url may race a teardown
            raise WebError("backend_error", f"could not read page url: {exc}") from exc
        empty: JsonObject = {
            "origin": "",
            "local_storage": {},
            "local_storage_truncated": False,
            "session_storage": {},
            "session_storage_truncated": False,
        }
        origin = _security_origin(url)
        if origin is None:
            # about:blank / data: URL: opaque origin, no origin-keyed storage.
            return empty

        def _read(is_local: bool) -> object:
            return self._runner(handle).call(
                lambda: handle.cdp.send(
                    "DOMStorage.getDOMStorageItems",
                    {"storageId": {"securityOrigin": origin, "isLocalStorage": is_local}},
                )
            )

        try:
            self._runner(handle).call(lambda: handle.cdp.send("DOMStorage.enable"))
            local_raw = _read(True)
            session_raw = _read(False)
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001 - CDP may reject an unloaded origin
            raise WebError("backend_error", f"could not read storage: {exc}") from exc
        local_entries = local_raw.get("entries") if isinstance(local_raw, dict) else None
        session_entries = session_raw.get("entries") if isinstance(session_raw, dict) else None
        local, local_cut = _bounded_storage(local_entries)
        session, session_cut = _bounded_storage(session_entries)
        return {
            "origin": origin,
            "local_storage": local,
            "local_storage_truncated": local_cut,
            "session_storage": session,
            "session_storage_truncated": session_cut,
        }

    def console(
        self,
        session_id: str,
        *,
        limit: int = 200,
        level: str | None = None,
        text_contains: str | None = None,
    ) -> JsonObject:
        handle = self._get(session_id)
        capped = max(1, min(int(limit), _MAX_CONSOLE))
        with handle.lock:
            held = list(handle.console)
            dropped = handle.console_dropped
        level_f = _norm_str_filter(level)
        text_f = _norm_str_filter(text_contains)
        filtered = level_f is not None or text_f is not None
        # Filter the whole buffer first, then take the most-recent N of the
        # matches, so has_more describes the filtered tail the caller is actually
        # reading (not the raw ring). dropped stays a property of the capture ring
        # -- what it already evicted, independent of any filter -- and captured
        # reports the pre-filter buffer size, mirroring network_list / proxy.flows
        # so the capture surfaces read the same.
        matched = (
            [row for row in held if _console_matches(row, level=level_f, text_contains=text_f)]
            if filtered
            else held
        )
        page = matched[-capped:]
        # Bound the page by its JSON-encoded size too: each message text is
        # capped at 8 KiB, so a 2000-row page can reach ~16 MB and be discarded
        # whole by the transport for a ~16 KiB summary. This is a "last N" view
        # with no offset, so keep the most recent rows and drop the oldest of
        # the page: trim the reversed page (fit_json_list keeps a leading run)
        # and restore order. Fold the cut into has_more so a trimmed page is not
        # read as the whole recent buffer.
        kept_recent, _dropped_old, budget_cut = fit_json_list(
            list(reversed(page)), reserve=_LIST_FIELD_RESERVE
        )
        page = list(reversed(kept_recent))
        result: JsonObject = {
            "console": page,
            "count": len(page),
            "has_more": len(matched) > capped or budget_cut,
            "dropped": dropped,
        }
        if filtered:
            # The recent-N view now counts only matches, so surface both the flag
            # and the pre-filter buffer size to keep the narrowing honest.
            result["filtered"] = True
            result["captured"] = len(held)
        return result

    def scripts(
        self,
        session_id: str,
        *,
        wasm_only: bool = False,
        offset: int = 0,
        limit: int = 100,
        url_contains: str | None = None,
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            all_values = list(handle.scripts.values())
        values = all_values
        if wasm_only:
            values = [s for s in values if str(s.get("language")).lower() == "webassembly"]
        url_f = _norm_str_filter(url_contains)
        if url_f is not None:
            needle = url_f.casefold()
            values = [s for s in values if needle in str(s.get("url") or "").casefold()]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = values[start : start + cap]
        # Bound the page by encoded size too: each entry carries a url of up to
        # 16 KiB (this tool's docstring records a full list at 441 KiB), so a
        # windowed page can still outrun the budget and be discarded whole. See
        # network_list.
        window = fit_json_list(window, reserve=_LIST_FIELD_RESERVE)[0]
        result: JsonObject = {
            "scripts": window,
            "count": len(window),
            "total": len(values),
            "offset": start,
            "has_more": start + len(window) < len(values),
            "dropped": handle.scripts_dropped,
        }
        if url_f is not None:
            # total now counts only url matches, so flag the narrowing and report
            # the pre-filter ring size -- mirroring network_list. wasm_only keeps
            # its existing flag-free contract (web.wasm.list depends on it), so
            # only the url substring filter surfaces filtered/captured here.
            result["filtered"] = True
            result["captured"] = len(all_values)
        return result

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        handle = self._get(session_id)
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Debugger.getScriptSource", {"scriptId": script_id})
            )
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WebError(
                "not_found", f"cannot fetch script source: {exc}", script_id=script_id
            ) from exc
        source = resp.get("scriptSource", "")
        if not isinstance(source, str):
            source = str(source)
        inline, spill, cut = _spill_text(
            source,
            artifact_dir=artifact_dir,
            filename=f"script-{uuid4().hex}.js",
            kind="script source",
        )
        result: JsonObject = {
            "scriptId": script_id,
            "bytes": len(source.encode("utf-8", errors="replace")),
            "source": inline,
            "truncated": cut,
        }
        if spill is not None:
            result["source_path"] = str(spill)
        return result

    def dom_snapshot(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                clipped = handle.page.evaluate(
                    """(cap) => {
                        const html = document.documentElement
                          ? document.documentElement.outerHTML
                          : (document.body ? document.body.outerHTML : "");
                        const text = typeof html === "string" ? html : "";
                        return {
                          html: text.length > cap ? text.slice(0, cap) : text,
                          truncated: text.length > cap
                        };
                    }""",
                    _MAX_INLINE_BODY,
                )
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"dom snapshot failed: {exc}") from exc
            if not isinstance(clipped, dict):
                raise WebError("backend_error", "dom snapshot returned no document")
            html = clipped.get("html")
            text = html if isinstance(html, str) else ""
            # Bound the inline HTML by encoded size too, not only the raw char
            # cap: a page controls its own DOM, and an escape-heavy 200 KB
            # snapshot could push the reply past the result budget and be
            # discarded whole. There is no spill here, so this only trims the
            # inline and flags it -- the full DOM was never retained.
            html_inline, _html_bytes, html_cut = fit_json_text(
                text[:_MAX_INLINE_BODY], reserve=_WEB_FIELD_RESERVE
            )
            return {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
                "html": html_inline,
                "truncated": (
                    bool(clipped.get("truncated"))
                    or len(text) > _MAX_INLINE_BODY
                    or html_cut
                ),
            }

        return self._runner(handle).call(work)

    def screenshot(self, session_id: str, out_path: Path, *, full_page: bool = False) -> JsonObject:
        handle = self._get(session_id)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        def work() -> JsonObject:
            try:
                handle.page.screenshot(path=str(out_path), full_page=full_page)
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"screenshot failed: {exc}") from exc
            size, over = capped_file_size(out_path, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
            if over:
                raise WebError(
                    "too_large",
                    "screenshot exceeds capture cap",
                    size=size,
                    cap=UNREGISTERED_CAPTURE_MAX_BYTES,
                )
            return {"path": str(out_path), "size": size}

        return self._runner(handle).call(work)

    def har_export(self, session_id: str, out_path: Path) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entries = [
                {
                    "request": {"method": e.get("method"), "url": e.get("url")},
                    "response": {
                        "status": e.get("status") or 0,
                        "content": {"mimeType": e.get("mimeType") or ""},
                    },
                    "_resourceType": e.get("resourceType"),
                }
                for e in handle.requests.values()
            ]
        import json

        har = {
            "log": {"version": "1.2", "creator": {"name": "headless-re-mcp"}, "entries": entries}
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(har, ensure_ascii=False)
        truncated = False
        encoded = text.encode("utf-8")
        while entries and len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            drop = max(1, len(entries) // 8)
            del entries[-drop:]
            har["log"]["entries"] = entries
            text = json.dumps(har, ensure_ascii=False)
            encoded = text.encode("utf-8")
            truncated = True
        if len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise WebError(
                "too_large",
                "HAR export exceeds capture cap",
                size=len(encoded),
                cap=UNREGISTERED_CAPTURE_MAX_BYTES,
            )
        out_path.write_text(text, encoding="utf-8")
        return {
            "path": str(out_path),
            "entry_count": len(entries),
            "truncated": truncated,
            "size": len(encoded),
        }

    def close_all(self) -> None:
        with self._lock:
            session_ids = list(self._sessions)
        for session_id in session_ids:
            with contextlib.suppress(WebError):
                self.close(session_id)


def _safe_title(page: Any) -> str:
    try:
        return _bounded_metadata(page.title(), _MAX_METADATA_BYTES)[0]
    except Exception:  # noqa: BLE001
        return ""


def _playwright_driver_pid(playwright: Any) -> int | None:
    """PID of the node driver that owns Chromium.

    Playwright does not publish this. The private chain is the only handle a
    wedged session has left, because the objects themselves cannot be touched
    from any thread other than the one that created them.
    """
    current: Any = playwright
    for attr in ("_impl_obj", "_connection", "_transport", "_proc"):
        current = getattr(current, attr, None)
        if current is None:
            return None
    pid = getattr(current, "pid", None)
    return pid if isinstance(pid, int) and pid > 0 else None


_DRIVER_IMAGE_MARKERS = ("node", "chromium", "chrome", "playwright")


def _reap_driver_pid(pid: int | None) -> None:
    if not isinstance(pid, int) or pid <= 0:
        return
    image = (process_image_path(pid) or "").casefold()
    if not image or not any(marker in image for marker in _DRIVER_IMAGE_MARKERS):
        return
    terminate_pid_tree(pid)


def _reap_web_session(handle: _WebSession) -> None:
    _reap_driver_pid(getattr(handle, "driver_pid", None))
