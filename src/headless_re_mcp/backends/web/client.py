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

import base64
import binascii
import contextlib
import queue
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

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
# Header maps carry the RE-relevant metadata (auth, cookies, content type, CORS),
# but a set can be large (long cookies/tokens), so both the count and each value
# are bounded before entering the per-request ring.
_MAX_HEADERS = 100
_MAX_HEADER_VALUE_BYTES = 4 * 1024
# A context's cookie jar: bounded on count (an ad-heavy page can set dozens per
# domain) and, like headers, on each value (session JWTs run to kilobytes).
_MAX_COOKIES = 500
# Web Storage (localStorage/sessionStorage) per store: an origin can hold ~5-10 MB,
# so cap the number of keys returned and each value's length. The in-page slice
# below keeps a multi-megabyte value from ever crossing the CDP bridge; the byte
# bound here is the one that decides what the reply carries.
_MAX_STORAGE_ITEMS = 500
_MAX_STORAGE_VALUE_BYTES = 4 * 1024
# Chars, not bytes: a coarse in-page ceiling so the driver never ships an entire
# multi-megabyte value across the bridge only for Python to clip it. Set well
# above the byte cap so the byte cap stays the effective one for normal values.
_MAX_STORAGE_VALUE_CHARS = 16 * 1024
# Kept in the per-request entry but stripped from network.list rows so a page of
# the list stays cheap; network.get returns them in full.
_HEADER_KEYS = ("request_headers", "response_headers")
# network.stats returns the top hosts and content types rather than every one; a
# single page can touch hundreds of distinct hosts (ad/analytics/CDN fan-out),
# and the summary is for triage, not a second full listing.
_MAX_STATS_HOSTS = 50
_MAX_STATS_CONTENT_TYPES = 50
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


def _request_matches(
    entry: JsonObject,
    method: str | None,
    url_contains: str | None,
    status: int | None,
    resource_type: str | None,
    failed: bool | None,
) -> bool:
    """Whether a captured request passes the (already-non-None) filters.

    method and resource_type are exact, case-insensitive matches (GET is not
    POST, ``script`` is not ``xhr``); url_contains is a case-insensitive
    substring so a host or path fragment matches its URL; status is an exact
    integer, and a request with no status yet (still pending, or one that
    failed before a response) never matches a status filter rather than
    matching everything. failed selects only blocked/aborted requests when
    true, and only requests that were not flagged failed when false.
    """
    if method is not None and str(entry.get("method", "")).upper() != method.upper():
        return False
    if resource_type is not None and (
        str(entry.get("resourceType", "")).casefold() != resource_type.casefold()
    ):
        return False
    if url_contains is not None and (
        url_contains.casefold() not in str(entry.get("url", "")).casefold()
    ):
        return False
    if status is not None:
        entry_status = entry.get("status")
        if not isinstance(entry_status, int) or entry_status != status:
            return False
    return failed is None or bool(entry.get("failed")) is failed


def _console_matches(entry: JsonObject, level: str | None, contains: str | None) -> bool:
    """Whether a console entry passes the (already-non-None) filters.

    level is an exact, case-insensitive match on the entry's CDP type
    (log/info/warning/error/debug/...); an uncaught exception carries type
    error, so level=error selects it too. contains is a case-insensitive
    substring of the message text.
    """
    if level is not None and str(entry.get("type", "")).casefold() != level.casefold():
        return False
    return contains is None or contains.casefold() in str(entry.get("text", "")).casefold()


def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    payload = text.encode("utf-8", errors="replace")
    if len(payload) <= max_bytes:
        return text, False
    return payload[:max_bytes].decode("utf-8", errors="ignore"), True


def _bound_storage_area(area: object) -> JsonObject:
    """Bound one Web Storage area (the JS dump of localStorage/sessionStorage).

    ``area`` is the ``{entries: [[k, v], ...], total, error?}`` shape produced
    in-page. Keys and values are re-bounded here (the in-page slice is only a
    coarse transfer guard), and ``total`` vs the returned count drives has_more
    so a store cut at the item cap is never read as the whole store.
    """
    if not isinstance(area, dict):
        return {"items": [], "count": 0, "total": 0, "has_more": False}
    raw_entries = area.get("entries")
    entries = raw_entries if isinstance(raw_entries, list) else []
    items: list[JsonObject] = []
    for pair in entries:
        if not (isinstance(pair, (list, tuple)) and len(pair) == 2):
            continue
        key, key_cut = _bounded_metadata(pair[0], _MAX_METADATA_BYTES)
        value, value_cut = _bounded_metadata(pair[1], _MAX_STORAGE_VALUE_BYTES)
        item: JsonObject = {"key": key, "value": value}
        if key_cut or value_cut:
            item["metadata_truncated"] = True
        items.append(item)
    total = area.get("total")
    total_int = total if isinstance(total, int) and total >= 0 else len(items)
    out: JsonObject = {
        "items": items,
        "count": len(items),
        "total": total_int,
        "has_more": total_int > len(items),
    }
    error = area.get("error")
    if isinstance(error, str) and error:
        # The origin denied storage access (opaque origin, storage disabled):
        # say so rather than reporting an empty store as if it were empty.
        out["error"] = _bounded_metadata(error, _MAX_METADATA_BYTES)[0]
    return out


def _bounded_headers(raw: object) -> tuple[dict[str, str], bool]:
    """Bound a CDP header map for storage in the capture ring.

    A header set can be large (long cookies, bearer tokens), so cap the number
    of headers and the length of each name/value; one response must not be able
    to balloon a request's footprint. Returns the bounded map and whether
    anything was dropped or clipped.
    """
    if not isinstance(raw, dict):
        return {}, False
    out: dict[str, str] = {}
    truncated = False
    for name, value in raw.items():
        if len(out) >= _MAX_HEADERS:
            truncated = True
            break
        key, key_cut = _bounded_metadata(name, _MAX_METADATA_BYTES)
        val, val_cut = _bounded_metadata(value, _MAX_HEADER_VALUE_BYTES)
        out[key] = val
        if key_cut or val_cut:
            truncated = True
    return out, truncated


def _har_headers(mapping: object) -> list[JsonObject]:
    """A captured header map as HAR's name/value array (empty when none)."""
    if not isinstance(mapping, dict):
        return []
    return [{"name": str(name), "value": str(value)} for name, value in mapping.items()]


def _har_query_string(url: str) -> list[JsonObject]:
    """The URL's query as HAR's name/value array; a bad URL yields an empty one."""
    try:
        query = urlsplit(url).query
    except (ValueError, TypeError):
        return []
    return [
        {"name": name, "value": value}
        for name, value in parse_qsl(query, keep_blank_values=True)
    ]


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


def _location_fields(source: JsonObject) -> JsonObject:
    """Structured origin (url/line/column/function) of a console line or error.

    Chromium hands both ``Runtime.consoleAPICalled`` and
    ``Runtime.exceptionThrown`` a ``stackTrace`` whose first ``callFrame`` is the
    call site; an exception additionally carries ``url``/``lineNumber`` at the
    top of ``exceptionDetails``. Without this an analyst sees the message text
    but not *where* it came from -- useless for locating the offending script.

    CDP line/column numbers are 0-based; report 1-based to match what DevTools
    and a printed stack trace show. Strings are bounded like every other piece
    of page-controlled metadata so a hostile page cannot bloat the ring.
    """
    url = ""
    line: object = None
    column: object = None
    function = ""
    frames = ((source.get("stackTrace") or {}).get("callFrames")) or []
    if frames and isinstance(frames[0], dict):
        top = frames[0]
        url = str(top.get("url") or "")
        line = top.get("lineNumber")
        column = top.get("columnNumber")
        function = str(top.get("functionName") or "")
    # An exceptionDetails record pins the throw site even when no frame is set.
    if not url:
        url = str(source.get("url") or "")
    if not isinstance(line, int):
        line = source.get("lineNumber")
    if not isinstance(column, int):
        column = source.get("columnNumber")
    out: JsonObject = {}
    if url:
        out["url"] = _bounded_metadata(url, _MAX_URL_BYTES)[0]
    if isinstance(line, int) and line >= 0:
        out["line"] = line + 1
    if isinstance(column, int) and column >= 0:
        out["column"] = column + 1
    if function:
        out["function"] = _bounded_metadata(function, _MAX_METADATA_BYTES)[0]
    return out


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
    if size <= _MAX_INLINE_BODY:
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
    preview = payload[:_MAX_INLINE_BODY].decode("utf-8", errors="ignore")
    return preview, out, True


def _spill_bytes(
    payload: bytes,
    *,
    artifact_dir: Path,
    filename: str,
    kind: str,
) -> tuple[int, Path]:
    """Write a binary blob (e.g. a Wasm module) to the session artifact dir.

    Binary payloads are never inlined -- they always land in a file so a tool
    like ``wasm.wat`` can read them back. Refuses past the capture cap.
    """
    size = len(payload)
    if size > UNREGISTERED_CAPTURE_MAX_BYTES:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=size,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
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
    return size, out


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
            }
            # The body itself is fetched on demand in network_get (it can be
            # large, and there are up to _MAX_REQUESTS of these); record only
            # that one exists so the fetch is not attempted on plain GETs.
            if req.get("hasPostData") or req.get("postData") is not None:
                entry["has_request_body"] = True
            headers, headers_truncated = _bounded_headers(req.get("headers"))
            if headers:
                entry["request_headers"] = headers
            if url_truncated or method_truncated or type_truncated or headers_truncated:
                entry["metadata_truncated"] = True
            with handle.lock:
                handle.requests[str(params.get("requestId"))] = entry
                while len(handle.requests) > _MAX_REQUESTS:
                    handle.requests.popitem(last=False)
                    handle.requests_dropped += 1

        def on_response(params: JsonObject) -> None:
            resp = params.get("response") or {}
            mime_type, mime_truncated = _bounded_metadata(
                resp.get("mimeType"), _MAX_METADATA_BYTES
            )
            headers, headers_truncated = _bounded_headers(resp.get("headers"))
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    entry["status"] = resp.get("status")
                    entry["mimeType"] = mime_type
                    if headers:
                        entry["response_headers"] = headers
                    if mime_truncated or headers_truncated:
                        entry["metadata_truncated"] = True

        def on_loading_failed(params: JsonObject) -> None:
            # A blocked/aborted request (CSP, CORS, net::ERR_*, cancellation)
            # never yields a responseReceived, so without this it would sit at
            # status None -- indistinguishable from pending, with the reason
            # lost. Mark it failed and keep the error text CDP hands us.
            error_text, err_truncated = _bounded_metadata(
                params.get("errorText"), _MAX_METADATA_BYTES
            )
            blocked, blocked_truncated = _bounded_metadata(
                params.get("blockedReason"), _MAX_METADATA_BYTES
            )
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    entry["failed"] = True
                    entry["error_text"] = error_text
                    if params.get("canceled"):
                        entry["canceled"] = True
                    if blocked:
                        entry["blocked_reason"] = blocked
                    if err_truncated or blocked_truncated:
                        entry["metadata_truncated"] = True

        def on_data_received(params: JsonObject) -> None:
            # CDP streams the body in chunks; summing the chunk lengths is the
            # only way to know a response's size without fetching the whole
            # body. dataLength is the decoded (post-gzip) size, encodedDataLength
            # the bytes actually on the wire.
            data_len = params.get("dataLength")
            enc_len = params.get("encodedDataLength")
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is None:
                    return
                if isinstance(data_len, int) and data_len >= 0:
                    entry["response_size"] = int(entry.get("response_size", 0)) + data_len
                if isinstance(enc_len, int) and enc_len >= 0:
                    entry["response_encoded_size"] = (
                        int(entry.get("response_encoded_size", 0)) + enc_len
                    )

        def on_loading_finished(params: JsonObject) -> None:
            # The authoritative total transfer size (headers + encoded body),
            # and the marker that the response completed rather than stalling.
            total = params.get("encodedDataLength")
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is None:
                    return
                entry["finished"] = True
                if isinstance(total, int | float) and total >= 0:
                    entry["transfer_size"] = int(total)
                entry.setdefault("response_size", 0)

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

        def _append_console(entry: JsonObject) -> None:
            with handle.lock:
                if (
                    handle.console.maxlen is not None
                    and len(handle.console) == handle.console.maxlen
                ):
                    handle.console_dropped += 1
                handle.console.append(entry)

        def on_console(params: JsonObject) -> None:
            text, text_truncated = _clip_console_text(params)
            entry: JsonObject = {
                "type": str(params.get("type") or "log"),
                "text": text,
            }
            if text_truncated:
                entry["text_truncated"] = True
            entry.update(_location_fields(params))
            _append_console(entry)

        def on_exception(params: JsonObject) -> None:
            # Uncaught errors never come through consoleAPICalled; dropping them
            # meant web.console hid every unhandled exception and stack trace,
            # which is often the most useful line on the page for an analyst.
            details = params.get("exceptionDetails")
            if not isinstance(details, dict):
                return
            exception = details.get("exception")
            raw = ""
            if isinstance(exception, dict):
                raw = str(exception.get("description") or exception.get("value") or "")
            if not raw:
                raw = str(details.get("text") or "Uncaught exception")
            text, text_truncated = _bounded_metadata(raw, _MAX_CONSOLE_TEXT)
            entry: JsonObject = {"type": "error", "text": text, "source": "exception"}
            if text_truncated:
                entry["text_truncated"] = True
            entry.update(_location_fields(details))
            _append_console(entry)

        cdp.on("Network.requestWillBeSent", on_request)
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Network.dataReceived", on_data_received)
        cdp.on("Network.loadingFinished", on_loading_finished)
        cdp.on("Network.loadingFailed", on_loading_failed)
        cdp.on("Debugger.scriptParsed", on_script)
        # Over CDP like the rest, not page.on("console"). The high-level event
        # hands over a ConsoleMessage whose args are remote JSHandle wrappers,
        # and nothing disposes them: measured at 120 OS handles per navigation
        # on a page logging 60 lines, growing for as long as the session lived.
        # The same information arrives here as plain data.
        cdp.on("Runtime.consoleAPICalled", on_console)
        cdp.on("Runtime.exceptionThrown", on_exception)

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
        status: int | None = None,
        resource_type: str | None = None,
        failed: bool | None = None,
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        # ``dropped`` is the ring-eviction count for the whole capture, measured
        # against every recorded request before any filter narrows the view, so a
        # filtered page cannot misreport how much history the ring has lost.
        unfiltered_total = len(items)
        filtered = any(
            v is not None for v in (method, url_contains, status, resource_type, failed)
        )
        if filtered:
            # Narrow before paginating so the pagination fields describe the set
            # the caller is actually walking. Finding one XHR among thousands of
            # requests otherwise meant paging the whole capture by hand.
            items = [
                row
                for row in items
                if _request_matches(row, method, url_contains, status, resource_type, failed)
            ]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        # Headers live on the entry for network.get, but a list page must stay
        # cheap, so hand back copies without them.
        slim = [{k: v for k, v in row.items() if k not in _HEADER_KEYS} for row in window]
        result: JsonObject = {
            "requests": slim,
            "count": len(slim),
            "total": len(items),
            "offset": start,
            "has_more": start + len(slim) < len(items),
            "dropped": dropped,
        }
        if filtered:
            # total already reports the matched count; unfiltered_total keeps the
            # size of the whole capture visible so a small match is not read as a
            # small capture.
            result["filtered"] = True
            result["unfiltered_total"] = unfiltered_total
        return result

    def network_stats(self, session_id: str) -> JsonObject:
        """Fold the whole request capture into a triage summary.

        network.list is a paged listing; on a page with hundreds of requests a
        caller had to walk every page to learn what hosts, methods, statuses,
        resource types and content types are present before it could sensibly
        filter. This folds the ring once into counts: by method, by status class
        (2xx/4xx/...), by resource type, the top hosts and content types (capped,
        with the distinct totals so a trimmed list is visible), and how many
        requests failed, carried a request body, finished, or have no status yet.
        dropped mirrors network.list: the ring evictions the summary can no
        longer see.
        """
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        by_method: dict[str, int] = {}
        by_status_class: dict[str, int] = {}
        by_resource_type: dict[str, int] = {}
        host_counts: dict[str, int] = {}
        content_counts: dict[str, int] = {}
        failed = with_request_body = finished = no_status = 0
        for entry in items:
            method = (str(entry.get("method", "") or "")).upper() or "UNKNOWN"
            by_method[method] = by_method.get(method, 0) + 1
            status = entry.get("status")
            if isinstance(status, int):
                cls = f"{status // 100}xx"
                by_status_class[cls] = by_status_class.get(cls, 0) + 1
            else:
                no_status += 1
            rtype = str(entry.get("resourceType", "") or "")
            if rtype:
                by_resource_type[rtype] = by_resource_type.get(rtype, 0) + 1
            host = urlsplit(str(entry.get("url", "") or "")).netloc
            if host:
                host_counts[host] = host_counts.get(host, 0) + 1
            # Drop the ``; charset=...`` parameter so the same media type is one
            # bucket, not several.
            ctype = str(entry.get("mimeType", "") or "").split(";")[0].strip().lower()
            if ctype:
                content_counts[ctype] = content_counts.get(ctype, 0) + 1
            if entry.get("failed"):
                failed += 1
            if entry.get("has_request_body"):
                with_request_body += 1
            if entry.get("finished"):
                finished += 1

        def _top(counts: dict[str, int], key: str, cap: int) -> list[JsonObject]:
            ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            return [{key: name, "count": count} for name, count in ranked[:cap]]

        return {
            "total": len(items),
            "dropped": dropped,
            "by_method": by_method,
            "by_status_class": by_status_class,
            "by_resource_type": by_resource_type,
            "top_hosts": _top(host_counts, "host", _MAX_STATS_HOSTS),
            "host_count": len(host_counts),
            "top_content_types": _top(content_counts, "content_type", _MAX_STATS_CONTENT_TYPES),
            "content_type_count": len(content_counts),
            "failed": failed,
            "with_request_body": with_request_body,
            "finished": finished,
            "no_status": no_status,
        }

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entry = handle.requests.get(request_id)
        if entry is None:
            raise WebError("not_found", "unknown request id", request_id=request_id)
        body = ""
        base64_encoded = False
        try:
            resp = self._runner(handle).call(
                lambda: handle.cdp.send("Network.getResponseBody", {"requestId": request_id})
            )
            body = resp.get("body", "")
            base64_encoded = bool(resp.get("base64Encoded"))
        except Exception as exc:  # noqa: BLE001
            return {**entry, "body_error": str(exc)}
        if not isinstance(body, str):
            body = str(body)
        result = dict(entry)
        result["base64_encoded"] = base64_encoded
        if base64_encoded:
            # CDP returns a binary response (image, font, wasm, protobuf, any
            # gzip'd or non-text body) as base64 text. Spilling that text into
            # a .bin file -- as this did -- meant body_path held base64, not the
            # resource: anything that read it back (save the image, parse the
            # protobuf, feed the module to wasm.*) got the wrong bytes. Decode
            # first and spill the *bytes*, mirroring the wasm-module handling.
            try:
                raw = base64.b64decode(body, validate=False)
            except (ValueError, binascii.Error) as exc:
                result["body"] = ""
                result["body_truncated"] = False
                result["body_error"] = f"failed to decode base64 body: {exc}"
            else:
                size, out = _spill_bytes(
                    raw,
                    artifact_dir=artifact_dir,
                    filename=f"body-{uuid4().hex}.bin",
                    kind="response body",
                )
                result["body_path"] = str(out)
                result["body_bytes"] = size
                # A bounded base64 preview keeps a small binary inspectable
                # inline without a second read; body itself stays empty because
                # the payload is not text.
                result["body"] = ""
                result["body_base64"] = base64.b64encode(
                    raw[:_MAX_INLINE_BODY]
                ).decode("ascii")
                result["body_base64_truncated"] = size > _MAX_INLINE_BODY
                result["body_truncated"] = False
        else:
            inline, spill, cut = _spill_text(
                body,
                artifact_dir=artifact_dir,
                filename=f"body-{uuid4().hex}.bin",
                kind="response body",
            )
            result["body"] = inline
            result["body_truncated"] = cut
            if spill is not None:
                result["body_path"] = str(spill)
        # The request payload (an XHR/fetch JSON body, a form POST) is often the
        # point of the capture; fetch it too when the request carried one, inline
        # when small and spilled when large, mirroring the response body.
        if entry.get("has_request_body"):
            try:
                sent = self._runner(handle).call(
                    lambda: handle.cdp.send(
                        "Network.getRequestPostData", {"requestId": request_id}
                    )
                )
                req_body = sent.get("postData", "")
                if not isinstance(req_body, str):
                    req_body = str(req_body)
                r_inline, r_spill, r_cut = _spill_text(
                    req_body,
                    artifact_dir=artifact_dir,
                    filename=f"reqbody-{uuid4().hex}.bin",
                    kind="request body",
                )
                result["request_body"] = r_inline
                result["request_body_truncated"] = r_cut
                if r_spill is not None:
                    result["request_body_path"] = str(r_spill)
            except Exception as exc:  # noqa: BLE001 - a missing body is not fatal
                result["request_body_error"] = str(exc)
        return result

    def console(
        self,
        session_id: str,
        *,
        limit: int = 200,
        level: str | None = None,
        contains: str | None = None,
    ) -> JsonObject:
        handle = self._get(session_id)
        capped = max(1, min(int(limit), _MAX_CONSOLE))
        with handle.lock:
            held = list(handle.console)
            dropped = handle.console_dropped
        # dropped is the whole-ring eviction count, measured before any filter
        # narrows the view, so a filtered page cannot misreport lost history.
        unfiltered_total = len(held)
        filtered = level is not None or contains is not None
        if filtered:
            # Narrow before taking the tail so the page is the most recent
            # matches -- hunting the one error in thousands of debug lines
            # otherwise meant paging the whole ring by hand.
            held = [entry for entry in held if _console_matches(entry, level, contains)]
        page = held[-capped:]
        result: JsonObject = {
            "console": page,
            "count": len(page),
            "has_more": len(held) > capped,
            "dropped": dropped,
        }
        if filtered:
            # has_more/count describe the matched subset; unfiltered_total keeps
            # the whole ring's size visible so a small match is not read as a
            # small console.
            result["filtered"] = True
            result["unfiltered_total"] = unfiltered_total
        return result

    def cookies(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                raw = handle.context.cookies()
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"cookie read failed: {exc}") from exc
            items: list[JsonObject] = []
            has_more = False
            for cookie in raw or []:
                if len(items) >= _MAX_COOKIES:
                    has_more = True
                    break
                if not isinstance(cookie, dict):
                    continue
                name, name_cut = _bounded_metadata(cookie.get("name"), _MAX_METADATA_BYTES)
                # The value is the payload an analyst is usually after (auth
                # tokens, session ids) -- return it, but bounded like a header
                # value so a kilobyte JWT cannot bloat the reply unbounded.
                value, value_cut = _bounded_metadata(cookie.get("value"), _MAX_HEADER_VALUE_BYTES)
                entry: JsonObject = {
                    "name": name,
                    "value": value,
                    "domain": _bounded_metadata(cookie.get("domain"), _MAX_METADATA_BYTES)[0],
                    "path": _bounded_metadata(cookie.get("path"), _MAX_METADATA_BYTES)[0],
                    "http_only": bool(cookie.get("httpOnly")),
                    "secure": bool(cookie.get("secure")),
                }
                same_site = cookie.get("sameSite")
                if same_site:
                    entry["same_site"] = _bounded_metadata(same_site, _MAX_METADATA_BYTES)[0]
                expires = cookie.get("expires")
                if isinstance(expires, int | float) and expires >= 0:
                    # Session cookies come back as -1; only surface a real expiry.
                    entry["expires"] = expires
                if name_cut or value_cut:
                    entry["metadata_truncated"] = True
                items.append(entry)
            return {"cookies": items, "count": len(items), "has_more": has_more}

        return self._runner(handle).call(work)

    def storage(self, session_id: str) -> JsonObject:
        handle = self._get(session_id)

        # Read both Web Storage areas in-page. Each area is fetched behind a
        # getter so a SecurityError on `window.localStorage` (opaque origins,
        # storage disabled) degrades to an empty area with a reason instead of
        # throwing the whole call. Values are sliced in-page so a multi-megabyte
        # entry never crosses the bridge; count and value bytes are re-bounded
        # in Python below.
        script = """
        (cfg) => {
          const fail = (e) => ({ entries: [], total: 0, error: String(e) });
          const dump = (getStore) => {
            let store;
            try { store = getStore(); } catch (e) { return fail(e); }
            if (!store) { return { entries: [], total: 0 }; }
            let total = 0;
            try { total = store.length; } catch (e) { return fail(e); }
            const out = [];
            const n = Math.min(total, cfg.maxItems);
            for (let i = 0; i < n; i++) {
              let key, val;
              try { key = store.key(i); val = store.getItem(key); } catch (e) { continue; }
              if (key == null) { continue; }
              if (val == null) { val = ""; }
              out.push([String(key), String(val).slice(0, cfg.maxValueChars)]);
            }
            return { entries: out, total: total };
          };
          let origin = "";
          try { origin = window.location.origin; } catch (e) { origin = ""; }
          return {
            origin: origin,
            local: dump(() => window.localStorage),
            session: dump(() => window.sessionStorage),
          };
        }
        """

        def work() -> JsonObject:
            try:
                raw = handle.page.evaluate(
                    script,
                    {
                        "maxItems": _MAX_STORAGE_ITEMS,
                        "maxValueChars": _MAX_STORAGE_VALUE_CHARS,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"storage read failed: {exc}") from exc
            if not isinstance(raw, dict):
                raw = {}
            result: JsonObject = {
                "origin": _bounded_metadata(raw.get("origin"), _MAX_URL_BYTES)[0],
                "local": _bound_storage_area(raw.get("local")),
                "session": _bound_storage_area(raw.get("session")),
            }
            return result

        return self._runner(handle).call(work)

    def scripts(
        self,
        session_id: str,
        *,
        wasm_only: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            values = list(handle.scripts.values())
        if wasm_only:
            values = [s for s in values if str(s.get("language")).lower() == "webassembly"]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = values[start : start + cap]
        return {
            "scripts": window,
            "count": len(window),
            "total": len(values),
            "offset": start,
            "has_more": start + len(window) < len(values),
            "dropped": handle.scripts_dropped,
        }

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
        # A WebAssembly module returns its bytes in ``bytecode`` (base64), not
        # ``scriptSource`` (which is empty for Wasm). Without this, listing a
        # Wasm module over web.wasm.list gave no way to get the bytes for the
        # wasm.* tools. Spill the module so it can be analysed offline.
        bytecode = resp.get("bytecode")
        if isinstance(bytecode, str) and bytecode:
            try:
                raw = base64.b64decode(bytecode, validate=True)
            except (ValueError, binascii.Error):
                raw = b""
            if raw:
                wasm_size, wasm_out = _spill_bytes(
                    raw,
                    artifact_dir=artifact_dir,
                    filename=f"module-{uuid4().hex}.wasm",
                    kind="wasm module",
                )
                result["is_wasm"] = True
                result["wasm_bytes"] = wasm_size
                result["wasm_path"] = str(wasm_out)
        return result

    def dom_snapshot(self, session_id: str, artifact_dir: Path | None = None) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                html = handle.page.content()
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"dom snapshot failed: {exc}") from exc
            if not isinstance(html, str):
                html = str(html)
            result: JsonObject = {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
                "bytes": len(html.encode("utf-8", errors="replace")),
            }
            if artifact_dir is not None:
                # The DOM was previously sliced to 200 KB in the browser and the
                # rest thrown away: a real SPA's markup runs well past that, so
                # the snapshot -- often the whole point of the capture -- came
                # back cut with no way to reach the full document. Inline a
                # preview and spill the rest to a file (like web.script.source).
                inline, spill, cut = _spill_text(
                    html,
                    artifact_dir=artifact_dir,
                    filename=f"dom-{uuid4().hex}.html",
                    kind="dom snapshot",
                )
                result["html"] = inline
                result["truncated"] = cut
                if spill is not None:
                    result["html_path"] = str(spill)
            else:
                # A direct backend caller with no artifact area: inline a
                # bounded prefix and still flag when the page was larger.
                payload = html.encode("utf-8", errors="replace")
                result["html"] = payload[:_MAX_INLINE_BODY].decode("utf-8", errors="ignore")
                result["truncated"] = len(payload) > _MAX_INLINE_BODY
            return result

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
        # A HAR whose entries omit startedDateTime/timings/cookies/headers/
        # queryString/cache is not valid HAR 1.2 -- the viewers this export
        # feeds (DevTools Import HAR, HAR Analyzer, har-validator) reject it.
        # Emit conformant entries and populate the request/response headers now
        # that they are captured, so the export is actually loadable.
        started = datetime.now(UTC).isoformat()
        with handle.lock:
            entries = [
                {
                    "startedDateTime": started,
                    "time": 0,
                    "request": {
                        "method": e.get("method") or "",
                        "url": e.get("url") or "",
                        "httpVersion": "HTTP/1.1",
                        "cookies": [],
                        "headers": _har_headers(e.get("request_headers")),
                        "queryString": _har_query_string(e.get("url") or ""),
                        "headersSize": -1,
                        "bodySize": -1,
                    },
                    "response": {
                        "status": e.get("status") or 0,
                        "statusText": "",
                        "httpVersion": "HTTP/1.1",
                        "cookies": [],
                        "headers": _har_headers(e.get("response_headers")),
                        "content": {
                            "size": int(e.get("response_size") or 0),
                            "mimeType": e.get("mimeType") or "",
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": int(e["response_encoded_size"])
                        if e.get("response_encoded_size") is not None
                        else -1,
                    },
                    "cache": {},
                    "timings": {"send": 0, "wait": 0, "receive": 0},
                    "_resourceType": e.get("resourceType"),
                    "_transferSize": int(e["transfer_size"])
                    if e.get("transfer_size") is not None
                    else -1,
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
