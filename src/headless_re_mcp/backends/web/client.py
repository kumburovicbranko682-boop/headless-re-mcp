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
from pathlib import Path
from typing import Any, TypeVar
from uuid import uuid4

from headless_re_mcp.backends.common.har import har_entry, iso_from_epoch, serialize_har
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
# Playwright enforces its own timeouts inside the driver process, so they stop
# existing the moment the driver does. This is the outer bound that keeps a call
# from parking a worker thread forever when that happens.
_CALL_TIMEOUT = 60.0
# Ceiling for a caller-supplied navigation timeout, matching the web.open /
# web.navigate tool schema (``0 < timeout <= 120``). See ``_bound_nav_timeout``.
_MAX_NAV_TIMEOUT_S = 120.0
_OPENING = object()


class WebError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _is_timeout(exc: BaseException) -> bool:
    """Whether a browser exception is a deadline, not a hard failure.

    Playwright raises ``TimeoutError`` (a distinct class whose name says timeout)
    when ``goto`` outruns its budget; a DNS/refused/protocol failure raises the
    plain ``Error`` instead. Keying off the class name (and the "timed out"
    phrasing) is the same version-tolerant check the adb and frida backends use,
    and it needs no import of the optional playwright package. Classifying the
    deadline as ``code="timeout"`` -- not the catch-all ``backend_error`` -- lets
    the caller tell "the page was slow, retry" from "this will never load", and
    the envelope marks the timeout retryable to match every other timeout path.
    """
    name = type(exc).__name__.lower()
    return "timeout" in name or "timed out" in str(exc).lower()


def _bound_nav_timeout(timeout: float) -> float:
    """Clamp a caller navigation timeout at the backend boundary.

    The tool schema declares ``0 < timeout <= 120``, but the agent transport
    invokes handlers straight from model arguments with no schema enforcement
    (``CommandCatalog.invoke`` -> ``spec.handler(**arguments)``), the same gap
    frida guards with ``_bound_timeout``. A non-positive value would reach
    ``Future.result(timeout<=0)``, which returns immediately and flips the
    runner to ``_wedged`` -- bricking a healthy session until ``web.close`` --
    while a huge one would park the session thread and a pool worker for as long
    as the page took. Reject the first and cap the second before any work is
    queued, so a stray timeout can never wedge a live browser.

    ``value != value`` catches NaN too: it is not ``<= 0`` (every NaN comparison
    is False) and ``min(nan, ceiling)`` stays nan, so a NaN deadline would sail
    past the plain guard into exactly the ``Future.result`` that wedges the
    session -- the very outcome this function exists to prevent. The canonical
    ``clamp_cli_timeout`` rejects NaN the same way.
    """
    value = float(timeout)
    if value != value or value <= 0:
        raise WebError("invalid_params", "timeout must be positive")
    return min(value, _MAX_NAV_TIMEOUT_S)


def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    payload = text.encode("utf-8", errors="replace")
    if len(payload) <= max_bytes:
        return text, False
    return payload[:max_bytes].decode("utf-8", errors="ignore"), True


def _cdp_phase_timings(timing: Any) -> JsonObject:
    """HAR send/wait (ms) from CDP's ResourceTiming, the way Chrome's HAR does.

    ``Network.responseReceived`` carries ``response.timing``, whose ``*Start`` /
    ``*End`` members are millisecond ticks relative to ``requestTime`` -- so a
    difference between two of them is already a duration in ms. ``send`` is the
    request write (``sendEnd - sendStart``) and ``wait`` is the server's think
    time until the first response header (``receiveHeadersEnd - sendEnd``), the
    two phases this event alone can measure and exactly what Chrome DevTools'
    own HAR export derives from this object. ``receive`` (body download) ends at
    ``loadingFinished``, a separate event, so it is not measured here: the
    response handler stores this timing's headers-received instant (see
    ``_receive_anchor``) and the finished handler computes receive from it. Only
    a phase whose both offsets are present and ordered is emitted; a -1 "not
    applicable" endpoint or a backwards pair is dropped rather than shipped as a
    negative duration.
    """
    if not isinstance(timing, dict):
        return {}
    phases: JsonObject = {}

    def measure(name: str, start: Any, end: Any) -> None:
        if (
            isinstance(start, (int, float))
            and isinstance(end, (int, float))
            and start >= 0
            and end >= start
        ):
            phases[name] = round(float(end) - float(start), 3)

    measure("send", timing.get("sendStart"), timing.get("sendEnd"))
    measure("wait", timing.get("sendEnd"), timing.get("receiveHeadersEnd"))
    return phases


def _receive_anchor(timing: Any) -> float | None:
    """The monotonic instant response headers finished arriving, in seconds.

    ResourceTiming's ``requestTime`` is a monotonic baseline in seconds and
    ``receiveHeadersEnd`` a millisecond offset from it, so their sum is the
    headers-received instant on the same clock ``loadingFinished.timestamp``
    uses -- their difference is HAR's receive phase (body download), computed
    exactly the way Chrome DevTools' HAR export computes it. ``None`` when
    either member is absent or junk (a -1 "not applicable" offset, a NaN, a
    non-positive baseline), so no anchor is stored and receive honestly stays
    the -1 "not measured" sentinel.
    """
    if not isinstance(timing, dict):
        return None
    base = timing.get("requestTime")
    headers_end = timing.get("receiveHeadersEnd")
    if (
        isinstance(base, (int, float))
        and isinstance(headers_end, (int, float))
        and base > 0
        and headers_end >= 0
    ):
        return float(base) + float(headers_end) / 1000.0
    return None


def _preserve_redirect_hop(
    handle: _WebSession,
    request_id: str,
    redirect_response: JsonObject,
    next_url: str,
) -> None:
    """Keep a redirect hop as its own request row before the chain reuses its id.

    Must be called while ``handle.lock`` is held. CDP fires one requestWillBeSent
    per hop of a redirect chain, all sharing a requestId, each carrying the prior
    hop's response as ``redirectResponse``. The prior entry is finalised here
    from that response -- status, mime, and whatever send/wait phases its timing
    measured -- given ``redirect_url`` (the next hop's URL, the Location it sent
    the client to) and re-keyed under a synthetic id so the new hop can take the
    real requestId without erasing it. The synthetic id is self-consistent for
    web.network.get: the lookup finds this row, and CDP's getResponseBody then
    reports no body for it (a redirect carries none), the documented body_error
    path. A stale receive anchor for the reused id is dropped so it cannot bind
    to the new hop.
    """
    prior = handle.requests.pop(request_id, None)
    if prior is None:
        return
    status = redirect_response.get("status")
    if isinstance(status, int):
        prior["status"] = status
    mime_type, mime_truncated = _bounded_metadata(
        redirect_response.get("mimeType"), _MAX_METADATA_BYTES
    )
    if mime_type:
        prior["mimeType"] = mime_type
    timings = _cdp_phase_timings(redirect_response.get("timing"))
    if timings:
        prior["timings"] = timings
    prior["redirect"] = True
    prior["redirect_url"] = next_url
    if mime_truncated:
        prior["metadata_truncated"] = True
    preserved_id = f"{request_id}:redirect:{uuid4().hex[:8]}"
    prior["requestId"] = preserved_id
    handle.requests[preserved_id] = prior
    handle.receive_anchors.pop(request_id, None)


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
    raw: bytes,
    *,
    artifact_dir: Path,
    filename: str,
    kind: str,
) -> Path:
    """Write raw bytes to a session artifact, refusing over the capture cap.

    The bytes counterpart of ``_spill_text``: a binary response body cannot be
    represented as JSON text, so it always goes to disk. The cap is measured on
    the real bytes, not on a base64 expansion of them.
    """
    if len(raw) > UNREGISTERED_CAPTURE_MAX_BYTES:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=len(raw),
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
    out.write_bytes(raw)
    written, over = capped_file_size(out, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
    if over:
        raise WebError(
            "too_large",
            f"{kind} exceeds capture cap",
            size=written,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    return out


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
        # Monotonic instant each request's response headers finished arriving
        # (ResourceTiming's requestTime + receiveHeadersEnd), kept until its
        # loadingFinished computes the HAR receive phase from it. Held beside
        # the row, not in it, because rows are handed to callers verbatim
        # (network.list / network.get) and a raw clock anchor is not part of
        # that contract. Popped on finish/failure and evicted in lockstep with
        # the requests ring, so it can never outgrow it.
        self.receive_anchors: dict[str, float] = {}
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
        timeout = _bound_nav_timeout(timeout)

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
                response = None
                if url:
                    response = page.goto(
                        url, timeout=timeout * 1000.0, wait_until="domcontentloaded"
                    )
                # Summarised here rather than by a second call: between the two,
                # a browser exists that no session yet refers to, and a failure
                # in that window would leave it with nothing able to close it.
                summary = {
                    "opened": True,
                    "url": _bounded_metadata(page.url, _MAX_URL_BYTES)[0],
                    "title": _safe_title(page),
                    "headless": headless,
                }
                status = _response_status(response)
                if status is not None:
                    summary["status"] = status
            except Exception as exc:  # noqa: BLE001
                with contextlib.suppress(Exception):
                    pw.stop()
                if _is_timeout(exc):
                    raise WebError(
                        "timeout", f"navigation did not complete within {timeout:g}s", url=url
                    ) from exc
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
            # CDP's requestWillBeSent carries wallTime: the real epoch the
            # request was initiated. Keeping it lets the HAR export stamp each
            # entry's startedDateTime with the true time instead of the single
            # export instant, so a HAR viewer's waterfall reflects request order.
            wall_time = params.get("wallTime")
            if isinstance(wall_time, (int, float)) and wall_time > 0:
                entry["started_at"] = float(wall_time)
            if url_truncated or method_truncated or type_truncated:
                entry["metadata_truncated"] = True
            request_id = str(params.get("requestId"))
            # CDP reuses one requestId across a redirect chain: each hop arrives
            # as a fresh requestWillBeSent carrying redirectResponse -- the
            # response that caused the redirect. Storing the new hop straight
            # over the old one dropped that 3xx entirely, so an auth handoff, a
            # tracker bounce or a URL shortener showed up in network.list/HAR as
            # only its final landing, the redirect (often the finding) invisible.
            # Finalise the prior hop with the redirect's status/mime/timings and
            # re-key it under a synthetic id so it survives as its own row, with
            # redirect_url pointing at where it sent the client next.
            redirect_response = params.get("redirectResponse")
            with handle.lock:
                if isinstance(redirect_response, dict):
                    _preserve_redirect_hop(handle, request_id, redirect_response, url)
                handle.requests[request_id] = entry
                while len(handle.requests) > _MAX_REQUESTS:
                    evicted_id, _ = handle.requests.popitem(last=False)
                    handle.receive_anchors.pop(evicted_id, None)
                    handle.requests_dropped += 1

        def on_response(params: JsonObject) -> None:
            resp = params.get("response") or {}
            mime_type, mime_truncated = _bounded_metadata(
                resp.get("mimeType"), _MAX_METADATA_BYTES
            )
            # CDP hands the real per-phase durations in response.timing; keep the
            # ones this event can measure so the HAR export reports them instead
            # of the -1 "not measured" sentinel, the same fidelity the proxy HAR
            # gets from mitmproxy's flow timestamps.
            timings = _cdp_phase_timings(resp.get("timing"))
            anchor = _receive_anchor(resp.get("timing"))
            with handle.lock:
                request_id = str(params.get("requestId"))
                entry = handle.requests.get(request_id)
                if entry is not None:
                    entry["status"] = resp.get("status")
                    entry["mimeType"] = mime_type
                    if timings:
                        entry["timings"] = timings
                    if anchor is not None:
                        handle.receive_anchors[request_id] = anchor
                    if mime_truncated:
                        entry["metadata_truncated"] = True

        def on_finished(params: JsonObject) -> None:
            # loadingFinished's timestamp is on the same monotonic clock as
            # ResourceTiming's requestTime, so its distance from the anchor the
            # response event stored (headers fully received) is the body
            # download -- HAR's receive phase, computed exactly the way Chrome
            # DevTools' own HAR export computes it. The anchor is consumed here:
            # a request finishes once, and a stray duplicate must be a no-op.
            timestamp = params.get("timestamp")
            with handle.lock:
                request_id = str(params.get("requestId"))
                anchor = handle.receive_anchors.pop(request_id, None)
                entry = handle.requests.get(request_id)
                if entry is None or anchor is None:
                    return
                # A NaN timestamp fails the ordering check, like every other
                # junk clock value in the timing pipeline.
                if isinstance(timestamp, (int, float)) and timestamp >= anchor:
                    timings = entry.get("timings")
                    if not isinstance(timings, dict):
                        timings = {}
                        entry["timings"] = timings
                    timings["receive"] = round((float(timestamp) - anchor) * 1000, 3)

        def on_failed(params: JsonObject) -> None:
            # CDP fires loadingFailed for a request that never produced a
            # response -- DNS/connect failure, a CSP/mixed-content/client block,
            # or a navigation that superseded an in-flight fetch. Without this
            # such a row kept status None forever, indistinguishable from one
            # still in flight, so a failed API call or a blocked tracker -- often
            # the finding in a web RE session -- was invisible. Mark it the way
            # the proxy marks an errored flow (error=true, error_msg, null
            # status), and keep CDP's own distinctions: canceled separates a
            # benign abort from a hard failure, blocked_reason names why a block
            # happened (csp, mixed-content, inspector, ...).
            error_text, error_truncated = _bounded_metadata(
                params.get("errorText"), _MAX_METADATA_BYTES
            )
            blocked_reason, blocked_truncated = _bounded_metadata(
                params.get("blockedReason"), _MAX_METADATA_BYTES
            )
            with handle.lock:
                request_id = str(params.get("requestId"))
                # A failed request never reaches loadingFinished, so its anchor
                # would otherwise sit in the map until ring eviction clears it.
                handle.receive_anchors.pop(request_id, None)
                entry = handle.requests.get(request_id)
                if entry is not None:
                    entry["error"] = True
                    entry["error_msg"] = error_text
                    if params.get("canceled"):
                        entry["canceled"] = True
                    if blocked_reason:
                        entry["blocked_reason"] = blocked_reason
                    if error_truncated or blocked_truncated:
                        entry["metadata_truncated"] = True

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
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Network.loadingFinished", on_finished)
        cdp.on("Network.loadingFailed", on_failed)
        cdp.on("Debugger.scriptParsed", on_script)
        # Over CDP like the rest, not page.on("console"). The high-level event
        # hands over a ConsoleMessage whose args are remote JSHandle wrappers,
        # and nothing disposes them: measured at 120 OS handles per navigation
        # on a page logging 60 lines, growing for as long as the session lived.
        # The same information arrives here as plain data.
        cdp.on("Runtime.consoleAPICalled", on_console)

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> JsonObject:
        handle = self._get(session_id)
        timeout = _bound_nav_timeout(timeout)

        def work() -> JsonObject:
            try:
                response = handle.page.goto(
                    url, timeout=timeout * 1000.0, wait_until="domcontentloaded"
                )
            except Exception as exc:  # noqa: BLE001
                if _is_timeout(exc):
                    raise WebError(
                        "timeout", f"navigation did not complete within {timeout:g}s", url=url
                    ) from exc
                raise WebError("backend_error", f"navigation failed: {exc}", url=url) from exc
            result: JsonObject = {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
            }
            status = _response_status(response)
            if status is not None:
                result["status"] = status
            return result

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

    def network_list(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        return {
            "requests": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
            "dropped": dropped,
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
            # CDP has no body for some requests -- a redirect, or a body already
            # evicted from its cache. Keep the documented shape (empty body, not
            # base64, not truncated) with body_error explaining why, so a caller
            # reading result["body"] does not hit a missing key on this path.
            return {
                **entry,
                "body": "",
                "base64_encoded": False,
                "body_truncated": False,
                "body_error": str(exc),
            }
        if not isinstance(body, str):
            body = str(body)
        if base64_encoded:
            # CDP returns base64 for a binary body (image, font, wasm...). The
            # earlier code fed that base64 *string* to the text spill, so a large
            # binary body wrote base64 into the .bin artifact -- not the bytes a
            # caller opening body_path expects -- and measured the cap against
            # the ~33% larger base64. Decode once, cap on the real size, and
            # spill the actual bytes; a binary body is never inlined as text.
            try:
                raw = base64.b64decode(body, validate=False)
            except (ValueError, binascii.Error) as exc:
                # Same contract as the CDP-no-body arm above: a caller reading
                # result["body"] must not hit a missing key just because the
                # decode failed. Carry the documented body/base64_encoded/
                # body_truncated shape alongside the explanation, and spill
                # nothing.
                return {
                    **entry,
                    "body": "",
                    "base64_encoded": False,
                    "body_truncated": False,
                    "body_error": f"response body was not valid base64: {exc}",
                }
            spill_path = _spill_bytes(
                raw,
                artifact_dir=artifact_dir,
                filename=f"body-{uuid4().hex}.bin",
                kind="response body",
            )
            result = dict(entry)
            result["body"] = ""
            result["body_truncated"] = False
            result["body_path"] = str(spill_path)
            result["body_bytes"] = len(raw)
            result["base64_encoded"] = True
            return result
        inline, spill, cut = _spill_text(
            body,
            artifact_dir=artifact_dir,
            filename=f"body-{uuid4().hex}.bin",
            kind="response body",
        )
        result = dict(entry)
        result["body"] = inline
        result["body_truncated"] = cut
        if spill is not None:
            result["body_path"] = str(spill)
        result["base64_encoded"] = False
        return result

    def console(self, session_id: str, *, limit: int = 200) -> JsonObject:
        handle = self._get(session_id)
        capped = max(1, min(int(limit), _MAX_CONSOLE))
        with handle.lock:
            held = list(handle.console)
            dropped = handle.console_dropped
        # Newest tail, and total for parity with every other paginated reader:
        # has_more alone says "there is more", total says how much is buffered,
        # so a caller can size its next limit instead of guessing. No offset is
        # needed here -- the max limit equals the ring capacity, so one call can
        # return the whole buffer.
        page = held[-capped:]
        return {
            "console": page,
            "count": len(page),
            "total": len(held),
            "has_more": len(held) > capped,
            "dropped": dropped,
        }

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
        # A WebAssembly script (the kind wasm.list surfaces) has no text source:
        # Debugger.getScriptSource leaves scriptSource empty and returns the
        # module in a separate base64 `bytecode` field, which this tool does not
        # decode. Answering with a silent empty source is a dead end, so flag it
        # and name the path that does yield the bytes -- fetch the module's
        # response body with web.network.get, then run wasm.wat / wasm.info on
        # the saved .wasm. Only trips when bytecode is actually present, so a
        # genuinely empty JS source is unaffected.
        bytecode = resp.get("bytecode")
        if not source and isinstance(bytecode, str) and bytecode:
            result["is_wasm"] = True
            result["note"] = (
                "WebAssembly module: no text source here. Fetch the module's "
                "response body with web.network.get, then analyze the saved "
                ".wasm with wasm.wat or wasm.info."
            )
        return result

    def dom_snapshot(self, session_id: str, artifact_dir: Path) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                # Fetch the whole outerHTML rather than slicing it in the browser:
                # a DOM past the inline buffer used to lose everything past the cut
                # with no way back. _spill_text inlines a prefix and writes the full
                # document to disk, matching what script_source already does for a
                # large script source. The capture cap in _spill_text (not this
                # evaluate) bounds the transfer, so a pathological DOM is refused as
                # too_large rather than silently trimmed to a prefix.
                html = handle.page.evaluate(
                    """() => {
                        const doc = document.documentElement
                          ? document.documentElement.outerHTML
                          : (document.body ? document.body.outerHTML : "");
                        return typeof doc === "string" ? doc : "";
                    }"""
                )
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"dom snapshot failed: {exc}") from exc
            text = html if isinstance(html, str) else ""
            inline, spill, cut = _spill_text(
                text,
                artifact_dir=artifact_dir,
                filename=f"dom-{uuid4().hex}.html",
                kind="dom snapshot",
            )
            result: JsonObject = {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
                "bytes": len(text.encode("utf-8", errors="replace")),
                "html": inline,
                "truncated": cut,
            }
            if spill is not None:
                result["html_path"] = str(spill)
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
        with handle.lock:
            entries = [
                har_entry(
                    method=e.get("method"),
                    url=e.get("url"),
                    status=e.get("status"),
                    mime_type=e.get("mimeType") or "",
                    resource_type=e.get("resourceType"),
                    started_date_time=iso_from_epoch(e.get("started_at")),
                    timings_ms=e.get("timings"),
                    error=e.get("error_msg") if e.get("error") else None,
                    redirect_url=e.get("redirect_url"),
                )
                for e in handle.requests.values()
            ]
        serialized = serialize_har(entries, max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES)
        if serialized.size > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise WebError(
                "too_large",
                "HAR export exceeds capture cap",
                size=serialized.size,
                cap=UNREGISTERED_CAPTURE_MAX_BYTES,
            )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(serialized.text, encoding="utf-8")
        return {
            "path": str(out_path),
            "entry_count": serialized.entry_count,
            "truncated": serialized.truncated,
            "size": serialized.size,
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


def _response_status(response: Any) -> int | None:
    """HTTP status of a navigation, or None when it produced no response.

    page.goto only raises for transport failures (DNS, refused, timeout); a
    4xx/5xx main document resolves normally, so without surfacing this a
    navigation onto an error page reports the same success as a real hit. goto
    also returns None for about:blank and same-document navigations, which is
    an absent status rather than a failure.
    """
    if response is None:
        return None
    try:
        status = response.status
    except Exception:  # noqa: BLE001
        return None
    return status if isinstance(status, int) else None


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
