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

from headless_re_mcp.backends import har as har_builder
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
# A cookie jar is small (browsers cap ~180 cookies/domain, ~4 KB each), but a
# hostile or instrumented page can still pile them up, so the read is paged
# like the other capture readers rather than returned whole.
_MAX_COOKIES = 1000
# Web Storage: a page can put megabytes in localStorage, so cap the per-value
# preview and the number of keys pulled across the CDP bridge. The value cap is
# generous enough for a JWT or a serialised config blob; the key guard only
# fires on a pathological store and is disclosed via scan_capped.
_MAX_STORAGE_VALUE = 64 * 1024
_MAX_STORAGE_KEYS = 10_000
# A page's frame tree is normally small, but a hostile page can nest thousands
# of iframes; cap how many are flattened and disclose when the cap fired.
_MAX_FRAMES = 2000
_COOKIE_FIELDS = (
    "name",
    "value",
    "domain",
    "path",
    "expires",
    "size",
    "httpOnly",
    "secure",
    "session",
    "sameSite",
    "priority",
)
_MAX_METADATA_BYTES = 1024
# HAR enrichment: headers captured per request are metadata for the export, not
# a mirror of the wire, so bound how many and how long each is kept resident.
_MAX_HAR_HEADERS = 100
_MAX_HAR_HEADER_VALUE = 4 * 1024
_MAX_HAR_POST_DATA = 16 * 1024
# WebSocket capture: bound how many connections are tracked, how many frames
# each keeps, and how much of a frame's payload is held resident. A chatty
# socket (heartbeats, streaming) would otherwise grow these without limit, the
# same reasoning as the request/console/script rings.
_MAX_WEBSOCKETS = 256
_MAX_WS_FRAMES = 1000
_MAX_WS_PAYLOAD = 8 * 1024
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


def _without_har(entry: JsonObject) -> JsonObject:
    """A shallow copy of a request entry with the internal ``_har`` key removed."""
    return {key: value for key, value in entry.items() if key != "_har"}


# RFC 6455 opcodes, surfaced as a readable name next to the raw number so a
# caller does not have to memorise the numbering.
_WS_OPCODES = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}


_WS_INTERNAL_KEYS = frozenset({"_frames", "_har"})


def _ws_summary(entry: JsonObject) -> JsonObject:
    """A WebSocket connection row without its internal fields.

    ``_frames`` is a deque (not JSON-serialisable, potentially large) and
    ``_har`` holds handshake headers kept only for the HAR export; the list view
    projects both out and callers page the frames with ws.frames.
    """
    return {key: value for key, value in entry.items() if key not in _WS_INTERNAL_KEYS}


def _bounded_header_map(headers: Any) -> dict[str, str]:
    """A CDP header map, capped in count and per-value length for HAR retention.

    CDP hands headers as a plain ``{name: value}`` object; keep a bounded copy so
    the export carries them without letting one pathological response pin
    unbounded memory in the capture ring.
    """
    if not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for name, value in headers.items():
        if len(out) >= _MAX_HAR_HEADERS:
            break
        out[str(name)] = _bounded_metadata(value, _MAX_HAR_HEADER_VALUE)[0]
    return out


def _merge_capped(existing: Any, incoming: Any) -> dict[str, str]:
    """Union a stored header map with a freshly-bounded incoming one, capped.

    Extra-info events carry the authoritative on-the-wire headers, so their
    values win on conflict; keys the base already held are preserved, and new
    keys are added only until the retention cap is reached.
    """
    out: dict[str, str] = dict(existing) if isinstance(existing, dict) else {}
    for name, value in _bounded_header_map(incoming).items():
        if name not in out and len(out) >= _MAX_HAR_HEADERS:
            continue
        out[name] = value
    return out


def _merge_fill(existing: Any, incoming: Any) -> dict[str, str]:
    """Union where the *existing* map wins; incoming only fills absent keys.

    responseReceivedExtraInfo (which alone carries Set-Cookie) usually arrives
    before responseReceived, so the base event must not clobber what extra-info
    already recorded -- it may only add headers extra-info did not report.
    """
    out: dict[str, str] = dict(existing) if isinstance(existing, dict) else {}
    for name, value in _bounded_header_map(incoming).items():
        if name in out:
            continue
        if len(out) >= _MAX_HAR_HEADERS:
            break
        out[name] = value
    return out


def _record_response(entry: JsonObject, resp: JsonObject) -> None:
    """Fold a CDP response object into a captured request entry.

    Shared by the responseReceived handler and the redirect finaliser: a
    redirect's prior response arrives as ``requestWillBeSent.redirectResponse``,
    which is the same shape, so both fill status/mime and the HAR response meta
    identically.
    """
    mime_type, mime_truncated = _bounded_metadata(resp.get("mimeType"), _MAX_METADATA_BYTES)
    entry["status"] = resp.get("status")
    entry["mimeType"] = mime_type
    if mime_truncated:
        entry["metadata_truncated"] = True
    har_meta = entry.setdefault("_har", {})
    # Fill, don't overwrite: responseReceivedExtraInfo (with Set-Cookie) tends to
    # arrive before responseReceived, and its raw headers must survive.
    har_meta["response_headers"] = _merge_fill(
        har_meta.get("response_headers"), resp.get("headers")
    )
    har_meta["http_version"] = _bounded_metadata(resp.get("protocol"), _MAX_METADATA_BYTES)[0]
    har_meta["status_text"] = _bounded_metadata(resp.get("statusText"), _MAX_METADATA_BYTES)[0]
    timing = resp.get("timing")
    if isinstance(timing, dict):
        har_meta["timing"] = timing


def _map_header(headers: Any, name: str) -> str:
    """Case-insensitive lookup in a CDP header map (plain ``{name: value}``)."""
    if not isinstance(headers, dict):
        return ""
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return ""


def _cdp_timings(har_meta: JsonObject) -> tuple[float, JsonObject]:
    """Derive HAR ``time`` and ``timings`` from CDP ResourceTiming.

    CDP gives a ``requestTime`` baseline (monotonic seconds) and per-phase
    offsets in milliseconds, plus ``loadingFinished.timestamp`` on the same
    clock. HAR wants send/wait/receive (and optional dns/connect/ssl) in ms;
    anything CDP did not measure stays -1 so a reader never mistakes an
    unmeasured phase for an instant one.
    """
    timing = har_meta.get("timing")
    finished_ts = har_meta.get("finished_ts")
    request_time = har_meta.get("request_time")

    base: float | None = None
    if isinstance(timing, dict) and isinstance(timing.get("requestTime"), (int, float)):
        base = float(timing["requestTime"])
    elif isinstance(request_time, (int, float)):
        base = float(request_time)

    time_ms = 0.0
    if base is not None and isinstance(finished_ts, (int, float)):
        total = (float(finished_ts) - base) * 1000.0
        if total >= 0.0:
            time_ms = round(total, 3)

    if not isinstance(timing, dict):
        return time_ms, har_builder.timings(-1.0, -1.0, -1.0)

    def offset(name: str) -> float | None:
        value = timing.get(name)
        return float(value) if isinstance(value, (int, float)) and value >= 0.0 else None

    def span(start: float | None, end: float | None) -> float | None:
        if start is None or end is None or end < start:
            return None
        return end - start

    send = span(offset("sendStart"), offset("sendEnd"))
    wait = span(offset("sendEnd"), offset("receiveHeadersEnd"))
    dns = span(offset("dnsStart"), offset("dnsEnd"))
    connect = span(offset("connectStart"), offset("connectEnd"))
    ssl = span(offset("sslStart"), offset("sslEnd"))

    receive: float | None = None
    recv_headers_end = offset("receiveHeadersEnd")
    if base is not None and isinstance(finished_ts, (int, float)) and recv_headers_end is not None:
        candidate = (float(finished_ts) - base) * 1000.0 - recv_headers_end
        receive = candidate if candidate >= 0.0 else None

    return time_ms, har_builder.timings(
        send if send is not None else -1.0,
        wait if wait is not None else -1.0,
        receive if receive is not None else -1.0,
        dns=dns,
        connect=connect,
        ssl=ssl,
    )


def _cdp_entry_to_har(entry: JsonObject) -> JsonObject:
    """Build one HAR entry from a captured CDP request entry and its ``_har`` meta.

    The summary (method/url/status/mimeType) always exists; ``_har`` adds the
    request/response headers, protocol, timing and byte count CDP reported. When
    a request is still pending or its events were missed, the missing pieces are
    simply absent, yielding a valid-but-sparse entry rather than a broken one.
    """
    har_meta = entry.get("_har") or {}
    request_headers = har_meta.get("request_headers")
    response_headers = har_meta.get("response_headers")
    post_text = har_meta.get("post_data") or ""
    body_size = har_meta.get("body_size")
    body_size = int(body_size) if isinstance(body_size, (int, float)) else None
    http_version = har_meta.get("http_version") or "HTTP/1.1"

    request = har_builder.request_entry(
        method=entry.get("method"),
        url=entry.get("url"),
        http_version=http_version,
        headers=request_headers,
        body=post_text.encode("utf-8", "replace"),
        mime=_map_header(request_headers, "content-type"),
        cookies=har_builder.request_cookies(_map_header(request_headers, "cookie")),
    )
    response = har_builder.response_entry(
        status=entry.get("status") or 0,
        status_text=har_meta.get("status_text") or "",
        http_version=http_version,
        headers=response_headers,
        mime=entry.get("mimeType") or "",
        redirect_url=_map_header(response_headers, "location"),
        body_size=body_size,
        cookies=har_builder.response_cookies(_map_header(response_headers, "set-cookie")),
    )
    time_ms, timings = _cdp_timings(har_meta)
    ent = har_builder.entry(
        started=har_meta.get("wall_time"),
        time_ms=time_ms,
        request=request,
        response=response,
        timings_obj=timings,
    )
    # resourceType is not a HAR field; keep it as a HAR-legal custom extension.
    ent["_resourceType"] = entry.get("resourceType")
    return ent


def _ws_entry_to_har(conn: JsonObject) -> JsonObject:
    """Build a HAR entry for one WebSocket connection (handshake + frames).

    The handshake is a real GET/101 exchange CDP reports, so it becomes a normal
    entry; the frames ride along as DevTools' ``_webSocketMessages``. Frame
    timestamps are CDP's monotonic clock, so they are rebased onto epoch using
    the wallTime/timestamp pairing captured at the handshake -- a frame that
    cannot be rebased is emitted with time 0 rather than a fabricated instant.
    """
    har_meta = conn.get("_har") or {}
    frames = list(conn.get("_frames") or [])
    wall_time = har_meta.get("wall_time")
    request_time = har_meta.get("request_time")

    def _epoch(ts: Any) -> float | None:
        if (
            isinstance(ts, int | float)
            and isinstance(wall_time, int | float)
            and isinstance(request_time, int | float)
        ):
            return float(wall_time) + (float(ts) - float(request_time))
        return None

    rebased = [{**frame, "ts": _epoch(frame.get("ts"))} for frame in frames]
    request_headers = har_meta.get("request_headers")
    response_headers = har_meta.get("response_headers")
    request = har_builder.request_entry(
        method="GET",
        url=conn.get("url"),
        headers=request_headers,
        mime=_map_header(request_headers, "content-type"),
        body_size=-1,
        cookies=har_builder.request_cookies(_map_header(request_headers, "cookie")),
    )
    response = har_builder.response_entry(
        status=conn.get("status") or 0,
        status_text=har_meta.get("status_text") or "",
        headers=response_headers,
        redirect_url=_map_header(response_headers, "location"),
        body_size=-1,
        cookies=har_builder.response_cookies(_map_header(response_headers, "set-cookie")),
    )
    return har_builder.entry(
        started=wall_time,
        time_ms=0.0,
        request=request,
        response=response,
        extras={
            "_resourceType": "websocket",
            "_webSocketMessages": har_builder.websocket_messages(rebased),
        },
    )


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


def _reject_bad_artifact_name(filename: str, kind: str) -> None:
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise WebError("invalid_params", f"invalid {kind} artifact filename")


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
    _reject_bad_artifact_name(filename, kind)
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


def _spill_base64_body(
    b64_text: str,
    *,
    artifact_dir: Path,
    filename: str,
) -> tuple[str, Path | None, bool]:
    """Spill a binary (CDP base64Encoded) response body as its *decoded* bytes.

    ``Network.getResponseBody`` returns binary bodies base64-encoded. Passing that
    text straight to ``_spill_text`` wrote the base64 *text* into a ``.bin``: the
    artifact was 4/3 the real size and was not the resource -- a caller pulling a
    WASM module, image or encrypted blob got a file they had to base64-decode
    themselves, and the capture cap was measured against the inflated text. Decode
    once so the artifact is the real bytes. The inline field stays a base64 prefix
    (JSON cannot hold raw bytes, and ``base64_encoded`` already tells the caller),
    and a spill happens exactly when that inline prefix is truncated, so the full
    body is always recoverable from disk. Returns ``(inline, spill_path, truncated)``.
    """
    try:
        raw = base64.b64decode(b64_text or "", validate=False)
    except (binascii.Error, ValueError):
        # Flagged base64 that will not decode: keep the text so nothing is lost.
        return _spill_text(
            b64_text, artifact_dir=artifact_dir, filename=filename, kind="response body"
        )
    inline = b64_text[:_MAX_INLINE_BODY]
    if len(b64_text) <= _MAX_INLINE_BODY:
        # Whole base64 fits inline; the caller can decode it directly.
        return inline, None, False
    size = len(raw)
    if size > UNREGISTERED_CAPTURE_MAX_BYTES:
        raise WebError(
            "too_large",
            "response body exceeds capture cap",
            size=size,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    _reject_bad_artifact_name(filename, "response body")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    out = artifact_dir / filename
    out.write_bytes(raw)
    written, over = capped_file_size(out, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
    if over:
        raise WebError(
            "too_large",
            "response body exceeds capture cap",
            size=written,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    return inline, out, True


def _spill_wasm_bytecode(
    b64_bytecode: str,
    *,
    artifact_dir: Path,
    filename: str,
) -> tuple[Path, int]:
    """Write a WASM module's raw bytes to a .wasm the static tools can read.

    ``Debugger.getScriptSource`` returns two things for a WebAssembly script: a
    WAT-text ``scriptSource`` (readable, but no tool round-trips it) and the
    module's actual bytes as base64 ``bytecode``. Only the text was ever kept,
    so a module seen live in a page could not be handed to wasm.wat / wasm.info
    / ghidra.decompile, which all take a ``.wasm`` path. Decode the bytecode once
    to a real module on disk. Always spills (raw bytes are not JSON-inlineable
    and the WAT already covers the readable form); returns ``(path, byte_len)``.
    """
    raw = base64.b64decode(b64_bytecode or "", validate=False)
    size = len(raw)
    if size > UNREGISTERED_CAPTURE_MAX_BYTES:
        raise WebError(
            "too_large",
            "wasm module exceeds capture cap",
            size=size,
            cap=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
    _reject_bad_artifact_name(filename, "wasm module")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    out = artifact_dir / filename
    out.write_bytes(raw)
    return out, size


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
        # WebSocket connections seen on this page. Each entry carries a bounded
        # deque of recent frames under ``_frames``; the same bounding reasoning
        # as requests/scripts applies, since a long-lived socket streams forever.
        self.websockets: OrderedDict[str, JsonObject] = OrderedDict()
        self.websockets_dropped = 0
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
            # HAR enrichment kept out of the request summary (network.list stays
            # lean) and read only by the HAR export. wallTime is the epoch clock
            # for startedDateTime; timestamp is the monotonic clock the response
            # timing and loadingFinished share, so durations can be derived.
            post_data, post_truncated = _bounded_metadata(
                req.get("postData"), _MAX_HAR_POST_DATA
            )
            har_meta: JsonObject = {
                "request_headers": _bounded_header_map(req.get("headers")),
                "wall_time": params.get("wallTime"),
                "request_time": params.get("timestamp"),
            }
            if post_data:
                har_meta["post_data"] = post_data
                har_meta["post_data_truncated"] = post_truncated
            entry: JsonObject = {
                "requestId": params.get("requestId"),
                "url": url,
                "method": method,
                "resourceType": resource_type,
                "status": None,
                "mimeType": None,
                "_har": har_meta,
            }
            if url_truncated or method_truncated or type_truncated:
                entry["metadata_truncated"] = True
            request_id = str(params.get("requestId"))
            redirect = params.get("redirectResponse")
            with handle.lock:
                # A redirect reuses the requestId: CDP hands the prior hop's
                # response here as redirectResponse. Finalise that hop under its
                # own key so the chain survives instead of being overwritten by
                # the request to the redirect target.
                if isinstance(redirect, dict):
                    prev = handle.requests.pop(request_id, None)
                    if prev is not None:
                        _record_response(prev, redirect)
                        hop_key = f"{request_id}#redirect-{uuid4().hex[:8]}"
                        prev["requestId"] = hop_key
                        handle.requests[hop_key] = prev
                handle.requests[request_id] = entry
                while len(handle.requests) > _MAX_REQUESTS:
                    handle.requests.popitem(last=False)
                    handle.requests_dropped += 1

        def on_response(params: JsonObject) -> None:
            resp = params.get("response") or {}
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    _record_response(entry, resp)

        def on_loading_finished(params: JsonObject) -> None:
            # Network.loadingFinished carries the final byte count and the finish
            # time on the same monotonic clock as the request/timing, which is
            # what the HAR export needs to fill bodySize and the receive phase.
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    har_meta = entry.setdefault("_har", {})
                    har_meta["finished_ts"] = params.get("timestamp")
                    har_meta["body_size"] = params.get("encodedDataLength")

        def on_request_extra_info(params: JsonObject) -> None:
            # The *actual* on-the-wire request headers (Host, Cookie, ...), which
            # requestWillBeSent's headers omit. Merged over what that event had so
            # the HAR carries the real request, not the pre-send guess.
            headers = params.get("headers")
            if not isinstance(headers, dict):
                return
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    har_meta = entry.setdefault("_har", {})
                    har_meta["request_headers"] = _merge_capped(
                        har_meta.get("request_headers"), headers
                    )

        def on_response_extra_info(params: JsonObject) -> None:
            # The complete raw response headers, including every Set-Cookie (CDP
            # joins them with newlines here); responseReceived's headers can be a
            # filtered/parsed view. Merge so cookies and duplicates survive.
            headers = params.get("headers")
            if not isinstance(headers, dict):
                return
            with handle.lock:
                entry = handle.requests.get(str(params.get("requestId")))
                if entry is not None:
                    har_meta = entry.setdefault("_har", {})
                    har_meta["response_headers"] = _merge_capped(
                        har_meta.get("response_headers"), headers
                    )

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

        def on_ws_created(params: JsonObject) -> None:
            url, url_truncated = _bounded_metadata(params.get("url"), _MAX_URL_BYTES)
            entry: JsonObject = {
                "wsId": params.get("requestId"),
                "url": url,
                "status": None,
                "closed": False,
                "frames_sent": 0,
                "frames_received": 0,
                "frames_dropped": 0,
                # Internal, projected out of the list view by _ws_summary.
                "_frames": deque(maxlen=_MAX_WS_FRAMES),
            }
            if url_truncated:
                entry["metadata_truncated"] = True
            with handle.lock:
                handle.websockets[str(params.get("requestId"))] = entry
                while len(handle.websockets) > _MAX_WEBSOCKETS:
                    handle.websockets.popitem(last=False)
                    handle.websockets_dropped += 1

        def on_ws_will_send_handshake(params: JsonObject) -> None:
            # The handshake request carries the epoch/monotonic clock pairing
            # (wallTime/timestamp) plus the request headers; both are kept only
            # for the HAR export, so they live under the internal ``_har`` key.
            request = params.get("request") or {}
            with handle.lock:
                entry = handle.websockets.get(str(params.get("requestId")))
                if entry is not None:
                    har_meta = entry.setdefault("_har", {})
                    har_meta["request_headers"] = _bounded_header_map(request.get("headers"))
                    har_meta["wall_time"] = params.get("wallTime")
                    har_meta["request_time"] = params.get("timestamp")

        def on_ws_handshake(params: JsonObject) -> None:
            resp = params.get("response") or {}
            with handle.lock:
                entry = handle.websockets.get(str(params.get("requestId")))
                if entry is not None:
                    entry["status"] = resp.get("status")
                    har_meta = entry.setdefault("_har", {})
                    har_meta["response_headers"] = _bounded_header_map(resp.get("headers"))
                    har_meta["status_text"] = resp.get("statusText")

        def _record_frame(params: JsonObject, direction: str) -> None:
            # Sent and received frames arrive under the same ``response`` shape
            # (a WebSocketFrame: opcode, mask, payloadData). For a text frame
            # payloadData is the text; for a binary frame CDP base64-encodes it.
            frame = params.get("response") or {}
            raw = frame.get("payloadData")
            raw = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
            payload, truncated = _bounded_metadata(raw, _MAX_WS_PAYLOAD)
            opcode = frame.get("opcode")
            kind = _WS_OPCODES.get(opcode, "other") if isinstance(opcode, int) else "other"
            record: JsonObject = {
                "direction": direction,
                "opcode": opcode,
                "type": kind,
                "payload": payload,
                "payload_len": len(raw.encode("utf-8", errors="replace")),
                "ts": params.get("timestamp"),
            }
            if truncated:
                record["payload_truncated"] = True
            with handle.lock:
                entry = handle.websockets.get(str(params.get("requestId")))
                if entry is None:
                    return
                frames = entry["_frames"]
                if frames.maxlen is not None and len(frames) == frames.maxlen:
                    entry["frames_dropped"] += 1
                frames.append(record)
                if direction == "sent":
                    entry["frames_sent"] += 1
                else:
                    entry["frames_received"] += 1

        def on_ws_frame_sent(params: JsonObject) -> None:
            _record_frame(params, "sent")

        def on_ws_frame_received(params: JsonObject) -> None:
            _record_frame(params, "received")

        def on_ws_frame_error(params: JsonObject) -> None:
            message, _ = _bounded_metadata(params.get("errorMessage"), _MAX_METADATA_BYTES)
            with handle.lock:
                entry = handle.websockets.get(str(params.get("requestId")))
                if entry is not None:
                    entry["error"] = message

        def on_ws_closed(params: JsonObject) -> None:
            with handle.lock:
                entry = handle.websockets.get(str(params.get("requestId")))
                if entry is not None:
                    entry["closed"] = True

        cdp.on("Network.requestWillBeSent", on_request)
        cdp.on("Network.requestWillBeSentExtraInfo", on_request_extra_info)
        cdp.on("Network.responseReceived", on_response)
        cdp.on("Network.responseReceivedExtraInfo", on_response_extra_info)
        cdp.on("Network.loadingFinished", on_loading_finished)
        cdp.on("Network.webSocketCreated", on_ws_created)
        cdp.on("Network.webSocketWillSendHandshakeRequest", on_ws_will_send_handshake)
        cdp.on("Network.webSocketHandshakeResponseReceived", on_ws_handshake)
        cdp.on("Network.webSocketFrameSent", on_ws_frame_sent)
        cdp.on("Network.webSocketFrameReceived", on_ws_frame_received)
        cdp.on("Network.webSocketFrameError", on_ws_frame_error)
        cdp.on("Network.webSocketClosed", on_ws_closed)
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

    def network_list(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = list(handle.requests.values())
            dropped = handle.requests_dropped
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        # ``_har`` is the internal HAR-enrichment payload (headers, timing); it
        # is deliberately not part of the lean network.list row, so project it
        # out without mutating the stored entry.
        window = [_without_har(item) for item in items[start : start + cap]]
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
            return {**_without_har(entry), "body_error": str(exc)}
        if not isinstance(body, str):
            body = str(body)
        if base64_encoded:
            # A binary body: hand back the decoded resource on disk, not base64 text.
            inline, spill, cut = _spill_base64_body(
                body, artifact_dir=artifact_dir, filename=f"body-{uuid4().hex}.bin"
            )
        else:
            inline, spill, cut = _spill_text(
                body,
                artifact_dir=artifact_dir,
                filename=f"body-{uuid4().hex}.bin",
                kind="response body",
            )
        result = _without_har(entry)
        result["body"] = inline
        result["body_truncated"] = cut
        if spill is not None:
            result["body_path"] = str(spill)
        result["base64_encoded"] = base64_encoded
        return result

    def ws_list(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            items = [_ws_summary(entry) for entry in handle.websockets.values()]
            dropped = handle.websockets_dropped
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        return {
            "websockets": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
            "dropped": dropped,
        }

    def ws_frames(
        self, session_id: str, ws_id: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        handle = self._get(session_id)
        with handle.lock:
            entry = handle.websockets.get(ws_id)
            if entry is None:
                raise WebError("not_found", "unknown websocket id", ws_id=ws_id)
            frames = list(entry["_frames"])
            frames_dropped = int(entry.get("frames_dropped", 0))
            url = entry.get("url")
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = frames[start : start + cap]
        return {
            "wsId": ws_id,
            "url": url,
            "frames": window,
            "count": len(window),
            "total": len(frames),
            "offset": start,
            "has_more": start + len(window) < len(frames),
            "dropped": frames_dropped,
        }

    def console(self, session_id: str, *, limit: int = 200) -> JsonObject:
        handle = self._get(session_id)
        capped = max(1, min(int(limit), _MAX_CONSOLE))
        with handle.lock:
            held = list(handle.console)
            dropped = handle.console_dropped
        page = held[-capped:]
        return {
            "console": page,
            "count": len(page),
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
        # A WebAssembly script carries its module bytes as base64 ``bytecode``
        # alongside the WAT-text ``scriptSource``. The text spills as .wat; the
        # bytes become a real .wasm below so static analysis can pick them up.
        bytecode = resp.get("bytecode")
        is_wasm = isinstance(bytecode, str) and bytecode != ""
        inline, spill, cut = _spill_text(
            source,
            artifact_dir=artifact_dir,
            filename=f"script-{uuid4().hex}.{'wat' if is_wasm else 'js'}",
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
        if is_wasm:
            result["language"] = "WebAssembly"
            wasm_path, wasm_bytes = _spill_wasm_bytecode(
                bytecode,
                artifact_dir=artifact_dir,
                filename=f"module-{uuid4().hex}.wasm",
            )
            result["wasm_bytecode_path"] = str(wasm_path)
            result["wasm_bytes"] = wasm_bytes
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
            return {
                "url": _bounded_metadata(handle.page.url, _MAX_URL_BYTES)[0],
                "title": _safe_title(handle.page),
                "html": text[:_MAX_INLINE_BODY],
                "truncated": bool(clipped.get("truncated")) or len(text) > _MAX_INLINE_BODY,
            }

        return self._runner(handle).call(work)

    def cookies(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                resp = handle.cdp.send("Network.getAllCookies")
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"cannot read cookies: {exc}") from exc
            raw = resp.get("cookies") if isinstance(resp, dict) else None
            return raw if isinstance(raw, list) else []

        # Network.getAllCookies returns the whole browser-context jar, including
        # HttpOnly cookies that page JS (document.cookie) can never see -- the
        # reason this exists beside the per-request Cookie headers in
        # network.list. Normalise to a stable field set so a missing sameSite or
        # priority is a null, not an absent key a caller has to guard.
        entries = self._runner(handle).call(work)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_COOKIES))
        window = entries[start : start + cap]
        cookies = [
            {field: cookie.get(field) for field in _COOKIE_FIELDS}
            for cookie in window
            if isinstance(cookie, dict)
        ]
        return {
            "cookies": cookies,
            "count": len(cookies),
            "total": len(entries),
            "offset": start,
            "has_more": start + len(window) < len(entries),
        }

    def storage(
        self, session_id: str, *, which: str = "local", offset: int = 0, limit: int = 100
    ) -> JsonObject:
        if which not in ("local", "session"):
            raise WebError("invalid_params", "which must be local or session", which=which)
        handle = self._get(session_id)

        # Bound both the per-value preview and the key count in the page so a
        # bloated store cannot pull megabytes across the bridge. The store is
        # per-origin (local) or per-tab (session); reading it needs the page's
        # own context, so this goes through page.evaluate, not a CDP domain.
        script = (
            "(args) => {"
            " const [store, maxval, maxkeys] = args;"
            " const s = store === 'session' ? window.sessionStorage : window.localStorage;"
            " const n = s.length; const out = []; const lim = Math.min(n, maxkeys);"
            " for (let i = 0; i < lim; i++) {"
            "  const k = s.key(i); const v = s.getItem(k) ?? '';"
            "  out.push([k, v.length > maxval ? v.slice(0, maxval) : v, v.length]);"
            " }"
            " return { total: n, entries: out, capped: n > maxkeys };"
            "}"
        )

        def work() -> JsonObject:
            try:
                raw = handle.page.evaluate(script, [which, _MAX_STORAGE_VALUE, _MAX_STORAGE_KEYS])
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"cannot read storage: {exc}") from exc
            if not isinstance(raw, dict):
                raise WebError("backend_error", "storage read returned no object")
            return raw

        raw = self._runner(handle).call(work)
        rows = raw.get("entries") if isinstance(raw.get("entries"), list) else []
        total = int(raw.get("total") or 0)
        # Sort by key so paging is stable across calls; the store's own order is
        # insertion order and not something a caller can rely on.
        parsed: list[JsonObject] = []
        for row in rows:
            if not isinstance(row, list) or len(row) != 3:
                continue
            key, value, true_len = str(row[0]), str(row[1]), int(row[2])
            parsed.append(
                {
                    "key": key,
                    "value": value,
                    "value_len": true_len,
                    "value_truncated": true_len > len(value),
                }
            )
        parsed.sort(key=lambda item: item["key"])
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_STORAGE_KEYS))
        window = parsed[start : start + cap]
        return {
            "which": which,
            "entries": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < len(parsed),
            # The store had more keys than the page-side read guard, so total can
            # exceed what was actually pulled -- say so rather than let a caller
            # read a short list as the whole store.
            "scan_capped": bool(raw.get("capped")),
        }

    def frames(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        handle = self._get(session_id)

        def work() -> JsonObject:
            try:
                resp = handle.cdp.send("Page.getFrameTree")
            except Exception as exc:  # noqa: BLE001
                raise WebError("backend_error", f"cannot read frame tree: {exc}") from exc
            if not isinstance(resp, dict):
                raise WebError("backend_error", "frame tree read returned no object")
            return resp

        resp = self._runner(handle).call(work)
        tree = resp.get("frameTree")
        flat: list[JsonObject] = []
        capped = False

        # Page.getFrameTree is a nested {frame, childFrames} structure; flatten it
        # depth-first so a parent always precedes its children, which is the order
        # a caller reads the embedding from. Cross-origin iframes (ads, payment
        # widgets, embedded SPAs) are exactly what the main-frame DOM snapshot
        # misses, so each row keeps its securityOrigin and parent link.
        def walk(node: object, depth: int) -> None:
            nonlocal capped
            if not isinstance(node, dict):
                return
            if len(flat) >= _MAX_FRAMES:
                capped = True
                return
            frame = node.get("frame")
            if isinstance(frame, dict):
                url, url_cut = _bounded_metadata(str(frame.get("url", "")), _MAX_URL_BYTES)
                parent = frame.get("parentId")
                flat.append(
                    {
                        "frameId": str(frame.get("id", "")),
                        "parentFrameId": str(parent) if parent else None,
                        "name": _bounded_metadata(str(frame.get("name", "")), _MAX_METADATA_BYTES)[
                            0
                        ],
                        "url": url,
                        "url_truncated": url_cut,
                        "securityOrigin": _bounded_metadata(
                            str(frame.get("securityOrigin", "")), _MAX_URL_BYTES
                        )[0],
                        "mimeType": str(frame.get("mimeType", "")),
                        "depth": depth,
                        "is_main": depth == 0,
                    }
                )
            for child in node.get("childFrames") or []:
                walk(child, depth + 1)

        if isinstance(tree, dict):
            walk(tree, 0)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_FRAMES))
        window = flat[start : start + cap]
        return {
            "frames": window,
            "count": len(window),
            "total": len(flat),
            "offset": start,
            "has_more": start + len(window) < len(flat),
            # The tree had more frames than the flatten guard, so total counts
            # only what was pulled -- say so rather than let a short list read as
            # the whole tree.
            "scan_capped": capped,
        }

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
            entries = [_cdp_entry_to_har(e) for e in handle.requests.values()]
            entries.extend(_ws_entry_to_har(c) for c in handle.websockets.values())
        import json

        har = har_builder.document(entries)
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
