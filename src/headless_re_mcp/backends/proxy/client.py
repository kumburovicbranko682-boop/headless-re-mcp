"""In-process HTTP(S) interception via a threaded mitmproxy DumpMaster.

One proxy per session. mitmproxy runs its own asyncio loop, so it lives on a
dedicated thread; a bounded addon records flows into a ring buffer that the
read tools query. mitmproxy is optional and the API differs across versions, so
startup is defensive and a missing module degrades to ``capability_unavailable``.
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import contextlib
import hashlib
import json
import logging
import os
import re
import socket
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from headless_re_mcp.backends import har

JsonObject = dict[str, Any]
_MAX_FLOWS = 2000
_REPLAY_WAIT_S = 15.0
# The ring is count-capped, but each slot can still hold a multi-megabyte
# request or response. Two thousand of those is the overnight OOM the count
# cap was supposed to prevent.
_MAX_STORED_BODY = 2 * 1024 * 1024
_MAX_RETAINED_BYTES = 64 * 1024 * 1024
_MAX_URL_BYTES = 16 * 1024
_MAX_METADATA_BYTES = 1024
_OMITTED_BODY = object()
# WebSocket message surfacing on a flow: bound the payload preview per message
# and how many messages one flow.get returns, so a chatty socket cannot produce
# an unbounded tool result.
_MAX_WS_PAYLOAD = 8 * 1024
_MAX_WS_MESSAGES = 500
# The frames themselves ride on mitmproxy's own flow object, which grows for the
# whole life of the socket -- a long-lived chatty socket is the same overnight
# OOM the body caps guard against, just via a container the recorder does not
# own. Bound the retained frames per flow by count and by total bytes, evicting
# the oldest and disclosing how many were dropped, so the process stays bounded
# no matter how long a socket stays open.
_MAX_WS_RETAINED = 2000
_MAX_WS_RETAINED_BYTES = 16 * 1024 * 1024
# A flow body at or below this inlines as text; a larger one spills to a file.
_MAX_INLINE_BODY = 200_000


def _looks_textual(data: bytes) -> bool:
    """True when the bytes are safe to inline as text rather than spill to a file.

    A binary body (a .wasm, an image, a font) inlined via ``decode`` is useless
    for the very static tools a proxy capture exists to feed: either it comes
    back as mojibake (bytes >= 0x80) or, for an all-low-byte module, it reads as
    a string a path-taking tool cannot open. Two cheap sniffs decide it:

    * a NUL byte never appears in real text (HTML/JSON/JS/CSS) but is pervasive
      in binary formats -- and it catches an all-ASCII-range wasm module that a
      strict utf-8 decode would otherwise wrongly accept as text;
    * bytes that are not valid UTF-8 at all.

    Anything that trips either is spilled to a file where the exact bytes
    survive, the same contract the web line already keeps for a binary body.
    """
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


class ProxyError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


# DumpMaster ships addons that exist to run the mitmdump *command*, not to serve
# an embedded proxy, and two of them break a threaded embedding on cold start:
#   * errorcheck calls sys.exit() as soon as anything is logged at ERROR during
#     startup -- it is meant to end the mitmdump process on a bad flag.
#   * readfilestdin / keepserving exist to read flows from a "-r rfile" and keep
#     the CLI alive afterwards; their async running() hooks read ctx.options.rfile
#     and, on a cold start, race option registration and log
#     "Addon error: No such option: rfile".
# errorcheck then turns that benign race into sys.exit(1), which surfaced here as
# an intermittent (~7% of starts) "mitmproxy failed to start: 1" or a port that
# never got released. This backend owns the proxy lifecycle and never reads a
# flow file, so none of these belong; dropping them removes both the error source
# and the process-killing reaction.
_CLI_ONLY_ADDONS: tuple[str, ...] = ("errorcheck", "readfilestdin", "readfile", "keepserving")


def _strip_cli_only_addons(master: Any) -> None:
    manager = getattr(master, "addons", None)
    if manager is None:
        return
    for name in _CLI_ONLY_ADDONS:
        with contextlib.suppress(Exception):
            existing = manager.get(name)
            if existing is not None:
                manager.remove(existing)


def _shutdown_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel and await every remaining task, then close the loop.

    Transports (including the proxy's listening socket) are only closed when the
    tasks owning them are allowed to unwind, so this is what actually frees the
    port rather than merely dropping the loop's reference to it.
    """
    try:
        pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
    finally:
        loop.close()


def _port_accepts(host: str, port: int, timeout: float = 0.25) -> bool:
    """True when something is listening and accepting on host:port."""
    with contextlib.suppress(OSError), socket.socket() as probe:
        probe.settimeout(timeout)
        return probe.connect_ex((host, port)) == 0
    return False


def _port_bindable(host: str, port: int) -> bool:
    """True when a listener could take host:port right now.

    ``_port_accepts`` answers a different question -- whether somebody is
    serving -- and says "free" for a port held by a socket that is not
    accepting: one whose backlog is full, one bound without ``listen``, one
    behind a filter. Believing it there means mitmproxy is started on a port it
    cannot bind, and the caller waits out the whole readiness timeout for an
    answer that was available immediately.
    """
    with contextlib.suppress(OSError), socket.socket() as probe:
        # Match what asyncio will do when it binds for real, so this probe never
        # refuses a port the server itself would have taken.
        if os.name != "nt":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    return False


def _uninstall_master_logging(
    master: Any, loop: asyncio.AbstractEventLoop | None = None
) -> None:
    """Detach the root-logger handler mitmproxy installs in ``Master.__init__``.

    mitmproxy removes it in ``Master.done()``, which only runs after a normal
    ``run()``; a startup that fails never gets there. What is left behind is
    worse than a lost object: the handler stays on the root logger holding the
    master, its addons and every captured flow, and each later log record from
    anywhere in the process is dispatched into an event loop that is closed.
    """
    if master is None and loop is None:
        return
    handler = getattr(master, "_legacy_log_events", None)
    if handler is not None:
        with contextlib.suppress(Exception):
            handler.uninstall()
    root = logging.getLogger()
    for candidate in list(root.handlers):
        owner = getattr(candidate, "master", None)
        if owner is None:
            continue
        # By loop as well as by identity: a constructor that raises after
        # installing the handler leaves a master nothing else can reach.
        if owner is master or (loop is not None and getattr(owner, "event_loop", None) is loop):
            with contextlib.suppress(Exception):
                root.removeHandler(candidate)


def _content_len(part: Any) -> int:
    if part is None:
        return 0
    content = getattr(part, "raw_content", None)
    if not content:
        return 0
    try:
        return len(content)
    except TypeError:
        return 0


def _encoded_len(value: object) -> int:
    try:
        return len(str(value).encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return _MAX_STORED_BODY + 1


def _headers_len(part: Any) -> int:
    headers = getattr(part, "headers", None)
    if headers is None:
        return 0
    try:
        try:
            items = headers.items(multi=True)
        except TypeError:
            items = headers.items()
        total = 0
        for key, value in items:
            total += _encoded_len(key) + _encoded_len(value)
            if total > _MAX_STORED_BODY:
                break
        return total
    except Exception:  # noqa: BLE001
        return 0


def _flow_stored_bytes(flow: Any) -> int:
    request = getattr(flow, "request", None)
    response = getattr(flow, "response", None)
    total = _content_len(request) + _content_len(response)
    for value in (
        getattr(request, "method", ""),
        getattr(request, "pretty_url", ""),
        getattr(request, "host", ""),
    ):
        total += _encoded_len(value)
    return total + _headers_len(request) + _headers_len(response)


def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    payload = text.encode("utf-8", errors="replace")
    if len(payload) <= max_bytes:
        return text, False
    return payload[:max_bytes].decode("utf-8", errors="ignore"), True


def _ws_message_size(msg: Any) -> int:
    content = getattr(msg, "content", b"") or b""
    if isinstance(content, bytes | bytearray):
        return len(content)
    return len(str(content).encode(errors="replace"))


def _normalize_ws_message(msg: Any) -> JsonObject:
    """Normalise one mitmproxy WebSocket message into a JSON-safe record.

    A text message keeps a bounded text preview, a binary message is base64 so the
    bytes survive, and direction is sent (client -> server) or received (server ->
    client). Oversized payloads are capped and flagged with ``payload_truncated``.
    """
    content = getattr(msg, "content", b"") or b""
    if not isinstance(content, bytes | bytearray):
        content = str(content).encode(errors="replace")
    content = bytes(content)
    opcode = getattr(msg, "type", None)
    opcode_int = int(opcode) if isinstance(opcode, int) else None
    is_text = opcode_int == 0x1
    if is_text:
        payload, truncated = _bounded_metadata(
            content.decode("utf-8", errors="replace"), _MAX_WS_PAYLOAD
        )
        kind = "text"
    else:
        payload = base64.b64encode(content[:_MAX_WS_PAYLOAD]).decode("ascii")
        truncated = len(content) > _MAX_WS_PAYLOAD
        kind = "binary"
    record: JsonObject = {
        "direction": "sent" if bool(getattr(msg, "from_client", False)) else "received",
        "opcode": opcode_int,
        "type": kind,
        "payload": payload,
        "payload_len": len(content),
        "ts": getattr(msg, "timestamp", None),
    }
    if truncated:
        record["payload_truncated"] = True
    return record


def _ws_search_text(msg: Any) -> tuple[str, str, str, int, Any]:
    """A WebSocket message rendered for content search: (text, direction, type, len, ts).

    Unlike ``_normalize_ws_message`` (which base64s binary and bounds the preview
    for display), this decodes the full frame content -- text or binary alike --
    with replacement so a JSON payload sent on a binary opcode is still matchable.
    """
    content = getattr(msg, "content", b"") or b""
    if not isinstance(content, bytes | bytearray):
        content = str(content).encode(errors="replace")
    content = bytes(content)
    opcode = getattr(msg, "type", None)
    opcode_int = int(opcode) if isinstance(opcode, int) else None
    kind = "text" if opcode_int == 0x1 else "binary"
    direction = "sent" if bool(getattr(msg, "from_client", False)) else "received"
    return (
        content.decode("utf-8", errors="replace"),
        direction,
        kind,
        len(content),
        getattr(msg, "timestamp", None),
    )


def _ws_messages_view(
    flow: Any, *, offset: int = 0, limit: int = _MAX_WS_MESSAGES
) -> JsonObject | None:
    """The WebSocket messages mitmproxy accumulated on a flow, bounded for a reply.

    Returns None for a plain HTTP flow. For a WebSocket flow, a window of ``limit``
    messages starting at ``offset`` is normalised (see ``_normalize_ws_message``),
    with ``total``/``offset``/``has_more`` so a page that filled the limit is not
    mistaken for the whole conversation.
    """
    ws = getattr(flow, "websocket", None)
    if ws is None:
        return None
    messages = list(getattr(ws, "messages", None) or [])
    start = max(0, int(offset))
    cap = max(0, int(limit))
    window = messages[start : start + cap] if cap else []
    out = [_normalize_ws_message(msg) for msg in window]
    view: JsonObject = {
        "messages": out,
        "count": len(out),
        "total": len(messages),
        "offset": start,
        "has_more": start + len(out) < len(messages),
        "closed": getattr(ws, "timestamp_end", None) is not None,
    }
    close_code = getattr(ws, "close_code", None)
    if close_code is not None:
        view["close_code"] = close_code
    return view


def _http_version(part: Any) -> str:
    version = getattr(part, "http_version", None)
    return str(version) if version else "HTTP/1.1"


def _header_value(part: Any, name: str) -> str:
    headers = getattr(part, "headers", None)
    if headers is None:
        return ""
    try:
        value = headers.get(name, "")
    except (AttributeError, TypeError):
        return ""
    return str(value or "")


def _header_all(part: Any, name: str) -> str:
    """All values for one header, newline-joined so Set-Cookie stays splittable.

    mitmproxy's ``headers.get`` comma-joins duplicates, which corrupts cookies
    (an Expires date contains commas); ``get_all`` keeps each value intact.
    """
    headers = getattr(part, "headers", None)
    if headers is not None:
        getter = getattr(headers, "get_all", None)
        if callable(getter):
            try:
                values = getter(name)
            except (AttributeError, TypeError):
                values = None
            if values:
                return "\n".join(str(v) for v in values)
    return _header_value(part, name)


def _har_body(part: Any) -> bytes:
    """The exchange body for HAR: mitmproxy's decoded ``content`` when available.

    ``content`` is the decompressed body a HAR consumer expects; ``raw_content``
    is the fallback for stubs that only set that. Accessing ``.content`` can
    raise on a malformed encoding, so it is guarded -- a body we cannot decode
    simply becomes an empty preview rather than failing the whole export.
    """
    if part is None:
        return b""
    for attr in ("content", "raw_content"):
        try:
            value = getattr(part, attr, None)
        except Exception:  # noqa: BLE001 - mitmproxy .content decodes and may raise
            value = None
        if value:
            if isinstance(value, bytes):
                return value
            try:
                return bytes(value)
            except (TypeError, ValueError):
                continue
    return b""


def _flow_to_har_entry(summary: JsonObject, flow: Any) -> JsonObject:
    """Build one HAR entry from a recorded summary plus its raw flow (if kept).

    The summary always has method/url/status/content_type; the raw flow, when it
    survived body omission and eviction, adds headers, the request/response
    bodies and the real timestamps. When it did not, the entry is still valid --
    just sparse -- so a HAR export never fails because some flows aged out.
    """
    url = str(summary.get("url") or "")
    method = str(summary.get("method") or "")
    status = summary.get("status")
    content_type = str(summary.get("content_type") or "")
    req = getattr(flow, "request", None) if flow is not None else None
    resp = getattr(flow, "response", None) if flow is not None else None

    req_start = getattr(req, "timestamp_start", None)
    req_end = getattr(req, "timestamp_end", None)
    resp_start = getattr(resp, "timestamp_start", None)
    resp_end = getattr(resp, "timestamp_end", None)
    send = har.duration_ms(req_start, req_end)
    wait = har.duration_ms(req_end if req_end is not None else req_start, resp_start)
    receive = har.duration_ms(resp_start, resp_end)

    request = har.request_entry(
        method=method,
        url=url,
        http_version=_http_version(req),
        headers=getattr(req, "headers", None),
        body=_har_body(req),
        mime=_header_value(req, "content-type"),
        body_size=_content_len(req) if req is not None else -1,
        cookies=har.request_cookies(_header_value(req, "cookie")),
    )
    response = har.response_entry(
        status=status if status is not None else 0,
        status_text=str(getattr(resp, "reason", "") or ""),
        http_version=_http_version(resp),
        headers=getattr(resp, "headers", None),
        body=_har_body(resp),
        mime=content_type,
        redirect_url=_header_value(resp, "location"),
        body_size=_content_len(resp) if resp is not None else -1,
        cookies=har.response_cookies(_header_all(resp, "set-cookie")),
    )
    extras: JsonObject | None = None
    ws_view = _ws_messages_view(flow) if flow is not None else None
    if ws_view is not None:
        extras = {
            "_resourceType": "websocket",
            "_webSocketMessages": har.websocket_messages(ws_view["messages"]),
        }
    return har.entry(
        started=req_start,
        time_ms=har.total_time(send, wait, receive),
        request=request,
        response=response,
        timings_obj=har.timings(send, wait, receive),
        extras=extras,
    )


class _FlowRecorder:
    """A mitmproxy addon that snapshots finished flows into a ring buffer.

    Written from mitmproxy's event-loop thread and read from MCP worker threads,
    so every access takes the lock. Both containers are bounded and evicted in
    lockstep: the summaries are small, but ``_raw`` holds whole flow objects
    including bodies, so letting it grow with the capture is how an unattended
    run runs the host out of memory overnight.
    """

    def __init__(self, capacity: int = _MAX_FLOWS) -> None:
        self._capacity = max(1, capacity)
        self.flows: deque[JsonObject] = deque(maxlen=self._capacity)
        self._seq = 0
        self._raw: OrderedDict[str, Any] = OrderedDict()
        self._raw_sizes: dict[str, int] = {}
        self._retained_bytes = 0
        # Per-flow WebSocket accounting, kept alongside the raw retention: how
        # many frame bytes are still held on each flow and how many were evicted
        # to stay under the caps. These live for the socket, not just the ring.
        self._ws_bytes: dict[str, int] = {}
        self._ws_dropped: dict[str, int] = {}
        self._lock = threading.RLock()

    def _omit_retained(self, flow_id: str) -> None:
        retained = self._raw.get(flow_id)
        if retained is None or retained is _OMITTED_BODY:
            return
        self._raw[flow_id] = _OMITTED_BODY
        self._retained_bytes -= self._raw_sizes.pop(flow_id, 0)
        for summary in reversed(self.flows):
            if summary.get("id") == flow_id:
                summary["body_omitted"] = True
                break

    def response(self, flow: Any) -> None:  # mitmproxy calls this on each response
        req = flow.request
        resp = flow.response
        stored_bytes = _flow_stored_bytes(flow)
        omitted = stored_bytes > _MAX_STORED_BODY
        method, method_truncated = _bounded_metadata(req.method, _MAX_METADATA_BYTES)
        url, url_truncated = _bounded_metadata(req.pretty_url, _MAX_URL_BYTES)
        host, host_truncated = _bounded_metadata(req.host, _MAX_METADATA_BYTES)
        content_type, type_truncated = _bounded_metadata(
            resp.headers.get("content-type", "") if resp else "",
            _MAX_METADATA_BYTES,
        )
        with self._lock:
            self._seq += 1
            flow_id = str(getattr(flow, "id", None) or self._seq)
            self._raw.pop(flow_id, None)
            self._retained_bytes -= self._raw_sizes.pop(flow_id, 0)
            self._ws_bytes.pop(flow_id, None)
            self._ws_dropped.pop(flow_id, None)
            if not omitted:
                for retained_id, retained in list(self._raw.items()):
                    if self._retained_bytes + stored_bytes <= _MAX_RETAINED_BYTES:
                        break
                    if retained is not _OMITTED_BODY:
                        self._omit_retained(retained_id)
                omitted = self._retained_bytes + stored_bytes > _MAX_RETAINED_BYTES
            self._raw[flow_id] = _OMITTED_BODY if omitted else flow
            if not omitted:
                self._raw_sizes[flow_id] = stored_bytes
                self._retained_bytes += stored_bytes
            # Evict oldest raw flows in lockstep with the summary ring so the
            # two views can never disagree about which flows are retrievable.
            while len(self._raw) > self._capacity:
                evicted_id, _ = self._raw.popitem(last=False)
                self._retained_bytes -= self._raw_sizes.pop(evicted_id, 0)
                self._ws_bytes.pop(evicted_id, None)
                self._ws_dropped.pop(evicted_id, None)
            entry: JsonObject = {
                "id": flow_id,
                "seq": self._seq,
                "method": method,
                "url": url,
                "host": host,
                "status": getattr(resp, "status_code", None),
                "content_type": content_type,
            }
            if omitted:
                entry["body_omitted"] = True
            if method_truncated or url_truncated or host_truncated or type_truncated:
                entry["metadata_truncated"] = True
            self.flows.append(entry)

    def _refresh_ws_summary(self, flow_id: str, retained: int, dropped: int) -> None:
        # The flow was summarised at its 101 handshake response; mark it a
        # WebSocket flow and keep the retained/dropped counts current so
        # proxy.flows shows which flows carry frames, and that eviction happened,
        # without re-reading the raw.
        for summary in reversed(self.flows):
            if summary.get("id") == flow_id:
                summary["websocket"] = True
                summary["ws_messages"] = retained
                if dropped:
                    summary["ws_dropped"] = dropped
                break

    def websocket_message(self, flow: Any) -> None:  # mitmproxy calls this per WS message
        ws = getattr(flow, "websocket", None)
        messages = getattr(ws, "messages", None) if ws is not None else None
        if not isinstance(messages, list):
            return
        flow_id = str(getattr(flow, "id", None) or "")
        with self._lock:
            # Exactly one new message is appended per hook call; account its
            # bytes, then evict the oldest until the per-flow count and byte caps
            # hold again. A single frame larger than the byte cap is kept (we
            # cannot shrink it) rather than dropping the whole conversation.
            if messages:
                self._ws_bytes[flow_id] = self._ws_bytes.get(flow_id, 0) + _ws_message_size(
                    messages[-1]
                )
            dropped = 0
            while len(messages) > 1 and (
                len(messages) > _MAX_WS_RETAINED
                or self._ws_bytes.get(flow_id, 0) > _MAX_WS_RETAINED_BYTES
            ):
                evicted = messages.pop(0)
                self._ws_bytes[flow_id] = max(
                    0, self._ws_bytes.get(flow_id, 0) - _ws_message_size(evicted)
                )
                dropped += 1
            if dropped:
                self._ws_dropped[flow_id] = self._ws_dropped.get(flow_id, 0) + dropped
            self._refresh_ws_summary(flow_id, len(messages), self._ws_dropped.get(flow_id, 0))

    def websocket_end(self, flow: Any) -> None:  # mitmproxy calls this on WS close
        ws = getattr(flow, "websocket", None)
        messages = getattr(ws, "messages", None) if ws is not None else None
        flow_id = str(getattr(flow, "id", None) or "")
        with self._lock:
            retained = len(messages) if isinstance(messages, list) else 0
            self._refresh_ws_summary(flow_id, retained, self._ws_dropped.get(flow_id, 0))

    def ws_dropped(self, flow_id: str) -> int:
        with self._lock:
            return int(self._ws_dropped.get(flow_id, 0))

    def snapshot(self) -> list[JsonObject]:
        with self._lock:
            return list(self.flows)

    def raw(self, flow_id: str) -> Any | None:
        with self._lock:
            return self._raw.get(flow_id)

    def count(self) -> int:
        with self._lock:
            return len(self.flows)

    def retained_bytes(self) -> int:
        with self._lock:
            return self._retained_bytes


class _ProxyInstance:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.recorder = _FlowRecorder()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: Any = None
        self._started = threading.Event()
        self._error: BaseException | None = None

    def start(self, timeout: float = 15.0) -> None:
        """Return only once the proxy is actually accepting connections.

        Reaching mitmproxy's run() is not the same as having bound the port: a
        busy port fails a moment later, and reporting "running" for a proxy that
        is about to die is how an unattended capture silently records nothing.
        """
        # Refuse up front if the port is already taken -- typically a proxy this
        # service leaked on a previous run. Without this the readiness probe
        # below would see the foreign listener and call it success, which is the
        # same lie in a different disguise. Both questions have to be asked: a
        # holder that never accepts is invisible to the connect probe.
        if _port_accepts(self.host, self.port) or not _port_bindable(self.host, self.port):
            raise ProxyError(
                "invalid_state",
                "port is already in use; stop the existing listener first",
                host=self.host,
                port=self.port,
            )
        self._thread = threading.Thread(
            target=self._run, name=f"mitmproxy-{self.port}", daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            if self._error is not None:
                raise ProxyError("backend_error", f"mitmproxy failed to start: {self._error}")
            if not self._thread.is_alive():
                raise ProxyError("backend_error", "mitmproxy exited during startup")
            if _port_accepts(self.host, self.port):
                return
            time.sleep(0.05)
        self.stop()
        raise ProxyError(
            "timeout", "mitmproxy did not begin listening in time", port=self.port
        )

    def _run(self) -> None:
        loop: asyncio.AbstractEventLoop | None = None
        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            opts = options.Options(listen_host=self.host, listen_port=self.port)
            # Only the constructor may disagree about kwargs across mitmproxy
            # versions. Catching TypeError around run() too would treat a bug
            # inside a running proxy as a signature mismatch and start a second
            # DumpMaster on the same port.
            try:
                master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            except TypeError:
                master = DumpMaster(opts)
            _strip_cli_only_addons(master)
            master.addons.add(self.recorder)
            self._master = master
            self._started.set()
            loop.run_until_complete(master.run())
        except BaseException as exc:  # noqa: BLE001 - report to the starting thread
            self._error = exc
            self._started.set()
        finally:
            # Closing the loop outright abandons mitmproxy's still-pending
            # accept task, which leaves the listening socket open at the OS
            # level: stop() would appear to work while the port stayed bound
            # and the next capture could never start. Unwind the tasks first.
            if loop is not None:
                with contextlib.suppress(Exception):
                    _shutdown_loop(loop)
            _uninstall_master_logging(self._master, loop)

    def _close_servers(self, master: Any, loop: asyncio.AbstractEventLoop) -> None:
        """Close the proxyserver addon's listening sockets on the loop thread.

        ``master.shutdown()`` only sets ``should_exit``; from mitmproxy 10 the
        proxyserver addon frees its listening sockets when its server list is
        emptied, not on the Done hook that a plain shutdown fires. ``mitmdump``
        never noticed because the process exits and the OS reclaims the port, but
        this backend runs mitmproxy on a thread inside a long-lived service, so
        the socket would stay bound and the next capture on that port would be
        refused. Stopping each running server here is what actually frees it.

        Best-effort by design: the addon layout differs across mitmproxy
        versions, so any failure falls through to the shutdown() path below
        rather than blocking stop().
        """
        ps = None
        with contextlib.suppress(Exception):
            ps = master.addons.get("proxyserver")
        servers = getattr(ps, "servers", None)
        if servers is None:
            return
        done: concurrent.futures.Future[bool] = concurrent.futures.Future()

        async def _teardown() -> None:
            try:
                # Stop each ServerInstance directly rather than via update([]),
                # so freeing this proxy's port does not depend on the
                # process-global mitmproxy.ctx (shared by every proxy) still
                # pointing at this master.
                stop_tasks = [
                    server.stop()
                    for server in list(servers)
                    if getattr(server, "stop", None) is not None
                ]
                if stop_tasks:
                    await asyncio.gather(*stop_tasks, return_exceptions=True)
            finally:
                if not done.done():
                    done.set_result(True)

        def _schedule() -> None:
            try:
                asyncio.ensure_future(_teardown())
            except Exception as exc:  # noqa: BLE001 - loop may be closing
                if not done.done():
                    done.set_exception(exc)

        with contextlib.suppress(Exception):
            loop.call_soon_threadsafe(_schedule)
            with contextlib.suppress(Exception):
                done.result(timeout=8.0)

    def stop(self) -> None:
        master = self._master
        loop = self._loop
        if master is not None and loop is not None:
            self._close_servers(master, loop)
            with contextlib.suppress(Exception):
                loop.call_soon_threadsafe(master.shutdown)
        if self._thread is not None:
            self._thread.join(timeout=10.0)
        # Also here, not only in the thread's own unwind: a thread that is wedged
        # never runs its finally, and a stale handler is the one piece of a dead
        # proxy that keeps costing the whole process something.
        _uninstall_master_logging(master)
        self._master = None
        self._loop = None


def _flow_filter(
    method: str, host: str, url_contains: str, content_type: str, status: int
) -> JsonObject:
    """The active, normalised proxy.flows filter -- empty when nothing was asked.

    Each field is folded to the case the comparison uses (method upper, the
    substring fields lower) so the echoed ``filter`` in the reply is exactly what
    was matched, and an all-blank request produces an empty dict, which the caller
    reads as "unfiltered".
    """
    active: JsonObject = {}
    if isinstance(method, str) and method.strip():
        active["method"] = method.strip().upper()
    if isinstance(host, str) and host.strip():
        active["host"] = host.strip().lower()
    if isinstance(url_contains, str) and url_contains.strip():
        active["url_contains"] = url_contains.strip().lower()
    if isinstance(content_type, str) and content_type.strip():
        active["content_type"] = content_type.strip().lower()
    if isinstance(status, int) and status > 0:
        active["status"] = int(status)
    return active


# Cap the ranked stats groups (hosts, content types, status codes) so a capture
# that saw thousands of distinct hosts cannot make one stats reply unbounded; the
# omission is disclosed with a *_truncated flag.
_MAX_STATS_GROUPS = 50


def _ranked(counts: dict[str, int], key_name: str, cap: int) -> tuple[list[JsonObject], bool]:
    """A count-descending, key-ascending ranked list plus a truncated flag.

    Ties break on the key so the ranking is stable across calls, and the list is
    capped so an unbounded dimension (hosts, content types) cannot blow the reply.
    """
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    rows = [{key_name: key, "count": value} for key, value in ordered[:cap]]
    return rows, len(ordered) > cap


# proxy.endpoints bounds: the page of endpoint rows and the ranked content-type
# list kept per endpoint, so a capture that touched thousands of routes or one
# route that returned many media types cannot make a reply unbounded.
_MAX_ENDPOINTS_PAGE = 1000
_MAX_ENDPOINT_CTYPES = 20
_UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX_RE = re.compile(r"(?i)^[0-9a-f]+$")
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9._~-]+$")


def _is_variable_segment(seg: str) -> bool:
    """True when a path segment looks like an id/hash/token, not a route name.

    Collapsing these to a placeholder is what turns ``/users/123`` and
    ``/users/456`` into one endpoint. Conservative on purpose: a plain numeric
    segment, a UUID, a hex string of 12+ chars (an object id / md5 / sha) or a
    long (24+) mixed alnum token qualifies, but an ordinary word never does.
    """
    if seg.isdigit():
        return True
    if _UUID_RE.match(seg):
        return True
    if len(seg) >= 12 and _HEX_RE.match(seg):
        return True
    return bool(
        len(seg) >= 24 and _TOKENISH_RE.match(seg) and any(c.isdigit() for c in seg)
    )


def _normalize_endpoint_path(path: str) -> str:
    """Replace id-like path segments with ``{id}`` so routes group together."""
    if not path:
        return "/"
    return "/".join("{id}" if _is_variable_segment(seg) else seg for seg in path.split("/"))


def _endpoint_path(url: str) -> tuple[str, bool]:
    """Split a captured URL into (path, has_query); path defaults to ``/``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "/", False
    return (parts.path or "/"), bool(parts.query)


def _flow_matches(row: JsonObject, active: JsonObject) -> bool:
    """True when one summary row satisfies every field of an active filter.

    method is exact (case-insensitive); host/url/content_type are
    case-insensitive substrings so a caller can name ``api.example.com`` or
    ``json`` without knowing the exact value; status is an exact code. A row with
    no status (a still-pending flow) never matches a status filter.
    """
    if "method" in active and str(row.get("method") or "").upper() != active["method"]:
        return False
    if "host" in active and active["host"] not in str(row.get("host") or "").lower():
        return False
    if "url_contains" in active and active["url_contains"] not in str(row.get("url") or "").lower():
        return False
    if (
        "content_type" in active
        and active["content_type"] not in str(row.get("content_type") or "").lower()
    ):
        return False
    return not ("status" in active and row.get("status") != active["status"])


# proxy.search bounds: the query length, the context shown around each hit, the
# per-flow occurrence tally (so one flow full of the needle cannot dominate the
# count), and the number of matching flows one reply carries.
_MAX_SEARCH_QUERY = 1024
_SEARCH_SNIPPET_CONTEXT = 80
_MAX_SEARCH_MATCHES_PER_FLOW = 1000
_MAX_SEARCH_RESULTS = 1000
# proxy.ws.search walks individual frames, not flows, so it needs its own scan
# ceiling (a long socket can hold far more frames than the ring holds flows) and
# a collected-match ceiling so a chatty channel cannot build an unbounded reply.
_MAX_WS_SEARCH_SCAN = 50_000
_MAX_WS_SEARCH_MATCHES = 5000


def _headers_text(part: Any) -> str:
    """One flow part's headers rendered as ``key: value`` lines for searching.

    Kept multi so a duplicated header (several Set-Cookie) is each searchable,
    and defensive because header containers differ across mitmproxy versions.
    """
    headers = getattr(part, "headers", None)
    if headers is None:
        return ""
    try:
        try:
            items = headers.items(multi=True)
        except TypeError:
            items = headers.items()
        return "\n".join(f"{key}: {value}" for key, value in items)
    except Exception:  # noqa: BLE001 - header containers vary by version
        return ""


def _body_text(part: Any) -> str:
    """A flow part's decoded body as text for substring search.

    ``_har_body`` returns the decompressed bytes; decoding with replacement
    keeps a text query matchable even when a body is partly binary, and the
    stored-body cap already bounds the length scanned.
    """
    return _har_body(part).decode("utf-8", errors="replace")


def _served_body(part: Any, *, raw: bool) -> tuple[bytes, bool, str]:
    """A flow part's body bytes, stripped of its content-encoding by default.

    mitmproxy's ``.content`` removes the HTTP content-encoding (gzip, br,
    deflate, zstd), so it is the readable text of a JSON/HTML response and the
    real file bytes of an image or ``.wasm`` to feed the static tools;
    ``.raw_content`` keeps the on-wire compression, which is almost never what a
    reader wants. So flow.get decodes by default and ``raw=True`` asks for the
    exact on-wire bytes instead. Returns (bytes, decoded, content_encoding),
    where decoded is False when the on-wire bytes were served -- raw was asked,
    or a malformed encoding ``.content`` could not decompress -- so a still
    compressed body is never misread as plaintext. Accessing ``.content`` decodes
    and can raise, so it is guarded.
    """
    if part is None:
        return b"", False, ""
    enc = _header_value(part, "content-encoding").strip()
    if raw:
        try:
            return (getattr(part, "raw_content", None) or b""), False, enc
        except Exception:  # noqa: BLE001 - mitmproxy attribute access can raise
            return b"", False, enc
    try:
        content = getattr(part, "content", None)
    except Exception:  # noqa: BLE001 - .content decodes and may raise
        content = None
    if isinstance(content, (bytes, bytearray)):
        return bytes(content), True, enc
    # ``.content`` is unavailable or raised: fall back to the on-wire bytes.
    # They are the decoded body only when there was no content-encoding to strip.
    try:
        raw_bytes = getattr(part, "raw_content", None) or b""
    except Exception:  # noqa: BLE001 - mitmproxy attribute access can raise
        raw_bytes = b""
    return bytes(raw_bytes), enc == "", enc


def _emit_body(
    target: JsonObject, body: bytes, decoded: bool, enc: str, artifact_dir: Path
) -> None:
    """Attach a body to a request/response dict: inline text, or spill the bytes.

    A text body at most the inline cap rides inline as ``body``; a larger body,
    or a binary one (a NUL or non-UTF-8 byte -- a captured image, font or
    ``.wasm``), spills to a ``.bin`` artifact named by ``body_path`` so the exact
    bytes reach the static tools instead of being mangled into replacement text.
    ``size`` is the served byte count. ``content_encoding`` and ``decoded`` are
    disclosed only when the part carried a content-encoding, so a compressed body
    a caller could not decompress (decoded False) is never read as plaintext.
    """
    target["size"] = len(body)
    if enc:
        target["content_encoding"] = enc
        target["decoded"] = decoded
    if body and (len(body) > _MAX_INLINE_BODY or not _looks_textual(body)):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        out = artifact_dir / f"flow-{uuid4().hex}.bin"
        out.write_bytes(body)
        target["body_path"] = str(out)
    else:
        target["body"] = body.decode("utf-8", errors="replace")


def _search_snippet(text: str, index: int, needle_len: int) -> str:
    """A one-line context window around a hit, with ellipses when clipped."""
    start = max(0, index - _SEARCH_SNIPPET_CONTEXT)
    end = min(len(text), index + needle_len + _SEARCH_SNIPPET_CONTEXT)
    fragment = text[start:end].replace("\r", " ").replace("\n", " ").replace("\t", " ")
    prefix = "\u2026" if start > 0 else ""
    suffix = "\u2026" if end < len(text) else ""
    return f"{prefix}{fragment}{suffix}"


def _count_occurrences(haystack: str, needle: str, cap: int) -> int:
    """Count non-overlapping occurrences of ``needle`` in ``haystack``, capped."""
    if not needle:
        return 0
    count = 0
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return count
        count += 1
        if count >= cap:
            return count
        start = index + len(needle)


# proxy.secrets bounds. Distinct findings, the page returned, distinct hosts
# kept per finding, and the per-flow scan ceilings, so a capture full of unique
# tokens or one flow with thousands of headers/cookies cannot build an unbounded
# reply. Values are clipped before storage so a huge header cannot bloat memory.
_MAX_SECRETS_COLLECT = 5000
_MAX_SECRETS_PAGE = 500
_MAX_SECRET_HOSTS = 20
_MAX_HEADERS_PER_FLOW = 200
_MAX_COOKIES_PER_FLOW = 100
_MAX_QUERY_PARAMS_PER_FLOW = 100
_MAX_SECRET_VALUE = 4096
_SECRET_VALUE_KEEP = 4
_SECRET_KINDS = frozenset(
    {"authorization", "api_key_header", "query_param", "cookie", "set_cookie"}
)
# Request headers that carry credentials directly (scheme + token).
_AUTH_HEADER_NAMES = frozenset({"authorization", "proxy-authorization"})
# Request headers commonly used to carry an API key / bearer token / CSRF token.
_APIKEY_HEADER_NAMES = frozenset(
    {
        "x-api-key", "api-key", "apikey", "x-apikey",
        "x-auth-token", "x-access-token", "x-session-token", "x-app-token",
        "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
        "x-goog-api-key", "x-functions-key", "private-token", "access-token",
        "auth-token", "authentication", "x-secret", "x-auth", "token",
    }
)
# Query-string parameter names that typically hold a secret.
_SECRET_QUERY_NAMES = frozenset(
    {
        "token", "access_token", "refresh_token", "id_token",
        "api_key", "apikey", "key", "auth", "authorization",
        "sig", "signature", "password", "passwd", "pwd",
        "secret", "client_secret", "session", "sessionid", "sid", "code",
    }
)
# Cookie-name fragments that mark a session/auth cookie (vs. an analytics one).
_SESSION_COOKIE_SUBSTR = (
    "session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf",
    "access", "refresh", "login", "identity",
)
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")


def _header_pairs(part: Any) -> list[tuple[str, str]]:
    """Every (name, value) header of a flow part, multi so duplicates survive."""
    headers = getattr(part, "headers", None)
    if headers is None:
        return []
    try:
        try:
            items = headers.items(multi=True)
        except TypeError:
            items = headers.items()
        return [(str(key), str(value)) for key, value in items]
    except Exception:  # noqa: BLE001 - header containers vary by version
        return []


def _is_apikey_header(lname: str) -> bool:
    """True when a request header name looks like an API-key/token carrier."""
    if lname in _APIKEY_HEADER_NAMES:
        return True
    if any(frag in lname for frag in ("api-key", "apikey", "api_key")):
        return True
    return lname.startswith("x-") and (
        lname.endswith("-token") or lname.endswith("-key") or "auth" in lname
    )


def _is_secret_query(lname: str) -> bool:
    if lname in _SECRET_QUERY_NAMES:
        return True
    return any(
        frag in lname
        for frag in ("token", "secret", "password", "apikey", "api_key", "signature")
    )


def _is_session_cookie(lname: str) -> bool:
    return any(frag in lname for frag in _SESSION_COOKIE_SUBSTR)


def _clip_secret(value: str) -> tuple[str, bool]:
    """Clip an over-long value before storage; returns (clipped, was_clipped)."""
    if len(value) > _MAX_SECRET_VALUE:
        return value[:_MAX_SECRET_VALUE], True
    return value, False


def _redact_value(value: str) -> str:
    """A safe-to-display preview: first/last few chars with the middle masked."""
    n = len(value)
    if n <= 4:
        return "\u2026"
    if n <= 2 * _SECRET_VALUE_KEEP + 3:
        return value[:2] + "\u2026" + value[-1:]
    return f"{value[:_SECRET_VALUE_KEEP]}\u2026{value[-_SECRET_VALUE_KEEP:]}"


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _decode_jwt(token: str) -> JsonObject | None:
    """Decode a JWT's header and registered claims (never its signature).

    Returns the algorithm/type from the header and the standard registered
    claims (issuer, subject, audience, expiry, ...) plus the names of every
    payload claim, so a caller can see who issued a token and when it expires
    without the tool interpreting arbitrary custom claim values. Any structural
    fault yields None -- the value is simply reported as an opaque token.
    """
    if not _JWT_RE.match(token):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:  # noqa: BLE001 - malformed base64/JSON is just "not a JWT"
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    hdr = {k: header[k] for k in ("alg", "typ", "kid") if k in header}
    claims = {
        k: payload[k]
        for k in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "azp", "scope")
        if k in payload
    }
    return {
        "header": hdr,
        "claims": claims,
        "claim_names": sorted(str(k) for k in payload)[:64],
    }


def _split_cookie_header(value: str) -> list[tuple[str, str]]:
    """Parse a request Cookie header into (name, value) pairs."""
    pairs: list[tuple[str, str]] = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, val = chunk.partition("=")
        name = name.strip()
        if sep and name:
            pairs.append((name, val.strip()))
    return pairs


def _parse_set_cookie(value: str) -> tuple[str, str, JsonObject]:
    """Parse a Set-Cookie value into (name, value, attribute-flags)."""
    first, _, rest = value.partition(";")
    name, sep, val = first.partition("=")
    name = name.strip()
    val = val.strip() if sep else ""
    attrs: JsonObject = {}
    for chunk in rest.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        akey, asep, aval = chunk.partition("=")
        akey = akey.strip().lower()
        if not akey:
            continue
        if asep:
            attrs[akey] = aval.strip()
        else:
            attrs[akey] = True
    return name, val, attrs


def _record_secret(
    aggregated: OrderedDict[tuple[str, str, str, str], JsonObject],
    seen: set[tuple[str, str, str, str]],
    finding: JsonObject,
) -> bool:
    """Fold one finding into the aggregate; return True if the collect cap blocked it.

    ``seen`` is reset per flow so a secret repeated within one exchange is counted
    once, making ``count`` the number of distinct flows a secret appeared in.
    Identical (kind, name, location, value) findings across flows collapse into
    one row whose count and host set grow. A JWT value is decoded once, on first
    sight, into its header/claims (never its signature).
    """
    value = str(finding["value"])
    clipped, was_clipped = _clip_secret(value)
    key = (
        str(finding["kind"]),
        str(finding["name"]),
        str(finding["location"]),
        clipped,
    )
    if key in seen:
        return False
    seen.add(key)
    agg = aggregated.get(key)
    if agg is None:
        if len(aggregated) >= _MAX_SECRETS_COLLECT:
            return True
        agg = {
            "kind": finding["kind"],
            "name": finding["name"],
            "location": finding["location"],
            "_value": clipped,
            "value_length": len(value),
            "value_sha256": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16],
            "count": 0,
            "_hosts": set(),
            "example_id": finding.get("flow_id", ""),
        }
        if was_clipped:
            agg["value_clipped"] = True
        if finding.get("scheme"):
            agg["scheme"] = finding["scheme"]
        if "session" in finding:
            agg["session"] = bool(finding["session"])
        if finding.get("cookie_attributes"):
            agg["cookie_attributes"] = finding["cookie_attributes"]
        jwt = _decode_jwt(value)
        if jwt is not None:
            agg["jwt"] = jwt
        aggregated[key] = agg
    agg["count"] = int(agg["count"]) + 1
    hostname = str(finding.get("host") or "")
    hosts: set[str] = agg["_hosts"]
    if hostname and len(hosts) < _MAX_SECRET_HOSTS:
        hosts.add(hostname)
    return False


class ProxyBackend:
    def __init__(self) -> None:
        self._instances: dict[str, _ProxyInstance] = {}
        self._lock = threading.RLock()
        self._available: bool | None = None

    def _check_available(self) -> None:
        if self._available is None:
            try:
                import mitmproxy  # noqa: F401

                self._available = True
            except Exception:
                self._available = False
        if not self._available:
            raise ProxyError("capability_unavailable", "mitmproxy is not installed")

    def _get(self, session_id: str) -> _ProxyInstance:
        with self._lock:
            inst = self._instances.get(session_id)
        if inst is None:
            raise ProxyError("invalid_state", "no proxy running for this session; call proxy.start")
        return inst

    def start(self, session_id: str, host: str = "127.0.0.1", port: int = 8080) -> JsonObject:
        self._check_available()
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ProxyError("invalid_params", "port must be 1..65535", port=port)
        with self._lock:
            if session_id in self._instances:
                raise ProxyError("invalid_state", "proxy already running for this session")
            for owner, existing in self._instances.items():
                if existing.host == host and existing.port == port:
                    raise ProxyError(
                        "invalid_state",
                        "port is already reserved by another session",
                        host=host,
                        port=port,
                        owner_session_id=owner,
                    )
            # Reserve before listen: two workers racing start() used to each
            # bind a port, and only the last write to this dict was tracked.
            inst = _ProxyInstance(host, port)
            self._instances[session_id] = inst
        try:
            inst.start()
        except BaseException:
            with self._lock:
                if self._instances.get(session_id) is inst:
                    self._instances.pop(session_id, None)
            with contextlib.suppress(Exception):
                inst.stop()
            raise
        with self._lock:
            if self._instances.get(session_id) is inst:
                return {
                    "running": True,
                    "host": host,
                    "port": port,
                    "endpoint": f"{host}:{port}",
                }
        with contextlib.suppress(Exception):
            inst.stop()
        raise ProxyError("invalid_state", "proxy was stopped while starting")

    def stop(self, session_id: str) -> JsonObject:
        with self._lock:
            inst = self._instances.pop(session_id, None)
        if inst is None:
            return {"stopped": False, "note": "no proxy was running"}
        inst.stop()
        return {"stopped": True}

    def status(self, session_id: str) -> JsonObject:
        with self._lock:
            inst = self._instances.get(session_id)
        if inst is None:
            return {"running": False}
        return {
            "running": True,
            "host": inst.host,
            "port": inst.port,
            "flow_count": inst.recorder.count(),
            "retained_max": _MAX_FLOWS,
            "retained_bytes": inst.recorder.retained_bytes(),
            "retained_bytes_max": _MAX_RETAINED_BYTES,
        }

    def flows(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: int = 0,
    ) -> JsonObject:
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        captured = len(items)
        # dropped is a property of the capture ring, not of any filter: compute it
        # from the full snapshot before narrowing, so a filtered view still
        # discloses that older flows were evicted.
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        active = _flow_filter(method, host, url_contains, content_type, status)
        matched = [row for row in items if _flow_matches(row, active)] if active else items
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = matched[start : start + cap]
        result: JsonObject = {
            "flows": window,
            "count": len(window),
            # total is the size of the set being paged: the matches when a filter
            # is active, so offset/has_more stay honest over the filtered view.
            "total": len(matched),
            "offset": start,
            "has_more": start + len(window) < len(matched),
            "dropped": dropped,
            # Every flow still in the ring, so a caller sees the filter narrow
            # captured -> total and cannot misread a small match set as a small
            # capture.
            "captured": captured,
        }
        if active:
            result["filter"] = active
        return result

    def stats(
        self,
        session_id: str,
        *,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: int = 0,
    ) -> JsonObject:
        """Aggregate the capture ring into a triage summary.

        proxy.flows lists individual exchanges; on a capture of thousands this
        answers the first triage question instead -- what is in here -- by
        counting flows across the dimensions that decide where to look: HTTP
        method, response status (both the exact codes and the 2xx/4xx/... class),
        the hosts contacted and the content types returned, plus how many flows
        are WebSockets or had their body omitted. Hosts, content types and status
        codes come back as count-descending ranked lists (capped, with a
        *_truncated flag); methods and status classes as small maps. It accepts
        the same filter surface as proxy.flows, so a caller can profile just one
        host or method. captured is the whole ring and total the counted subset,
        so a filter narrows captured -> total visibly.
        """
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        captured = len(items)
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        active = _flow_filter(method, host, url_contains, content_type, status)
        rows = [row for row in items if _flow_matches(row, active)] if active else items
        methods: dict[str, int] = {}
        status_classes: dict[str, int] = {}
        statuses: dict[int, int] = {}
        hosts: dict[str, int] = {}
        content_types: dict[str, int] = {}
        websocket_flows = 0
        body_omitted = 0
        for row in rows:
            verb = str(row.get("method") or "").upper()
            if verb:
                methods[verb] = methods.get(verb, 0) + 1
            code = row.get("status")
            if isinstance(code, int):
                statuses[code] = statuses.get(code, 0) + 1
                cls = f"{code // 100}xx"
            else:
                cls = "pending"
            status_classes[cls] = status_classes.get(cls, 0) + 1
            hostname = str(row.get("host") or "")
            hosts[hostname] = hosts.get(hostname, 0) + 1
            # Normalise "application/json; charset=utf-8" down to the media type so
            # the same payload kind does not split across charset variants.
            ctype = str(row.get("content_type") or "").split(";", 1)[0].strip().lower()
            content_types[ctype] = content_types.get(ctype, 0) + 1
            if row.get("websocket"):
                websocket_flows += 1
            if row.get("body_omitted"):
                body_omitted += 1
        host_rows, hosts_truncated = _ranked(hosts, "host", _MAX_STATS_GROUPS)
        ctype_rows, ctypes_truncated = _ranked(content_types, "content_type", _MAX_STATS_GROUPS)
        status_ordered = sorted(statuses.items(), key=lambda kv: (-kv[1], kv[0]))
        status_rows = [
            {"status": code, "count": count} for code, count in status_ordered[:_MAX_STATS_GROUPS]
        ]
        result: JsonObject = {
            "captured": captured,
            "dropped": dropped,
            "total": len(rows),
            "methods": methods,
            "status_classes": status_classes,
            "statuses": status_rows,
            "hosts": host_rows,
            "content_types": ctype_rows,
            "websocket_flows": websocket_flows,
            "body_omitted": body_omitted,
        }
        if hosts_truncated:
            result["hosts_truncated"] = True
        if ctypes_truncated:
            result["content_types_truncated"] = True
        if len(status_ordered) > _MAX_STATS_GROUPS:
            result["statuses_truncated"] = True
        if active:
            result["filter"] = active
        return result

    def endpoints(
        self,
        session_id: str,
        *,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: int = 0,
        normalize: bool = True,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        """Collapse the capture into the target's API surface, grouped by route.

        proxy.stats counts flows by method/host/status/content-type but never by
        URL path, so it cannot answer "what endpoints does this app call". This
        groups the retained flows by (host, path) -- normalising id-like path
        segments (numeric, UUID, long hex, long mixed-alnum token) to {id} by
        default so /users/1 and /users/2 fold into one /users/{id} route -- and
        reports each route's method set, request count, status-class mix,
        response content types and an example flow id to drill into with
        proxy.flow.get. It is the traffic-side analogue of an imports table: the
        backend routes the app depends on. Set normalize false to key on the
        exact path instead.

        Accepts the same filter surface as proxy.flows
        (method/host/url_contains/content_type/status), echoed back as filter.
        Answers with endpoints (host, path, count, methods, status_classes,
        content_types, example_id, plus websocket / has_query when seen), ranked
        by count then host then path and paged with count, total (distinct
        routes), offset and has_more; captured is the whole ring, dropped how
        many the ring evicted, and normalized whether {id} folding was applied.
        The list field is endpoints, not routes or results.
        """
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        captured = len(items)
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        active = _flow_filter(method, host, url_contains, content_type, status)
        rows = [row for row in items if _flow_matches(row, active)] if active else items
        groups: OrderedDict[tuple[str, str], JsonObject] = OrderedDict()
        for row in rows:
            hostname = str(row.get("host") or "")
            raw_path, has_query = _endpoint_path(str(row.get("url") or ""))
            path = _normalize_endpoint_path(raw_path) if normalize else (raw_path or "/")
            key = (hostname, path)
            agg = groups.get(key)
            if agg is None:
                agg = {
                    "host": hostname,
                    "path": path,
                    "count": 0,
                    "methods": {},
                    "status_classes": {},
                    "content_types": {},
                    "websocket": False,
                    "has_query": False,
                    "example_id": row.get("id"),
                }
                groups[key] = agg
            agg["count"] += 1
            verb = str(row.get("method") or "").upper()
            if verb:
                agg["methods"][verb] = agg["methods"].get(verb, 0) + 1
            code = row.get("status")
            cls = f"{code // 100}xx" if isinstance(code, int) else "pending"
            agg["status_classes"][cls] = agg["status_classes"].get(cls, 0) + 1
            ctype = str(row.get("content_type") or "").split(";", 1)[0].strip().lower()
            if ctype:
                agg["content_types"][ctype] = agg["content_types"].get(ctype, 0) + 1
            if row.get("websocket"):
                agg["websocket"] = True
            if has_query:
                agg["has_query"] = True
        ordered = sorted(
            groups.values(), key=lambda a: (-int(a["count"]), a["host"], a["path"])
        )
        total = len(ordered)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_ENDPOINTS_PAGE))
        window = ordered[start : start + cap]
        endpoints: list[JsonObject] = []
        for agg in window:
            ctype_rows, ctypes_truncated = _ranked(
                agg["content_types"], "content_type", _MAX_ENDPOINT_CTYPES
            )
            item: JsonObject = {
                "host": agg["host"],
                "path": agg["path"],
                "count": agg["count"],
                "methods": sorted(agg["methods"].keys()),
                "status_classes": agg["status_classes"],
                "content_types": ctype_rows,
                "example_id": agg["example_id"],
            }
            if agg["websocket"]:
                item["websocket"] = True
            if agg["has_query"]:
                item["has_query"] = True
            if ctypes_truncated:
                item["content_types_truncated"] = True
            endpoints.append(item)
        result: JsonObject = {
            "captured": captured,
            "dropped": dropped,
            "endpoints": endpoints,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "normalized": bool(normalize),
        }
        if active:
            result["filter"] = active
        return result

    def secrets(
        self,
        session_id: str,
        *,
        kind: str = "",
        reveal: bool = False,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: int = 0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        """Extract authentication and secret material from the capture.

        proxy.search finds a literal a caller already knows; this is the inverse
        -- it enumerates the credentials flowing through the capture without one:
        the Authorization/Proxy-Authorization request headers (with their scheme
        and, for a JWT bearer, the decoded header/claims), the common API-key and
        token request headers, the secret-ish URL query parameters, and the
        cookies from request Cookie and response Set-Cookie. It is the traffic
        analogue of a secret scan over a codebase. Identical secrets across flows
        collapse into one row whose count and hosts grow, so the reply is the set
        of distinct credentials, ranked by how widely each is used.

        Values are redacted to a first/last-few-chars preview by default (with
        value_length and value_sha256 so the same secret can be correlated across
        rows without exposure); pass reveal true to return the full value for
        replay. Accepts the same filters as proxy.flows
        (method/host/url_contains/content_type/status), plus kind to keep only one
        category (authorization, api_key_header, query_param, cookie, set_cookie).
        Answers with secrets (each {kind, name, location, value, value_length,
        value_sha256, count, hosts, example_id}, plus scheme for an authorization,
        session and cookie_attributes for a cookie, jwt for a decoded token) paged
        by count/total/offset/has_more; captured is the whole ring, dropped how
        many it evicted, scanned how many flows still had their headers retained
        and headers_unavailable how many were body-omitted or evicted so only
        their URL query could be read. kind_counts tallies the categories and
        collect_capped marks the 5000-distinct ceiling. The list field is secrets.
        """
        inst = self._get(session_id)
        if kind and kind not in _SECRET_KINDS:
            raise ProxyError(
                "invalid_params",
                f"unknown kind {kind!r}; expected one of {sorted(_SECRET_KINDS)}",
                kind=kind,
            )
        items = inst.recorder.snapshot()
        captured = len(items)
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        active = _flow_filter(method, host, url_contains, content_type, status)
        candidates = [row for row in items if _flow_matches(row, active)] if active else items
        aggregated: OrderedDict[tuple[str, str, str, str], JsonObject] = OrderedDict()
        scanned = 0
        headers_unavailable = 0
        collect_capped = False
        for summary in candidates:
            flow_id = str(summary.get("id"))
            hostname = str(summary.get("host") or "")
            url = str(summary.get("url") or "")
            findings: list[JsonObject] = []
            try:
                query = urlsplit(url).query
            except ValueError:
                query = ""
            if query and (not kind or kind == "query_param"):
                for i, (qname, qval) in enumerate(parse_qsl(query, keep_blank_values=False)):
                    if i >= _MAX_QUERY_PARAMS_PER_FLOW:
                        break
                    if qval and _is_secret_query(qname.lower()):
                        findings.append(
                            {
                                "kind": "query_param",
                                "name": qname,
                                "location": "request",
                                "value": qval,
                            }
                        )
            raw = inst.recorder.raw(flow_id)
            flow = raw if (raw is not None and raw is not _OMITTED_BODY) else None
            if flow is None:
                headers_unavailable += 1
            else:
                scanned += 1
                req = getattr(flow, "request", None)
                resp = getattr(flow, "response", None)
                for hi, (hname, hval) in enumerate(_header_pairs(req)):
                    if hi >= _MAX_HEADERS_PER_FLOW:
                        break
                    lname = hname.lower()
                    if not hval:
                        continue
                    if lname in _AUTH_HEADER_NAMES:
                        if kind and kind != "authorization":
                            continue
                        scheme, sep, cred = hval.partition(" ")
                        token = cred.strip() if sep else hval
                        findings.append(
                            {
                                "kind": "authorization",
                                "name": hname,
                                "location": "request",
                                "value": token,
                                "scheme": scheme if sep else "",
                            }
                        )
                    elif lname == "cookie":
                        if kind and kind != "cookie":
                            continue
                        for ci, (cname, cval) in enumerate(_split_cookie_header(hval)):
                            if ci >= _MAX_COOKIES_PER_FLOW:
                                break
                            if not cval:
                                continue
                            findings.append(
                                {
                                    "kind": "cookie",
                                    "name": cname,
                                    "location": "request",
                                    "value": cval,
                                    "session": _is_session_cookie(cname.lower()),
                                }
                            )
                    elif _is_apikey_header(lname):
                        if kind and kind != "api_key_header":
                            continue
                        findings.append(
                            {
                                "kind": "api_key_header",
                                "name": hname,
                                "location": "request",
                                "value": hval,
                            }
                        )
                if not kind or kind == "set_cookie":
                    for hi, (hname, hval) in enumerate(_header_pairs(resp)):
                        if hi >= _MAX_HEADERS_PER_FLOW:
                            break
                        if hname.lower() != "set-cookie" or not hval:
                            continue
                        cname, cval, cattrs = _parse_set_cookie(hval)
                        if not cname or not cval:
                            continue
                        session = _is_session_cookie(cname.lower()) or ("httponly" in cattrs)
                        findings.append(
                            {
                                "kind": "set_cookie",
                                "name": cname,
                                "location": "response",
                                "value": cval,
                                "session": session,
                                "cookie_attributes": cattrs,
                            }
                        )
            seen_this_flow: set[tuple[str, str, str, str]] = set()
            for finding in findings:
                finding["flow_id"] = flow_id
                finding["host"] = hostname
                if _record_secret(aggregated, seen_this_flow, finding):
                    collect_capped = True
        collected = list(aggregated.values())
        collected.sort(
            key=lambda s: (-int(s["count"]), s["kind"], s["name"], s["value_sha256"])
        )
        kind_counts: dict[str, int] = {}
        for entry in collected:
            kind_counts[entry["kind"]] = kind_counts.get(entry["kind"], 0) + 1
        total = len(collected)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_SECRETS_PAGE))
        window = collected[start : start + cap]
        secrets: list[JsonObject] = []
        for entry in window:
            item = {k: v for k, v in entry.items() if not k.startswith("_")}
            item["hosts"] = sorted(entry["_hosts"])
            item["value"] = entry["_value"] if reveal else _redact_value(entry["_value"])
            secrets.append(item)
        result: JsonObject = {
            "secrets": secrets,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "captured": captured,
            "dropped": dropped,
            "scanned": scanned,
            "headers_unavailable": headers_unavailable,
            "reveal": bool(reveal),
            "kind_counts": kind_counts,
        }
        if collect_capped:
            result["collect_capped"] = True
        if active:
            result["filter"] = active
        if kind:
            result["kind"] = kind
        return result

    def search(
        self,
        session_id: str,
        query: str,
        *,
        case_sensitive: bool = False,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: int = 0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        """Find captured flows whose content contains a literal string.

        proxy.flows and proxy.stats only see a flow's metadata (method, url,
        host, status, content type); this reads the retained request/response
        headers and bodies, so it answers the question those cannot -- which
        exchange actually carries a token, an endpoint, a marker, a leaked
        secret. It is the traffic-side twin of static.search / r2.search: a
        literal (case-insensitive by default) substring search across, per flow,
        the response body, request body, response headers, request headers and
        the URL, in that priority order. Accepts the same filter surface as
        proxy.flows (method/host/url_contains/content_type/status) so a caller
        can search just one host or content type first. Answers with matches,
        each carrying id, method, url, status, content_type, matched_in (the
        locations that hit, in the priority order above), match_count (bounded
        occurrence tally), snippet (a one-line context window around the first
        hit) and snippet_from (which location it came from), plus count, total
        (matching flows), offset and has_more for paging. captured is the whole
        ring, searched is how many candidate flows still had their body/headers
        retained, and body_unavailable is how many were body-omitted or evicted
        so only their URL could be searched -- so a miss is legible as "not
        present" versus "not retained". There is no flows or results field.
        """
        inst = self._get(session_id)
        if not isinstance(query, str) or not query:
            raise ProxyError("invalid_params", "query is required")
        if len(query) > _MAX_SEARCH_QUERY:
            raise ProxyError(
                "invalid_params", f"query must be at most {_MAX_SEARCH_QUERY} chars"
            )
        items = inst.recorder.snapshot()
        captured = len(items)
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        active = _flow_filter(method, host, url_contains, content_type, status)
        candidates = [row for row in items if _flow_matches(row, active)] if active else items
        needle = query if case_sensitive else query.lower()
        matches: list[JsonObject] = []
        searched = 0
        body_unavailable = 0
        for summary in candidates:
            flow_id = str(summary.get("id"))
            raw = inst.recorder.raw(flow_id)
            flow = raw if (raw is not None and raw is not _OMITTED_BODY) else None
            if flow is None:
                body_unavailable += 1
            else:
                searched += 1
            # Priority order: the most informative location first, so the
            # snippet is taken from the response body when it matched there and
            # matched_in reads highest-value first. URL is always searchable.
            haystacks: list[tuple[str, str]] = []
            if flow is not None:
                req = getattr(flow, "request", None)
                resp = getattr(flow, "response", None)
                haystacks.append(("response_body", _body_text(resp)))
                haystacks.append(("request_body", _body_text(req)))
                haystacks.append(("response_headers", _headers_text(resp)))
                haystacks.append(("request_headers", _headers_text(req)))
            haystacks.append(("url", str(summary.get("url") or "")))
            matched_in: list[str] = []
            match_count = 0
            snippet = ""
            snippet_from = ""
            for location, text in haystacks:
                hay = text if case_sensitive else text.lower()
                index = hay.find(needle)
                if index < 0:
                    continue
                matched_in.append(location)
                match_count += _count_occurrences(hay, needle, _MAX_SEARCH_MATCHES_PER_FLOW)
                if not snippet:
                    snippet = _search_snippet(text, index, len(query))
                    snippet_from = location
            if not matched_in:
                continue
            matches.append(
                {
                    "id": flow_id,
                    "method": summary.get("method"),
                    "url": summary.get("url"),
                    "status": summary.get("status"),
                    "content_type": summary.get("content_type"),
                    "matched_in": matched_in,
                    "match_count": match_count,
                    "snippet": snippet,
                    "snippet_from": snippet_from,
                }
            )
        total = len(matches)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_SEARCH_RESULTS))
        window = matches[start : start + cap]
        result: JsonObject = {
            "query": query,
            "case_sensitive": bool(case_sensitive),
            "matches": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "captured": captured,
            "dropped": dropped,
            "searched": searched,
            "body_unavailable": body_unavailable,
        }
        if active:
            result["filter"] = active
        return result

    def flow_get(
        self, session_id: str, flow_id: str, artifact_dir: Path, *, raw: bool = False
    ) -> JsonObject:
        inst = self._get(session_id)
        flow = inst.recorder.raw(flow_id)
        if flow is None:
            raise ProxyError(
                "not_found",
                "unknown flow id (it may have been evicted from the capture ring)",
                flow_id=flow_id,
            )
        if flow is _OMITTED_BODY:
            raise ProxyError(
                "too_large",
                "flow body was not retained",
                flow_id=flow_id,
            )
        req = flow.request
        resp = flow.response
        # Both bodies are served decoded of their content-encoding (raw=True asks
        # for the exact on-wire bytes). The request body is returned too: a POST's
        # form/JSON/upload payload is what a caller most needs to see, and until
        # now flow.get dropped it. Each part inlines small text and spills binary
        # or oversized bytes to a body_path, so a captured image/.wasm still
        # reaches the static tools rather than being mangled into inline text.
        request: JsonObject = {
            "method": getattr(req, "method", None),
            "url": getattr(req, "pretty_url", None),
            "headers": dict(req.headers) if req else {},
        }
        req_body, req_decoded, req_enc = _served_body(req, raw=raw)
        _emit_body(request, req_body, req_decoded, req_enc, artifact_dir)
        response: JsonObject = {
            "status": getattr(resp, "status_code", None),
            "headers": dict(resp.headers) if resp else {},
        }
        resp_body, resp_decoded, resp_enc = _served_body(resp, raw=raw)
        _emit_body(response, resp_body, resp_decoded, resp_enc, artifact_dir)
        result: JsonObject = {"id": flow_id, "request": request, "response": response}
        websocket = _ws_messages_view(flow)
        if websocket is not None:
            websocket["dropped"] = inst.recorder.ws_dropped(flow_id)
            result["websocket"] = websocket
        return result

    def ws_frames(
        self, session_id: str, flow_id: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        inst = self._get(session_id)
        flow = inst.recorder.raw(flow_id)
        if flow is None:
            raise ProxyError(
                "not_found",
                "unknown flow id (it may have been evicted from the capture ring)",
                flow_id=flow_id,
            )
        if flow is _OMITTED_BODY:
            raise ProxyError(
                "too_large",
                "flow body was not retained",
                flow_id=flow_id,
            )
        view = _ws_messages_view(flow, offset=offset, limit=limit)
        if view is None:
            raise ProxyError(
                "invalid_state",
                "flow is not a websocket",
                flow_id=flow_id,
            )
        return {
            "flow_id": flow_id,
            "url": getattr(flow.request, "pretty_url", None),
            "frames": view["messages"],
            "count": view["count"],
            "total": view["total"],
            "offset": view["offset"],
            "has_more": view["has_more"],
            "dropped": inst.recorder.ws_dropped(flow_id),
            "closed": view["closed"],
            **({"close_code": view["close_code"]} if "close_code" in view else {}),
        }

    def ws_search(
        self,
        session_id: str,
        query: str,
        *,
        case_sensitive: bool = False,
        direction: str = "",
        flow_id: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        """Find a literal string inside captured WebSocket frames, across flows.

        proxy.search reads the HTTP request/response bodies, headers and URL but
        never the WebSocket conversation, and proxy.ws.frames needs a flow id and
        pages one socket at a time. Real-time app protocols, auth tokens and RPC
        payloads ride the WebSocket, so this is the frame-level twin of
        proxy.search: a literal (case-insensitive unless case_sensitive)
        substring scan over the decoded content of every retained frame -- text
        and binary opcodes alike, so a JSON payload sent as a binary message is
        still found. Restrict to one socket with flow_id, or to a direction with
        ``sent`` (client -> server) / ``received`` (server -> client).

        Answers with matches, each carrying flow_id, url, frame_index (its
        position in that socket's retained frame list, feedable to
        proxy.ws.frames offset), direction, type (text/binary), match_count (a
        bounded per-frame tally), snippet (a one-line context window) and
        payload_len/ts; plus count, total (matching frames), offset and has_more
        for paging. ws_flows is how many WebSocket flows were considered,
        frames_searched how many frames were scanned, and frames_capped /
        matches_capped disclose when the 50000-frame scan or the 5000-match
        collection ceiling was hit. The list field is matches (there is no frames
        or results field). A flow_id that is not a WebSocket is invalid_state and
        an unknown one is not_found.
        """
        inst = self._get(session_id)
        if not isinstance(query, str) or not query:
            raise ProxyError("invalid_params", "query is required")
        if len(query) > _MAX_SEARCH_QUERY:
            raise ProxyError(
                "invalid_params", f"query must be at most {_MAX_SEARCH_QUERY} chars"
            )
        dir_filter = direction.strip().lower()
        if dir_filter and dir_filter not in ("sent", "received"):
            raise ProxyError(
                "invalid_params", "direction must be 'sent', 'received' or empty"
            )
        needle = query if case_sensitive else query.lower()

        # Resolve the candidate WebSocket flows. A pinned flow_id is validated
        # like proxy.ws.frames (not_found / invalid_state); otherwise every
        # WebSocket flow the ring still retains is a candidate.
        candidates: list[tuple[str, Any, str]] = []
        if flow_id:
            raw = inst.recorder.raw(flow_id)
            if raw is None:
                raise ProxyError(
                    "not_found",
                    "unknown flow id (it may have been evicted from the capture ring)",
                    flow_id=flow_id,
                )
            if raw is _OMITTED_BODY or getattr(raw, "websocket", None) is None:
                raise ProxyError("invalid_state", "flow is not a websocket", flow_id=flow_id)
            url = str(getattr(getattr(raw, "request", None), "pretty_url", "") or "")
            candidates.append((flow_id, raw, url))
        else:
            for row in inst.recorder.snapshot():
                if not row.get("websocket"):
                    continue
                fid = str(row.get("id"))
                raw = inst.recorder.raw(fid)
                if raw is None or raw is _OMITTED_BODY:
                    continue
                if getattr(raw, "websocket", None) is None:
                    continue
                candidates.append((fid, raw, str(row.get("url") or "")))

        ws_flows = len(candidates)
        matches: list[JsonObject] = []
        frames_searched = 0
        frames_capped = False
        matches_capped = False
        for fid, flow, url in candidates:
            ws = getattr(flow, "websocket", None)
            messages = list(getattr(ws, "messages", None) or [])
            for index, msg in enumerate(messages):
                if frames_searched >= _MAX_WS_SEARCH_SCAN:
                    frames_capped = True
                    break
                frames_searched += 1
                text, msg_dir, kind, payload_len, ts = _ws_search_text(msg)
                if dir_filter and msg_dir != dir_filter:
                    continue
                hay = text if case_sensitive else text.lower()
                hit = hay.find(needle)
                if hit < 0:
                    continue
                if len(matches) >= _MAX_WS_SEARCH_MATCHES:
                    matches_capped = True
                    break
                matches.append(
                    {
                        "flow_id": fid,
                        "url": url,
                        "frame_index": index,
                        "direction": msg_dir,
                        "type": kind,
                        "match_count": _count_occurrences(
                            hay, needle, _MAX_SEARCH_MATCHES_PER_FLOW
                        ),
                        "snippet": _search_snippet(text, hit, len(query)),
                        "payload_len": payload_len,
                        "ts": ts,
                    }
                )
            if frames_capped or matches_capped:
                break
        total = len(matches)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_SEARCH_RESULTS))
        window = matches[start : start + cap]
        result: JsonObject = {
            "query": query,
            "case_sensitive": bool(case_sensitive),
            "matches": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "ws_flows": ws_flows,
            "frames_searched": frames_searched,
            "frames_capped": frames_capped,
            "matches_capped": matches_capped,
        }
        if dir_filter:
            result["direction"] = dir_filter
        if flow_id:
            result["flow_id"] = flow_id
        return result

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        inst = self._get(session_id)
        flow = inst.recorder.raw(flow_id)
        master = inst._master
        if flow is None:
            raise ProxyError("not_found", "unknown flow id", flow_id=flow_id)
        if flow is _OMITTED_BODY:
            raise ProxyError(
                "too_large",
                "flow body was not retained; cannot replay",
                flow_id=flow_id,
            )
        if master is None or inst._loop is None:
            raise ProxyError("invalid_state", "proxy is not running")
        try:
            new_flow = flow.copy()
            done: concurrent.futures.Future[Any] = concurrent.futures.Future()

            def _run() -> None:
                try:
                    master.commands.call("replay.client", [new_flow])
                except Exception as exc:  # noqa: BLE001
                    if not done.done():
                        done.set_exception(exc)
                    return
                if not done.done():
                    done.set_result(True)

            inst._loop.call_soon_threadsafe(_run)
            done.result(timeout=_REPLAY_WAIT_S)
        except concurrent.futures.TimeoutError as exc:
            raise ProxyError(
                "timeout", "replay did not complete", flow_id=flow_id
            ) from exc
        except ProxyError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ProxyError("backend_error", f"replay failed: {exc}", flow_id=flow_id) from exc
        return {"replayed": True, "flow_id": flow_id}

    def export_har(
        self,
        session_id: str,
        out_path: Path,
        *,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: int = 0,
    ) -> JsonObject:
        inst = self._get(session_id)
        import json

        items = inst.recorder.snapshot()
        captured = len(items)
        # Same filter surface as proxy.flows: export exactly the slice a caller
        # narrowed to, rather than the whole ring, so triage and export share one
        # vocabulary. No filter == the whole capture, as before.
        active = _flow_filter(method, host, url_contains, content_type, status)
        rows = [row for row in items if _flow_matches(row, active)] if active else items
        entries: list[JsonObject] = []
        for summary in rows:
            flow_id = str(summary.get("id"))
            raw = inst.recorder.raw(flow_id)
            # A flow whose body was omitted/evicted keeps its summary but not the
            # rich object; emit a structurally-valid entry from the summary alone.
            flow = raw if (raw is not None and raw is not _OMITTED_BODY) else None
            entries.append(_flow_to_har_entry(summary, flow))
        doc = har.document(entries)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        # captured discloses the whole ring so entry_count is read as "exported N
        # of captured M", not "the capture only had N".
        result: JsonObject = {
            "path": str(out_path),
            "entry_count": len(entries),
            "captured": captured,
        }
        if active:
            result["filter"] = active
        return result

    def ca_cert_path(self) -> Path | None:
        for name in ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem"):
            candidate = Path.home() / ".mitmproxy" / name
            if candidate.is_file():
                return candidate
        return None

    def close_all(self) -> None:
        with self._lock:
            instances = list(self._instances.values())
            self._instances.clear()
        for inst in instances:
            inst.stop()
