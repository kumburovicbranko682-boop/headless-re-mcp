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
import logging
import os
import socket
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any
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

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
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
        body = b""
        try:
            body = resp.raw_content or b"" if resp else b""
        except Exception:  # noqa: BLE001
            body = b""
        result: JsonObject = {
            "id": flow_id,
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "headers": dict(req.headers),
            },
            "response": {
                "status": getattr(resp, "status_code", None),
                "headers": dict(resp.headers) if resp else {},
                "size": len(body),
            },
        }
        # Spill when the body is too big to inline OR when it is binary: a
        # utf-8-with-replacement decode of binary bytes is lossy and irreversible,
        # so a captured .wasm/image/font would come back as mojibake with no path
        # to the real bytes. Writing the exact bytes to a file keeps the proxy
        # capture feedable to the static tools (wasm.*, ghidra, ...), matching the
        # web line's binary-body contract. An empty body still inlines as "".
        if body and (len(body) > _MAX_INLINE_BODY or not _looks_textual(body)):
            artifact_dir.mkdir(parents=True, exist_ok=True)
            out = artifact_dir / f"flow-{uuid4().hex}.bin"
            out.write_bytes(body)
            result["response"]["body_path"] = str(out)
        else:
            result["response"]["body"] = body.decode("utf-8", errors="replace")
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
