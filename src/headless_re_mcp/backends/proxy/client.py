"""In-process HTTP(S) interception via a threaded mitmproxy DumpMaster.

One proxy per session. mitmproxy runs its own asyncio loop, so it lives on a
dedicated thread; a bounded addon records flows into a ring buffer that the
read tools query. mitmproxy is optional and the API differs across versions, so
startup is defensive and a missing module degrades to ``capability_unavailable``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import io
import logging
import os
import socket
import threading
import time
import zlib
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any
from uuid import uuid4

from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES

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
# A hostile server can answer a captured request with a small compressed body
# that inflates to gigabytes. The ring only bounds the *compressed* size, so
# decoding has to stop at a fixed ceiling rather than trust the wire length.
_MAX_DECODED_BODY = 8 * 1024 * 1024
_OMITTED_BODY = object()


def _response_encoding(resp: Any) -> str:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return ""
    try:
        return str(headers.get("content-encoding", "") or "").strip().lower()
    except Exception:  # noqa: BLE001
        return ""


def _decode_body(resp: Any, raw: bytes) -> tuple[bytes, str, bool, bool]:
    """Return (body, encoding, decoded, truncated) for a captured response.

    ``raw_content`` is the body exactly as it crossed the wire, which for most
    real responses is gzip/deflate/zstd/brotli. Returned verbatim and decoded as
    UTF-8 it read as garbage, so the tool that exists to show a response body
    handed back noise for the common case. Decode the encodings that can be
    bounded (gzip, deflate, zstd) within ``_MAX_DECODED_BODY`` so a decompression
    bomb cannot turn a retained few-hundred-KB body into an OOM. Brotli cannot be
    output-bounded with the installed binding and anything unrecognised is left
    as-is with ``decoded`` False -- honest bytes the caller can still spill,
    rather than compressed data mislabelled as text.
    """
    encoding = _response_encoding(resp)
    if encoding in ("", "identity"):
        return raw, "", True, False
    cap = _MAX_DECODED_BODY
    try:
        if encoding in ("gzip", "x-gzip", "deflate", "x-deflate"):
            # 47 auto-detects the gzip and zlib headers; raw deflate (no header)
            # needs -15, so fall through to it when the first attempt rejects
            # the stream rather than reporting a decode failure.
            for wbits in (47, -15):
                obj = zlib.decompressobj(wbits)
                try:
                    out = obj.decompress(raw, cap + 1)
                except zlib.error:
                    continue
                if obj.unconsumed_tail or len(out) > cap:
                    return out[:cap], encoding, True, True
                tail = obj.flush()
                if len(out) + len(tail) > cap:
                    return (out + tail)[:cap], encoding, True, True
                return out + tail, encoding, True, False
            return raw, encoding, False, False
        if encoding == "zstd":
            import zstandard

            reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw))
            out = reader.read(cap + 1)
            if len(out) > cap:
                return out[:cap], encoding, True, True
            return out, encoding, True, False
    except Exception:  # noqa: BLE001
        return raw, encoding, False, False
    return raw, encoding, False, False


class ProxyError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


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

    def _store_raw_locked(self, flow_id: str, flow: Any, stored_bytes: int) -> bool:
        """Insert a flow's raw object under the byte cap; returns whether omitted.

        Shared by response() and error(): drops any stale entry for this id,
        evicts older bodies (then, failing that, this one) to stay under
        _MAX_RETAINED_BYTES, and keeps _raw evicting in lockstep with the summary
        ring. Caller must hold self._lock.
        """
        self._raw.pop(flow_id, None)
        self._retained_bytes -= self._raw_sizes.pop(flow_id, 0)
        omitted = stored_bytes > _MAX_STORED_BODY
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
        # Evict oldest raw flows in lockstep with the summary ring so the two
        # views can never disagree about which flows are retrievable.
        while len(self._raw) > self._capacity:
            evicted_id, _ = self._raw.popitem(last=False)
            self._retained_bytes -= self._raw_sizes.pop(evicted_id, 0)
        return omitted

    def response(self, flow: Any) -> None:  # mitmproxy calls this on each response
        req = flow.request
        resp = flow.response
        stored_bytes = _flow_stored_bytes(flow)
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
            omitted = self._store_raw_locked(flow_id, flow, stored_bytes)
            entry: JsonObject = {
                "id": flow_id,
                "seq": self._seq,
                "method": method,
                "url": url,
                "host": host,
                "status": getattr(resp, "status_code", None),
                "content_type": content_type,
                # The wire start time, so a HAR export can place the request in
                # real time rather than all at the export instant. Falls back to
                # now if mitmproxy did not stamp it.
                "started_at": float(getattr(req, "timestamp_start", None) or time.time()),
            }
            if omitted:
                entry["body_omitted"] = True
            if method_truncated or url_truncated or host_truncated or type_truncated:
                entry["metadata_truncated"] = True
            self.flows.append(entry)

    def error(self, flow: Any) -> None:  # mitmproxy calls this when a flow fails
        # A flow that never receives a response -- upstream refused/reset, DNS
        # or TLS handshake failure (the usual culprit when a pinned mobile app
        # is put behind the proxy), or a timeout -- fires error(), not
        # response(). Without recording it, proxy.flows silently drops every
        # failed connection, which is exactly the evidence the proxy was set up
        # to catch. Record it as a finished flow marked failed, retaining the
        # attempted request the same bounded way so flow.get can still show what
        # was sent.
        req = getattr(flow, "request", None)
        err = getattr(flow, "error", None)
        stored_bytes = _flow_stored_bytes(flow)
        method, method_truncated = _bounded_metadata(
            getattr(req, "method", "") if req is not None else "", _MAX_METADATA_BYTES
        )
        url, url_truncated = _bounded_metadata(
            getattr(req, "pretty_url", "") if req is not None else "", _MAX_URL_BYTES
        )
        host, host_truncated = _bounded_metadata(
            getattr(req, "host", "") if req is not None else "", _MAX_METADATA_BYTES
        )
        error_text, error_truncated = _bounded_metadata(
            getattr(err, "msg", None) or (str(err) if err is not None else ""),
            _MAX_METADATA_BYTES,
        )
        with self._lock:
            self._seq += 1
            flow_id = str(getattr(flow, "id", None) or self._seq)
            omitted = self._store_raw_locked(flow_id, flow, stored_bytes)
            entry: JsonObject = {
                "id": flow_id,
                "seq": self._seq,
                "method": method,
                "url": url,
                "host": host,
                "status": None,
                "content_type": "",
                "started_at": (
                    float(getattr(req, "timestamp_start", None) or time.time())
                    if req is not None
                    else time.time()
                ),
                "failed": True,
                "error_text": error_text or "flow error",
            }
            if omitted:
                entry["body_omitted"] = True
            if method_truncated or url_truncated or host_truncated or error_truncated:
                entry["metadata_truncated"] = True
            self.flows.append(entry)

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

    def stop(self) -> None:
        master = self._master
        loop = self._loop
        if master is not None and loop is not None:
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

    def flows(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        start = max(0, int(offset))
        cap = max(1, min(int(limit), 1000))
        window = items[start : start + cap]
        dropped = 0
        if items:
            dropped = max(0, int(items[-1].get("seq") or 0) - len(items))
        return {
            "flows": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            "has_more": start + len(window) < len(items),
            "dropped": dropped,
        }

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
        from headless_re_mcp.backends.common.har import har_headers

        req = flow.request
        resp = flow.response
        # A list of {name, value} in wire order, not dict(headers): mitmproxy
        # folds repeated names into one comma-joined value, which for Set-Cookie
        # is corruption -- RFC 6265 forbids comma-combining, and an Expires date
        # is itself comma-bearing -- so a response setting several cookies came
        # back as one mangled string. The list preserves every repeat (and order,
        # itself a fingerprinting signal) and is bounded by har_headers.
        request: JsonObject = {
            "method": req.method,
            "url": req.pretty_url,
            "headers": har_headers(req.headers),
        }
        response: JsonObject = {
            "status": getattr(resp, "status_code", None),
            "headers": har_headers(resp.headers) if resp else [],
        }
        # The request body carries the POST/PUT payload -- API params, tokens,
        # the thing traffic analysis is usually after. A response-only view left
        # it unreachable; decode both the same bounded way. Only attach a request
        # body when there is one, so a plain GET stays method/url/headers.
        self._attach_body(request, req, artifact_dir, name="req", always=False)
        self._attach_body(response, resp, artifact_dir, name="resp", always=True)
        result: JsonObject = {"id": flow_id, "request": request, "response": response}
        # A failed flow (upstream reset, TLS handshake failure, timeout) has an
        # empty response by definition; say why rather than let it read as a
        # successful fetch of a zero-length body.
        err = getattr(flow, "error", None)
        if err is not None:
            error_text, _ = _bounded_metadata(
                getattr(err, "msg", None) or str(err), _MAX_METADATA_BYTES
            )
            result["failed"] = True
            result["error_text"] = error_text or "flow error"
        return result

    def _attach_body(
        self, part: JsonObject, message: Any, artifact_dir: Path, *, name: str, always: bool
    ) -> None:
        """Decode a request/response body onto ``part``, inline or spilled.

        Bodies over the inline cap spill to an artifact the service registers so
        retention can reclaim them; smaller ones are returned inline. Content
        encoding is surfaced (see ``_decode_body``): ``size`` is the decoded
        length, ``encoded_size`` the on-wire length, ``body_decoded`` whether the
        bytes were actually decoded.
        """
        raw = b""
        try:
            raw = (message.raw_content or b"") if message is not None else b""
        except Exception:  # noqa: BLE001
            raw = b""
        if not raw and not always:
            return
        body, encoding, decoded, truncated = _decode_body(message, raw)
        part["size"] = len(body)
        if encoding:
            part["body_encoding"] = encoding
            part["body_decoded"] = decoded
            part["encoded_size"] = len(raw)
        if truncated:
            part["body_truncated"] = True
        if len(body) > 200_000:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            out = artifact_dir / f"flow-{name}-{uuid4().hex}.bin"
            out.write_bytes(body)
            part["body_path"] = str(out)
        else:
            part["body"] = body.decode("utf-8", errors="replace")

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

    def export_har(self, session_id: str, out_path: Path) -> JsonObject:
        inst = self._get(session_id)
        import json

        from headless_re_mcp.backends.common.har import (
            har_document,
            har_entry,
            har_headers,
        )

        entries = []
        for f in inst.recorder.snapshot():
            # The summary carries method/url/status; the retained raw flow still
            # holds the real request/response headers -- the auth tokens,
            # content types and Set-Cookie lines that make a HAR worth opening.
            # A flow evicted or body-omitted from the ring has no raw object; its
            # headers stay empty rather than fabricated.
            raw = inst.recorder.raw(str(f.get("id") or ""))
            req_headers: list[JsonObject] = []
            resp_headers: list[JsonObject] = []
            if raw is not None and raw is not _OMITTED_BODY:
                req_headers = har_headers(getattr(getattr(raw, "request", None), "headers", None))
                resp_headers = har_headers(getattr(getattr(raw, "response", None), "headers", None))
            entries.append(
                har_entry(
                    started_at=f.get("started_at"),
                    method=f.get("method"),
                    url=f.get("url"),
                    status=f.get("status"),
                    mime_type=f.get("content_type"),
                    request_headers=req_headers,
                    response_headers=resp_headers,
                )
            )
        har = har_document(entries)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(har, ensure_ascii=False)
        encoded = text.encode("utf-8")
        truncated = False
        # The flow ring is count-bounded, but a single summary can carry a
        # 16 KiB URL, so a full 2000-flow capture serialises to tens of MiB.
        # _register_capture records whatever size this writes without a cap of
        # its own, so an unattended proxy.export_har would grow the artifact
        # root by that much every call. Drop entries until the file fits the
        # capture cap -- the same bound web.har_export already applies.
        while entries and len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            drop = max(1, len(entries) // 8)
            del entries[-drop:]
            har["log"]["entries"] = entries
            text = json.dumps(har, ensure_ascii=False)
            encoded = text.encode("utf-8")
            truncated = True
        if len(encoded) > UNREGISTERED_CAPTURE_MAX_BYTES:
            raise ProxyError(
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
