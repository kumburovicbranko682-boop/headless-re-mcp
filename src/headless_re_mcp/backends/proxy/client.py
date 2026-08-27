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
import logging
import os
import socket
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar
from uuid import uuid4

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


def _close_proxy_servers(master: Any, loop: asyncio.AbstractEventLoop) -> None:
    """Stop the proxyserver addon's listeners so the OS reclaims the port.

    mitmproxy's ``Master.run()`` teardown (the ``DoneHook``) does *not* close the
    proxy server sockets -- upstream reclaims them by exiting the process, and
    the ``proxyserver`` addon has no ``done`` hook. Embedded in a long-lived
    service we have to free the port ourselves, or a stopped session keeps its
    listener bound (mitmproxy 12 runs it in the ``mitmproxy_rs`` core, so it
    survives the Python loop) and the next ``start()`` on that port is refused.

    Must run on ``loop`` while it is still open (before ``_shutdown_loop``
    closes it), because ``ServerInstance.stop()`` is a coroutine on that loop.
    ``servers.update([])`` removes every mode, awaiting each instance's stop.
    """
    if master is None:
        return
    ps = None
    with contextlib.suppress(Exception):
        ps = master.addons.get("proxyserver")
    servers = getattr(ps, "servers", None)
    if servers is None:
        return
    with contextlib.suppress(Exception):
        loop.run_until_complete(servers.update([]))


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


class _StartupBarrier:
    """A no-op mitmproxy addon whose ``running`` hook fires a callback.

    Registered last, so its ``running()`` runs after every built-in addon's
    ``running()`` -- the point past which this master's startup hooks have
    finished reading the process-global ``mitmproxy.ctx``. Used to release the
    construction lock exactly when it is safe for another master to take it.
    """

    def __init__(self, on_running: Callable[[], None]) -> None:
        self._on_running = on_running

    def running(self) -> None:
        self._on_running()


class _ProxyInstance:
    # mitmproxy keeps the active master in a process-global ``mitmproxy.ctx``.
    # Two DumpMasters built on different threads race on it: one master's
    # ``running()`` hook (keepserving) reads ``ctx.options.rfile`` while the
    # other master's construction has momentarily swapped ``ctx.options`` to a
    # not-yet-loaded Options, and the AttributeError that mitmproxy logs trips
    # its errorcheck addon into aborting the innocent master ("mitmproxy failed
    # to start"). One proxy per session is a supported multi-session shape, so
    # this raced ~2/15 concurrent starts. Serialize construction through the
    # first ``running()`` hook so only one master owns the global ctx at a time.
    _ctx_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, host: str, port: int, *, ssl_insecure: bool = False) -> None:
        self.host = host
        self.port = port
        self.ssl_insecure = bool(ssl_insecure)
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
        # Held from before DumpMaster construction until this master's first
        # running() hook has fired (see _ctx_lock). A list cell so the barrier
        # callback and the finally can flip it exactly once between threads --
        # the barrier runs on this same loop thread, so no extra lock is needed.
        holding = [False]

        def _release_ctx_lock() -> None:
            if holding[0]:
                holding[0] = False
                with contextlib.suppress(RuntimeError):
                    _ProxyInstance._ctx_lock.release()

        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            opts = options.Options(listen_host=self.host, listen_port=self.port)
            if self.ssl_insecure:
                # Intercepting an origin that serves an untrusted certificate --
                # a self-signed local server, a pinned staging host, an expired
                # cert -- fails mitmproxy's upstream verification, so it returns
                # its own 502 and the decrypted flow is never recorded. Opt in
                # per session to skip that verification. Off by default: it is
                # the client's TLS safety net, dropped only when the caller
                # deliberately points the proxy at an origin it cannot verify.
                opts.ssl_insecure = True
            _ProxyInstance._ctx_lock.acquire()
            holding[0] = True
            # Only the constructor may disagree about kwargs across mitmproxy
            # versions. Catching TypeError around run() too would treat a bug
            # inside a running proxy as a signature mismatch and start a second
            # DumpMaster on the same port.
            try:
                master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            except TypeError:
                master = DumpMaster(opts)
            master.addons.add(self.recorder)
            # Added last so its running() runs after every built-in running()
            # hook; releasing there hands the global ctx to the next master only
            # once this one's startup has stopped reading it.
            master.addons.add(_StartupBarrier(_release_ctx_lock))
            self._master = master
            self._started.set()
            loop.run_until_complete(master.run())
        except BaseException as exc:  # noqa: BLE001 - report to the starting thread
            self._error = exc
            self._started.set()
        finally:
            # A startup that failed before running() never reached the barrier;
            # release here so a crashed start cannot wedge every later start.
            _release_ctx_lock()
            # Closing the loop outright abandons mitmproxy's still-pending
            # accept task, which leaves the listening socket open at the OS
            # level: stop() would appear to work while the port stayed bound
            # and the next capture could never start. Tear the servers down
            # explicitly (run()'s own teardown does not) and then unwind the
            # remaining tasks, both while the loop is still open.
            if loop is not None:
                with contextlib.suppress(Exception):
                    _close_proxy_servers(self._master, loop)
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

    def start(
        self,
        session_id: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        ssl_insecure: bool = False,
    ) -> JsonObject:
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
            inst = _ProxyInstance(host, port, ssl_insecure=ssl_insecure)
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
        if len(body) > 200_000:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            out = artifact_dir / f"flow-{uuid4().hex}.bin"
            out.write_bytes(body)
            result["response"]["body_path"] = str(out)
        else:
            result["response"]["body"] = body.decode("utf-8", errors="replace")
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

    def export_har(self, session_id: str, out_path: Path) -> JsonObject:
        inst = self._get(session_id)
        import json

        entries = [
            {
                "request": {"method": f.get("method"), "url": f.get("url")},
                "response": {
                    "status": f.get("status") or 0,
                    "content": {"mimeType": f.get("content_type") or ""},
                },
            }
            for f in inst.recorder.snapshot()
        ]
        har = {
            "log": {"version": "1.2", "creator": {"name": "headless-re-mcp"}, "entries": entries}
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(har, ensure_ascii=False), encoding="utf-8")
        return {"path": str(out_path), "entry_count": len(entries)}

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
