"""In-process HTTP(S) interception via a threaded mitmproxy DumpMaster.

One proxy per session. mitmproxy runs its own asyncio loop, so it lives on a
dedicated thread; a bounded addon records flows into a ring buffer that the
read tools query. mitmproxy is optional and the API differs across versions, so
startup is defensive and a missing module degrades to ``capability_unavailable``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]
_MAX_FLOWS = 2000


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
        self._lock = threading.RLock()

    def response(self, flow: Any) -> None:  # mitmproxy calls this on each response
        req = flow.request
        resp = flow.response
        with self._lock:
            self._seq += 1
            flow_id = str(getattr(flow, "id", None) or self._seq)
            self._raw[flow_id] = flow
            # Evict oldest raw flows in lockstep with the summary ring so the
            # two views can never disagree about which flows are retrievable.
            while len(self._raw) > self._capacity:
                self._raw.popitem(last=False)
            self.flows.append(
                {
                    "id": flow_id,
                    "seq": self._seq,
                    "method": req.method,
                    "url": req.pretty_url,
                    "host": req.host,
                    "status": getattr(resp, "status_code", None),
                    "content_type": resp.headers.get("content-type", "") if resp else "",
                }
            )

    def snapshot(self) -> list[JsonObject]:
        with self._lock:
            return list(self.flows)

    def raw(self, flow_id: str) -> Any | None:
        with self._lock:
            return self._raw.get(flow_id)

    def count(self) -> int:
        with self._lock:
            return len(self.flows)


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
        inst = _ProxyInstance(host, port)
        inst.start()
        with self._lock:
            self._instances[session_id] = inst
        return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

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
        }

    def flows(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        inst = self._get(session_id)
        items = inst.recorder.snapshot()
        cap = max(1, int(limit))
        start = max(0, int(offset))
        window = items[start : start + cap]
        return {
            "flows": window,
            "count": len(window),
            "total": len(items),
            "offset": start,
            # A caller deciding "these are all the flows" has to know
            # whether the ring ended or this page merely stopped.
            "has_more": start + len(window) < len(items),
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
            out = artifact_dir / f"flow-{flow_id}.bin"
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
        if master is None or inst._loop is None:
            raise ProxyError("invalid_state", "proxy is not running")
        try:
            new_flow = flow.copy()
            inst._loop.call_soon_threadsafe(master.commands.call, "replay.client", [new_flow])
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
