from __future__ import annotations

import ctypes
import json
import os
import secrets
import subprocess
import time
from collections import deque
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Lock, RLock, Thread
from typing import Any, TextIO
from uuid import uuid4

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.backends.common.text_stream import read_bounded_text_line
from headless_re_mcp.backends.x64dbg.limits import MAX_FRAME_BYTES
from headless_re_mcp.core.desktop_isolation import (
    DesktopIsolationJob,
    hide_input_desktop_windows_for_pids,
)
from headless_re_mcp.core.events import (
    DEFAULT_DEBUG_EVENT_BATCH,
    MAX_DEBUG_EVENT_BATCH,
    DebugEventBatch,
    DebugEventProtocolError,
    parse_debug_event_batch,
)
from headless_re_mcp.core.hidden_desktop import DesktopProcess, HiddenDesktop
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.core.process_tree import enumerate_direct_children, terminate_process_tree
from headless_re_mcp.core.session import detect_pe_architecture
from headless_re_mcp.core.windows import describe_process_windows
from headless_re_mcp.process_group import assign_to_process_group

JsonObject = dict[str, Any]

_PROTOCOL = "headless-re-xdbg"
_PROTOCOL_VERSION = 1
_MAX_FRAME_BYTES = MAX_FRAME_BYTES
_MAX_DISPATCH_TIMEOUT_MS = 30_000
# A reconnect can only succeed once the worker finishes whatever request the
# dropped connection left it running, so allow for that without letting a stuck
# worker block the caller indefinitely.
_RECONNECT_TIMEOUT_SECONDS = 30.0
_MAX_JSON_INTEGER = (1 << 63) - 1
_MAX_DIAGNOSTIC_LINE_CHARS = 16 * 1024


class XdbgRpcError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: JsonObject | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}
        self.retryable = retryable

    @classmethod
    def from_payload(cls, payload: object) -> XdbgRpcError:
        if not isinstance(payload, dict):
            return cls("rpc_protocol_error", "x64dbg returned an invalid error payload")
        details = payload.get("details")
        return cls(
            str(payload.get("code", "backend_error")),
            str(payload.get("message", "x64dbg RPC request failed")),
            details=details if isinstance(details, dict) else {},
            retryable=bool(payload.get("retryable", False)),
        )


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.c_ulong),
        ("OffsetHigh", ctypes.c_ulong),
        ("hEvent", ctypes.c_void_p),
    ]


class _NamedPipeTransport:
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _FILE_FLAG_OVERLAPPED = 0x40000000
    _SECURITY_SQOS_PRESENT = 0x00100000
    _SECURITY_IDENTIFICATION = 0x00010000
    _ERROR_FILE_NOT_FOUND = 2
    _ERROR_PIPE_BUSY = 231
    _ERROR_IO_PENDING = 997
    _ERROR_OPERATION_ABORTED = 995
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 258
    # CancelIoEx is best-effort. Waiting forever after it failed held the
    # request lock for the rest of the process life. Two seconds is enough for
    # a healthy cancel to signal and short enough that a wedged driver cannot
    # pin the client.
    _CANCEL_WAIT_MS = 2_000
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self, handle: int, pipe_name: str) -> None:
        self._kernel32 = ctypes.WinDLL(  # type: ignore[attr-defined,unused-ignore]
            "kernel32", use_last_error=True
        )
        self._configure_api()
        self._handle = handle
        self._pipe_name = pipe_name
        self._event = self._kernel32.CreateEventW(None, True, False, None)
        if not self._event:
            error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
            self._kernel32.CloseHandle(self._handle)
            raise OSError(error, "CreateEventW failed")
        self._closed = False

    @classmethod
    def connect(
        cls,
        pipe_name: str,
        *,
        timeout: float,
        process: subprocess.Popen[str] | DesktopProcess,
    ) -> _NamedPipeTransport:
        if os.name != "nt":
            raise XdbgRpcError("backend_unavailable", "x64dbg RPC requires Windows")
        kernel32 = ctypes.WinDLL(  # type: ignore[attr-defined,unused-ignore]
            "kernel32", use_last_error=True
        )
        kernel32.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong]
        kernel32.WaitNamedPipeW.restype = ctypes.c_int
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p

        deadline = time.monotonic() + timeout
        while True:
            if process.poll() is not None:
                raise XdbgRpcError(
                    "worker_exited",
                    f"x64dbg exited before RPC connected with code {process.returncode}",
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise XdbgRpcError(
                    "rpc_startup_timeout",
                    f"x64dbg RPC pipe was unavailable after {timeout:g} seconds",
                    retryable=True,
                )
            wait_ms = max(1, min(50, int(remaining * 1000)))
            if not kernel32.WaitNamedPipeW(pipe_name, wait_ms):
                error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
                if error in {cls._ERROR_FILE_NOT_FOUND, cls._ERROR_PIPE_BUSY}:
                    time.sleep(min(0.05, remaining))
                    continue
                raise OSError(error, f"WaitNamedPipeW failed for {pipe_name}")

            flags = (
                cls._FILE_FLAG_OVERLAPPED
                | cls._SECURITY_SQOS_PRESENT
                | cls._SECURITY_IDENTIFICATION
            )
            handle = kernel32.CreateFileW(
                pipe_name,
                cls._GENERIC_READ | cls._GENERIC_WRITE,
                0,
                None,
                cls._OPEN_EXISTING,
                flags,
                None,
            )
            if handle != cls._INVALID_HANDLE_VALUE:
                return cls(int(handle), pipe_name)
            error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
            if error in {cls._ERROR_FILE_NOT_FOUND, cls._ERROR_PIPE_BUSY}:
                continue
            raise OSError(error, f"CreateFileW failed for {pipe_name}")

    @property
    def server_pid(self) -> int:
        pid = ctypes.c_ulong()
        if not self._kernel32.GetNamedPipeServerProcessId(self._handle, ctypes.byref(pid)):
            error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
            raise OSError(error, "GetNamedPipeServerProcessId failed")
        return int(pid.value)

    def write_all(self, data: bytes, *, timeout: float) -> None:
        offset = 0
        deadline = time.monotonic() + timeout
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("named-pipe write timed out")
            written = self._write_once(data[offset:], remaining)
            if written <= 0:
                raise BrokenPipeError("named-pipe write returned no bytes")
            offset += written

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        result = bytearray(size)
        offset = 0
        deadline = time.monotonic() + timeout
        while offset < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("named-pipe read timed out")
            chunk = self._read_once(size - offset, remaining)
            if not chunk:
                raise BrokenPipeError("named-pipe peer closed")
            result[offset : offset + len(chunk)] = chunk
            offset += len(chunk)
        return bytes(result)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._kernel32.CancelIoEx(self._handle, None)
        self._kernel32.CloseHandle(self._event)
        self._kernel32.CloseHandle(self._handle)

    def _read_once(self, size: int, timeout: float) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        transferred = self._run_io(
            self._kernel32.ReadFile,
            buffer,
            size,
            timeout,
        )
        return buffer.raw[:transferred]

    def _write_once(self, data: bytes, timeout: float) -> int:
        buffer = ctypes.create_string_buffer(data)
        return self._run_io(
            self._kernel32.WriteFile,
            buffer,
            len(data),
            timeout,
        )

    def _run_io(
        self,
        operation: Any,
        buffer: ctypes.Array[ctypes.c_char],
        size: int,
        timeout: float,
    ) -> int:
        if self._closed:
            raise BrokenPipeError("named-pipe transport is closed")
        self._kernel32.ResetEvent(self._event)
        overlapped = _Overlapped()
        overlapped.hEvent = self._event
        transferred = ctypes.c_ulong()
        if operation(
            self._handle,
            buffer,
            size,
            ctypes.byref(transferred),
            ctypes.byref(overlapped),
        ):
            return int(transferred.value)

        error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
        if error != self._ERROR_IO_PENDING:
            raise OSError(error, "named-pipe I/O failed")
        wait_ms = max(1, min(0xFFFFFFFE, int(timeout * 1000)))
        wait_result = self._kernel32.WaitForSingleObject(self._event, wait_ms)
        if wait_result == self._WAIT_TIMEOUT:
            self._kernel32.CancelIoEx(self._handle, ctypes.byref(overlapped))
            cancel_ms = max(1, min(0xFFFFFFFE, int(self._CANCEL_WAIT_MS)))
            self._kernel32.WaitForSingleObject(self._event, cancel_ms)
            raise TimeoutError("named-pipe I/O timed out")
        if wait_result != self._WAIT_OBJECT_0:
            error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
            raise OSError(error, "WaitForSingleObject failed")
        if not self._kernel32.GetOverlappedResult(
            self._handle, ctypes.byref(overlapped), ctypes.byref(transferred), False
        ):
            error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
            if error == self._ERROR_OPERATION_ABORTED:
                raise TimeoutError("named-pipe I/O was cancelled")
            raise OSError(error, "GetOverlappedResult failed")
        return int(transferred.value)

    def _configure_api(self) -> None:
        kernel32 = self._kernel32
        kernel32.CreateEventW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_wchar_p,
        ]
        kernel32.CreateEventW.restype = ctypes.c_void_p
        kernel32.ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(_Overlapped),
        ]
        kernel32.ReadFile.restype = ctypes.c_int
        kernel32.WriteFile.argtypes = kernel32.ReadFile.argtypes
        kernel32.WriteFile.restype = ctypes.c_int
        kernel32.GetOverlappedResult.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Overlapped),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_int,
        ]
        kernel32.GetOverlappedResult.restype = ctypes.c_int
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        kernel32.ResetEvent.argtypes = [ctypes.c_void_p]
        kernel32.ResetEvent.restype = ctypes.c_int
        kernel32.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.CancelIoEx.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        kernel32.GetNamedPipeServerProcessId.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.GetNamedPipeServerProcessId.restype = ctypes.c_int


# Debugged GUI targets often load IME/input DLLs whose TLS callbacks would pause
# the debuggee under x64dbg defaults (Events/TlsCallbacks=true). Headless UI
# automation cannot make progress while those incidental breaks fire.
_HEADLESS_EVENT_INI = """[Events]
TlsCallbacks=0
TlsCallbacksSystem=0
"""


def seed_headless_event_settings(user_directory: Path) -> Path:
    """Write headless.ini into the Bridge -userdir before process start."""
    path = Path(user_directory) / "headless.ini"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(_HEADLESS_EVENT_INI, encoding="utf-8", newline="\n")
    return path

class XdbgClient:
    def __init__(
        self,
        executable: Path,
        architecture: Architecture,
        *,
        startup_timeout: float = 60.0,
        hidden_desktop: bool = False,
    ) -> None:
        path = executable.resolve(strict=True)
        actual_architecture = detect_pe_architecture(path)
        if actual_architecture != architecture:
            raise XdbgRpcError(
                "architecture_mismatch",
                f"expected {architecture.value} x64dbg, got {actual_architecture.value}",
                details={"executable": str(path)},
            )

        self._request_lock = RLock()
        self._window_lock = Lock()
        self._monitor_stop = Event()
        self._observed_windows: set[str] = set()
        self._stdout_log: deque[str] = deque(maxlen=200)
        self._stderr_log: deque[str] = deque(maxlen=200)
        self._request_id = 0
        self._closed = False
        self._transport: _NamedPipeTransport | None = None
        self._desktop: HiddenDesktop | None = None
        self._isolation_job: DesktopIsolationJob | None = None
        self._debuggee_pid: int | None = None
        self._metadata: JsonObject = {}
        self._capabilities: frozenset[str] = frozenset()
        self._user_directory = TemporaryDirectory(
            prefix=f"headless-re-xdbg-rpc-{architecture.value}-",
            # x64dbg writes symbols and a database here, and the handles are not
            # always gone the moment the process is. A userdir that outlives its
            # worker is a stale directory; a cleanup that throws would abort the
            # shutdown that was removing it.
            ignore_cleanup_errors=True,
        )
        seed_headless_event_settings(Path(self._user_directory.name))

        pipe_suffix = f"headless-re-{uuid4().hex}"
        pipe_name = rf"\\.\pipe\{pipe_suffix}"
        token = secrets.token_hex(32)
        # Retained so a dropped connection can be rebuilt: the worker keeps
        # serving the same pipe and keeps the same token for its whole lifetime.
        self._pipe_name = pipe_name
        self._token = token
        self._architecture = architecture
        self._startup_timeout = startup_timeout
        popen_kw = no_window_popen_kwargs()
        child_environment = os.environ.copy()
        child_environment["HEADLESS_RE_XDBG_RPC_PIPE"] = pipe_suffix
        child_environment["HEADLESS_RE_XDBG_RPC_TOKEN"] = token
        argv = [
            str(path),
            "-userdir",
            self._user_directory.name,
        ]
        if hidden_desktop:
            self._desktop = HiddenDesktop.create(prefix=f"HeadlessRE-{architecture.value}")
            self._process: subprocess.Popen[str] | DesktopProcess = self._desktop.spawn(
                argv,
                environment=child_environment,
                encoding="utf-8",
                errors="replace",
            )
            self._isolation_job = DesktopIsolationJob.create()
            if self._isolation_job is not None:
                self._isolation_job.assign(int(self._process.pid))
        else:
            self._process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=child_environment,
                **popen_kw,
            )
        # x64dbg owns the debuggee, so an ungrouped one left behind by a hard
        # kill is a sample still executing with nothing attached to it.
        assign_to_process_group(int(self._process.pid))
        assert self._process.stdout is not None
        assert self._process.stderr is not None
        self._stdout_thread = Thread(
            target=self._read_log,
            args=(self._process.stdout, self._stdout_log),
            name=f"xdbg-{architecture.value}-{self._process.pid}-stdout",
            daemon=True,
        )
        self._stderr_thread = Thread(
            target=self._read_log,
            args=(self._process.stderr, self._stderr_log),
            name=f"xdbg-{architecture.value}-{self._process.pid}-stderr",
            daemon=True,
        )
        self._window_thread = Thread(
            target=self._monitor_windows,
            name=f"xdbg-{architecture.value}-{self._process.pid}-windows",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()
        self._window_thread.start()

        try:
            hello = self._connect_transport(startup_timeout)
            self._metadata = dict(hello)
            self._metadata["desktop"] = self.desktop_snapshot()
            raw_capabilities = hello.get("capabilities")
            if not isinstance(raw_capabilities, list):
                raise XdbgRpcError("rpc_protocol_error", "RPC hello capabilities must be an array")
            self._capabilities = frozenset(str(item) for item in raw_capabilities)
            self._observe_windows()
        except BaseException:
            self.terminate()
            raise

    def _connect_transport(self, timeout: float) -> JsonObject:
        """Open the pipe, authenticate, and return the hello payload.

        The worker tracks authentication per connection, so a reconnect has to
        repeat the handshake rather than resume the previous one.
        """
        transport = _NamedPipeTransport.connect(
            self._pipe_name,
            timeout=timeout,
            process=self._process,
        )
        # Both callers check for None first, but overwriting without closing
        # would leak a pipe handle the moment one of them stops.
        previous = self._transport
        if previous is not None:
            previous.close()
        self._transport = transport
        try:
            if transport.server_pid != self._process.pid:
                raise XdbgRpcError(
                    "rpc_peer_mismatch",
                    "named-pipe server PID does not match the spawned x64dbg process",
                )
            hello = self._request("rpc.hello", {"token": self._token}, timeout=timeout)
            if hello.get("pid") != self._process.pid:
                raise XdbgRpcError(
                    "rpc_peer_mismatch", "RPC hello PID does not match the spawned process"
                )
            if hello.get("architecture") != self._architecture.value:
                raise XdbgRpcError(
                    "architecture_mismatch", "RPC hello architecture does not match the client"
                )
        except BaseException:
            transport.close()
            self._transport = None
            raise
        return hello

    def _reconnect(self) -> None:
        """Rebuild a dropped connection without disturbing the debuggee.

        A transport fault leaves the worker running, and the worker is what owns
        the debuggee, so replacing the connection preserves live state that
        restarting the backend would throw away.
        """
        hello = self._connect_transport(_RECONNECT_TIMEOUT_SECONDS)
        capabilities = hello.get("capabilities")
        if not isinstance(capabilities, list):
            # Keeping the old set would treat a degraded worker as fully capable
            # and only surface the problem as a confusing failure later. The
            # initial handshake rejects the same payload.
            raise XdbgRpcError("rpc_protocol_error", "RPC hello capabilities must be an array")
        self._capabilities = frozenset(str(item) for item in capabilities)

    def reconnect(self) -> None:
        """Rebuild a dropped connection on demand, for explicit recovery."""
        with self._request_lock:
            if self._closed:
                raise XdbgRpcError("session_closed", "x64dbg RPC client is closed")
            if self._process.poll() is not None:
                raise self._process_exit_error()
            if self._transport is not None:
                return
            self._reconnect()

    @property
    def transport_connected(self) -> bool:
        """False once a fault dropped the connection, until it is rebuilt."""
        return self._transport is not None

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def exit_code(self) -> int | None:
        return self._process.poll()

    @property
    def runtime_directory(self) -> Path:
        return Path(self._user_directory.name)

    @property
    def capabilities(self) -> frozenset[str]:
        return self._capabilities

    @property
    def metadata(self) -> JsonObject:
        return dict(self._metadata)

    @property
    def analyzer_windows(self) -> tuple[str, ...]:
        with self._window_lock:
            return tuple(sorted(self._observed_windows))

    def desktop_snapshot(
        self,
        *,
        allowed_pids: frozenset[int] | None = None,
    ) -> JsonObject:
        desktop = self._desktop
        if desktop is None:
            from headless_re_mcp.core.windows import snapshot_input_desktop

            return snapshot_input_desktop(allowed_pids=allowed_pids)
        return desktop.snapshot(allowed_pids=allowed_pids)

    def desktop_capture(
        self,
        hwnd: int,
        *,
        allowed_pids: frozenset[int],
        output_path: str | Path,
    ) -> JsonObject:
        desktop = self._desktop
        if desktop is None:
            from headless_re_mcp.core.ui_win32 import capture_hwnd_screenshot
            from headless_re_mcp.core.windows import list_input_desktop_windows

            listed = list_input_desktop_windows(allowed_pids=allowed_pids)
            hwnds = {int(row["hwnd"]) for row in listed}
            if int(hwnd) not in hwnds:
                raise XdbgRpcError(
                    "window_not_authorized",
                    "window is not owned by the authorized debuggee on the input desktop",
                )
            return capture_hwnd_screenshot(hwnd, allowed_pids, output_path)
        return desktop.capture(
            hwnd,
            allowed_pids=allowed_pids,
            output_path=output_path,
        )

    def request(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        with self._request_lock:
            if self._closed:
                raise XdbgRpcError("session_closed", "x64dbg RPC client is closed")
            if self._process.poll() is not None:
                raise self._process_exit_error()
            # Checked before reconnecting: a call the worker cannot serve should
            # fail immediately rather than after spending the reconnect timeout
            # only to be rejected anyway.
            if method not in self._capabilities and not method.startswith("rpc."):
                raise XdbgRpcError(
                    "capability_unavailable",
                    f"x64dbg RPC does not provide {method}",
                    details={"capability": method},
                )
            if self._transport is None:
                # Heal here rather than in _request: the call that hit the fault
                # already failed, and replaying it could run a state-changing
                # operation twice. Only later calls get the rebuilt connection.
                self._reconnect()
            self._observe_windows()
            return self._request(method, params or {}, timeout=timeout)

    def memory_regions(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Return a paused-only page of VirtualQuery-style memory regions."""
        params: JsonObject = {"offset": offset}
        if limit is not None:
            params["limit"] = limit
        return self.request("memory.regions", params, timeout=timeout)

    def memory_protect_query(self, address: int, *, timeout: float = 10.0) -> JsonObject:
        """Return the memory region that contains ``address`` (paused-only)."""
        return self.request("memory.protect.query", {"address": address}, timeout=timeout)

    def memory_protection(
        self,
        address: int,
        *,
        rights: str | None = None,
        timeout: float = 10.0,
    ) -> JsonObject:
        """Query or set page rights at ``address`` (paused-only; rights allowlisted)."""
        params: JsonObject = {"address": address}
        if rights is not None:
            params["rights"] = rights
        return self.request("memory.protection", params, timeout=timeout)

    def threads_list(
        self,
        *,
        offset: int = 0,
        limit: int = 256,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "threads.list",
            {"offset": offset, "limit": limit},
            timeout=timeout,
        )

    def threads_current(self, *, timeout: float = 10.0) -> JsonObject:
        return self.request("threads.current", timeout=timeout)

    def threads_context_read(self, tid: int, *, timeout: float = 10.0) -> JsonObject:
        return self.request("threads.context.read", {"tid": tid}, timeout=timeout)

    def threads_context_write(
        self,
        tid: int,
        name: str,
        value: int,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "threads.context.write",
            {"tid": tid, "name": name, "value": value},
            timeout=timeout,
        )

    def stack_read(
        self,
        *,
        address: int | None = None,
        count: int = 32,
        timeout: float = 10.0,
    ) -> JsonObject:
        params: JsonObject = {"count": count}
        if address is not None:
            params["address"] = address
        return self.request("stack.read", params, timeout=timeout)

    def stack_trace(self, *, limit: int = 256, timeout: float = 10.0) -> JsonObject:
        return self.request("stack.trace", {"limit": limit}, timeout=timeout)

    def disassembly_read(
        self,
        address: int,
        *,
        count: int = 32,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "disassembly.read",
            {"address": address, "count": count},
            timeout=timeout,
        )

    def symbols_list(
        self,
        module_base: int,
        *,
        limit: int = 256,
        timeout: float = 30.0,
    ) -> JsonObject:
        return self.request(
            "symbols.list",
            {"module_base": module_base, "limit": limit},
            timeout=timeout,
        )

    def symbols_resolve(self, expression: str, *, timeout: float = 10.0) -> JsonObject:
        return self.request("symbols.resolve", {"expression": expression}, timeout=timeout)

    def breakpoints_hardware_set(
        self,
        address: int,
        *,
        bp_type: str = "x",
        size: int = 1,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "breakpoints.hardware.set",
            {"address": address, "type": bp_type, "size": size},
            timeout=timeout,
        )

    def breakpoints_hardware_remove(
        self,
        address: int,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "breakpoints.hardware.remove",
            {"address": address},
            timeout=timeout,
        )

    def breakpoints_hardware_list(self, *, timeout: float = 10.0) -> JsonObject:
        return self.request("breakpoints.hardware.list", timeout=timeout)

    def breakpoints_memory_set(
        self,
        address: int,
        *,
        bp_type: str = "a",
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "breakpoints.memory.set",
            {"address": address, "type": bp_type},
            timeout=timeout,
        )

    def breakpoints_memory_remove(
        self,
        address: int,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "breakpoints.memory.remove",
            {"address": address},
            timeout=timeout,
        )

    def breakpoints_memory_list(self, *, timeout: float = 10.0) -> JsonObject:
        return self.request("breakpoints.memory.list", timeout=timeout)

    def breakpoints_condition_set(
        self,
        address: int,
        expression: str,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "breakpoints.condition.set",
            {"address": address, "expression": expression},
            timeout=timeout,
        )

    def breakpoints_condition_get(
        self,
        address: int,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "breakpoints.condition.get",
            {"address": address},
            timeout=timeout,
        )

    def patches_list(self, *, timeout: float = 10.0) -> JsonObject:
        return self.request("patches.list", timeout=timeout)

    def patches_apply(
        self,
        address: int,
        data: str,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        return self.request(
            "patches.apply",
            {"address": address, "data": data},
            timeout=timeout,
        )

    def patches_restore(self, address: int, *, timeout: float = 10.0) -> JsonObject:
        return self.request("patches.restore", {"address": address}, timeout=timeout)

    def trace_start(
        self,
        path: str | Path,
        *,
        max_events: int = 10_000,
        timeout_ms: int = 60_000,
        max_file_bytes: int = 16 * 1024 * 1024,
        timeout: float = 10.0,
    ) -> JsonObject:
        trace_path = Path(path)
        if not trace_path.is_absolute():
            raise ValueError("trace path must be absolute")
        if type(max_events) is not int or not 1 <= max_events <= 1_000_000:
            raise ValueError("max_events must be between 1 and 1000000")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 3_600_000:
            raise ValueError("timeout_ms must be between 1 and 3600000")
        if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= 256 * 1024 * 1024:
            raise ValueError("max_file_bytes must be between 1 and 268435456")
        result = self.request(
            "trace.start",
            {
                "path": str(trace_path),
                "max_events": max_events,
                "timeout_ms": timeout_ms,
                "max_file_bytes": max_file_bytes,
            },
            timeout=timeout,
        )
        self._validate_trace_result(
            result,
            path=trace_path,
            max_events=max_events,
            timeout_ms=timeout_ms,
            max_file_bytes=max_file_bytes,
            recording=True,
        )
        return result

    def trace_stop(self, *, timeout: float = 10.0) -> JsonObject:
        result = self.request("trace.stop", timeout=timeout)
        if result.get("initialized") is not False:
            self._validate_trace_result(result, recording=False)
        return result

    def trace_cancel(self, *, timeout: float = 10.0) -> JsonObject:
        """Cancel the active trace; the bounded partial artifact is retained."""
        return self.trace_stop(timeout=timeout)

    def trace_status(self, *, timeout: float = 10.0) -> JsonObject:
        result = self.request("trace.status", timeout=timeout)
        if result.get("initialized") is not False:
            self._validate_trace_result(result)
        return result

    @staticmethod
    def _validate_trace_result(
        result: JsonObject,
        *,
        path: Path | None = None,
        max_events: int | None = None,
        timeout_ms: int | None = None,
        max_file_bytes: int | None = None,
        recording: bool | None = None,
    ) -> None:
        if type(result.get("recording")) is not bool:
            raise XdbgRpcError(
                "rpc_protocol_error",
                "x64dbg returned a trace result without boolean recording state",
            )
        if recording is not None and result["recording"] is not recording:
            raise XdbgRpcError(
                "rpc_protocol_error",
                "x64dbg returned an unexpected trace recording state",
                details={"expected": recording, "actual": result["recording"]},
            )
        if path is not None:
            returned = result.get("path")
            try:
                actual_path = Path(str(returned)).resolve()
            except (OSError, ValueError, TypeError) as exc:
                raise XdbgRpcError(
                    "rpc_protocol_error", "x64dbg returned an invalid trace path"
                ) from exc
            if actual_path != path.resolve():
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "x64dbg returned a different trace path",
                    details={"expected": str(path), "actual": str(returned)},
                )
        expected = {
            "max_events": max_events,
            "timeout_ms": timeout_ms,
            "max_file_bytes": max_file_bytes,
        }
        for key, value in expected.items():
            if value is not None and result.get(key) != value:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    f"x64dbg returned an unexpected {key}",
                    details={"expected": value, "actual": result.get(key)},
                )
        for key in ("events_written", "file_bytes", "elapsed_ms"):
            if result.get(key) is None:
                result[key] = 0
            if type(result.get(key)) is not int or int(result[key]) < 0:
                raise XdbgRpcError("rpc_protocol_error", f"x64dbg returned an invalid {key}")
        if not isinstance(result.get("stop_reason"), str) or not result["stop_reason"]:
            result["stop_reason"] = "none"
        if not isinstance(result.get("stop_reason"), str):
            raise XdbgRpcError("rpc_protocol_error", "x64dbg returned no trace stop reason")

    def modules_dump(
        self,
        base: int,
        output_path: str | Path,
        *,
        size: int | None = None,
        timeout: float = 60.0,
    ) -> JsonObject:
        """Dump a module image range to ``output_path`` (artifact path, paused-only)."""
        params: JsonObject = {
            "base": base,
            "output_path": str(Path(output_path)),
        }
        if size is not None:
            params["size"] = size
        return self.request("modules.dump", params, timeout=timeout)

    def pe_headers_runtime(
        self,
        base: int,
        *,
        output_path: str | Path | None = None,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Read paused-only runtime PE headers for the module at ``base``."""
        params: JsonObject = {"base": base}
        if output_path is not None:
            params["output_path"] = str(Path(output_path))
        return self.request("pe.headers.runtime", params, timeout=timeout)

    def imports_scan(
        self,
        module_base: int,
        *,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int | None = None,
        mode: str | None = None,
        timeout: float = 60.0,
    ) -> JsonObject:
        """Scan for candidate IAT ranges inside a paused module (no blind selection)."""
        params: JsonObject = {"module_base": module_base}
        if search_start is not None:
            params["search_start"] = search_start
        if search_size is not None:
            params["search_size"] = search_size
        if max_candidates is not None:
            params["max_candidates"] = max_candidates
        if mode is not None:
            params["mode"] = mode
        return self.request("imports.scan", params, timeout=timeout)

    def imports_read(
        self,
        iat_va: int,
        size: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Read and resolve one confirmed IAT range against the export catalog."""
        return self.request(
            "imports.read",
            {"iat_va": iat_va, "size": size},
            timeout=timeout,
        )

    def read_events(
        self,
        cursor: int,
        *,
        limit: int = DEFAULT_DEBUG_EVENT_BATCH,
        timeout: float = 10.0,
    ) -> DebugEventBatch:
        if type(cursor) is not int or not 0 <= cursor <= _MAX_JSON_INTEGER:
            raise ValueError("cursor must be a non-negative signed 64-bit integer")
        if type(limit) is not int or not 1 <= limit <= MAX_DEBUG_EVENT_BATCH:
            raise ValueError(f"limit must be between 1 and {MAX_DEBUG_EVENT_BATCH}")
        payload = self.request(
            "events.read",
            {"cursor": cursor, "limit": limit},
            timeout=timeout,
        )
        try:
            return parse_debug_event_batch(
                payload,
                requested_cursor=cursor,
                requested_limit=limit,
            )
        except DebugEventProtocolError as exc:
            raise XdbgRpcError(
                "rpc_protocol_error",
                f"x64dbg returned an invalid event batch: {exc}",
            ) from exc

    def wait_for_state(
        self,
        states: set[str],
        *,
        timeout: float = 30.0,
        after_event_sequence: int | None = None,
        transition_event_kinds: frozenset[str] = frozenset(),
    ) -> JsonObject:
        deadline = time.monotonic() + timeout
        last_state: JsonObject = {}
        event_cursor = after_event_sequence
        transition_observed = after_event_sequence is None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise XdbgRpcError(
                    "debug_state_timeout",
                    f"x64dbg did not reach {sorted(states)} within {timeout:g} seconds",
                    details={"last_state": last_state, **self._diagnostics()},
                    retryable=True,
                )
            if not transition_observed:
                assert event_cursor is not None
                batch = self.read_events(
                    event_cursor,
                    limit=MAX_DEBUG_EVENT_BATCH,
                    timeout=min(5.0, max(0.1, remaining)),
                )
                event_cursor = batch.next_cursor
                # A wrap-around is not proof the command ran. Resume/step wait
                # for a named transition; treating dropped>0 as that event
                # reports success while the target is still paused.
                transition_observed = any(
                    event.kind in transition_event_kinds for event in batch.events
                )
            last_state = self.request("debug.state", timeout=min(5.0, max(0.1, remaining)))
            if last_state.get("state") in states and transition_observed:
                return last_state
            time.sleep(min(0.05, remaining))

    def close(self, *, timeout: float = 15.0) -> None:
        with self._request_lock:
            if self._closed:
                return
            try:
                if self._process.poll() is None and self._transport is not None:
                    try:
                        if "trace.status" in self._capabilities:
                            trace = self._request("trace.status", {}, timeout=min(timeout, 5.0))
                            if (
                                trace.get("recording") is True
                                and "trace.stop" in self._capabilities
                            ):
                                self._request("trace.stop", {}, timeout=min(timeout, 10.0))
                        state = self._request("debug.state", {}, timeout=min(timeout, 5.0))
                        if state.get("debugging") is True:
                            self._request("debug.stop", {}, timeout=min(timeout, 10.0))
                    except XdbgRpcError:
                        pass
            finally:
                self._closed = True
                self._request_exit()
                try:
                    self._process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._terminate_process()
                if self._transport is not None:
                    self._transport.close()
                    self._transport = None
                self._finish_threads()

    def terminate(self) -> None:
        # Kill the process first so a reconnect already in flight cannot outlive
        # this call, then take the lock to mutate state the way close() does.
        # Without the lock a concurrent reconnect could publish a transport onto
        # a client that is being torn down.
        self._terminate_process()
        with self._request_lock:
            self._closed = True
            if self._transport is not None:
                self._transport.close()
                self._transport = None
        self._finish_threads()

    def _request(self, method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        transport = self._transport
        if transport is None:
            raise XdbgRpcError("rpc_unavailable", "x64dbg RPC transport is unavailable")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._request_id += 1
        request_id = str(self._request_id)
        dispatch_timeout_ms = min(
            _MAX_DISPATCH_TIMEOUT_MS,
            max(1, int(timeout * 1000)),
        )
        payload = {
            "protocol": _PROTOCOL,
            "version": _PROTOCOL_VERSION,
            "id": request_id,
            "method": method,
            "params": params,
            "timeout_ms": dispatch_timeout_ms,
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if not encoded or len(encoded) > _MAX_FRAME_BYTES:
            raise XdbgRpcError("request_too_large", "RPC request exceeds the frame limit")
        frame = len(encoded).to_bytes(4, "little") + encoded
        # One deadline for the whole exchange. Given to each I/O separately, the
        # write, the length read and the body read each got the full timeout, so
        # a caller asking for ten seconds could wait thirty and every bound in
        # the tool catalog was worth three times what it said. The IDA worker
        # already runs a single deadline across its exchange.
        deadline = time.monotonic() + timeout

        def remaining() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"x64dbg RPC call exceeded {timeout:g}s")
            return left

        try:
            transport.write_all(frame, timeout=remaining())
            response_size = int.from_bytes(transport.read_exact(4, timeout=remaining()), "little")
            if response_size <= 0 or response_size > _MAX_FRAME_BYTES:
                raise XdbgRpcError("rpc_protocol_error", "RPC response frame length is invalid")
            response_raw = transport.read_exact(response_size, timeout=remaining())
        except (OSError, TimeoutError, BrokenPipeError) as exc:
            transport.close()
            self._transport = None
            if self._process.poll() is not None:
                raise self._process_exit_error() from exc
            raise XdbgRpcError(
                "rpc_transport_error",
                f"x64dbg RPC transport failed: {exc}",
                details=self._diagnostics(),
                # The worker outlived the fault, so the next call rebuilds the
                # connection instead of failing for the rest of the session.
                retryable=True,
            ) from exc

        try:
            response = json.loads(response_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise XdbgRpcError(
                "rpc_protocol_error", "RPC response is not valid UTF-8 JSON"
            ) from exc
        if not isinstance(response, dict):
            raise XdbgRpcError("rpc_protocol_error", "RPC response must be an object")
        if (
            response.get("protocol") != _PROTOCOL
            or response.get("version") != _PROTOCOL_VERSION
            or response.get("id") != request_id
            or not isinstance(response.get("ok"), bool)
        ):
            raise XdbgRpcError("rpc_protocol_error", "RPC response envelope is invalid")
        if response["ok"] is not True:
            raise XdbgRpcError.from_payload(response.get("error"))
        result = response.get("result")
        if not isinstance(result, dict):
            raise XdbgRpcError("rpc_protocol_error", "RPC result must be an object")
        self._observe_windows()
        self._note_debuggee_pid(result)
        return result

    def _read_log(self, stream: TextIO, target: deque[str]) -> None:
        while True:
            line = read_bounded_text_line(
                stream,
                max_chars=_MAX_DIAGNOSTIC_LINE_CHARS,
            )
            if line is None:
                return
            target.append(line)

    def _monitor_windows(self) -> None:
        while not self._monitor_stop.wait(0.05):
            windows = self._describe_analyzer_windows()
            if windows:
                with self._window_lock:
                    self._observed_windows.update(windows)
            if self._desktop is not None:
                self._suppress_input_desktop_leaks()

    def _note_debuggee_pid(self, payload: JsonObject) -> None:
        if "process_id" not in payload and "debuggee_pid" not in payload:
            return
        value = payload.get("process_id")
        if value is None:
            value = payload.get("debuggee_pid")
        pid: int | None = None
        if type(value) is int and value > 0:
            pid = value
        elif isinstance(value, str) and value.isdigit():
            parsed = int(value)
            if parsed > 0:
                pid = parsed
        with self._window_lock:
            self._debuggee_pid = pid

    def _suppress_input_desktop_leaks(self) -> None:
        pids = {int(self._process.pid)}
        with self._window_lock:
            debuggee = self._debuggee_pid
        if isinstance(debuggee, int) and debuggee > 0:
            pids.add(debuggee)
            pids.update(enumerate_direct_children(debuggee))
        hide_input_desktop_windows_for_pids(pids)

    def _observe_windows(self) -> None:
        """Refuse the call while a window is up, without latching on history.

        ``analyzer_windows`` stays cumulative because a gate has to fail on a
        window that appeared and closed between two calls. Refusing on that same
        history would be a different rule: the passive monitor records windows
        the request path never saw, so one dialog x64dbg opened and dismissed on
        its own would kill the next call and every call after it, against a
        worker that is once again headless.
        """
        windows = self._describe_analyzer_windows()
        if not windows:
            return
        with self._window_lock:
            self._observed_windows.update(windows)
        raise XdbgRpcError(
            "analyzer_window_detected",
            "x64dbg has a top-level analyzer window open",
            details={"windows": sorted(windows)},
        )

    def _describe_analyzer_windows(self) -> list[str]:
        desktop: HiddenDesktop | None = getattr(self, "_desktop", None)
        if desktop is not None:
            return desktop.process_window_descriptions(self._process.pid)
        return sorted(describe_process_windows(self._process.pid))

    def _request_exit(self) -> None:
        if self._process.poll() is not None or self._process.stdin is None:
            return
        try:
            self._process.stdin.write("exit\n")
            self._process.stdin.flush()
            self._process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    def _terminate_process(self) -> None:
        # terminate()/kill() on the headless exe leaves its children running.
        # Same leak as the IDA worker: a launcher was dead after this method
        # while the sleeper it started was still alive.
        terminate_process_tree(self._process, wait_s=5.0)

    def _finish_threads(self) -> None:
        self._monitor_stop.set()
        if hasattr(self, "_window_thread"):
            self._window_thread.join(timeout=2)
        if hasattr(self, "_stdout_thread"):
            self._stdout_thread.join(timeout=2)
        if hasattr(self, "_stderr_thread"):
            self._stderr_thread.join(timeout=2)
        desktop: HiddenDesktop | None = getattr(self, "_desktop", None)
        self._desktop = None
        if desktop is not None:
            with suppress(OSError):
                desktop.close()
        job = getattr(self, "_isolation_job", None)
        self._isolation_job = None
        if job is not None:
            with suppress(OSError):
                job.close()
        if hasattr(self, "_user_directory"):
            # Belt and braces with ignore_cleanup_errors: this runs from close
            # and from terminate, and a userdir this refuses to remove must not
            # be able to abort either one.
            with suppress(OSError):
                self._user_directory.cleanup()

    def _process_exit_error(self) -> XdbgRpcError:
        return XdbgRpcError(
            "worker_exited",
            f"x64dbg exited unexpectedly with code {self._process.poll()}",
            details=self._diagnostics(),
            retryable=True,
        )

    def _diagnostics(self) -> JsonObject:
        return {
            "pid": self._process.pid,
            "exit_code": self._process.poll(),
            "stdout": list(self._stdout_log),
            "stderr": list(self._stderr_log),
            "analyzer_windows": list(self.analyzer_windows),
        }
