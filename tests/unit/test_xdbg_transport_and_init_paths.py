"""Cross-platform coverage for the named-pipe transport logic and XdbgClient.__init__.

The Win32 calls themselves (WinDLL construction, WaitNamedPipeW polling) only
run on Windows, but everything around them is plain Python: the write/read
loops with their single deadline, the overlapped-I/O state machine in
``_run_io``, the API signature table, and the whole client constructor. Those
arms decide how a wedged pipe or a half-dead worker surfaces to the caller, so
they are pinned here with fake kernel32 tables and fake processes.
"""

from __future__ import annotations

import io
import types
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.client as client_module
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.core.models import Architecture
from tests.unit.test_xdbg_client_paths import FlexHandshake

JsonObject = dict[str, Any]

_IO_PENDING = 997
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_OPERATION_ABORTED = 995


def _bare_transport(kernel32: Any = None) -> Any:
    transport = object.__new__(client_module._NamedPipeTransport)
    transport._closed = False
    transport._kernel32 = kernel32 or types.SimpleNamespace()
    transport._event = 111
    transport._handle = 222
    transport._pipe_name = "test-pipe"
    return transport


def _fake_last_error(monkeypatch: pytest.MonkeyPatch, values: list[int]) -> None:
    """Install ctypes.get_last_error (absent off Windows) popping from ``values``."""
    monkeypatch.setattr(
        client_module.ctypes,
        "get_last_error",
        lambda: values.pop(0),
        raising=False,
    )


# --------------------------------------------------------------------------- #
# connect / close / server_pid
# --------------------------------------------------------------------------- #


class _ApiFn:
    """A kernel32 entry point: callable, and accepts argtypes/restype assignment."""

    def __init__(self, behavior: Any = None) -> None:
        self._behavior = behavior
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *args: Any) -> Any:
        if self._behavior is None:
            return 1
        return self._behavior(*args)


def _fake_windll(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> Any:
    """Install a ctypes.WinDLL substitute returning one shared kernel32 table."""
    names = (
        "WaitNamedPipeW",
        "CreateFileW",
        "CreateEventW",
        "ReadFile",
        "WriteFile",
        "GetOverlappedResult",
        "WaitForSingleObject",
        "ResetEvent",
        "CancelIoEx",
        "CloseHandle",
        "GetNamedPipeServerProcessId",
    )
    kernel32 = types.SimpleNamespace(**{name: overrides.get(name, _ApiFn()) for name in names})
    monkeypatch.setattr(
        client_module.ctypes,
        "WinDLL",
        lambda name, use_last_error=False: kernel32,
        raising=False,
    )
    return kernel32


def _live_process() -> Any:
    return types.SimpleNamespace(poll=lambda: None, returncode=None)


def test_connect_refuses_off_windows() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        client_module._NamedPipeTransport.connect(
            r"\\.\pipe\headless-re-test",
            timeout=1.0,
            process=types.SimpleNamespace(poll=lambda: None),  # type: ignore[arg-type]
        )
    assert exc.value.code == "unsupported_on_platform"


def test_connect_opens_the_pipe_and_builds_a_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The happy path: wait succeeds, the handle is valid, the event is created."""
    monkeypatch.setattr(client_module.os, "name", "nt")
    _fake_windll(
        monkeypatch,
        CreateFileW=_ApiFn(lambda *args: 1234),
        CreateEventW=_ApiFn(lambda *args: 5678),
    )

    transport = client_module._NamedPipeTransport.connect(
        r"\\.\pipe\headless-re-test", timeout=5.0, process=_live_process()
    )

    assert transport._handle == 1234
    assert transport._event == 5678
    assert transport._closed is False


def test_connect_reports_a_worker_that_exited_before_the_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module.os, "name", "nt")
    _fake_windll(monkeypatch)
    dead = types.SimpleNamespace(poll=lambda: 9, returncode=9)

    with pytest.raises(XdbgRpcError) as exc:
        client_module._NamedPipeTransport.connect(
            r"\\.\pipe\headless-re-test", timeout=5.0, process=dead
        )
    assert exc.value.code == "worker_exited"


def test_connect_times_out_when_the_pipe_never_appears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module.os, "name", "nt")
    _fake_windll(monkeypatch)

    with pytest.raises(XdbgRpcError) as exc:
        client_module._NamedPipeTransport.connect(
            r"\\.\pipe\headless-re-test", timeout=0, process=_live_process()
        )
    assert exc.value.code == "rpc_startup_timeout"
    assert exc.value.retryable is True


def test_connect_retries_a_pipe_that_is_not_ready_yet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FILE_NOT_FOUND from WaitNamedPipeW means "not created yet", not failure."""
    monkeypatch.setattr(client_module.os, "name", "nt")
    _fake_last_error(monkeypatch, [2])  # ERROR_FILE_NOT_FOUND
    wait_results = [0, 1]
    _fake_windll(
        monkeypatch,
        WaitNamedPipeW=_ApiFn(lambda *args: wait_results.pop(0)),
        CreateFileW=_ApiFn(lambda *args: 1234),
        CreateEventW=_ApiFn(lambda *args: 5678),
    )

    transport = client_module._NamedPipeTransport.connect(
        r"\\.\pipe\headless-re-test", timeout=5.0, process=_live_process()
    )
    assert transport._handle == 1234


def test_connect_raises_when_the_wait_fails_outright(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module.os, "name", "nt")
    _fake_last_error(monkeypatch, [5])  # ERROR_ACCESS_DENIED
    _fake_windll(monkeypatch, WaitNamedPipeW=_ApiFn(lambda *args: 0))

    with pytest.raises(OSError, match="WaitNamedPipeW"):
        client_module._NamedPipeTransport.connect(
            r"\\.\pipe\headless-re-test", timeout=5.0, process=_live_process()
        )


def test_connect_retries_a_busy_open_and_raises_on_other_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module.os, "name", "nt")
    invalid = client_module._NamedPipeTransport._INVALID_HANDLE_VALUE
    _fake_last_error(monkeypatch, [231, 5])  # ERROR_PIPE_BUSY then ERROR_ACCESS_DENIED
    _fake_windll(monkeypatch, CreateFileW=_ApiFn(lambda *args: invalid))

    with pytest.raises(OSError, match="CreateFileW"):
        client_module._NamedPipeTransport.connect(
            r"\\.\pipe\headless-re-test", timeout=5.0, process=_live_process()
        )


def test_transport_init_closes_the_pipe_when_the_event_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed CreateEventW must release the pipe handle before raising."""
    closed: list[Any] = []
    _fake_last_error(monkeypatch, [8])  # ERROR_NOT_ENOUGH_MEMORY
    _fake_windll(
        monkeypatch,
        CreateEventW=_ApiFn(lambda *args: 0),
        CloseHandle=_ApiFn(lambda handle: closed.append(handle) or 1),
    )

    with pytest.raises(OSError, match="CreateEventW"):
        client_module._NamedPipeTransport(1234, "test-pipe")

    assert closed == [1234]


def test_close_cancels_io_and_releases_handles_exactly_once() -> None:
    calls: list[tuple[str, Any]] = []
    kernel32 = types.SimpleNamespace(
        CancelIoEx=lambda handle, overlapped: calls.append(("cancel", handle)),
        CloseHandle=lambda handle: calls.append(("close", handle)),
    )
    transport = _bare_transport(kernel32)

    transport.close()
    transport.close()  # idempotent: the second call must not double-free

    assert calls == [("cancel", 222), ("close", 111), ("close", 222)]


def test_server_pid_reads_the_peer_process_id() -> None:
    def get_pid(handle: Any, pid_ref: Any) -> int:
        pid_ref._obj.value = 777
        return 1

    transport = _bare_transport(types.SimpleNamespace(GetNamedPipeServerProcessId=get_pid))
    assert transport.server_pid == 777


def test_server_pid_raises_when_the_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_last_error(monkeypatch, [5])
    transport = _bare_transport(
        types.SimpleNamespace(GetNamedPipeServerProcessId=lambda handle, pid_ref: 0)
    )
    with pytest.raises(OSError, match="GetNamedPipeServerProcessId"):
        _ = transport.server_pid


# --------------------------------------------------------------------------- #
# write_all / read_exact deadline loops
# --------------------------------------------------------------------------- #


def test_write_all_chunks_until_the_payload_is_flushed() -> None:
    transport = _bare_transport()
    written: list[bytes] = []

    def write_two(data: bytes, timeout: float) -> int:
        written.append(data[:2])
        return min(2, len(data))

    transport._write_once = write_two
    transport.write_all(b"abcdef", timeout=5.0)
    assert written == [b"ab", b"cd", b"ef"]


def test_write_all_times_out_before_any_io_when_the_deadline_passed() -> None:
    transport = _bare_transport()
    transport._write_once = lambda data, timeout: pytest.fail("must not reach I/O")
    with pytest.raises(TimeoutError, match="write timed out"):
        transport.write_all(b"x", timeout=0)


def test_write_all_rejects_a_zero_byte_write_as_a_broken_pipe() -> None:
    transport = _bare_transport()
    transport._write_once = lambda data, timeout: 0
    with pytest.raises(BrokenPipeError, match="no bytes"):
        transport.write_all(b"x", timeout=5.0)


def test_read_exact_reassembles_the_frame_from_partial_reads() -> None:
    transport = _bare_transport()
    chunks = [b"ab", b"cd"]
    transport._read_once = lambda size, timeout: chunks.pop(0)
    assert transport.read_exact(4, timeout=5.0) == b"abcd"


def test_read_exact_times_out_when_the_deadline_passed() -> None:
    transport = _bare_transport()
    transport._read_once = lambda size, timeout: pytest.fail("must not reach I/O")
    with pytest.raises(TimeoutError, match="read timed out"):
        transport.read_exact(4, timeout=0)


def test_read_exact_reports_a_peer_close_as_a_broken_pipe() -> None:
    transport = _bare_transport()
    transport._read_once = lambda size, timeout: b""
    with pytest.raises(BrokenPipeError, match="peer closed"):
        transport.read_exact(4, timeout=5.0)


# --------------------------------------------------------------------------- #
# _run_io overlapped state machine (via _read_once / _write_once)
# --------------------------------------------------------------------------- #


def _sync_kernel32() -> Any:
    """A kernel32 whose operations complete synchronously."""
    return types.SimpleNamespace(ResetEvent=lambda event: 1)


def test_read_once_returns_the_bytes_a_synchronous_read_produced() -> None:
    transport = _bare_transport(_sync_kernel32())

    def read_file(handle: Any, buffer: Any, size: int, transferred_ref: Any, ovl_ref: Any) -> int:
        buffer.value = b"ok"
        transferred_ref._obj.value = 2
        return 1

    transport._kernel32.ReadFile = read_file
    assert transport._read_once(8, 5.0) == b"ok"


def test_write_once_returns_the_synchronously_written_count() -> None:
    transport = _bare_transport(_sync_kernel32())

    def write_file(handle: Any, buffer: Any, size: int, transferred_ref: Any, ovl_ref: Any) -> int:
        transferred_ref._obj.value = size
        return 1

    transport._kernel32.WriteFile = write_file
    assert transport._write_once(b"abc", 5.0) == 3


def test_run_io_refuses_a_closed_transport() -> None:
    transport = _bare_transport(_sync_kernel32())
    transport._kernel32.ReadFile = lambda *args: pytest.fail("closed transport must not read")
    transport._closed = True
    with pytest.raises(BrokenPipeError, match="closed"):
        transport._read_once(4, 5.0)


def test_run_io_raises_when_the_failure_is_not_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_last_error(monkeypatch, [5])  # ERROR_ACCESS_DENIED
    transport = _bare_transport(_sync_kernel32())
    transport._kernel32.ReadFile = lambda *args: 0
    with pytest.raises(OSError, match="named-pipe I/O failed"):
        transport._read_once(4, 5.0)


def _pending_kernel32(
    *,
    wait_results: list[int],
    overlapped_ok: bool = True,
    transferred: int = 4,
) -> tuple[Any, list[str]]:
    calls: list[str] = []

    def wait(event: Any, wait_ms: int) -> int:
        calls.append("wait")
        return wait_results.pop(0)

    def overlapped_result(handle: Any, ovl_ref: Any, transferred_ref: Any, block: Any) -> int:
        calls.append("overlapped")
        if not overlapped_ok:
            return 0
        transferred_ref._obj.value = transferred
        return 1

    kernel32 = types.SimpleNamespace(
        ResetEvent=lambda event: 1,
        WaitForSingleObject=wait,
        GetOverlappedResult=overlapped_result,
        CancelIoEx=lambda handle, ovl_ref: calls.append("cancel"),
        ReadFile=lambda *args: 0,
    )
    return kernel32, calls


def test_run_io_completes_a_pending_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_last_error(monkeypatch, [_IO_PENDING])
    kernel32, calls = _pending_kernel32(wait_results=[_WAIT_OBJECT_0], transferred=0)
    transport = _bare_transport(kernel32)
    # transferred=0 keeps the assertion simple: the read returns no bytes.
    assert transport._read_once(4, 5.0) == b""
    assert calls == ["wait", "overlapped"]


def test_run_io_cancels_and_times_out_when_the_wait_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_last_error(monkeypatch, [_IO_PENDING])
    kernel32, calls = _pending_kernel32(wait_results=[_WAIT_TIMEOUT, _WAIT_OBJECT_0])
    transport = _bare_transport(kernel32)
    with pytest.raises(TimeoutError, match="timed out"):
        transport._read_once(4, 5.0)
    # The cancel is issued and then awaited so the buffer cannot be reused
    # while the kernel still owns it.
    assert calls == ["wait", "cancel", "wait"]


def test_run_io_raises_when_the_wait_itself_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_last_error(monkeypatch, [_IO_PENDING, 6])  # ERROR_INVALID_HANDLE
    kernel32, _calls = _pending_kernel32(wait_results=[0xFFFFFFFF])
    transport = _bare_transport(kernel32)
    with pytest.raises(OSError, match="WaitForSingleObject"):
        transport._read_once(4, 5.0)


def test_run_io_maps_an_aborted_overlapped_result_to_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_last_error(monkeypatch, [_IO_PENDING, _OPERATION_ABORTED])
    kernel32, _calls = _pending_kernel32(wait_results=[_WAIT_OBJECT_0], overlapped_ok=False)
    transport = _bare_transport(kernel32)
    with pytest.raises(TimeoutError, match="cancelled"):
        transport._read_once(4, 5.0)


def test_run_io_raises_when_the_overlapped_result_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_last_error(monkeypatch, [_IO_PENDING, 5])
    kernel32, _calls = _pending_kernel32(wait_results=[_WAIT_OBJECT_0], overlapped_ok=False)
    transport = _bare_transport(kernel32)
    with pytest.raises(OSError, match="GetOverlappedResult"):
        transport._read_once(4, 5.0)


def test_configure_api_declares_matching_read_write_signatures() -> None:
    class _Fn:
        argtypes: Any = None
        restype: Any = None

    names = (
        "CreateEventW",
        "ReadFile",
        "WriteFile",
        "GetOverlappedResult",
        "WaitForSingleObject",
        "ResetEvent",
        "CancelIoEx",
        "CloseHandle",
        "GetNamedPipeServerProcessId",
    )
    kernel32 = types.SimpleNamespace(**{name: _Fn() for name in names})
    transport = _bare_transport(kernel32)

    transport._configure_api()

    assert kernel32.WriteFile.argtypes == kernel32.ReadFile.argtypes
    for name in names:
        assert getattr(kernel32, name).restype is not None


# --------------------------------------------------------------------------- #
# XdbgClient.__init__
# --------------------------------------------------------------------------- #


class _InitFakeProcess:
    """Stands in for the spawned x64dbg process during construction."""

    def __init__(self, argv: list[str], **kwargs: Any) -> None:
        self.argv = argv
        self.kwargs = kwargs
        self.pid = 4242
        self.returncode: int | None = None
        self.stdin = io.StringIO()
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.returncode = 0
        return 0


def _init_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    capabilities: list[str] | None,
) -> tuple[Path, list[_InitFakeProcess]]:
    executable = tmp_path / "x64dbg.exe"
    executable.write_bytes(b"MZ fake")
    spawned: list[_InitFakeProcess] = []

    def fake_popen(argv: list[str], **kwargs: Any) -> _InitFakeProcess:
        process = _InitFakeProcess(argv, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(client_module, "detect_pe_architecture", lambda path: Architecture.X64)
    monkeypatch.setattr(client_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(client_module, "terminate_process_tree", lambda process, wait_s: None)
    monkeypatch.setattr(
        client_module._NamedPipeTransport,
        "connect",
        classmethod(
            lambda cls, pipe_name, *, timeout, process: FlexHandshake(
                server_pid=4242, hello_pid=4242, capabilities=capabilities
            )
        ),
    )
    return executable, spawned


def test_init_spawns_connects_and_publishes_capabilities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable, spawned = _init_environment(
        monkeypatch, tmp_path, capabilities=["events.read", "debug.state"]
    )

    client = XdbgClient(executable, Architecture.X64, startup_timeout=5.0)
    try:
        assert client.pid == 4242
        assert client.capabilities == frozenset({"events.read", "debug.state"})
        assert "desktop" in client.metadata
        process = spawned[0]
        assert "-userdir" in process.argv
        environment = process.kwargs["env"]
        assert environment["HEADLESS_RE_XDBG_RPC_PIPE"]
        assert environment["HEADLESS_RE_XDBG_RPC_TOKEN"]
    finally:
        client.terminate()
    assert client.exit_code is None or client._closed is True


def test_init_rejects_an_executable_of_the_wrong_architecture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "x32dbg.exe"
    executable.write_bytes(b"MZ fake")
    monkeypatch.setattr(client_module, "detect_pe_architecture", lambda path: Architecture.X86)

    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient(executable, Architecture.X64, startup_timeout=5.0)

    assert exc.value.code == "architecture_mismatch"
    assert exc.value.details["executable"] == str(executable.resolve())


def test_init_terminates_the_worker_when_the_hello_is_malformed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A hello without a capabilities array must kill the spawn, not leak it."""
    executable, spawned = _init_environment(monkeypatch, tmp_path, capabilities=None)
    killed: list[int] = []
    monkeypatch.setattr(
        client_module,
        "terminate_process_tree",
        lambda process, wait_s: killed.append(process.pid),
    )

    with pytest.raises(XdbgRpcError, match="capabilities must be an array"):
        XdbgClient(executable, Architecture.X64, startup_timeout=5.0)

    assert killed == [4242]


def test_init_uses_a_hidden_desktop_when_requested(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable, _spawned = _init_environment(monkeypatch, tmp_path, capabilities=["events.read"])
    assigned: list[int] = []

    class _FakeDesktop:
        @classmethod
        def create(cls, *, prefix: str) -> _FakeDesktop:
            return cls()

        def spawn(self, argv: list[str], **kwargs: Any) -> _InitFakeProcess:
            return _InitFakeProcess(argv, **kwargs)

        def snapshot(self, *, allowed_pids: frozenset[int] | None = None) -> JsonObject:
            return {"desktop": "hidden"}

        def process_window_descriptions(self, pid: int) -> list[str]:
            return []

        def close(self) -> None:
            pass

    class _FakeJob:
        @classmethod
        def create(cls) -> _FakeJob:
            return cls()

        def assign(self, pid: int) -> None:
            assigned.append(pid)

        def close(self) -> None:
            pass

    monkeypatch.setattr(client_module, "HiddenDesktop", _FakeDesktop)
    monkeypatch.setattr(client_module, "DesktopIsolationJob", _FakeJob)
    monkeypatch.setattr(client_module, "hide_input_desktop_windows_for_pids", lambda pids: None)

    client = XdbgClient(executable, Architecture.X64, startup_timeout=5.0, hidden_desktop=True)
    try:
        assert assigned == [4242]
        assert client.metadata["desktop"] == {"desktop": "hidden"}
    finally:
        client.terminate()


def test_init_tolerates_an_unavailable_isolation_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Job objects can be refused (nested containers); the desktop still works."""
    executable, _spawned = _init_environment(monkeypatch, tmp_path, capabilities=["events.read"])

    class _FakeDesktop:
        @classmethod
        def create(cls, *, prefix: str) -> _FakeDesktop:
            return cls()

        def spawn(self, argv: list[str], **kwargs: Any) -> _InitFakeProcess:
            return _InitFakeProcess(argv, **kwargs)

        def snapshot(self, *, allowed_pids: frozenset[int] | None = None) -> JsonObject:
            return {}

        def process_window_descriptions(self, pid: int) -> list[str]:
            return []

        def close(self) -> None:
            pass

    class _NoJob:
        @classmethod
        def create(cls) -> None:
            return None

    monkeypatch.setattr(client_module, "HiddenDesktop", _FakeDesktop)
    monkeypatch.setattr(client_module, "DesktopIsolationJob", _NoJob)
    monkeypatch.setattr(client_module, "hide_input_desktop_windows_for_pids", lambda pids: None)

    client = XdbgClient(executable, Architecture.X64, startup_timeout=5.0, hidden_desktop=True)
    try:
        assert client._isolation_job is None
    finally:
        client.terminate()
