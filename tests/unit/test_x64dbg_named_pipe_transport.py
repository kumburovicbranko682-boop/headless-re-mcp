"""Coverage for ``_NamedPipeTransport`` in the x64dbg RPC client.

The transport speaks straight to ``kernel32`` through ``ctypes.WinDLL`` with
overlapped I/O (CreateFile/WaitNamedPipe on connect; ReadFile/WriteFile plus
WaitForSingleObject/GetOverlappedResult/CancelIoEx per request), so on a Linux
runner the entire class is dark. This fake kernel32 lets the connect handshake,
the bounded read/write loops, and every overlapped-completion branch (immediate
completion, IO_PENDING, timeout-then-cancel, wait failure, aborted, error) run
without a real pipe.
"""

from __future__ import annotations

import ctypes
import os
import time
from collections import deque
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError, _NamedPipeTransport

_T = _NamedPipeTransport
_IO_PENDING = _T._ERROR_IO_PENDING
_FILE_NOT_FOUND = _T._ERROR_FILE_NOT_FOUND
_PIPE_BUSY = _T._ERROR_PIPE_BUSY
_ABORTED = _T._ERROR_OPERATION_ABORTED
_WAIT_OBJECT_0 = _T._WAIT_OBJECT_0
_WAIT_TIMEOUT = _T._WAIT_TIMEOUT
_INVALID = int(_T._INVALID_HANDLE_VALUE or 0)


class _Fn:
    """Callable that tolerates the argtypes/restype assignment the code does."""

    def __init__(self, fn: Any) -> None:
        self._fn = fn
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._fn(*args, **kwargs)


class FakeKernel32:
    def __init__(self) -> None:
        self.last_error = 0
        self.event_result = 0xE0E0
        self.closed: list[int] = []
        self.reset_count = 0
        self.cancel_count = 0
        self.wait_named_pipe: deque[tuple[int, int]] = deque()
        self.create_file: deque[tuple[int, int]] = deque()
        self.io: deque[dict[str, Any]] = deque()
        self.wait_single: deque[int] = deque()
        self.overlapped: deque[dict[str, Any]] = deque()
        self._pending_transferred = 0
        self.server_pid_ok = True
        self.server_pid_value = 4242
        binds = {
            "CreateEventW": self._create_event,
            "WaitNamedPipeW": self._wait_named_pipe,
            "CreateFileW": self._create_file,
            "ReadFile": self._io_op,
            "WriteFile": self._io_op,
            "GetOverlappedResult": self._get_overlapped,
            "WaitForSingleObject": self._wait_for_single,
            "ResetEvent": self._reset_event,
            "CancelIoEx": self._cancel_io,
            "CloseHandle": self._close_handle,
            "GetNamedPipeServerProcessId": self._get_server_pid,
        }
        for name, fn in binds.items():
            setattr(self, name, _Fn(fn))

    def _create_event(self, *_a: Any) -> int:
        if not self.event_result:
            self.last_error = 6
        return self.event_result

    def _wait_named_pipe(self, _name: Any, _ms: int) -> int:
        ret, err = self.wait_named_pipe.popleft()
        self.last_error = err
        return ret

    def _create_file(self, *_a: Any) -> int:
        handle, err = self.create_file.popleft()
        self.last_error = err
        return handle

    def _io_op(self, _handle: Any, buffer: Any, size: int, p_transferred: Any, _p_ov: Any) -> int:
        beh = self.io.popleft()
        payload = beh.get("payload")
        transferred = beh.get("transferred")
        if payload is not None:
            ctypes.memmove(buffer, payload, len(payload))
            transferred = len(payload)
        if beh["mode"] == "immediate":
            p_transferred._obj.value = int(transferred or 0)
            return 1
        # pending / error: the synchronous call "fails"; caller inspects errno.
        self.last_error = beh.get("error", _IO_PENDING)
        self._pending_transferred = int(transferred or 0)
        return 0

    def _get_overlapped(self, _handle: Any, _p_ov: Any, p_transferred: Any, _wait: Any) -> int:
        beh = self.overlapped.popleft()
        if beh["ok"]:
            p_transferred._obj.value = int(beh.get("transferred", self._pending_transferred))
            return 1
        self.last_error = beh.get("error", 0)
        return 0

    def _wait_for_single(self, _handle: Any, _ms: int) -> int:
        return self.wait_single.popleft()

    def _reset_event(self, _handle: Any) -> int:
        self.reset_count += 1
        return 1

    def _cancel_io(self, _handle: Any, _ov: Any) -> int:
        self.cancel_count += 1
        return 1

    def _close_handle(self, handle: Any) -> int:
        self.closed.append(int(handle) if handle is not None else 0)
        return 1

    def _get_server_pid(self, _handle: Any, p_pid: Any) -> int:
        if not self.server_pid_ok:
            self.last_error = 87
            return 0
        p_pid._obj.value = self.server_pid_value
        return 1


class _FakeProcess:
    def __init__(self, *, poll_value: Any = None, returncode: int = 0) -> None:
        self._poll_value = poll_value
        self.returncode = returncode

    def poll(self) -> Any:
        return self._poll_value


def _fake_process(*, poll_value: Any = None, returncode: int = 0) -> Any:
    return _FakeProcess(poll_value=poll_value, returncode=returncode)


def _wire(monkeypatch: pytest.MonkeyPatch, kernel32: FakeKernel32) -> None:
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: kernel32, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: kernel32.last_error, raising=False)


def _build(monkeypatch: pytest.MonkeyPatch, kernel32: FakeKernel32, *, handle: int = 0x100) -> _T:
    _wire(monkeypatch, kernel32)
    return _NamedPipeTransport(handle, r"\\.\pipe\headless-test")


# ---------------------------------------------------------------------------
# __init__


def test_init_creates_event(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    transport = _build(monkeypatch, kernel32, handle=0x111)
    assert transport._event == 0xE0E0
    assert transport._closed is False


def test_init_raises_when_event_creation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.event_result = 0  # CreateEventW fails
    _wire(monkeypatch, kernel32)
    with pytest.raises(OSError):
        _NamedPipeTransport(0x222, r"\\.\pipe\x")
    assert 0x222 in kernel32.closed  # the pipe handle was released


# ---------------------------------------------------------------------------
# connect


def test_connect_refuses_off_windows() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _NamedPipeTransport.connect(
            r"\\.\pipe\x", timeout=1.0, process=_fake_process(poll_value=None)
        )
    assert exc.value.code == "unsupported_on_platform"


def test_connect_reports_worker_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    kernel32 = FakeKernel32()
    _wire(monkeypatch, kernel32)
    with pytest.raises(XdbgRpcError) as exc:
        _NamedPipeTransport.connect(
            r"\\.\pipe\x", timeout=5.0, process=_fake_process(poll_value=1, returncode=3)
        )
    assert exc.value.code == "worker_exited"


def test_connect_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    kernel32 = FakeKernel32()
    _wire(monkeypatch, kernel32)
    with pytest.raises(XdbgRpcError) as exc:
        _NamedPipeTransport.connect(
            r"\\.\pipe\x", timeout=0.0, process=_fake_process(poll_value=None)
        )
    assert exc.value.code == "rpc_startup_timeout"


def test_connect_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    kernel32 = FakeKernel32()
    # First wait says "not there yet" (retry), then it is ready; the file opens.
    kernel32.wait_named_pipe.extend([(0, _FILE_NOT_FOUND), (1, 0)])
    kernel32.create_file.append((0x900, 0))
    _wire(monkeypatch, kernel32)
    transport = _NamedPipeTransport.connect(
        r"\\.\pipe\x", timeout=5.0, process=_fake_process(poll_value=None)
    )
    assert isinstance(transport, _NamedPipeTransport)
    assert transport._handle == 0x900


def test_connect_wait_named_pipe_hard_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    kernel32 = FakeKernel32()
    kernel32.wait_named_pipe.append((0, 999))  # not a retryable errno
    _wire(monkeypatch, kernel32)
    with pytest.raises(OSError):
        _NamedPipeTransport.connect(
            r"\\.\pipe\x", timeout=5.0, process=_fake_process(poll_value=None)
        )


def test_connect_create_file_busy_then_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    kernel32 = FakeKernel32()
    kernel32.wait_named_pipe.extend([(1, 0), (1, 0)])
    # First open is busy (retry the whole loop), then it succeeds.
    kernel32.create_file.extend([(_INVALID, _PIPE_BUSY), (0xABC, 0)])
    _wire(monkeypatch, kernel32)
    transport = _NamedPipeTransport.connect(
        r"\\.\pipe\x", timeout=5.0, process=_fake_process(poll_value=None)
    )
    assert transport._handle == 0xABC


def test_connect_create_file_hard_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    kernel32 = FakeKernel32()
    kernel32.wait_named_pipe.append((1, 0))
    kernel32.create_file.append((_INVALID, 5))  # access denied, not retryable
    _wire(monkeypatch, kernel32)
    with pytest.raises(OSError):
        _NamedPipeTransport.connect(
            r"\\.\pipe\x", timeout=5.0, process=_fake_process(poll_value=None)
        )


# ---------------------------------------------------------------------------
# server_pid


def test_server_pid_returns_value(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.server_pid_value = 7788
    transport = _build(monkeypatch, kernel32)
    assert transport.server_pid == 7788


def test_server_pid_raises_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.server_pid_ok = False
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(OSError):
        _ = transport.server_pid


# ---------------------------------------------------------------------------
# _run_io via _read_once / _write_once


def test_read_once_immediate(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "immediate", "payload": b"hello"})
    transport = _build(monkeypatch, kernel32)
    assert transport._read_once(16, timeout=1.0) == b"hello"
    assert kernel32.reset_count == 1


def test_write_once_immediate(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "immediate", "transferred": 4})
    transport = _build(monkeypatch, kernel32)
    assert transport._write_once(b"data", timeout=1.0) == 4


def test_run_io_refuses_when_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    transport = _build(monkeypatch, kernel32)
    transport.close()
    with pytest.raises(BrokenPipeError):
        transport._read_once(4, timeout=1.0)


def test_run_io_synchronous_error(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "error", "error": 5})  # not IO_PENDING
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(OSError):
        transport._read_once(4, timeout=1.0)


def test_run_io_pending_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "pending", "payload": b"abcd"})
    kernel32.wait_single.append(_WAIT_OBJECT_0)
    kernel32.overlapped.append({"ok": True})
    transport = _build(monkeypatch, kernel32)
    assert transport._read_once(8, timeout=1.0) == b"abcd"


def test_run_io_pending_times_out_and_cancels(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "pending", "payload": b"x"})
    kernel32.wait_single.extend([_WAIT_TIMEOUT, _WAIT_OBJECT_0])  # main wait + post-cancel wait
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(TimeoutError):
        transport._read_once(4, timeout=0.01)
    assert kernel32.cancel_count == 1


def test_run_io_pending_wait_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "pending", "payload": b"x"})
    kernel32.wait_single.append(0xFFFFFFFF)  # neither signalled nor timeout
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(OSError):
        transport._read_once(4, timeout=1.0)


def test_run_io_overlapped_aborted_is_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "pending", "payload": b"x"})
    kernel32.wait_single.append(_WAIT_OBJECT_0)
    kernel32.overlapped.append({"ok": False, "error": _ABORTED})
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(TimeoutError):
        transport._read_once(4, timeout=1.0)


def test_run_io_overlapped_other_error(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "pending", "payload": b"x"})
    kernel32.wait_single.append(_WAIT_OBJECT_0)
    kernel32.overlapped.append({"ok": False, "error": 6})
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(OSError):
        transport._read_once(4, timeout=1.0)


# ---------------------------------------------------------------------------
# write_all / read_exact loops


def test_write_all_sends_in_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.extend(
        [
            {"mode": "immediate", "transferred": 3},
            {"mode": "immediate", "transferred": 2},
        ]
    )
    transport = _build(monkeypatch, kernel32)
    transport.write_all(b"hello", timeout=1.0)  # 3 + 2 = 5 bytes
    assert not kernel32.io  # both writes consumed


def test_write_all_raises_on_zero_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "immediate", "transferred": 0})
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(BrokenPipeError):
        transport.write_all(b"data", timeout=1.0)


def test_write_all_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(TimeoutError):
        transport.write_all(b"data", timeout=-1.0)


def test_read_exact_reassembles(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.extend(
        [
            {"mode": "immediate", "payload": b"ab"},
            {"mode": "immediate", "payload": b"cd"},
        ]
    )
    transport = _build(monkeypatch, kernel32)
    assert transport.read_exact(4, timeout=1.0) == b"abcd"


def test_read_exact_raises_on_peer_close(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    kernel32.io.append({"mode": "immediate", "transferred": 0})  # empty read
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(BrokenPipeError):
        transport.read_exact(4, timeout=1.0)


def test_read_exact_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    transport = _build(monkeypatch, kernel32)
    with pytest.raises(TimeoutError):
        transport.read_exact(4, timeout=-1.0)


# ---------------------------------------------------------------------------
# close


def test_close_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = FakeKernel32()
    transport = _build(monkeypatch, kernel32, handle=0x555)
    transport.close()
    transport.close()  # second call is a no-op
    # event + handle each closed exactly once.
    assert kernel32.closed.count(0x555) == 1
    assert kernel32.closed.count(0xE0E0) == 1
    assert kernel32.cancel_count == 1
