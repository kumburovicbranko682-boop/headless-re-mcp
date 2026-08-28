"""Win32 hidden-desktop lifecycle, process launch, and enumeration.

``core.hidden_desktop`` owns a CreateProcessW wrapper (so the x64dbg worker can
be pinned to a non-input desktop via ``STARTUPINFO.lpDesktop``) plus the desktop
create/close/enumerate lifecycle. All of it speaks straight to user32/kernel32,
so off Windows the module was ~18% covered. These tests fake the two DLL
handles (patching ``_api``), stub the ``ctypes`` last-error/WinError shims that
only exist on Windows, inject a fake ``msvcrt`` for the spawn path, and drive the
enumeration callback through a real ``ctypes.byref`` so the pointer writes run.
"""

from __future__ import annotations

import ctypes
import io
import os
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest

import headless_re_mcp.core.hidden_desktop as hd
from headless_re_mcp.core.hidden_desktop import (
    DesktopProcess,
    HiddenDesktop,
    HiddenDesktopError,
)

_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF


def _stub_winerr(monkeypatch: pytest.MonkeyPatch, errno: int = 5) -> None:
    """Provide the Windows-only ctypes error shims the module reaches for."""
    monkeypatch.setattr(ctypes, "get_last_error", lambda: errno, raising=False)
    monkeypatch.setattr(ctypes, "set_last_error", lambda _e=0: None, raising=False)
    monkeypatch.setattr(
        ctypes, "WinError", lambda err=None, descr=None: OSError(f"WinError {err}"), raising=False
    )


def _identity_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hd, "wnd_enum_callback_type", lambda: lambda cb: cb)


# ---------------------------------------------------------------------------
# _require_windows / _api


def test_require_windows_refuses_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(HiddenDesktopError, match="require Windows"):
        hd._require_windows()


class _Fn:
    """A Win32 function stub tolerant of argtypes/restype assignment."""

    def __init__(self) -> None:
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *_a: Any, **_k: Any) -> int:
        return 0


class _AutoDLL:
    def __getattr__(self, name: str) -> Any:
        fn = _Fn()
        object.__setattr__(self, name, fn)
        return fn


def test_api_configures_both_dlls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda _name, **_k: _AutoDLL(), raising=False)
    user32, kernel32 = hd._api()
    assert isinstance(user32, _AutoDLL)
    assert isinstance(kernel32, _AutoDLL)
    # argtypes assignment stuck, proving each function object was configured.
    assert user32.CreateDesktopW.restype is ctypes.c_void_p


# ---------------------------------------------------------------------------
# _desktop_name


class _NameUser32:
    def __init__(
        self, name: str, *, required: int | None = None, fail_second: bool = False
    ) -> None:
        self._name = name
        default_required = (len(name) + 1) * ctypes.sizeof(ctypes.c_wchar)
        self._required = default_required if required is None else required
        self._calls = 0
        self._fail_second = fail_second

    def GetUserObjectInformationW(
        self, _handle: Any, _index: int, pbuf: Any, _nbytes: int, preq: Any
    ) -> int:
        self._calls += 1
        if self._calls == 1:
            preq._obj.value = self._required
            return 1
        if self._fail_second:
            return 0
        pbuf.value = self._name
        return 1


def test_desktop_name_returns_empty_when_size_is_zero() -> None:
    user32 = _NameUser32("ignored", required=0)
    assert hd._desktop_name(user32, 1) == ""


def test_desktop_name_reads_the_object_name() -> None:
    user32 = _NameUser32("HeadlessRE-abc")
    assert hd._desktop_name(user32, 1) == "HeadlessRE-abc"


def test_desktop_name_raises_when_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    user32 = _NameUser32("x", fail_second=True)
    with pytest.raises(OSError, match="WinError"):
        hd._desktop_name(user32, 1)


# ---------------------------------------------------------------------------
# _environment_block


def test_environment_block_sorts_and_null_terminates() -> None:
    buffer = hd._environment_block({"Beta": "2", "alpha": "1"})
    block = cast(str, buffer[:])
    entries = block.split("\x00")
    # casefold sort keeps alpha before Beta; block ends with a double NUL.
    assert entries[0] == "alpha=1"
    assert entries[1] == "Beta=2"
    assert block.endswith("\x00\x00")


# ---------------------------------------------------------------------------
# DesktopProcess


class _ProcKernel32:
    def __init__(
        self,
        *,
        wait_result: int = _WAIT_OBJECT_0,
        exit_code: int = 0,
        exit_ok: int = 1,
        terminate_ok: int = 1,
    ) -> None:
        self.wait_result = wait_result
        self.exit_code = exit_code
        self.exit_ok = exit_ok
        self.terminate_ok = terminate_ok
        self.closed: list[Any] = []
        self.terminated: list[Any] = []

    def WaitForSingleObject(self, _handle: Any, _ms: int) -> int:
        return self.wait_result

    def GetExitCodeProcess(self, _handle: Any, lp: Any) -> int:
        lp._obj.value = self.exit_code
        return self.exit_ok

    def CloseHandle(self, handle: Any) -> int:
        self.closed.append(handle)
        return 1

    def TerminateProcess(self, handle: Any, code: int) -> int:
        self.terminated.append((handle, code))
        return self.terminate_ok


def _make_proc(handle: int = 111) -> DesktopProcess:
    return DesktopProcess(
        args=["worker"],
        process_handle=handle,
        pid=222,
        stdin=io.StringIO(),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


def _patch_kernel(monkeypatch: pytest.MonkeyPatch, kernel32: _ProcKernel32) -> None:
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel32))


def test_poll_returns_cached_returncode() -> None:
    proc = _make_proc()
    proc.returncode = 9
    assert proc.poll() == 9


def test_poll_finalises_on_signalled_process(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = _ProcKernel32(wait_result=_WAIT_OBJECT_0, exit_code=3)
    _patch_kernel(monkeypatch, kernel32)
    proc = _make_proc(handle=111)
    assert proc.poll() == 3
    assert proc.returncode == 3
    assert kernel32.closed  # handle closed exactly once
    # A second close is a no-op (handle already released).
    proc._close_handle()
    assert len(kernel32.closed) == 1


def test_poll_raises_on_wait_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    _patch_kernel(monkeypatch, _ProcKernel32(wait_result=_WAIT_FAILED))
    with pytest.raises(OSError, match="WinError"):
        _make_proc().poll()


def test_poll_returns_none_while_running(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_kernel(monkeypatch, _ProcKernel32(wait_result=_WAIT_TIMEOUT))
    assert _make_proc().poll() is None


def test_exit_code_raises_when_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    _patch_kernel(monkeypatch, _ProcKernel32(wait_result=_WAIT_OBJECT_0, exit_ok=0))
    with pytest.raises(OSError, match="WinError"):
        _make_proc().poll()


def test_wait_returns_cached_returncode() -> None:
    proc = _make_proc()
    proc.returncode = 4
    assert proc.wait(timeout=1.0) == 4


def test_wait_blocks_until_exit_without_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = _ProcKernel32(wait_result=_WAIT_OBJECT_0, exit_code=5)
    _patch_kernel(monkeypatch, kernel32)
    assert _make_proc().wait() == 5
    assert kernel32.closed


def test_wait_clamps_a_finite_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_kernel(monkeypatch, _ProcKernel32(wait_result=_WAIT_OBJECT_0, exit_code=0))
    assert _make_proc().wait(timeout=1.5) == 0


def test_wait_raises_timeout_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_kernel(monkeypatch, _ProcKernel32(wait_result=_WAIT_TIMEOUT))
    with pytest.raises(subprocess.TimeoutExpired):
        _make_proc().wait(timeout=0.5)


def test_wait_raises_on_wait_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    _patch_kernel(monkeypatch, _ProcKernel32(wait_result=_WAIT_FAILED))
    with pytest.raises(OSError, match="WinError"):
        _make_proc().wait()


def test_terminate_is_a_noop_once_exited(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = _ProcKernel32()
    _patch_kernel(monkeypatch, kernel32)
    proc = _make_proc()
    proc.returncode = 0  # poll() returns immediately -> terminate returns early
    proc.terminate()
    assert kernel32.terminated == []


def test_terminate_kills_a_running_process(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = _ProcKernel32(wait_result=_WAIT_TIMEOUT)  # poll() -> None (running)
    _patch_kernel(monkeypatch, kernel32)
    _make_proc(handle=321).kill()  # kill delegates to terminate
    assert kernel32.terminated and kernel32.terminated[0][1] == 1


def test_terminate_raises_when_kernel_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    _patch_kernel(monkeypatch, _ProcKernel32(wait_result=_WAIT_TIMEOUT, terminate_ok=0))
    with pytest.raises(OSError, match="WinError"):
        _make_proc().terminate()


# ---------------------------------------------------------------------------
# _text_stream


def test_text_stream_roundtrips_a_pipe() -> None:
    read_fd, write_fd = os.pipe()
    writer = hd._text_stream(write_fd, "wb", encoding="utf-8", errors="replace")
    reader = hd._text_stream(read_fd, "rb", encoding="utf-8", errors="replace")
    try:
        writer.write("ping")
        writer.flush()
        writer.close()
        assert reader.readline() == "ping"
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# create_process_on_desktop


class _SpawnKernel32:
    def __init__(self, *, ok: bool = True, handle: int = 555, pid: int = 666) -> None:
        self.ok = ok
        self.handle = handle
        self.pid = pid
        self.closed: list[Any] = []

    def CreateProcessW(
        self,
        _app: Any,
        _cmd: Any,
        _pa: Any,
        _ta: Any,
        _inherit: Any,
        _flags: int,
        _env: Any,
        _cwd: Any,
        _si_ref: Any,
        pi_ref: Any,
    ) -> int:
        if self.ok:
            info = pi_ref._obj
            info.hProcess = self.handle
            info.hThread = 777
            info.dwProcessId = self.pid
        return 1 if self.ok else 0

    def CloseHandle(self, handle: Any) -> int:
        self.closed.append(handle)
        return 1


def _inject_msvcrt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=lambda fd: fd))


def test_create_process_rejects_empty_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _inject_msvcrt(monkeypatch)
    with pytest.raises(ValueError, match="must not be empty"):
        hd.create_process_on_desktop([], r"WinSta0\Desk")


def test_create_process_launches_a_redirected_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _inject_msvcrt(monkeypatch)
    kernel32 = _SpawnKernel32(ok=True, handle=555, pid=666)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel32))
    proc = hd.create_process_on_desktop(
        ["worker.exe", "--flag"],
        r"WinSta0\Desk",
        environment={"A": "1"},
    )
    try:
        assert proc.pid == 666
        assert proc.args == ["worker.exe", "--flag"]
        assert 777 in kernel32.closed  # the thread handle is closed immediately
    finally:
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()


def test_create_process_cleans_up_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _inject_msvcrt(monkeypatch)
    _stub_winerr(monkeypatch)
    monkeypatch.setattr(hd, "_api", lambda: (None, _SpawnKernel32(ok=False)))
    opened: list[int] = []
    real_pipe = os.pipe

    def tracking_pipe() -> tuple[int, int]:
        read_fd, write_fd = real_pipe()
        opened.extend((read_fd, write_fd))
        return read_fd, write_fd

    monkeypatch.setattr(os, "pipe", tracking_pipe)
    with pytest.raises(OSError, match="WinError"):
        hd.create_process_on_desktop(["worker.exe"], r"WinSta0\Desk", cwd="/tmp")
    # Every pipe fd opened by the failed launch was closed by the guard.
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)


# ---------------------------------------------------------------------------
# HiddenDesktop lifecycle


class _CreateUser32:
    def __init__(self, *, handle: int = 999, close_ok: bool = True) -> None:
        self.handle = handle
        self.close_ok = close_ok
        self.closed: list[Any] = []
        self.created_name: str | None = None

    def CreateDesktopW(self, name: str, *_rest: Any) -> int:
        self.created_name = name
        return self.handle

    def CloseDesktop(self, handle: Any) -> int:
        self.closed.append(handle)
        return 1 if self.close_ok else 0


def test_create_rounds_trips_the_desktop_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _CreateUser32(handle=999)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    monkeypatch.setattr(hd, "_desktop_name", lambda u, _h: u.created_name)
    desktop = HiddenDesktop.create(prefix="HeadlessRE-Test")
    assert desktop.name.startswith("HeadlessRE-Test-")
    assert desktop.qualified_name == rf"WinSta0\{desktop.name}"


def test_create_raises_when_the_handle_is_null(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    monkeypatch.setattr(hd, "_api", lambda: (_CreateUser32(handle=0), None))
    with pytest.raises(OSError, match="WinError"):
        HiddenDesktop.create()


def test_create_refuses_a_mismatched_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _CreateUser32(handle=999)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    monkeypatch.setattr(hd, "_desktop_name", lambda _u, _h: "unexpected-name")
    with pytest.raises(HiddenDesktopError, match="did not round-trip"):
        HiddenDesktop.create()
    assert user32.closed  # the mis-created desktop handle is released


def test_spawn_refuses_a_closed_desktop() -> None:
    desktop = HiddenDesktop("Desk", 1)
    desktop._closed = True
    with pytest.raises(HiddenDesktopError, match="desktop is closed"):
        desktop.spawn(["x"])


def test_spawn_delegates_to_create_process(monkeypatch: pytest.MonkeyPatch) -> None:
    desktop = HiddenDesktop("Desk", 1)
    seen: dict[str, Any] = {}

    def fake_create(args: Any, desk: str, **kwargs: Any) -> str:
        seen["args"] = list(args)
        seen["desktop"] = desk
        seen["kwargs"] = kwargs
        return "child"

    monkeypatch.setattr(hd, "create_process_on_desktop", fake_create)
    result: Any = desktop.spawn(["a", "b"], cwd="/tmp")
    assert result == "child"
    assert seen["desktop"] == r"WinSta0\Desk"
    assert seen["args"] == ["a", "b"]
    assert seen["kwargs"]["cwd"] == "/tmp"


# ---------------------------------------------------------------------------
# _enumerate_windows / windows / snapshot / process_window_descriptions


class _EnumUser32:
    def __init__(self, windows: list[dict[str, Any]], *, enum_result: int = 1) -> None:
        self._by = {int(w["hwnd"]): w for w in windows}
        self._order = [int(w["hwnd"]) for w in windows]
        self.enum_result = enum_result

    def EnumDesktopWindows(self, _handle: Any, callback: Any, _lparam: Any) -> int:
        for hwnd in self._order:
            callback(hwnd, None)
        return self.enum_result

    def GetWindowThreadProcessId(self, hwnd: int, lp: Any) -> int:
        lp._obj.value = int(self._by[int(hwnd)]["pid"])
        return 4

    def GetWindowTextLengthW(self, hwnd: int) -> int:
        return len(str(self._by[int(hwnd)].get("title", "")))

    def GetWindowTextW(self, hwnd: int, buf: Any, _n: int) -> int:
        buf.value = str(self._by[int(hwnd)].get("title", ""))
        return len(buf.value)

    def GetClassNameW(self, hwnd: int, buf: Any, _n: int) -> int:
        buf.value = str(self._by[int(hwnd)].get("class_name", ""))
        return len(buf.value)

    def GetWindowRect(self, hwnd: int, lp: Any) -> int:
        left, top, right, bottom = self._by[int(hwnd)].get("rect", (0, 0, 0, 0))
        rect = lp._obj
        rect.left, rect.top, rect.right, rect.bottom = left, top, right, bottom
        return 1

    def IsWindowVisible(self, hwnd: int) -> int:
        return 1 if self._by[int(hwnd)].get("visible") else 0

    def IsWindowEnabled(self, hwnd: int) -> int:
        return 1 if self._by[int(hwnd)].get("enabled", True) else 0

    def IsIconic(self, hwnd: int) -> int:
        return 1 if self._by[int(hwnd)].get("minimized") else 0


_SAMPLE_WINDOWS = [
    {
        "hwnd": 0x10,
        "pid": 7,
        "title": "Main",
        "class_name": "Win",
        "visible": True,
        "enabled": True,
        "minimized": False,
        "rect": (0, 0, 100, 50),
    },
    {
        "hwnd": 0x20,
        "pid": 9,
        "title": "Other",
        "class_name": "Aux",
        "visible": False,
        "enabled": True,
        "minimized": False,
        "rect": (0, 0, 10, 10),
    },
]


def test_enumerate_windows_returns_empty_when_closed() -> None:
    desktop = HiddenDesktop("Desk", 1)
    desktop._closed = True
    assert desktop._enumerate_windows() == []


def test_enumerate_windows_builds_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    _identity_callback(monkeypatch)
    monkeypatch.setattr(hd, "_api", lambda: (_EnumUser32(_SAMPLE_WINDOWS), None))
    rows = HiddenDesktop("Desk", 1)._enumerate_windows()
    assert [row["hwnd"] for row in rows] == [0x10, 0x20]
    assert rows[0]["title"] == "Main"
    assert rows[0]["rect"]["width"] == 100
    assert rows[0]["area"] == 100 * 50


def test_enumerate_windows_raises_on_enum_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch, errno=1400)
    _identity_callback(monkeypatch)
    monkeypatch.setattr(hd, "_api", lambda: (_EnumUser32([], enum_result=0), None))
    with pytest.raises(OSError, match="WinError"):
        HiddenDesktop("Desk", 1)._enumerate_windows()


def test_enumerate_windows_tolerates_falsy_return_without_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_winerr(monkeypatch, errno=0)
    _identity_callback(monkeypatch)
    monkeypatch.setattr(hd, "_api", lambda: (_EnumUser32(_SAMPLE_WINDOWS, enum_result=0), None))
    rows = HiddenDesktop("Desk", 1)._enumerate_windows()
    assert [row["hwnd"] for row in rows] == [0x10, 0x20]


def test_windows_filters_by_allowed_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HiddenDesktop, "_enumerate_windows", lambda self: list(_SAMPLE_WINDOWS))
    desktop = HiddenDesktop("Desk", 1)
    assert [row["hwnd"] for row in desktop.windows()] == [0x10, 0x20]
    bounded = desktop.windows(allowed_pids=frozenset({7}))
    assert [row["hwnd"] for row in bounded] == [0x10]


def test_process_window_descriptions_formats_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HiddenDesktop, "_enumerate_windows", lambda self: list(_SAMPLE_WINDOWS))
    descriptions = HiddenDesktop("Desk", 1).process_window_descriptions(7)
    assert descriptions == ["Win:Main (hwnd=16)"]


def test_snapshot_sorts_and_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HiddenDesktop, "_enumerate_windows", lambda self: list(_SAMPLE_WINDOWS))
    snapshot = HiddenDesktop("Desk", 1).snapshot()
    assert snapshot["available"] is True
    assert snapshot["mode"] == "hidden_win32"
    assert snapshot["window_count"] == 2
    assert snapshot["desktop_window_count"] == 2
    # The capturable, larger window ranks ahead of the hidden 10x10 one.
    assert snapshot["windows"][0]["hwnd"] == 0x10

    bounded = HiddenDesktop("Desk", 1).snapshot(allowed_pids=frozenset({9}))
    assert bounded["window_count"] == 1
    assert bounded["windows"][0]["hwnd"] == 0x20


# ---------------------------------------------------------------------------
# capture / close / context manager


def test_capture_refuses_a_foreign_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HiddenDesktop, "_enumerate_windows", lambda self: [{"hwnd": 10, "pid": 7}])
    with pytest.raises(HiddenDesktopError, match="not on the authorized"):
        HiddenDesktop("Desk", 1).capture(999, allowed_pids=frozenset({7}), output_path="/tmp/x.png")


def test_capture_delegates_to_screenshot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HiddenDesktop, "_enumerate_windows", lambda self: [{"hwnd": 10, "pid": 7}])
    import headless_re_mcp.core.ui_win32 as uiwin

    monkeypatch.setattr(
        uiwin, "capture_hwnd_screenshot", lambda hwnd, pids, out: {"ok": True, "hwnd": hwnd}
    )
    result = HiddenDesktop("Desk", 1).capture(
        10, allowed_pids=frozenset({7}), output_path="/tmp/x.png"
    )
    assert result == {"ok": True, "hwnd": 10}


def test_close_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _CreateUser32()
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    desktop = HiddenDesktop("Desk", 42)
    desktop.close()
    assert user32.closed  # released once
    desktop.close()  # second close short-circuits
    assert len(user32.closed) == 1


def test_close_raises_when_the_desktop_will_not_release(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_winerr(monkeypatch)
    monkeypatch.setattr(hd, "_api", lambda: (_CreateUser32(close_ok=False), None))
    with pytest.raises(OSError, match="WinError"):
        HiddenDesktop("Desk", 42).close()


def test_context_manager_closes_on_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _CreateUser32()
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    with HiddenDesktop("Desk", 42) as desktop:
        assert isinstance(desktop, HiddenDesktop)
    assert user32.closed
