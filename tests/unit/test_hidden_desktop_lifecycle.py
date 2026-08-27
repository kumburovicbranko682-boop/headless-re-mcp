"""Cross-platform coverage for the Win32 hidden-desktop lifecycle.

``core.hidden_desktop`` owns an isolated (non-input) Win32 desktop, a
``CreateProcessW`` wrapper that pins ``STARTUPINFO.lpDesktop``, and bounded
passive window inspection. Everything Windows-specific funnels through
``_api()`` (a ``WinDLL`` pair), ``os.name``, ``msvcrt``, and the
``ctypes.WinError`` / ``get_last_error`` / ``set_last_error`` helpers -- none of
which exist on a POSIX ctypes. They are faked so the real logic runs here:

* ``os`` is proxied with ``name`` pinned.
* an autouse ``ctypes`` shim supplies the three Windows-only helpers and a
  scriptable ``WinDLL``, forwarding everything else (``Structure``, ``byref``,
  ``cast``, ``create_unicode_buffer`` ...) to the real module.
* ``_api`` is replaced with scripted ``user32`` / ``kernel32`` doubles.
* the enumeration callback factory is made an identity wrapper, so the Python
  callback is invoked directly rather than through a ctypes trampoline.

Byref write-backs rely on ``ctypes.byref(x)._obj is x`` (verified on CPython).
"""

from __future__ import annotations

import ctypes
import os
import sys
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

import headless_re_mcp.core.hidden_desktop as hd

_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF


class _OsProxy:
    """``os`` with ``name`` pinned and optional per-test overrides; rest forwarded."""

    def __init__(self, name: str = "nt", **overrides: Any) -> None:
        self.name = name
        self._overrides = overrides

    def __getattr__(self, attribute: str) -> Any:
        if attribute != "_overrides" and attribute in self._overrides:
            return self._overrides[attribute]
        return getattr(os, attribute)


class _CtypesShim:
    """Real ctypes plus the Windows-only helpers a POSIX build lacks."""

    def __init__(self) -> None:
        self.forced_last_error = 0
        self.windll_map: dict[str, Any] = {}
        self.set_errors: list[int] = []

    def WinError(self, code: int | None = 0) -> OSError:  # noqa: N802
        return OSError(code or 0, "winerror")

    def get_last_error(self) -> int:
        return self.forced_last_error

    def set_last_error(self, code: int) -> None:
        self.set_errors.append(int(code))

    def WinDLL(self, name: str, *args: Any, **kwargs: Any) -> Any:  # noqa: N802
        return self.windll_map[name]

    def __getattr__(self, attribute: str) -> Any:
        return getattr(ctypes, attribute)


@pytest.fixture(autouse=True)
def _ctypes_shim(monkeypatch: pytest.MonkeyPatch) -> _CtypesShim:
    shim = _CtypesShim()
    monkeypatch.setattr(hd, "ctypes", shim)
    return shim


def _pin_nt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hd, "os", _OsProxy("nt"))


def _pin_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hd, "os", _OsProxy("posix"))


# ---------------------------------------------------------------------------
# _require_windows / _environment_block / _text_stream
# ---------------------------------------------------------------------------


def test_require_windows_refuses_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_posix(monkeypatch)
    with pytest.raises(hd.HiddenDesktopError):
        hd._require_windows()


def test_environment_block_is_sorted_and_double_null_terminated() -> None:
    buf = hd._environment_block({"PATH": "/x", "aaa": "1", "Beta": "2"})
    text = cast(str, buf[:])  # full backing buffer including trailing NULs
    assert text.endswith("\0\0")
    entries = text.rstrip("\0").split("\0")
    # Case-insensitive sort: aaa, Beta, PATH.
    assert entries == ["aaa=1", "Beta=2", "PATH=/x"]


def test_text_stream_round_trips_over_a_real_pipe() -> None:
    read_fd, write_fd = os.pipe()
    writer = hd._text_stream(write_fd, "wb", encoding="utf-8", errors="replace")
    reader = hd._text_stream(read_fd, "rb", encoding="utf-8", errors="replace")
    try:
        writer.write("héllo\n")
        writer.flush()
        assert reader.readline() == "héllo\n"
    finally:
        writer.close()
        reader.close()


# ---------------------------------------------------------------------------
# _api builds the DLL surface (through the shim's WinDLL)
# ---------------------------------------------------------------------------


def _blank_dll() -> Any:
    """A namespace whose attributes accept ``.argtypes`` / ``.restype`` writes."""

    class _Fn:
        def __call__(self, *a: Any, **k: Any) -> int:
            return 0

    dll = SimpleNamespace()
    for name in (
        "CreateDesktopW",
        "CloseDesktop",
        "EnumDesktopWindows",
        "GetWindowThreadProcessId",
        "GetWindowTextLengthW",
        "GetWindowTextW",
        "GetClassNameW",
        "GetWindowRect",
        "IsWindowVisible",
        "IsWindowEnabled",
        "IsIconic",
        "GetUserObjectInformationW",
        "CreateProcessW",
        "CloseHandle",
        "WaitForSingleObject",
        "GetExitCodeProcess",
        "TerminateProcess",
    ):
        setattr(dll, name, _Fn())
    return dll


def test_api_configures_and_returns_both_dlls(
    monkeypatch: pytest.MonkeyPatch, _ctypes_shim: _CtypesShim
) -> None:
    _pin_nt(monkeypatch)
    user32 = _blank_dll()
    kernel32 = _blank_dll()
    _ctypes_shim.windll_map = {"user32": user32, "kernel32": kernel32}

    got_user32, got_kernel32 = hd._api()

    assert got_user32 is user32 and got_kernel32 is kernel32
    assert user32.CreateDesktopW.restype is ctypes.c_void_p
    assert kernel32.CreateProcessW.restype is ctypes.c_bool


# ---------------------------------------------------------------------------
# DesktopProcess: poll / wait / terminate / kill
# ---------------------------------------------------------------------------


class _FakeKernel32:
    """Scripted process-handle surface with byref write-backs."""

    def __init__(
        self,
        *,
        wait_results: list[int] | None = None,
        exit_code: int = 259,
        terminate_ok: bool = True,
    ) -> None:
        self.wait_results = list(wait_results or [])
        self.exit_code = exit_code
        self.terminate_ok = terminate_ok
        self.closed: list[int] = []
        self.terminated: list[int] = []

    def WaitForSingleObject(self, handle: Any, ms: Any) -> int:  # noqa: N802
        return self.wait_results.pop(0) if self.wait_results else _WAIT_TIMEOUT

    def GetExitCodeProcess(self, handle: Any, out: Any) -> int:  # noqa: N802
        out._obj.value = self.exit_code
        return 1

    def TerminateProcess(self, handle: Any, code: Any) -> int:  # noqa: N802
        self.terminated.append(int(getattr(handle, "value", 0) or 0))
        return 1 if self.terminate_ok else 0

    def CloseHandle(self, handle: Any) -> int:  # noqa: N802
        self.closed.append(int(getattr(handle, "value", 0) or 0))
        return 1


def _proc(handle: int = 0x55) -> hd.DesktopProcess:
    return hd.DesktopProcess(
        args=["worker.exe"],
        process_handle=handle,
        pid=4321,
        stdin=SimpleNamespace(),  # type: ignore[arg-type]
        stdout=SimpleNamespace(),  # type: ignore[arg-type]
        stderr=SimpleNamespace(),  # type: ignore[arg-type]
    )


def test_poll_returns_none_while_running(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_TIMEOUT])
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    assert _proc().poll() is None


def test_poll_captures_exit_code_and_closes_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_OBJECT_0], exit_code=7)
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    proc = _proc(0x55)
    assert proc.poll() == 7
    assert proc.returncode == 7
    assert k.closed == [0x55]
    assert proc.poll() == 7, "a cached return code needs no second wait"


def test_poll_raises_on_wait_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_FAILED])
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    with pytest.raises(OSError):
        _proc().poll()


def test_poll_raises_when_the_exit_code_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    class _K(_FakeKernel32):
        def GetExitCodeProcess(self, handle: Any, out: Any) -> int:  # noqa: N802
            return 0  # GetExitCodeProcess failed

    k = _K(wait_results=[_WAIT_OBJECT_0])
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    with pytest.raises(OSError):
        _proc().poll()


def test_wait_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    k = _FakeKernel32(wait_results=[_WAIT_TIMEOUT])
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    with pytest.raises(subprocess.TimeoutExpired):
        _proc().wait(timeout=0.01)


def test_wait_returns_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_OBJECT_0], exit_code=3)
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    proc = _proc(0x60)
    assert proc.wait(timeout=1.0) == 3
    assert k.closed == [0x60]
    assert proc.wait() == 3, "a cached return code short-circuits a second wait"


def test_wait_infinite_uses_the_infinite_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []

    class _K(_FakeKernel32):
        def WaitForSingleObject(self, handle: Any, ms: Any) -> int:  # noqa: N802
            seen.append(int(ms))
            return _WAIT_OBJECT_0

    monkeypatch.setattr(hd, "_api", lambda: (None, _K(exit_code=0)))
    assert _proc().wait() == 0
    assert seen == [0xFFFFFFFF]


def test_wait_raises_on_unexpected_wait_result(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_FAILED])
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    with pytest.raises(OSError):
        _proc().wait(timeout=1.0)


def test_terminate_skips_a_finished_process(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_OBJECT_0], exit_code=0)
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    proc = _proc()
    proc.terminate()
    assert k.terminated == [], "an exited process is not terminated again"


def test_terminate_kills_a_live_process(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_TIMEOUT])
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    _proc(0x71).terminate()
    assert k.terminated == [0x71]


def test_terminate_raises_when_the_kill_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_TIMEOUT], terminate_ok=False)
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    with pytest.raises(OSError):
        _proc().terminate()


def test_kill_delegates_to_terminate(monkeypatch: pytest.MonkeyPatch) -> None:
    k = _FakeKernel32(wait_results=[_WAIT_TIMEOUT])
    monkeypatch.setattr(hd, "_api", lambda: (None, k))
    _proc(0x72).kill()
    assert k.terminated == [0x72]


# ---------------------------------------------------------------------------
# HiddenDesktop.create / qualified_name / spawn / close
# ---------------------------------------------------------------------------


class _FakeUser32:
    """Scripted desktop/window surface for HiddenDesktop."""

    def __init__(
        self,
        *,
        create_handle: int = 0x900,
        desktop_name: str | None = None,
        close_ok: bool = True,
        windows: list[dict[str, Any]] | None = None,
        enum_ok: bool = True,
    ) -> None:
        self.create_handle = create_handle
        self.desktop_name = desktop_name
        self.close_ok = close_ok
        self.windows = list(windows or [])
        self.enum_ok = enum_ok
        self.closed: list[int] = []
        self._requested = ""

    def CreateDesktopW(self, name: Any, *rest: Any) -> int:  # noqa: N802
        self._requested = name
        return self.create_handle

    def CloseDesktop(self, handle: Any) -> int:  # noqa: N802
        self.closed.append(int(getattr(handle, "value", handle) or 0))
        return 1 if self.close_ok else 0

    def GetUserObjectInformationW(  # noqa: N802
        self, handle: Any, index: Any, buf: Any, size: Any, needed: Any
    ) -> int:
        name = self.desktop_name if self.desktop_name is not None else self._requested
        if buf is None:
            needed._obj.value = (len(name) + 1) * ctypes.sizeof(ctypes.c_wchar)
            return 1
        buf.value = name
        return 1

    def GetWindowThreadProcessId(self, hwnd: Any, owner: Any) -> int:  # noqa: N802
        owner._obj.value = int(self._by_hwnd(hwnd)["pid"])
        return 1

    def GetWindowTextLengthW(self, hwnd: Any) -> int:  # noqa: N802
        return len(self._by_hwnd(hwnd)["title"])

    def GetWindowTextW(self, hwnd: Any, buf: Any, n: Any) -> int:  # noqa: N802
        buf.value = self._by_hwnd(hwnd)["title"]
        return len(buf.value)

    def GetClassNameW(self, hwnd: Any, buf: Any, n: Any) -> int:  # noqa: N802
        buf.value = self._by_hwnd(hwnd)["class_name"]
        return len(buf.value)

    def GetWindowRect(self, hwnd: Any, rect: Any) -> int:  # noqa: N802
        left, top, right, bottom = self._by_hwnd(hwnd)["rect"]
        rect._obj.left, rect._obj.top = left, top
        rect._obj.right, rect._obj.bottom = right, bottom
        return 1

    def IsWindowVisible(self, hwnd: Any) -> bool:  # noqa: N802
        return bool(self._by_hwnd(hwnd).get("visible", True))

    def IsWindowEnabled(self, hwnd: Any) -> bool:  # noqa: N802
        return bool(self._by_hwnd(hwnd).get("enabled", True))

    def IsIconic(self, hwnd: Any) -> bool:  # noqa: N802
        return bool(self._by_hwnd(hwnd).get("minimized", False))

    def EnumDesktopWindows(self, handle: Any, cb: Any, lparam: Any) -> int:  # noqa: N802
        for row in self.windows:
            cb(row["hwnd"], 0)
        return 1 if self.enum_ok else 0

    def _by_hwnd(self, hwnd: Any) -> dict[str, Any]:
        key = int(getattr(hwnd, "value", hwnd) or 0)
        for row in self.windows:
            if int(row["hwnd"]) == key:
                return row
        raise KeyError(key)


def _identity_enum(monkeypatch: pytest.MonkeyPatch) -> None:
    # wnd_enum_callback_type() -> factory; factory(fn) -> fn (call callback directly).
    monkeypatch.setattr(hd, "wnd_enum_callback_type", lambda: lambda fn: fn)


def test_create_round_trips_the_desktop_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    user32 = _FakeUser32(create_handle=0x900)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))

    desktop = hd.HiddenDesktop.create(prefix="Test")

    assert desktop.name.startswith("Test-")
    assert desktop.qualified_name == rf"WinSta0\{desktop.name}"
    assert user32.closed == [], "a good desktop is not closed by create"


def test_create_raises_on_null_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    user32 = _FakeUser32(create_handle=0)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    with pytest.raises(OSError):
        hd.HiddenDesktop.create()


def test_create_rejects_a_name_that_does_not_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    user32 = _FakeUser32(create_handle=0x900, desktop_name="something-else")
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    with pytest.raises(hd.HiddenDesktopError):
        hd.HiddenDesktop.create()
    assert user32.closed == [0x900], "a mismatched desktop must be closed"


def test_desktop_name_returns_empty_when_length_is_zero() -> None:
    class _U:
        def GetUserObjectInformationW(  # noqa: N802
            self, handle: Any, index: Any, buf: Any, size: Any, needed: Any
        ) -> int:
            needed._obj.value = 0
            return 1

    assert hd._desktop_name(_U(), 0x10) == ""


def test_desktop_name_raises_when_the_second_query_fails() -> None:
    class _U:
        def __init__(self) -> None:
            self.calls = 0

        def GetUserObjectInformationW(  # noqa: N802
            self, handle: Any, index: Any, buf: Any, size: Any, needed: Any
        ) -> int:
            self.calls += 1
            if buf is None:
                needed._obj.value = 8  # non-zero length -> a buffer is allocated
                return 1
            return 0  # the filled query fails

    with pytest.raises(OSError):
        hd._desktop_name(_U(), 0x10)


def test_spawn_delegates_to_create_process(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    captured: dict[str, Any] = {}

    def fake_create(args: Any, desktop: str, **kwargs: Any) -> str:
        captured["args"] = list(args)
        captured["desktop"] = desktop
        return "PROC"

    monkeypatch.setattr(hd, "create_process_on_desktop", fake_create)
    desktop = hd.HiddenDesktop("HeadlessRE-abc", 0x10)

    spawned: Any = desktop.spawn(["worker.exe", "--rpc"])
    assert spawned == "PROC"
    assert captured["args"] == ["worker.exe", "--rpc"]
    assert captured["desktop"] == r"WinSta0\HeadlessRE-abc"


def test_spawn_refuses_a_closed_desktop(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    desktop = hd.HiddenDesktop("HeadlessRE-abc", 0x10)
    desktop._closed = True
    with pytest.raises(hd.HiddenDesktopError):
        desktop.spawn(["worker.exe"])


def test_close_releases_and_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    user32 = _FakeUser32()
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    desktop = hd.HiddenDesktop("HeadlessRE-abc", 0x123)

    desktop.close()
    assert user32.closed == [0x123]
    desktop.close()  # second close is a no-op
    assert user32.closed == [0x123]


def test_close_raises_when_the_desktop_will_not_close(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    user32 = _FakeUser32(close_ok=False)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    desktop = hd.HiddenDesktop("HeadlessRE-abc", 0x123)
    with pytest.raises(OSError):
        desktop.close()


def test_context_manager_closes_on_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    user32 = _FakeUser32()
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    with hd.HiddenDesktop("HeadlessRE-abc", 0x123) as desktop:
        assert desktop.name == "HeadlessRE-abc"
    assert user32.closed == [0x123]


# ---------------------------------------------------------------------------
# HiddenDesktop window enumeration / snapshot / capture
# ---------------------------------------------------------------------------


def _windowed_desktop(
    monkeypatch: pytest.MonkeyPatch, windows: list[dict[str, Any]], *, enum_ok: bool = True
) -> tuple[hd.HiddenDesktop, _FakeUser32]:
    _pin_nt(monkeypatch)
    _identity_enum(monkeypatch)
    user32 = _FakeUser32(windows=windows, enum_ok=enum_ok)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    return hd.HiddenDesktop("HeadlessRE-abc", 0x123), user32


def test_enumerate_yields_rows_with_geometry(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {
            "hwnd": 11,
            "pid": 4321,
            "title": "Main",
            "class_name": "Win",
            "rect": (10, 20, 110, 220),
            "visible": True,
        }
    ]
    desktop, _ = _windowed_desktop(monkeypatch, rows)
    out = desktop.windows()
    assert len(out) == 1
    row = out[0]
    assert row["hwnd"] == 11 and row["pid"] == 4321
    assert row["title"] == "Main" and row["class_name"] == "Win"
    assert row["rect"] == {
        "left": 10,
        "top": 20,
        "right": 110,
        "bottom": 220,
        "width": 100,
        "height": 200,
    }
    assert row["area"] == 20000


def test_windows_filters_by_allowed_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"hwnd": 1, "pid": 100, "title": "a", "class_name": "C", "rect": (0, 0, 1, 1)},
        {"hwnd": 2, "pid": 200, "title": "b", "class_name": "C", "rect": (0, 0, 1, 1)},
    ]
    desktop, _ = _windowed_desktop(monkeypatch, rows)
    only = desktop.windows(allowed_pids=frozenset({200}))
    assert [r["hwnd"] for r in only] == [2]


def test_enumerate_on_a_closed_desktop_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    desktop, _ = _windowed_desktop(monkeypatch, [])
    desktop._closed = True
    assert desktop.windows() == []


def test_enumerate_raises_when_enum_reports_failure(
    monkeypatch: pytest.MonkeyPatch, _ctypes_shim: _CtypesShim
) -> None:
    rows = [{"hwnd": 1, "pid": 1, "title": "a", "class_name": "C", "rect": (0, 0, 1, 1)}]
    desktop, _ = _windowed_desktop(monkeypatch, rows, enum_ok=False)
    _ctypes_shim.forced_last_error = 12
    with pytest.raises(OSError):
        desktop.windows()


def test_enumerate_swallows_a_zero_return_with_no_error(
    monkeypatch: pytest.MonkeyPatch, _ctypes_shim: _CtypesShim
) -> None:
    rows = [{"hwnd": 1, "pid": 1, "title": "a", "class_name": "C", "rect": (0, 0, 1, 1)}]
    desktop, _ = _windowed_desktop(monkeypatch, rows, enum_ok=False)
    _ctypes_shim.forced_last_error = 0
    # A zero return with GetLastError()==0 is treated as an empty-but-ok scan.
    assert [r["hwnd"] for r in desktop.windows()] == [1]


def test_process_window_descriptions(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"hwnd": 7, "pid": 55, "title": "OK", "class_name": "Button", "rect": (0, 0, 1, 1)},
        {"hwnd": 8, "pid": 99, "title": "x", "class_name": "Edit", "rect": (0, 0, 1, 1)},
    ]
    desktop, _ = _windowed_desktop(monkeypatch, rows)
    assert desktop.process_window_descriptions(55) == ["Button:OK (hwnd=7)"]


def test_snapshot_sorts_by_capture_rank_and_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {
            "hwnd": 1,
            "pid": 55,
            "title": "tiny",
            "class_name": "C",
            "rect": (0, 0, 0, 0),
            "visible": True,
        },
        {
            "hwnd": 2,
            "pid": 55,
            "title": "big",
            "class_name": "C",
            "rect": (0, 0, 100, 100),
            "visible": True,
        },
        {
            "hwnd": 3,
            "pid": 99,
            "title": "other",
            "class_name": "C",
            "rect": (0, 0, 50, 50),
            "visible": True,
        },
    ]
    desktop, _ = _windowed_desktop(monkeypatch, rows)
    snap = desktop.snapshot(allowed_pids=frozenset({55}))
    assert snap["available"] is True
    assert snap["mode"] == "hidden_win32"
    assert snap["input_desktop"] is False
    assert snap["window_count"] == 2, "only the allowed pid's windows are counted"
    assert snap["desktop_window_count"] == 3, "the full desktop count is disclosed"
    assert [r["hwnd"] for r in snap["windows"]] == [2, 1], "the larger window ranks first"


def test_snapshot_without_a_pid_filter_lists_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {
            "hwnd": 1,
            "pid": 55,
            "title": "a",
            "class_name": "C",
            "rect": (0, 0, 10, 10),
            "visible": True,
        },
        {
            "hwnd": 2,
            "pid": 99,
            "title": "b",
            "class_name": "C",
            "rect": (0, 0, 20, 20),
            "visible": True,
        },
    ]
    desktop, _ = _windowed_desktop(monkeypatch, rows)
    snap = desktop.snapshot()
    assert snap["window_count"] == 2 and snap["desktop_window_count"] == 2


def test_capture_refuses_a_window_off_the_authorized_desktop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [{"hwnd": 5, "pid": 55, "title": "a", "class_name": "C", "rect": (0, 0, 1, 1)}]
    desktop, _ = _windowed_desktop(monkeypatch, rows)
    with pytest.raises(hd.HiddenDesktopError):
        desktop.capture(999, allowed_pids=frozenset({55}), output_path="/tmp/x.bmp")


def test_capture_forwards_to_the_win32_screenshotter(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"hwnd": 5, "pid": 55, "title": "a", "class_name": "C", "rect": (0, 0, 1, 1)}]
    desktop, _ = _windowed_desktop(monkeypatch, rows)
    calls: dict[str, Any] = {}
    fake_ui = ModuleType("headless_re_mcp.core.ui_win32")

    def capture_hwnd_screenshot(hwnd: int, allowed: Any, out: Any) -> dict[str, Any]:
        calls["hwnd"] = hwnd
        calls["out"] = str(out)
        return {"ok": True}

    fake_ui.capture_hwnd_screenshot = capture_hwnd_screenshot  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "headless_re_mcp.core.ui_win32", fake_ui)

    result = desktop.capture(5, allowed_pids=frozenset({55}), output_path="/tmp/shot.bmp")
    assert result == {"ok": True}
    assert calls["hwnd"] == 5 and calls["out"] == "/tmp/shot.bmp"


# ---------------------------------------------------------------------------
# create_process_on_desktop
# ---------------------------------------------------------------------------


def _install_fake_msvcrt(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = ModuleType("msvcrt")
    fake.get_osfhandle = lambda fd: fd  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "msvcrt", fake)


def test_create_process_rejects_empty_args(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    _install_fake_msvcrt(monkeypatch)
    monkeypatch.setattr(hd, "_api", lambda: (_blank_dll(), _blank_dll()))
    with pytest.raises(ValueError):
        hd.create_process_on_desktop([], r"WinSta0\Test")


def test_create_process_spawns_and_wraps_the_child(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    _install_fake_msvcrt(monkeypatch)

    class _K:
        def __init__(self) -> None:
            self.closed: list[Any] = []

        def CreateProcessW(self, *args: Any) -> int:  # noqa: N802
            process = args[-1]._obj  # byref(PROCESS_INFORMATION)
            process.hProcess = 0xABC
            process.hThread = 0xDEF
            process.dwProcessId = 4321
            return 1

        def CloseHandle(self, handle: Any) -> int:  # noqa: N802
            self.closed.append(handle)
            return 1

    kernel32 = _K()
    monkeypatch.setattr(hd, "_api", lambda: (_blank_dll(), kernel32))

    proc = hd.create_process_on_desktop(["worker.exe", "--x"], r"WinSta0\Test")
    try:
        assert isinstance(proc, hd.DesktopProcess)
        assert proc.pid == 4321
        assert proc.args == ["worker.exe", "--x"]
        assert kernel32.closed, "the child thread handle must be closed after spawn"
    finally:
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()


def test_create_process_closes_fds_when_spawn_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_msvcrt(monkeypatch)
    opened: list[int] = []
    real_pipe = os.pipe

    def tracking_pipe() -> tuple[int, int]:
        pair = real_pipe()
        opened.extend(pair)
        return pair

    monkeypatch.setattr(hd, "os", _OsProxy("nt", pipe=tracking_pipe))

    class _K:
        def CreateProcessW(self, *args: Any) -> int:  # noqa: N802
            return 0

        def CloseHandle(self, handle: Any) -> int:  # noqa: N802
            return 1

    monkeypatch.setattr(hd, "_api", lambda: (_blank_dll(), _K()))

    with pytest.raises(OSError):
        hd.create_process_on_desktop(["worker.exe"], r"WinSta0\Test")

    # Every pipe fd the launcher opened must be closed on the failure path.
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)
