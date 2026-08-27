"""Cross-platform coverage for the Win32 desktop-isolation job.

``desktop_isolation`` keeps a debuggee's UI off the operator's input desktop:
a job object with UI restrictions plus a best-effort hide of any window that
still leaks through ``MB_SERVICE_NOTIFICATION``. Every Win32 call is funnelled
through ``_kernel32()`` or ``ctypes.WinDLL("user32")``; both are faked here so
the POSIX test host exercises the Windows branches. ``os.name`` is pinned to
"nt" with a proxy that forwards everything else to the real module.
"""

from __future__ import annotations

import ctypes
import os
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.desktop_isolation as di


class _OsProxy:
    """``os`` with ``name`` pinned; every other attribute forwarded."""

    def __init__(self, name: str = "nt") -> None:
        self.name = name

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


class _CtypesProxy:
    """``ctypes`` with a scripted ``WinDLL``; everything else forwarded."""

    def __init__(self, dlls: dict[str, Any]) -> None:
        self._dlls = dlls

    def WinDLL(self, name: str, *args: Any, **kwargs: Any) -> Any:  # noqa: N802
        return self._dlls[name]

    def __getattr__(self, attribute: str) -> Any:
        return getattr(ctypes, attribute)


def _pin_nt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(di, "os", _OsProxy("nt"))


def _pin_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(di, "os", _OsProxy("posix"))


def _fake_kernel32(**overrides: Any) -> SimpleNamespace:
    calls: list[tuple[str, tuple[Any, ...]]] = []

    def record(name: str) -> Any:
        def fn(*args: Any) -> Any:
            calls.append((name, args))
            behaviour = overrides.get(name)
            if callable(behaviour):
                return behaviour(*args)
            return 1 if behaviour is None else behaviour

        return fn

    dll = SimpleNamespace(
        CreateJobObjectW=record("CreateJobObjectW"),
        SetInformationJobObject=record("SetInformationJobObject"),
        CloseHandle=record("CloseHandle"),
        OpenProcess=record("OpenProcess"),
        AssignProcessToJobObject=record("AssignProcessToJobObject"),
        calls=calls,
    )
    return dll


def test_kernel32_loads_the_dll_with_last_error(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = SimpleNamespace(tag="kernel32")
    monkeypatch.setattr(di, "ctypes", _CtypesProxy({"kernel32": sentinel}))
    assert di._kernel32() is sentinel


# ---------------------------------------------------------------------------
# DesktopIsolationJob.create
# ---------------------------------------------------------------------------


def test_create_returns_none_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_posix(monkeypatch)
    assert di.DesktopIsolationJob.create() is None


def test_create_builds_a_job_with_ui_restrictions(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    dll = _fake_kernel32(CreateJobObjectW=0x4444)
    monkeypatch.setattr(di, "_kernel32", lambda: dll)

    job = di.DesktopIsolationJob.create()

    assert isinstance(job, di.DesktopIsolationJob)
    # Two SetInformationJobObject calls: extended limits then UI restrictions.
    classes = [args[1] for name, args in dll.calls if name == "SetInformationJobObject"]
    assert classes == [
        di._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        di._JOB_OBJECT_BASIC_UI_RESTRICTIONS,
    ]
    assert not any(name == "CloseHandle" for name, _ in dll.calls), "a good job is not closed"


def test_create_returns_none_when_the_job_handle_is_null(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    dll = _fake_kernel32(CreateJobObjectW=0)
    monkeypatch.setattr(di, "_kernel32", lambda: dll)
    assert di.DesktopIsolationJob.create() is None


def test_create_closes_and_bails_when_extended_limits_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_nt(monkeypatch)
    dll = _fake_kernel32(CreateJobObjectW=0x10, SetInformationJobObject=0)
    monkeypatch.setattr(di, "_kernel32", lambda: dll)

    assert di.DesktopIsolationJob.create() is None
    assert any(name == "CloseHandle" for name, _ in dll.calls)


def test_create_closes_and_bails_when_ui_restrictions_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_nt(monkeypatch)
    results = iter([1, 0])  # extended-limits ok, ui-restrictions refused

    dll = _fake_kernel32(
        CreateJobObjectW=0x10,
        SetInformationJobObject=lambda *a: next(results),
    )
    monkeypatch.setattr(di, "_kernel32", lambda: dll)

    assert di.DesktopIsolationJob.create() is None
    assert any(name == "CloseHandle" for name, _ in dll.calls)


def test_create_swallows_os_error_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)

    def raiser(*_: Any) -> int:
        raise OSError("job info refused")

    dll = _fake_kernel32(CreateJobObjectW=0x10, SetInformationJobObject=raiser)
    monkeypatch.setattr(di, "_kernel32", lambda: dll)

    assert di.DesktopIsolationJob.create() is None
    assert any(name == "CloseHandle" for name, _ in dll.calls)


# ---------------------------------------------------------------------------
# DesktopIsolationJob.assign
# ---------------------------------------------------------------------------


def test_assign_rejects_bad_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    job = di.DesktopIsolationJob(0x10)
    assert job.assign(0) is False
    assert job.assign(-1) is False
    assert job.assign(True) is False  # bool is not a plain int here
    closed = di.DesktopIsolationJob(0)
    assert closed.assign(1234) is False


def test_assign_returns_false_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_posix(monkeypatch)
    assert di.DesktopIsolationJob(0x10).assign(1234) is False


def test_assign_returns_false_when_open_process_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    dll = _fake_kernel32(OpenProcess=0)
    monkeypatch.setattr(di, "_kernel32", lambda: dll)
    assert di.DesktopIsolationJob(0x10).assign(1234) is False
    assert not any(name == "AssignProcessToJobObject" for name, _ in dll.calls)


def test_assign_closes_the_process_handle_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    dll = _fake_kernel32(OpenProcess=0x77, AssignProcessToJobObject=1)
    monkeypatch.setattr(di, "_kernel32", lambda: dll)

    assert di.DesktopIsolationJob(0x10).assign(1234) is True
    close_args = [args for name, args in dll.calls if name == "CloseHandle"]
    assert close_args == [(0x77,)], "the opened process handle must always be closed"


def test_assign_closes_the_handle_even_when_assignment_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_nt(monkeypatch)
    dll = _fake_kernel32(OpenProcess=0x77, AssignProcessToJobObject=0)
    monkeypatch.setattr(di, "_kernel32", lambda: dll)

    assert di.DesktopIsolationJob(0x10).assign(1234) is False
    assert any(name == "CloseHandle" and args == (0x77,) for name, args in dll.calls)


# ---------------------------------------------------------------------------
# DesktopIsolationJob.close
# ---------------------------------------------------------------------------


def test_close_is_a_noop_when_already_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    called: list[Any] = []

    def tripwire() -> SimpleNamespace:
        called.append("k")
        return SimpleNamespace()

    monkeypatch.setattr(di, "_kernel32", tripwire)
    job = di.DesktopIsolationJob(0)
    job.close()
    assert called == [], "a zero handle must not touch kernel32"


def test_close_is_a_noop_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_posix(monkeypatch)
    called: list[Any] = []

    def tripwire() -> SimpleNamespace:
        called.append("k")
        return SimpleNamespace()

    monkeypatch.setattr(di, "_kernel32", tripwire)
    di.DesktopIsolationJob(0x10).close()
    assert called == []


def test_close_releases_the_handle_and_zeroes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    dll = _fake_kernel32()
    monkeypatch.setattr(di, "_kernel32", lambda: dll)
    job = di.DesktopIsolationJob(0x55)

    job.close()
    assert any(name == "CloseHandle" and args == (0x55,) for name, args in dll.calls)
    # The handle is zeroed, so a second close does nothing.
    dll.calls.clear()
    job.close()
    assert dll.calls == []


# ---------------------------------------------------------------------------
# hide_input_desktop_windows_for_pids
# ---------------------------------------------------------------------------


def test_hide_returns_empty_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_posix(monkeypatch)
    assert di.hide_input_desktop_windows_for_pids([1234]) == []


def test_hide_returns_empty_for_no_valid_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    assert di.hide_input_desktop_windows_for_pids([0, -1, "x"]) == []  # type: ignore[list-item]


def test_hide_hides_each_owned_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    shown: list[tuple[int, int]] = []
    positioned: list[tuple[int, int]] = []

    def show_window(hwnd: int, cmd: int) -> bool:
        shown.append((hwnd, cmd))
        return True

    def set_window_pos(hwnd: int, after: Any, x: int, y: int, cx: int, cy: int, flags: int) -> bool:
        positioned.append((hwnd, flags))
        return True

    user32 = SimpleNamespace(ShowWindow=show_window, SetWindowPos=set_window_pos)
    monkeypatch.setattr(di, "ctypes", _CtypesProxy({"user32": user32}))
    monkeypatch.setattr(
        di,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 11}, {"hwnd": 22}],
    )

    hidden = di.hide_input_desktop_windows_for_pids([4000, 4000, 12])

    assert hidden == [11, 22]
    assert shown == [(11, di._SW_HIDE), (22, di._SW_HIDE)]
    expected_flags = (
        di._SWP_NOSIZE | di._SWP_NOMOVE | di._SWP_NOZORDER | di._SWP_NOACTIVATE | di._SWP_HIDEWINDOW
    )
    assert positioned == [(11, expected_flags), (22, expected_flags)]


def test_hide_forwards_deduplicated_sorted_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_nt(monkeypatch)
    seen: dict[str, Any] = {}
    user32 = SimpleNamespace(
        ShowWindow=lambda hwnd, cmd: True,
        SetWindowPos=lambda *a: True,
    )
    monkeypatch.setattr(di, "ctypes", _CtypesProxy({"user32": user32}))

    def capture(pids: Any) -> list[dict[str, int]]:
        seen["pids"] = list(pids)
        return []

    monkeypatch.setattr(di, "list_windows_for_pids", capture)

    di.hide_input_desktop_windows_for_pids([50, 10, 50, 10])
    assert seen["pids"] == [10, 50], "duplicate pids collapse and are passed in sorted order"
