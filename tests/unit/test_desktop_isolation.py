"""Regression cover for the input-desktop isolation surface.

``desktop_isolation`` is the leak surface an anti-debug ``MessageBox`` with
``MB_SERVICE_NOTIFICATION`` uses to reach the operator's session, and the job
object is what forbids a debuggee from switching desktops. The module is all
Win32 ctypes, so it never runs on the Linux CI -- these tests pin the parts a
refactor could quietly break: the non-Windows fail-safe returns, the PID
validation that gates ``OpenProcess``, the job's kill-on-close plus UI
restrictions with cleanup on failure, and above all the "hide, do not dismiss"
invariant, because dismissing an anti-debug dialog continues the sample as if
the operator clicked OK.
"""

from __future__ import annotations

import ctypes
import os
from typing import Any

import pytest

import headless_re_mcp.core.desktop_isolation as di

# Win32 verbs that would close or answer a window rather than merely hide it.
# hide_input_desktop_windows_for_pids must never call any of these.
_DISMISS_VERBS = frozenset(
    {
        "CloseWindow",
        "DestroyWindow",
        "EndDialog",
        "PostMessageW",
        "PostMessageA",
        "SendMessageW",
        "SendMessageA",
        "PostQuitMessage",
    }
)


class _RecordingLib:
    """A ctypes.WinDLL stand-in: every attribute is a call that returns 1."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def __getattr__(self, name: str) -> Any:
        def _call(*args: Any) -> int:
            self.calls.append((name, args))
            return 1

        return _call

    def names(self) -> list[str]:
        return [name for name, _args in self.calls]


class _FakeKernel32:
    """kernel32 stand-in for job-object creation and assignment."""

    def __init__(
        self,
        *,
        create_handle: int = 4321,
        set_results: list[int] | None = None,
        open_handle: int = 777,
        assign_result: int = 1,
    ) -> None:
        self.create_handle = create_handle
        self.set_results = list(set_results if set_results is not None else [1, 1])
        self.open_handle = open_handle
        self.assign_result = assign_result
        self.info_classes: list[int] = []
        self.closed: list[int] = []
        self.opened: list[tuple[int, int]] = []
        self.assigned: list[tuple[int, int]] = []

    def CreateJobObjectW(self, _a: Any, _b: Any) -> int:
        return self.create_handle

    def SetInformationJobObject(self, _handle: Any, klass: int, _ptr: Any, _size: Any) -> int:
        self.info_classes.append(int(klass))
        return self.set_results.pop(0) if self.set_results else 1

    def CloseHandle(self, handle: Any) -> int:
        self.closed.append(int(handle))
        return 1

    def OpenProcess(self, access: int, _inherit: Any, pid: int) -> int:
        self.opened.append((int(access), int(pid)))
        return self.open_handle

    def AssignProcessToJobObject(self, job: Any, proc: Any) -> int:
        self.assigned.append((int(job), int(proc)))
        return self.assign_result


def _force_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")


# ---- non-Windows fail-safe -------------------------------------------------


def test_create_is_none_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert di.DesktopIsolationJob.create() is None


def test_assign_and_close_are_safe_noops_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "posix")
    job = di.DesktopIsolationJob(handle=123)
    assert job.assign(456) is False
    job.close()  # must not raise and must not touch any Win32 call


def test_hide_is_empty_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert di.hide_input_desktop_windows_for_pids([1, 2, 3]) == []


# ---- hide, do not dismiss --------------------------------------------------


def test_hide_filters_pids_hides_windows_and_never_dismisses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    user32 = _RecordingLib()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: user32, raising=False)

    seen_pids: list[list[int]] = []

    def fake_list(pids: Any) -> list[dict[str, int]]:
        seen_pids.append(list(pids))
        return [{"hwnd": 0x10}, {"hwnd": 0x20}]

    monkeypatch.setattr(di, "list_windows_for_pids", fake_list)

    hidden = di.hide_input_desktop_windows_for_pids([42, 0, -5, 7, 7])

    assert hidden == [0x10, 0x20]
    # Only the positive integer PIDs survive, deduplicated and sorted.
    assert seen_pids == [[7, 42]]
    called = user32.names()
    assert called.count("ShowWindow") == 2
    assert called.count("SetWindowPos") == 2
    assert _DISMISS_VERBS.isdisjoint(called), f"must not dismiss: {called}"
    # Each hide is SW_HIDE plus a HIDEWINDOW SetWindowPos.
    show_args = [args for name, args in user32.calls if name == "ShowWindow"]
    assert all(args[1] == di._SW_HIDE for args in show_args)
    pos_flags = [args[-1] for name, args in user32.calls if name == "SetWindowPos"]
    assert all(flags & di._SWP_HIDEWINDOW for flags in pos_flags)


def test_hide_with_no_valid_pids_touches_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    called = {"list": False, "windll": False}

    def fake_list(_pids: Any) -> list[dict[str, int]]:
        called["list"] = True
        return []

    def fake_windll(*_a: Any, **_k: Any) -> Any:
        called["windll"] = True
        return _RecordingLib()

    monkeypatch.setattr(di, "list_windows_for_pids", fake_list)
    monkeypatch.setattr(ctypes, "WinDLL", fake_windll, raising=False)

    bad_pids: list[Any] = [0, -1, "nope"]
    assert di.hide_input_desktop_windows_for_pids(bad_pids) == []
    # Refused before enumerating windows or loading user32.
    assert called == {"list": False, "windll": False}


# ---- job object: kill-on-close, UI restrictions, cleanup -------------------


def test_create_sets_kill_on_close_and_ui_restrictions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    kernel = _FakeKernel32(set_results=[1, 1])
    monkeypatch.setattr(di, "_kernel32", lambda: kernel)

    job = di.DesktopIsolationJob.create()

    assert isinstance(job, di.DesktopIsolationJob)
    # Both the extended-limit (kill-on-close) and UI-restriction info classes
    # are installed, in that order.
    assert kernel.info_classes == [
        di._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        di._JOB_OBJECT_BASIC_UI_RESTRICTIONS,
    ]
    assert not kernel.closed  # a successful create keeps its handle


def test_create_closes_handle_when_ui_restriction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    # First SetInformationJobObject (kill-on-close) succeeds, second (UI) fails.
    kernel = _FakeKernel32(create_handle=4321, set_results=[1, 0])
    monkeypatch.setattr(di, "_kernel32", lambda: kernel)

    assert di.DesktopIsolationJob.create() is None
    assert kernel.closed == [4321]  # the leaked handle is reclaimed


def test_ui_restriction_flags_forbid_desktop_switch_and_exit() -> None:
    """A regression that dropped these bits would let a debuggee change desktop."""
    assert di.DESKTOP_UI_RESTRICTIONS & di.JOB_OBJECT_UILIMIT_DESKTOP
    assert di.DESKTOP_UI_RESTRICTIONS & di.JOB_OBJECT_UILIMIT_EXITWINDOWS
    assert di.DESKTOP_UI_RESTRICTIONS & di.JOB_OBJECT_UILIMIT_HANDLES


# ---- assign: PID validation gates OpenProcess ------------------------------


@pytest.mark.parametrize("bad_pid", [0, -1, -1000])
def test_assign_rejects_nonpositive_pids_without_opening(
    monkeypatch: pytest.MonkeyPatch, bad_pid: int
) -> None:
    _force_windows(monkeypatch)
    kernel = _FakeKernel32()
    monkeypatch.setattr(di, "_kernel32", lambda: kernel)

    assert di.DesktopIsolationJob(handle=999).assign(bad_pid) is False
    assert kernel.opened == []  # never reached OpenProcess


def test_assign_rejects_zero_handle_without_opening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    kernel = _FakeKernel32()
    monkeypatch.setattr(di, "_kernel32", lambda: kernel)

    assert di.DesktopIsolationJob(handle=0).assign(1234) is False
    assert kernel.opened == []


def test_assign_opens_and_assigns_a_valid_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    kernel = _FakeKernel32(open_handle=555, assign_result=1)
    monkeypatch.setattr(di, "_kernel32", lambda: kernel)

    assert di.DesktopIsolationJob(handle=999).assign(1234) is True
    assert kernel.opened == [(di._PROCESS_SET_QUOTA | di._PROCESS_TERMINATE, 1234)]
    assert kernel.assigned == [(999, 555)]
    assert kernel.closed == [555]  # the process handle is always released
