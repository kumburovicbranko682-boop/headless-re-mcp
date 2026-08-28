"""DesktopIsolationJob and input-desktop hiding, driven on a faked Win32 surface.

This module keeps a debuggee's UI off the operator's interactive desktop: a job
object with UI restrictions blocks the handle/desktop switch an anti-debug
``MessageBox`` uses, and a hide pass sweeps anything that still lands on the
input desktop. None of it runs on a hosted Linux platform -- every entry point
is gated on ``os.name == 'nt'`` and talks to kernel32/user32 -- so it sat at
38%. Faking exactly those two seams (``_kernel32`` and ``ctypes.WinDLL``) plus
the window enumerator drives the real job-creation, assignment, close, and
hide logic across its success and every failure branch, with real ctypes
structures so the SetInformationJobObject calls are shaped as Windows sees them.
"""

from __future__ import annotations

import ctypes
import os
from typing import Any

import pytest

import headless_re_mcp.core.desktop_isolation as desktop_isolation
from headless_re_mcp.core.desktop_isolation import (
    DesktopIsolationJob,
    hide_input_desktop_windows_for_pids,
)


class _FakeKernel32:
    """Records calls and returns scripted values for the kernel32 job APIs."""

    def __init__(
        self,
        *,
        create: int = 0x1000,
        set_info: tuple[bool, ...] = (True, True),
        set_info_raises: bool = False,
        open_process: int = 0x2000,
        assign: bool = True,
    ) -> None:
        self.create = create
        self.set_info = list(set_info)
        self.set_info_raises = set_info_raises
        self.open_process = open_process
        self.assign = assign
        self.closed: list[int] = []
        self.assigned: list[tuple[int, int]] = []

    def CreateJobObjectW(self, _attrs: Any, _name: Any) -> int:
        return self.create

    def SetInformationJobObject(self, _handle: int, _cls: int, _ref: Any, _size: int) -> bool:
        if self.set_info_raises:
            raise OSError("SetInformationJobObject blew up")
        return self.set_info.pop(0) if self.set_info else True

    def CloseHandle(self, handle: int) -> bool:
        self.closed.append(handle)
        return True

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return self.open_process

    def AssignProcessToJobObject(self, job: int, process: int) -> bool:
        self.assigned.append((job, process))
        return self.assign


def _force_nt(monkeypatch: pytest.MonkeyPatch, kernel32: _FakeKernel32 | None = None) -> None:
    monkeypatch.setattr(os, "name", "nt")
    if kernel32 is not None:
        monkeypatch.setattr(desktop_isolation, "_kernel32", lambda: kernel32)


# ---------------------------------------------------------------------------
# _kernel32()


def test_kernel32_loads_the_dll(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: sentinel, raising=False)
    assert desktop_isolation._kernel32() is sentinel


# ---------------------------------------------------------------------------
# create()


def test_create_returns_none_off_windows() -> None:
    assert DesktopIsolationJob.create() is None


def test_create_returns_none_when_the_job_handle_is_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeKernel32(create=0)
    _force_nt(monkeypatch, fake)
    assert DesktopIsolationJob.create() is None
    assert fake.closed == []  # nothing to close; the handle was never valid


def test_create_closes_and_fails_when_the_kill_on_close_limit_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeKernel32(set_info=(False,))
    _force_nt(monkeypatch, fake)
    assert DesktopIsolationJob.create() is None
    assert fake.closed == [0x1000]  # the job handle was released


def test_create_closes_and_fails_when_the_ui_restrictions_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeKernel32(set_info=(True, False))
    _force_nt(monkeypatch, fake)
    assert DesktopIsolationJob.create() is None
    assert fake.closed == [0x1000]


def test_create_closes_and_fails_when_a_job_call_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeKernel32(set_info_raises=True)
    _force_nt(monkeypatch, fake)
    assert DesktopIsolationJob.create() is None
    assert fake.closed == [0x1000]


def test_create_succeeds_and_carries_the_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeKernel32()
    _force_nt(monkeypatch, fake)
    job = DesktopIsolationJob.create()
    assert job is not None
    assert job._handle == 0x1000
    assert fake.closed == []  # kept open for later assign/close


# ---------------------------------------------------------------------------
# assign()


def test_assign_refuses_bad_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch, _FakeKernel32())
    job = DesktopIsolationJob(0)  # a zero handle can never assign
    assert job.assign(1234) is False
    live = DesktopIsolationJob(0x1000)
    assert live.assign(0) is False  # a non-positive pid is refused
    assert live.assign(True) is False  # a bool is not an int pid


def test_assign_returns_false_when_the_process_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeKernel32(open_process=0)
    _force_nt(monkeypatch, fake)
    job = DesktopIsolationJob(0x1000)
    assert job.assign(4321) is False
    assert fake.assigned == []  # never reached the assign call
    assert fake.closed == []  # no process handle to close


def test_assign_assigns_and_closes_the_process_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeKernel32()
    _force_nt(monkeypatch, fake)
    job = DesktopIsolationJob(0x1000)
    assert job.assign(4321) is True
    assert fake.assigned == [(0x1000, 0x2000)]
    assert fake.closed == [0x2000]  # the opened process handle is always closed


def test_assign_reports_a_failed_assignment_but_still_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeKernel32(assign=False)
    _force_nt(monkeypatch, fake)
    job = DesktopIsolationJob(0x1000)
    assert job.assign(4321) is False
    assert fake.closed == [0x2000]


# ---------------------------------------------------------------------------
# close()


def test_close_is_a_no_op_for_a_zero_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeKernel32()
    _force_nt(monkeypatch, fake)
    DesktopIsolationJob(0).close()
    assert fake.closed == []


def test_close_releases_a_live_handle_once(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeKernel32()
    _force_nt(monkeypatch, fake)
    job = DesktopIsolationJob(0x1000)
    job.close()
    assert fake.closed == [0x1000]
    assert job._handle == 0
    # A second close does nothing: the handle is already surrendered.
    job.close()
    assert fake.closed == [0x1000]


# ---------------------------------------------------------------------------
# hide_input_desktop_windows_for_pids()


class _FakeUser32:
    def __init__(self) -> None:
        self.shown: list[tuple[int, int]] = []
        self.positioned: list[int] = []

    def ShowWindow(self, hwnd: int, cmd: int) -> bool:
        self.shown.append((hwnd, cmd))
        return True

    def SetWindowPos(self, hwnd: int, *_rest: Any) -> bool:
        self.positioned.append(hwnd)
        return True


def test_hide_returns_empty_off_windows() -> None:
    assert hide_input_desktop_windows_for_pids([100]) == []


def test_hide_returns_empty_when_no_valid_pids_remain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    assert hide_input_desktop_windows_for_pids([0, -1, True]) == []


def test_hide_hides_each_enumerated_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    user32 = _FakeUser32()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: user32, raising=False)
    monkeypatch.setattr(
        desktop_isolation,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 0x111, "pid": 42}, {"hwnd": 0x222, "pid": 42}],
    )
    hidden = hide_input_desktop_windows_for_pids([42, 42, -1])
    assert hidden == [0x111, 0x222]
    hide = desktop_isolation._SW_HIDE
    assert user32.shown == [(0x111, hide), (0x222, hide)]
    assert user32.positioned == [0x111, 0x222]
