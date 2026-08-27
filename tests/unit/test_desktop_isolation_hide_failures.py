"""A window the tool cannot hide must not be reported as hidden.

``hide_input_desktop_windows_for_pids`` is the input-desktop leak guard: it
returns the windows it pushed off the operator's desktop. A hwnd can vanish
between enumeration and the hide call, and a dialog owned by a higher-integrity
process is one UIPI forbids a lower-integrity debugger to touch -- that
unhideable dialog is the exact leak the guard exists for. Reporting it in the
"hidden" list would claim the desktop was cleared while the operator can still
see the window, so the returned list has to be the windows actually hidden, not
every window the call swept over. These tests are Win32 ctypes, so they never
run on the Linux CI and pin the behavior with a fake user32.
"""

from __future__ import annotations

import ctypes
import os
from typing import Any

import pytest

import headless_re_mcp.core.desktop_isolation as di


class _FakeUser32:
    """user32 stand-in whose SetWindowPos fails for a chosen set of hwnds."""

    def __init__(self, *, fail_hwnds: set[int] | None = None) -> None:
        self.fail_hwnds = set(fail_hwnds or ())
        self.show_calls: list[tuple[int, int]] = []
        self.pos_calls: list[tuple[int, int]] = []

    def ShowWindow(self, hwnd: int, cmd: int) -> int:
        self.show_calls.append((int(hwnd), int(cmd)))
        # Prior visibility, not success; the module must not key the result on it.
        return 1

    def SetWindowPos(
        self, hwnd: int, after: Any, x: int, y: int, cx: int, cy: int, flags: int
    ) -> int:
        self.pos_calls.append((int(hwnd), int(flags)))
        return 0 if int(hwnd) in self.fail_hwnds else 1


def _force_windows(monkeypatch: pytest.MonkeyPatch, user32: _FakeUser32) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: user32, raising=False)


def test_a_window_that_cannot_be_hidden_is_not_reported_as_hidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(fail_hwnds={0x20})
    _force_windows(monkeypatch, user32)
    monkeypatch.setattr(
        di,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 0x10}, {"hwnd": 0x20}, {"hwnd": 0x30}],
    )

    hidden = di.hide_input_desktop_windows_for_pids([42])

    # 0x20 failed SetWindowPos, so it stays out of the record even though it was
    # swept -- claiming it was hidden would hide a live leak.
    assert hidden == [0x10, 0x30]
    # The failed window is still attempted, not skipped: best-effort hide.
    assert [hwnd for hwnd, _cmd in user32.show_calls] == [0x10, 0x20, 0x30]
    assert [hwnd for hwnd, _flags in user32.pos_calls] == [0x10, 0x20, 0x30]


def test_every_window_is_reported_when_each_hide_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32()
    _force_windows(monkeypatch, user32)
    monkeypatch.setattr(
        di,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 0x11}, {"hwnd": 0x22}],
    )

    hidden = di.hide_input_desktop_windows_for_pids([7])

    assert hidden == [0x11, 0x22]
    hide_flag = di._SWP_HIDEWINDOW
    assert all(flags & hide_flag for _hwnd, flags in user32.pos_calls)


def test_none_reported_when_no_window_can_be_hidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(fail_hwnds={0x10, 0x20})
    _force_windows(monkeypatch, user32)
    monkeypatch.setattr(
        di,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 0x10}, {"hwnd": 0x20}],
    )

    hidden = di.hide_input_desktop_windows_for_pids([99])

    assert hidden == []
    # Both were still attempted before the result came back empty.
    assert len(user32.pos_calls) == 2
