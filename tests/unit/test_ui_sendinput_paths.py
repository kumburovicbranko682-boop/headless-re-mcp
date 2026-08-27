"""Coverage for the SendInput UI fallback on a non-Windows host.

The module only runs on Windows: it reaches for ``ctypes.windll.user32`` and a
``kernel32`` WinDLL, and gates every action behind a foreground-PID re-check.
These tests fake ``os.name`` as ``"nt"``, install fake user32/kernel32 handles
that drive the real activation loop, and script a monotonic clock so the
2-second focus wait resolves instantly.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import time
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_sendinput as si
from headless_re_mcp.core.ui_sendinput import (
    _abs_mouse,
    _send_input,
    _user32,
    _window_center,
    click_hwnd_sendinput,
    foreground_pid,
    require_foreground_allowed,
    send_key_sendinput,
)
from headless_re_mcp.core.windows import UiPidBoundaryError


class _FakeUser32:
    def __init__(
        self,
        *,
        foreground: list[int],
        tid_map: dict[int, int] | None = None,
        rect: tuple[int, int, int, int] = (0, 0, 100, 50),
        rect_ok: bool = True,
        sysmetrics: tuple[int, int] = (1920, 1080),
        sendinput: int | None = None,
        ancestor: int | None = None,
    ) -> None:
        self._fg = foreground
        self._fg_i = 0
        self._tid_map = tid_map or {}
        self._rect = rect
        self._rect_ok = rect_ok
        self._w, self._h = sysmetrics
        self._sendinput = sendinput
        self._ancestor = ancestor

    def GetForegroundWindow(self) -> int:
        index = min(self._fg_i, len(self._fg) - 1)
        self._fg_i += 1
        return self._fg[index]

    def GetAncestor(self, hwnd: Any, flag: int) -> int:
        return self._ancestor if self._ancestor is not None else int(hwnd.value or 0)

    def ShowWindow(self, *args: Any) -> int:
        return 1

    def BringWindowToTop(self, *args: Any) -> int:
        return 1

    def SwitchToThisWindow(self, *args: Any) -> int:
        return 1

    def SetForegroundWindow(self, *args: Any) -> int:
        return 1

    def SetActiveWindow(self, *args: Any) -> int:
        return 1

    def SetFocus(self, *args: Any) -> int:
        return 1

    def keybd_event(self, *args: Any) -> int:
        return 0

    def GetWindowThreadProcessId(self, hwnd: Any, out: Any) -> int:
        value = int(hwnd.value or 0) if hwnd else 0
        return self._tid_map.get(value, 20)

    def AttachThreadInput(self, a: int, b: int, c: bool) -> int:
        return 1

    def GetWindowRect(self, hwnd: Any, rect_ptr: Any) -> int:
        if not self._rect_ok:
            return 0
        rect = rect_ptr._obj
        rect.left, rect.top, rect.right, rect.bottom = self._rect
        return 1

    def GetSystemMetrics(self, idx: int) -> int:
        return self._w if idx == 0 else self._h

    def SendInput(self, n: int, arr: Any, size: int) -> int:
        return n if self._sendinput is None else self._sendinput


def _install(monkeypatch: pytest.MonkeyPatch, user32: _FakeUser32) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(user32=user32), raising=False)
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, use_last_error=False: SimpleNamespace(GetCurrentThreadId=lambda: 10),
        raising=False,
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)


def _clock(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> None:
    ticks = iter(values)
    last = [values[-1] if values else 0.0]

    def monotonic() -> float:
        with contextlib.suppress(StopIteration):
            last[0] = next(ticks)
        return last[0]

    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(time, "sleep", lambda s: None)


def _allow_hwnd(monkeypatch: pytest.MonkeyPatch, pid_for_hwnd: Any) -> None:
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, allowed: None)
    monkeypatch.setattr(si, "hwnd_owner_pid", pid_for_hwnd)


# --------------------------------------------------------------------------
# _user32 / foreground helpers
# --------------------------------------------------------------------------


def test_user32_is_unavailable_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(UiPidBoundaryError) as info:
        _user32()
    assert info.value.code == "unsupported_on_platform"


def test_foreground_pid_is_zero_without_a_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[0]))
    assert foreground_pid() == 0


def test_foreground_pid_reads_the_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 5)
    assert foreground_pid() == 5


def test_require_foreground_allowed_needs_a_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[0]))
    with pytest.raises(UiPidBoundaryError, match="no foreground window"):
        require_foreground_allowed(frozenset({5}))


def test_require_foreground_allowed_rejects_a_foreign_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 999)
    with pytest.raises(UiPidBoundaryError) as info:
        require_foreground_allowed(frozenset({5}))
    assert info.value.code == "permission_denied"


def test_require_foreground_allowed_returns_the_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 5)
    assert require_foreground_allowed(frozenset({5})) == 5


# --------------------------------------------------------------------------
# _window_center / _abs_mouse / _send_input
# --------------------------------------------------------------------------


def test_window_center_averages_the_rect(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100], rect=(10, 20, 30, 60)))
    assert _window_center(100) == (20, 40)


def test_window_center_maps_a_getwindowrect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100], rect_ok=False))
    with pytest.raises(UiPidBoundaryError) as info:
        _window_center(100)
    assert info.value.code == "backend_error"


def test_abs_mouse_scales_to_the_virtual_desktop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100], sysmetrics=(1000, 500)))
    assert _abs_mouse(500, 250) == (32767, 32767)


def test_send_input_maps_a_partial_write(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100], sendinput=0))
    down = si._INPUT(type=si.INPUT_KEYBOARD)
    with pytest.raises(UiPidBoundaryError) as info:
        _send_input([down])
    assert info.value.code == "backend_error"


# --------------------------------------------------------------------------
# _bring_to_foreground activation loop
# --------------------------------------------------------------------------


def test_bring_to_foreground_returns_when_already_focused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100, 100]))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _clock(monkeypatch, [0.0, 0.0])
    si._bring_to_foreground(100, frozenset({5}))


def test_bring_to_foreground_activates_an_empty_desktop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First poll sees no foreground (fg<=0), driving the SwitchToThisWindow /
    # Alt-key activation path; the second poll finds the target focused.
    _install(monkeypatch, _FakeUser32(foreground=[0, 100, 100]))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _clock(monkeypatch, [0.0, 0.0, 0.1])
    si._bring_to_foreground(100, frozenset({5}))


def test_bring_to_foreground_attaches_to_a_foreign_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A different, live foreground window forces the AttachThreadInput dance.
    user32 = _FakeUser32(foreground=[0x999, 100, 100], tid_map={0x999: 20, 100: 30})
    _install(monkeypatch, user32)
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _clock(monkeypatch, [0.0, 0.0, 0.1])
    si._bring_to_foreground(100, frozenset({5}))


def test_bring_to_foreground_skips_attach_when_target_is_our_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # target tid == current thread id, so its AttachThreadInput is skipped on
    # both the attach and the detach side.
    user32 = _FakeUser32(foreground=[0x999, 100, 100], tid_map={0x999: 20, 100: 10})
    _install(monkeypatch, user32)
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _clock(monkeypatch, [0.0, 0.0, 0.1])
    si._bring_to_foreground(100, frozenset({5}))


def test_bring_to_foreground_times_out_but_pid_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[0x999], tid_map={0x999: 20, 100: 30}))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _clock(monkeypatch, [0.0, 0.0, 3.0])
    si._bring_to_foreground(100, frozenset({5}))


def test_bring_to_foreground_fails_when_focus_slips_after_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[0x999], tid_map={0x999: 20, 100: 30}))
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, allowed: None)
    owners = iter([5, 999, 999])

    def owner(hwnd: int) -> int:
        try:
            return next(owners)
        except StopIteration:
            return 999

    monkeypatch.setattr(si, "hwnd_owner_pid", owner)
    _clock(monkeypatch, [0.0, 3.0])
    with pytest.raises(UiPidBoundaryError) as info:
        si._bring_to_foreground(100, frozenset({5}))
    assert info.value.code == "permission_denied"


# --------------------------------------------------------------------------
# click_hwnd_sendinput / send_key_sendinput
# --------------------------------------------------------------------------


def _isolate_bring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(si, "_bring_to_foreground", lambda hwnd, allowed: None)


def test_click_sendinput_emits_the_three_mouse_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100], rect=(0, 0, 40, 20)))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _isolate_bring(monkeypatch)
    result = click_hwnd_sendinput(100, frozenset({5}))
    assert result["action"] == "click"
    assert result["backend"] == "sendinput"
    assert result["screen_x"] == 20
    assert result["foreground_pid"] == 5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"text": "a", "vk": 65},
        {},
    ],
)
def test_send_key_sendinput_requires_exactly_one_of_text_or_vk(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any]
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _isolate_bring(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="text or vk"):
        send_key_sendinput(100, allowed_pids=frozenset({5}), **kwargs)


def test_send_key_sendinput_types_text(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _isolate_bring(monkeypatch)
    result = send_key_sendinput(100, allowed_pids=frozenset({5}), text="hi")
    assert result["text"] == "hi"
    assert result["action"] == "key"


@pytest.mark.parametrize("text", ["", "x" * 33])
def test_send_key_sendinput_rejects_bad_text(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _isolate_bring(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="at most 32"):
        send_key_sendinput(100, allowed_pids=frozenset({5}), text=text)


def test_send_key_sendinput_sends_a_virtual_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _isolate_bring(monkeypatch)
    result = send_key_sendinput(100, allowed_pids=frozenset({5}), vk=65)
    assert result["vk"] == 65
    assert result["action"] == "key"


@pytest.mark.parametrize("vk", [0, 0xFF, 3.0])
def test_send_key_sendinput_rejects_a_bad_vk(monkeypatch: pytest.MonkeyPatch, vk: Any) -> None:
    _install(monkeypatch, _FakeUser32(foreground=[100]))
    _allow_hwnd(monkeypatch, lambda hwnd: 5)
    _isolate_bring(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="1..254"):
        send_key_sendinput(100, allowed_pids=frozenset({5}), vk=vk)
