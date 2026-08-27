"""Deterministic coverage for the SendInput UI fallback (``core.ui_sendinput``).

SendInput is the least-mediated UI backend: it synthesizes global input, so
every emission is bracketed by foreground-PID re-checks. These tests pin that
bracket on a non-Windows host by pinning ``os.name`` to ``"nt"`` and scripting
a fake ``user32`` (foreground sequence, window owners, rectangles), while the
real ctypes INPUT structures keep the wire format honest.
"""

from __future__ import annotations

import ctypes
import os
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_sendinput as si
from headless_re_mcp.core.windows import UiPidBoundaryError

ALLOWED = frozenset({100})


class _OsProxy:
    name = "nt"

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


class _FakeUser32:
    """Scripted Win32 surface: foreground sequence, owners, rect, SendInput."""

    def __init__(
        self,
        *,
        foreground_script: list[int] | None = None,
        tids: dict[int, int] | None = None,
        root_map: dict[int, int] | None = None,
        rect: tuple[int, int, int, int] = (100, 100, 300, 200),
        rect_ok: bool = True,
        screen: tuple[int, int] = (1920, 1080),
        send_result: int | None = None,
    ) -> None:
        self.foreground_script = list(foreground_script or [])
        self.tids = dict(tids or {})
        self.root_map = dict(root_map or {})
        self.rect = rect
        self.rect_ok = rect_ok
        self.screen = screen
        self.send_result = send_result
        self.sent: list[tuple[int, int, int, int, int]] = []
        self.calls: list[tuple[str, tuple[int, ...]]] = []

    @staticmethod
    def _hwnd(value: Any) -> int:
        return int(value.value or 0) if isinstance(value, ctypes.c_void_p) else int(value or 0)

    def GetForegroundWindow(self) -> int:
        if len(self.foreground_script) > 1:
            return self.foreground_script.pop(0)
        return self.foreground_script[0] if self.foreground_script else 0

    def GetAncestor(self, hwnd: Any, flag: int) -> int:
        return self.root_map.get(self._hwnd(hwnd), self._hwnd(hwnd))

    def GetWindowThreadProcessId(self, hwnd: Any, pid_out: Any) -> int:
        return self.tids.get(self._hwnd(hwnd), 0)

    def ShowWindow(self, hwnd: Any, mode: int) -> int:
        self.calls.append(("ShowWindow", (self._hwnd(hwnd), mode)))
        return 1

    def BringWindowToTop(self, hwnd: Any) -> int:
        self.calls.append(("BringWindowToTop", (self._hwnd(hwnd),)))
        return 1

    def SwitchToThisWindow(self, hwnd: Any, alt_tab: bool) -> None:
        self.calls.append(("SwitchToThisWindow", (self._hwnd(hwnd), int(alt_tab))))

    def AttachThreadInput(self, current: int, other: int, attach: bool) -> int:
        self.calls.append(("AttachThreadInput", (current, other, int(attach))))
        return 1

    def keybd_event(self, vk: int, scan: int, flags: int, extra: int) -> None:
        self.calls.append(("keybd_event", (vk, scan, flags, extra)))

    def SetForegroundWindow(self, hwnd: Any) -> int:
        self.calls.append(("SetForegroundWindow", (self._hwnd(hwnd),)))
        return 1

    def SetActiveWindow(self, hwnd: Any) -> int:
        self.calls.append(("SetActiveWindow", (self._hwnd(hwnd),)))
        return 1

    def SetFocus(self, hwnd: Any) -> int:
        self.calls.append(("SetFocus", (self._hwnd(hwnd),)))
        return 1

    def GetWindowRect(self, hwnd: Any, rect_ref: Any) -> int:
        if not self.rect_ok:
            return 0
        rect = rect_ref._obj
        rect.left, rect.top, rect.right, rect.bottom = self.rect
        return 1

    def GetSystemMetrics(self, index: int) -> int:
        return self.screen[index]

    def SendInput(self, count: int, array_ref: Any, size: int) -> int:
        for index in range(count):
            item = array_ref._obj[index]
            if item.type == si.INPUT_MOUSE:
                mi = item.union.mi
                self.sent.append((item.type, mi.dx, mi.dy, mi.dwFlags, 0))
            else:
                ki = item.union.ki
                self.sent.append((item.type, ki.wVk, ki.wScan, ki.dwFlags, 0))
        return self.send_result if self.send_result is not None else count

    def named(self, name: str) -> list[tuple[int, ...]]:
        return [args for called, args in self.calls if called == name]


class _CtypesProxy:
    def __init__(self, user32: _FakeUser32) -> None:
        self.windll = SimpleNamespace(user32=user32)

    def WinDLL(self, name: str, *, use_last_error: bool = False) -> Any:
        return SimpleNamespace(GetCurrentThreadId=lambda: 111)

    def get_last_error(self) -> int:
        return 5  # ERROR_ACCESS_DENIED, so envelopes carry a real-looking code

    def __getattr__(self, attribute: str) -> Any:
        return getattr(ctypes, attribute)


def _pin(
    monkeypatch: pytest.MonkeyPatch,
    user32: _FakeUser32,
    *,
    owners: dict[int, int] | None = None,
) -> None:
    owner_map = dict(owners or {})
    monkeypatch.setattr(si, "os", _OsProxy())
    monkeypatch.setattr(si, "ctypes", _CtypesProxy(user32))
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: owner_map.get(int(hwnd), 0))
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, allowed: None)
    monkeypatch.setattr(
        si,
        "time",
        SimpleNamespace(monotonic=_ticker(step=0.6), sleep=lambda seconds: None),
    )


def _ticker(*, step: float) -> Any:
    state = {"now": 0.0}

    def monotonic() -> float:
        state["now"] += step
        return state["now"]

    return monotonic


# ---------------------------------------------------------------------------
# Platform gate and foreground probes.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="the refusal only exists off Windows")
def test_sendinput_is_refused_off_windows() -> None:
    with pytest.raises(UiPidBoundaryError) as refused:
        si.foreground_hwnd()
    assert refused.value.code == "unsupported_on_platform"


def test_foreground_pid_is_zero_without_a_foreground_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(foreground_script=[0]), owners={7: 100})
    assert si.foreground_pid() == 0


def test_foreground_pid_reads_the_window_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(foreground_script=[7]), owners={7: 100})
    assert si.foreground_pid() == 100


def test_no_foreground_window_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(foreground_script=[0]))
    with pytest.raises(UiPidBoundaryError) as refused:
        si.require_foreground_allowed(ALLOWED)
    assert refused.value.code == "permission_denied"


def test_disallowed_foreground_owner_is_named_in_the_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(foreground_script=[7]), owners={7: 999})
    with pytest.raises(UiPidBoundaryError) as refused:
        si.require_foreground_allowed(ALLOWED)
    assert refused.value.code == "permission_denied"
    assert refused.value.details["foreground_pid"] == 999
    assert refused.value.details["allowed_pids"] == [100]


def test_allowed_foreground_returns_the_owner_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(foreground_script=[7]), owners={7: 100})
    assert si.require_foreground_allowed(ALLOWED) == 100


# ---------------------------------------------------------------------------
# Geometry helpers.
# ---------------------------------------------------------------------------


def test_window_center_averages_the_rectangle(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(rect=(100, 100, 300, 200)))
    assert si._window_center(5) == (200, 150)


def test_window_center_failure_carries_the_win32_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(rect_ok=False))
    with pytest.raises(UiPidBoundaryError) as refused:
        si._window_center(5)
    assert refused.value.code == "backend_error"
    assert refused.value.details["winerror"] == 5


def test_absolute_mouse_scaling_and_zero_screen_clamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(screen=(1920, 1080)))
    assert si._abs_mouse(960, 540) == (960 * 65535 // 1920, 540 * 65535 // 1080)

    _pin(monkeypatch, _FakeUser32(screen=(0, 0)))
    assert si._abs_mouse(3, 4) == (3 * 65535, 4 * 65535), "a 0x0 screen must not divide by zero"


def test_partial_sendinput_delivery_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(send_result=1)
    _pin(monkeypatch, user32)
    first = si._INPUT(type=si.INPUT_KEYBOARD)
    second = si._INPUT(type=si.INPUT_KEYBOARD)
    with pytest.raises(UiPidBoundaryError) as refused:
        si._send_input([first, second])
    assert refused.value.code == "backend_error"
    assert refused.value.details == {"expected": 2, "sent": 1, "winerror": 5}


# ---------------------------------------------------------------------------
# _bring_to_foreground: focus dance, activation fallbacks, and re-checks.
# ---------------------------------------------------------------------------


def test_focus_dance_attaches_and_detaches_the_foreground_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Another window (9, owned by 999) holds the foreground for one poll, then
    # the target (5) wins. Thread input must be attached and then detached.
    user32 = _FakeUser32(foreground_script=[9, 5, 5], tids={5: 222, 9: 990})
    _pin(monkeypatch, user32, owners={5: 100, 9: 999})

    si._bring_to_foreground(5, ALLOWED)

    assert ("AttachThreadInput", (111, 990, 1)) in user32.calls
    assert ("AttachThreadInput", (111, 990, 0)) in user32.calls
    assert ("AttachThreadInput", (111, 222, 1)) in user32.calls
    assert ("AttachThreadInput", (111, 222, 0)) in user32.calls
    assert user32.named("SetForegroundWindow") == [(5,)]
    assert not user32.named("keybd_event"), "no Alt nudge while a foreground queue exists"


def test_an_empty_desktop_uses_the_bounded_alt_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground_script=[0, 5, 5], tids={5: 222})
    _pin(monkeypatch, user32, owners={5: 100})

    si._bring_to_foreground(5, ALLOWED)

    assert user32.named("SwitchToThisWindow") == [(5, 1)]
    assert user32.named("keybd_event") == [
        (si.VK_MENU, 0, 0, 0),
        (si.VK_MENU, 0, si.KEYEVENTF_KEYUP, 0),
    ], "the Alt press must always be released"
    assert user32.named("SetActiveWindow") == [(5,)]
    assert user32.named("SetFocus") == [(5,)]


def test_a_child_hwnd_is_resolved_to_its_authorized_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground_script=[7, 7], root_map={5: 7}, tids={5: 222, 7: 222})
    _pin(monkeypatch, user32, owners={5: 100, 7: 100})
    checked: list[int] = []
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, allowed: checked.append(hwnd))

    si._bring_to_foreground(5, ALLOWED)

    assert checked == [5, 7], "both the child and its root run the PID boundary"
    assert user32.named("ShowWindow") == [(7, 9)], "the root, not the child, is restored"


def test_an_unauthorized_root_is_refused_before_any_focus_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground_script=[0], root_map={5: 7})
    _pin(monkeypatch, user32, owners={5: 100, 7: 999})

    def gate(hwnd: int, allowed: frozenset[int]) -> None:
        if hwnd == 7:
            raise UiPidBoundaryError("permission_denied", "root not allowed", hwnd=hwnd)

    monkeypatch.setattr(si, "require_allowed_hwnd", gate)

    with pytest.raises(UiPidBoundaryError):
        si._bring_to_foreground(5, ALLOWED)
    assert user32.named("ShowWindow") == [], "no window may be touched after a refusal"


def test_a_foreground_that_never_arrives_times_out_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground_script=[9], tids={5: 222, 9: 990})
    _pin(monkeypatch, user32, owners={5: 100, 9: 999})

    with pytest.raises(UiPidBoundaryError) as refused:
        si._bring_to_foreground(5, ALLOWED)

    assert refused.value.code == "permission_denied"
    assert refused.value.details["foreground_pid"] == 999


def test_an_owner_that_becomes_allowed_after_the_wait_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wait can lose the race and still end well: the re-check decides."""
    user32 = _FakeUser32(foreground_script=[5], tids={5: 111})
    _pin(monkeypatch, user32, owners={5: 100})

    clock = {"now": 0.0}

    def monotonic() -> float:
        clock["now"] += 0.6
        return clock["now"]

    monkeypatch.setattr(si, "time", SimpleNamespace(monotonic=monotonic, sleep=lambda s: None))
    # Disallowed while the wait polls, allowed once the deadline (0.6 + 2.0)
    # has passed: the poll never succeeds, but the final re-check does.
    monkeypatch.setattr(
        si,
        "hwnd_owner_pid",
        lambda hwnd: 100 if clock["now"] > 2.6 else 999,
    )

    si._bring_to_foreground(5, ALLOWED)

    attaches = user32.named("AttachThreadInput")
    assert attaches == [], "a target on the caller's own thread must not attach input"


def test_the_post_wait_owner_recheck_catches_a_foreground_flip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Line-of-defense test: even after the wait, the owner is read again."""
    user32 = _FakeUser32(foreground_script=[9], tids={5: 222, 9: 990})
    _pin(monkeypatch, user32, owners={5: 100, 9: 999})
    monkeypatch.setattr(si, "require_foreground_allowed", lambda allowed: 100)

    with pytest.raises(UiPidBoundaryError) as refused:
        si._bring_to_foreground(5, ALLOWED)

    assert refused.value.code == "permission_denied"
    assert "failed to bring target hwnd to foreground" in refused.value.message
    assert refused.value.details["foreground_pid"] == 999


# ---------------------------------------------------------------------------
# click / key emission through the full bracket.
# ---------------------------------------------------------------------------


def test_click_emits_move_down_up_at_the_window_center(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(
        foreground_script=[5],
        tids={5: 222},
        rect=(100, 100, 300, 200),
        screen=(1000, 500),
    )
    _pin(monkeypatch, user32, owners={5: 100})

    envelope = si.click_hwnd_sendinput(5, ALLOWED)

    ax, ay = 200 * 65535 // 1000, 150 * 65535 // 500
    move_abs = si.MOUSEEVENTF_MOVE | si.MOUSEEVENTF_ABSOLUTE
    assert user32.sent == [
        (si.INPUT_MOUSE, ax, ay, move_abs, 0),
        (si.INPUT_MOUSE, ax, ay, si.MOUSEEVENTF_LEFTDOWN | si.MOUSEEVENTF_ABSOLUTE, 0),
        (si.INPUT_MOUSE, ax, ay, si.MOUSEEVENTF_LEFTUP | si.MOUSEEVENTF_ABSOLUTE, 0),
    ]
    assert envelope["action"] == "click" and envelope["backend"] == "sendinput"
    assert envelope["foreground_pid"] == 100
    assert (envelope["screen_x"], envelope["screen_y"]) == (200, 150)


def test_text_keys_are_unicode_down_up_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(foreground_script=[5], tids={5: 222})
    _pin(monkeypatch, user32, owners={5: 100})

    envelope = si.send_key_sendinput(5, allowed_pids=ALLOWED, text="ab")

    unicode_up = si.KEYEVENTF_UNICODE | si.KEYEVENTF_KEYUP
    assert user32.sent == [
        (si.INPUT_KEYBOARD, 0, ord("a"), si.KEYEVENTF_UNICODE, 0),
        (si.INPUT_KEYBOARD, 0, ord("a"), unicode_up, 0),
        (si.INPUT_KEYBOARD, 0, ord("b"), si.KEYEVENTF_UNICODE, 0),
        (si.INPUT_KEYBOARD, 0, ord("b"), unicode_up, 0),
    ]
    assert envelope["text"] == "ab" and envelope["action"] == "key"


def test_virtual_keys_are_plain_down_up_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(foreground_script=[5], tids={5: 222})
    _pin(monkeypatch, user32, owners={5: 100})

    envelope = si.send_key_sendinput(5, allowed_pids=ALLOWED, vk=13)

    assert user32.sent == [
        (si.INPUT_KEYBOARD, 13, 0, 0, 0),
        (si.INPUT_KEYBOARD, 13, 0, si.KEYEVENTF_KEYUP, 0),
    ]
    assert envelope["vk"] == 13


def test_key_argument_shapes_are_refused_before_any_focus_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground_script=[5], tids={5: 222})
    _pin(monkeypatch, user32, owners={5: 100})

    for kwargs in ({"text": "a", "vk": 13}, {}):
        with pytest.raises(UiPidBoundaryError) as refused:
            si.send_key_sendinput(5, allowed_pids=ALLOWED, **kwargs)  # type: ignore[arg-type]
        assert refused.value.code == "invalid_params"
    assert user32.calls == [], "argument refusals must precede the focus dance"


@pytest.mark.parametrize("text", ["", "x" * 33, 42])
def test_hostile_text_payloads_are_refused(
    monkeypatch: pytest.MonkeyPatch,
    text: Any,
) -> None:
    user32 = _FakeUser32(foreground_script=[5], tids={5: 222})
    _pin(monkeypatch, user32, owners={5: 100})

    with pytest.raises(UiPidBoundaryError) as refused:
        si.send_key_sendinput(5, allowed_pids=ALLOWED, text=text)

    assert refused.value.code == "invalid_params"
    assert user32.sent == [], "nothing may be synthesized for a refused payload"


@pytest.mark.parametrize("vk", [0, 0xFF, True, "13"])
def test_hostile_virtual_keys_are_refused(monkeypatch: pytest.MonkeyPatch, vk: Any) -> None:
    user32 = _FakeUser32(foreground_script=[5], tids={5: 222})
    _pin(monkeypatch, user32, owners={5: 100})

    with pytest.raises(UiPidBoundaryError) as refused:
        si.send_key_sendinput(5, allowed_pids=ALLOWED, vk=vk)

    assert refused.value.code == "invalid_params"
    assert user32.sent == []
