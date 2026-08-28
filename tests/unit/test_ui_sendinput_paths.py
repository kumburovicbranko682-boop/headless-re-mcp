"""Coverage for the SendInput UI fallback and its fail-closed foreground gate.

ui_sendinput.py wraps a dozen user32/kernel32 entry points behind a strict
"foreground window must belong to an allowed PID" contract. The real DLL calls
are faked and the activation loop's clock is driven deterministically, so every
arm runs on any platform: the platform guard, the foreground allow-list, the
window-rect and SendInput error raises, the activation retry loop (immediate
match, full attach/activate path, and the two fail-closed exits), and the
click/key orchestration including argument validation.
"""

from __future__ import annotations

import ctypes
import os
import types
from typing import Any

import pytest

import headless_re_mcp.core.ui_sendinput as si
from headless_re_mcp.core.windows import UiPidBoundaryError

JsonObject = dict[str, Any]


class _NtOsProxy:
    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


class _FakeUser32:
    """A user32 stand-in recording focus calls and answering the geometry probes."""

    def __init__(
        self,
        *,
        foreground: list[int] | int = 0,
        rect: tuple[int, int, int, int] = (0, 0, 200, 100),
        rect_ok: bool = True,
        metrics: tuple[int, int] = (1920, 1080),
        send_input_count: int | None = None,
        ancestor: int = 0,
        tid: int = 10,
    ) -> None:
        self._foreground = foreground if isinstance(foreground, list) else [foreground]
        self._rect = rect
        self._rect_ok = rect_ok
        self._metrics = metrics
        self._send_input_count = send_input_count
        self._ancestor = ancestor
        self._tid = tid
        self.calls: list[str] = []

    def _next_foreground(self) -> int:
        if len(self._foreground) > 1:
            return self._foreground.pop(0)
        return self._foreground[0] if self._foreground else 0

    def GetForegroundWindow(self) -> int:  # noqa: N802
        return self._next_foreground()

    def GetWindowRect(self, hwnd: Any, rect_ref: Any) -> int:  # noqa: N802
        if not self._rect_ok:
            return 0
        rect = rect_ref._obj
        rect.left, rect.top, rect.right, rect.bottom = self._rect
        return 1

    def GetSystemMetrics(self, index: int) -> int:  # noqa: N802
        return self._metrics[0] if index == si.SM_CXSCREEN else self._metrics[1]

    def SendInput(self, count: int, array: Any, size: int) -> int:  # noqa: N802
        self.calls.append(f"SendInput:{count}")
        return count if self._send_input_count is None else self._send_input_count

    def GetAncestor(self, hwnd: Any, flag: int) -> int:  # noqa: N802
        return self._ancestor

    def GetWindowThreadProcessId(self, hwnd: Any, pid_ref: Any) -> int:  # noqa: N802
        return self._tid

    def AttachThreadInput(self, a: int, b: int, attach: bool) -> int:  # noqa: N802
        self.calls.append(f"attach:{a}:{b}:{attach}")
        return 1

    def __getattr__(self, name: str) -> Any:
        # Every remaining focus verb (ShowWindow, BringWindowToTop, keybd_event,
        # SwitchToThisWindow, SetForegroundWindow, SetActiveWindow, SetFocus) is
        # a fire-and-forget recorder.
        def recorder(*args: Any) -> int:
            self.calls.append(name)
            return 1

        return recorder


def _install_user32(monkeypatch: pytest.MonkeyPatch, user32: _FakeUser32) -> None:
    monkeypatch.setattr(si, "_user32", lambda: user32)


def _install_kernel32(monkeypatch: pytest.MonkeyPatch, *, tid: int = 1) -> None:
    kernel32 = types.SimpleNamespace(GetCurrentThreadId=lambda: tid)
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, use_last_error=False: kernel32, raising=False
    )


def _clock(monkeypatch: pytest.MonkeyPatch, monotonic_values: list[float]) -> None:
    values = list(monotonic_values)

    def monotonic() -> float:
        return values.pop(0) if len(values) > 1 else (values[0] if values else 0.0)

    monkeypatch.setattr(
        si, "time", types.SimpleNamespace(monotonic=monotonic, sleep=lambda _s: None)
    )


# --------------------------------------------------------------------------- #
# _user32 platform guard
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_user32_refuses_off_windows() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        si._user32()
    assert exc.value.code == "unsupported_on_platform"


def test_user32_returns_the_windll_table_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table = object()
    monkeypatch.setattr(si, "os", _NtOsProxy())
    monkeypatch.setattr(ctypes, "windll", types.SimpleNamespace(user32=table), raising=False)
    assert si._user32() is table


# --------------------------------------------------------------------------- #
# foreground probes and the allow-list
# --------------------------------------------------------------------------- #


def test_foreground_pid_is_zero_without_a_foreground_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_user32(monkeypatch, _FakeUser32(foreground=0))
    assert si.foreground_hwnd() == 0
    assert si.foreground_pid() == 0


def test_foreground_pid_resolves_the_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_user32(monkeypatch, _FakeUser32(foreground=55))
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)
    assert si.foreground_pid() == 4242


def test_require_foreground_refuses_when_there_is_no_foreground(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_user32(monkeypatch, _FakeUser32(foreground=0))
    with pytest.raises(UiPidBoundaryError) as exc:
        si.require_foreground_allowed(frozenset({4242}))
    assert exc.value.code == "permission_denied"


def test_require_foreground_refuses_a_disallowed_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_user32(monkeypatch, _FakeUser32(foreground=55))
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 999)
    with pytest.raises(UiPidBoundaryError) as exc:
        si.require_foreground_allowed(frozenset({4242}))
    assert exc.value.code == "permission_denied"
    assert exc.value.details["foreground_pid"] == 999


def test_require_foreground_accepts_an_allowed_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_user32(monkeypatch, _FakeUser32(foreground=55))
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)
    assert si.require_foreground_allowed(frozenset({4242})) == 4242


# --------------------------------------------------------------------------- #
# geometry helpers
# --------------------------------------------------------------------------- #


def test_window_center_averages_the_rect(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_user32(monkeypatch, _FakeUser32(rect=(10, 20, 110, 220)))
    assert si._window_center(123) == (60, 120)


def test_window_center_raises_when_the_rect_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    _install_user32(monkeypatch, _FakeUser32(rect_ok=False))
    with pytest.raises(UiPidBoundaryError) as exc:
        si._window_center(123)
    assert exc.value.code == "backend_error"


def test_abs_mouse_scales_into_the_0_65535_grid(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_user32(monkeypatch, _FakeUser32(metrics=(1920, 1080)))
    ax, ay = si._abs_mouse(960, 540)
    assert ax == int(960 * 65535 / 1920)
    assert ay == int(540 * 65535 / 1080)


def test_abs_mouse_floors_zero_metrics_to_one(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_user32(monkeypatch, _FakeUser32(metrics=(0, 0)))
    assert si._abs_mouse(0, 0) == (0, 0)


# --------------------------------------------------------------------------- #
# _send_input
# --------------------------------------------------------------------------- #


def test_send_input_accepts_a_full_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_user32(monkeypatch, _FakeUser32(send_input_count=2))
    si._send_input([si._INPUT(type=si.INPUT_MOUSE), si._INPUT(type=si.INPUT_MOUSE)])


def test_send_input_raises_on_a_short_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 8, raising=False)
    _install_user32(monkeypatch, _FakeUser32(send_input_count=1))
    with pytest.raises(UiPidBoundaryError) as exc:
        si._send_input([si._INPUT(type=si.INPUT_MOUSE), si._INPUT(type=si.INPUT_MOUSE)])
    assert exc.value.code == "backend_error"
    assert exc.value.details["sent"] == 1


# --------------------------------------------------------------------------- #
# _bring_to_foreground activation loop
# --------------------------------------------------------------------------- #


def test_bring_to_foreground_returns_when_the_target_is_already_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground=200, ancestor=200)
    _install_user32(monkeypatch, user32)
    _install_kernel32(monkeypatch)
    _clock(monkeypatch, [0.0])
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)

    si._bring_to_foreground(123, frozenset({4242}))

    # No activation verbs were needed because the root was already foreground.
    assert "SetForegroundWindow" not in user32.calls


def test_bring_to_foreground_runs_the_full_activation_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First loop sees no foreground (0), takes the attach + Alt-activate path,
    # then the root becomes foreground and the fail-closed post-check passes.
    user32 = _FakeUser32(foreground=[0, 200, 200, 200], ancestor=200, tid=10)
    _install_user32(monkeypatch, user32)
    _install_kernel32(monkeypatch, tid=1)
    _clock(monkeypatch, [0.0])
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)

    si._bring_to_foreground(123, frozenset({4242}))

    assert "SwitchToThisWindow" in user32.calls
    assert "SetForegroundWindow" in user32.calls
    assert any(call.startswith("attach:1:10:True") for call in user32.calls)


def test_bring_to_foreground_attaches_to_a_foreign_foreground_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A foreign app (positive HWND, not the target) owns the foreground, so the
    # loop attaches both input queues, activates, detaches, and then the target
    # becomes foreground on the next pass.
    user32 = _FakeUser32(foreground=[50, 200, 200, 200], ancestor=200, tid=10)
    _install_user32(monkeypatch, user32)
    _install_kernel32(monkeypatch, tid=1)
    _clock(monkeypatch, [0.0])
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)

    si._bring_to_foreground(123, frozenset({4242}))

    assert "SwitchToThisWindow" not in user32.calls, "a live foreground needs no SwitchTo"
    assert any(call == "attach:1:10:True" for call in user32.calls)
    assert any(call == "attach:1:10:False" for call in user32.calls)


def test_bring_to_foreground_fails_closed_when_focus_never_lands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground=7, ancestor=200)
    _install_user32(monkeypatch, user32)
    _install_kernel32(monkeypatch)
    # deadline calc reads 0.0; the loop guard reads 5.0 (past the 2s deadline).
    _clock(monkeypatch, [0.0, 5.0])
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 999)

    with pytest.raises(UiPidBoundaryError) as exc:
        si._bring_to_foreground(123, frozenset({4242}))
    assert exc.value.code == "permission_denied"


def test_bring_to_foreground_returns_after_the_loop_when_the_owner_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The loop guard is already past the deadline, but the foreground now
    # belongs to the allowed PID, so both post-checks pass and it returns.
    user32 = _FakeUser32(foreground=7, ancestor=200)
    _install_user32(monkeypatch, user32)
    _install_kernel32(monkeypatch)
    _clock(monkeypatch, [0.0, 5.0])
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)

    si._bring_to_foreground(123, frozenset({4242}))


def test_bring_to_foreground_skips_attach_when_target_is_the_current_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When the target and foreground threads are the caller's own thread there is
    # nothing to attach: the attach/detach arms are skipped entirely.
    user32 = _FakeUser32(foreground=[50, 200, 200, 200], ancestor=200, tid=1)
    _install_user32(monkeypatch, user32)
    _install_kernel32(monkeypatch, tid=1)
    _clock(monkeypatch, [0.0])
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)

    si._bring_to_foreground(123, frozenset({4242}))

    assert not any(call.startswith("attach:") for call in user32.calls)


def test_bring_to_foreground_rejects_a_sibling_owned_by_a_foreign_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground=7, ancestor=200)
    _install_user32(monkeypatch, user32)
    _install_kernel32(monkeypatch)
    _clock(monkeypatch, [0.0, 5.0])
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    # The allow-list post-check passes, but the immediate re-read of the
    # foreground owner returns a foreign PID: the extra guard must still fire.
    owners = iter([4242, 999, 999, 999])
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: next(owners))

    with pytest.raises(UiPidBoundaryError) as exc:
        si._bring_to_foreground(123, frozenset({4242}))
    assert exc.value.code == "permission_denied"
    assert "failed to bring target" in exc.value.args[0]


# --------------------------------------------------------------------------- #
# click orchestration
# --------------------------------------------------------------------------- #


def _click_ready(monkeypatch: pytest.MonkeyPatch, user32: _FakeUser32) -> None:
    _install_user32(monkeypatch, user32)
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda hwnd, pids: hwnd)
    monkeypatch.setattr(si, "_bring_to_foreground", lambda hwnd, pids: None)
    monkeypatch.setattr(si, "hwnd_owner_pid", lambda hwnd: 4242)


def test_click_moves_presses_and_releases_at_the_window_center(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(foreground=7, rect=(0, 0, 200, 100), metrics=(1920, 1080))
    _click_ready(monkeypatch, user32)

    result = si.click_hwnd_sendinput(123, frozenset({4242}))

    assert result["action"] == "click"
    assert result["backend"] == "sendinput"
    assert result["foreground_pid"] == 4242
    assert result["screen_x"] == 100
    assert result["screen_y"] == 50
    assert "SendInput:3" in user32.calls


# --------------------------------------------------------------------------- #
# send_key orchestration and validation
# --------------------------------------------------------------------------- #


def test_send_key_rejects_supplying_both_text_and_vk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _click_ready(monkeypatch, _FakeUser32(foreground=7))
    with pytest.raises(UiPidBoundaryError, match="not both"):
        si.send_key_sendinput(1, allowed_pids=frozenset({4242}), text="a", vk=65)


def test_send_key_requires_either_text_or_vk(monkeypatch: pytest.MonkeyPatch) -> None:
    _click_ready(monkeypatch, _FakeUser32(foreground=7))
    with pytest.raises(UiPidBoundaryError, match="provide text or vk"):
        si.send_key_sendinput(1, allowed_pids=frozenset({4242}))


@pytest.mark.parametrize("text", ["", "x" * 33])
def test_send_key_bounds_the_text_length(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    _click_ready(monkeypatch, _FakeUser32(foreground=7))
    with pytest.raises(UiPidBoundaryError, match="at most 32"):
        si.send_key_sendinput(1, allowed_pids=frozenset({4242}), text=text)


def test_send_key_types_unicode_text(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(foreground=7)
    _click_ready(monkeypatch, user32)

    result = si.send_key_sendinput(1, allowed_pids=frozenset({4242}), text="Hi")

    assert result["action"] == "key"
    assert result["text"] == "Hi"
    assert result["foreground_pid"] == 4242
    # Two characters produce two down/up pairs -> a four-event dispatch.
    assert "SendInput:4" in user32.calls


@pytest.mark.parametrize("vk", [0, 0xFF, 3.0, True])
def test_send_key_bounds_the_virtual_key(monkeypatch: pytest.MonkeyPatch, vk: Any) -> None:
    _click_ready(monkeypatch, _FakeUser32(foreground=7))
    with pytest.raises(UiPidBoundaryError, match="1..254"):
        si.send_key_sendinput(1, allowed_pids=frozenset({4242}), vk=vk)


def test_send_key_presses_a_virtual_key(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(foreground=7)
    _click_ready(monkeypatch, user32)

    result = si.send_key_sendinput(1, allowed_pids=frozenset({4242}), vk=0x41)

    assert result["vk"] == 0x41
    assert result["action"] == "key"
    assert "SendInput:2" in user32.calls
