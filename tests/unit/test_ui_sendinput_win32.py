"""SendInput UI fallback, driven on a faked user32/kernel32 surface.

``ui_sendinput`` is the last-resort input path: it brings a PID-authorised
window to the foreground and synthesises mouse/keyboard input, re-checking the
foreground owner before and after every send so input can never land in another
process. It needs live Win32 (``ctypes.windll``/SendInput), so on a hosted
platform it was 20% covered. Faking ``_user32``/``ctypes.WinDLL`` plus the two
ui_win32 boundary helpers drives the real foreground dance, the SendInput
marshalling, and the fail-closed re-checks. A click that fired at the wrong
foreground, or a SendInput short write reported as success, is what these pin.
"""

from __future__ import annotations

import ctypes
import os
import time
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_sendinput as si
from headless_re_mcp.core.ui_sendinput import (
    SM_CXSCREEN,
    SM_CYSCREEN,
    _abs_mouse,
    _bring_to_foreground,
    _send_input,
    _user32,
    _window_center,
    click_hwnd_sendinput,
    foreground_hwnd,
    foreground_pid,
    require_foreground_allowed,
    send_key_sendinput,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({100})
_TARGET = 0x1000


class _Seq:
    """Return scripted values per call, holding the last value once exhausted."""

    def __init__(self, values: list[int]) -> None:
        self._values = list(values)
        self._i = 0

    def __call__(self, *_args: Any, **_kwargs: Any) -> int:
        value = self._values[self._i] if self._i < len(self._values) else self._values[-1]
        self._i += 1
        return value


class _FakeUser32:
    def __init__(self, foreground: _Seq | None = None) -> None:
        self.foreground = foreground or _Seq([_TARGET])
        self.tid = 7
        self.rect_ok = 1
        self.metrics = {SM_CXSCREEN: 1920, SM_CYSCREEN: 1080}
        self.sendinput: Any = None  # callable(n)->sent, or None for n

    def GetForegroundWindow(self) -> int:
        return self.foreground()

    def GetAncestor(self, _hwnd: Any, _flag: int) -> int:
        return 0  # falsy -> the caller falls back to the original hwnd as root

    def GetWindowThreadProcessId(self, _hwnd: Any, _lp: Any) -> int:
        return self.tid

    def GetWindowRect(self, _hwnd: Any, _lp: Any) -> int:
        return self.rect_ok

    def GetSystemMetrics(self, index: int) -> int:
        return self.metrics[index]

    def SendInput(self, count: int, _arr: Any, _size: int) -> int:
        return self.sendinput(count) if self.sendinput else count

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *a, **k: 1


class _FakeKernel32:
    def GetCurrentThreadId(self) -> int:
        return 1

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *a, **k: 1


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    user32: _FakeUser32,
    *,
    owner_pid: Any = 100,
    kernel32: _FakeKernel32 | None = None,
) -> None:
    monkeypatch.setattr(si, "_user32", lambda: user32)
    # get_last_error is a Win32-only shim used only when building error payloads.
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)
    monkeypatch.setattr(si, "require_allowed_hwnd", lambda *a, **k: None)
    owner = owner_pid if isinstance(owner_pid, _Seq) else (lambda _hwnd: owner_pid)
    monkeypatch.setattr(si, "hwnd_owner_pid", owner)
    # si.time is the stdlib time module object; patch it directly for typing.
    monkeypatch.setattr(time, "sleep", lambda *_a: None)
    if kernel32 is not None:
        monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: kernel32, raising=False)


# ---------------------------------------------------------------------------
# _user32 gate


def test_user32_refuses_off_windows() -> None:
    with pytest.raises(UiPidBoundaryError, match="requires Windows"):
        _user32()


def test_user32_returns_the_windll_handle_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    sentinel = object()
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(user32=sentinel), raising=False)
    assert _user32() is sentinel


# ---------------------------------------------------------------------------
# foreground helpers


def test_foreground_hwnd_reads_the_active_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])))
    assert foreground_hwnd() == _TARGET


def test_foreground_pid_is_zero_without_a_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([0])))
    assert foreground_pid() == 0


def test_foreground_pid_reads_the_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100)
    assert foreground_pid() == 100


def test_require_foreground_allowed_refuses_no_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([0])))
    with pytest.raises(UiPidBoundaryError, match="no foreground window"):
        require_foreground_allowed(_PIDS)


def test_require_foreground_allowed_refuses_a_foreign_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=999)
    with pytest.raises(UiPidBoundaryError, match="not allowed for SendInput"):
        require_foreground_allowed(_PIDS)


def test_require_foreground_allowed_accepts_the_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100)
    assert require_foreground_allowed(_PIDS) == 100


# ---------------------------------------------------------------------------
# _window_center / _abs_mouse / _send_input


def test_window_center_computes_the_midpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32())
    assert _window_center(_TARGET) == (0, 0)  # zeroed rect -> origin


def test_window_center_raises_on_a_failed_rect(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32()
    user32.rect_ok = 0
    _wire(monkeypatch, user32)
    with pytest.raises(UiPidBoundaryError, match="GetWindowRect failed"):
        _window_center(_TARGET)


def test_abs_mouse_scales_to_the_virtual_range(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32())
    ax, ay = _abs_mouse(960, 540)
    assert ax == int(960 * 65535 / 1920)
    assert ay == int(540 * 65535 / 1080)


def test_send_input_raises_on_a_short_write(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32()
    user32.sendinput = lambda n: n - 1  # one fewer than requested
    _wire(monkeypatch, user32)
    move = si._INPUT(type=si.INPUT_MOUSE)
    with pytest.raises(UiPidBoundaryError, match="SendInput failed"):
        _send_input([move])


def test_send_input_accepts_a_full_write(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32())
    move = si._INPUT(type=si.INPUT_MOUSE)
    _send_input([move])  # returns cleanly when every input is delivered


# ---------------------------------------------------------------------------
# _bring_to_foreground


def test_bring_to_foreground_fast_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The target already being foreground returns on the first loop pass."""
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100, kernel32=_FakeKernel32())
    _bring_to_foreground(_TARGET, _PIDS)  # returns without raising


def test_bring_to_foreground_activates_from_no_foreground(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no foreground window, the Alt/activation dance runs, then it lands."""
    # First poll: no foreground (drives the fg<=0 activation branch); next poll:
    # the target is foreground, so the fast path returns on the second pass.
    user32 = _FakeUser32(_Seq([0, _TARGET]))
    _wire(monkeypatch, user32, owner_pid=100, kernel32=_FakeKernel32())
    _bring_to_foreground(_TARGET, _PIDS)


def test_bring_to_foreground_activates_over_a_foreign_foreground(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A different app owning the foreground drives the AttachThreadInput branch."""
    user32 = _FakeUser32(_Seq([0x999, _TARGET]))
    _wire(monkeypatch, user32, owner_pid=100, kernel32=_FakeKernel32())
    _bring_to_foreground(_TARGET, _PIDS)


def test_bring_to_foreground_skips_attach_when_target_shares_the_input_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreign foreground whose thread equals ours skips both AttachThreadInput calls."""
    user32 = _FakeUser32(_Seq([0x999, _TARGET]))
    user32.tid = 1  # equals _FakeKernel32.GetCurrentThreadId, so no attach is made
    _wire(monkeypatch, user32, owner_pid=100, kernel32=_FakeKernel32())
    _bring_to_foreground(_TARGET, _PIDS)


def test_bring_to_foreground_returns_after_the_deadline_when_owner_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wait can expire with an already-allowed foreground, so the post-check falls through."""
    user32 = _FakeUser32(_Seq([_TARGET]))
    # Expire the loop immediately; the post-deadline re-check sees an allowed owner.
    monkeypatch.setattr(time, "monotonic", _Seq([1000, 1003]))
    _wire(monkeypatch, user32, owner_pid=100, kernel32=_FakeKernel32())
    _bring_to_foreground(_TARGET, _PIDS)  # returns without raising


def test_bring_to_foreground_raises_when_the_owner_flips_after_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreground that passes the gate but flips owner right after is refused."""
    user32 = _FakeUser32(_Seq([_TARGET]))
    # Skip the wait loop entirely so the post-deadline re-check runs directly.
    monkeypatch.setattr(time, "monotonic", _Seq([1000, 1003]))
    # Allowed at the require_foreground_allowed gate, foreign at the final re-check.
    _wire(monkeypatch, user32, owner_pid=_Seq([100, 999, 999]), kernel32=_FakeKernel32())
    with pytest.raises(UiPidBoundaryError, match="failed to bring target hwnd"):
        _bring_to_foreground(_TARGET, _PIDS)


# ---------------------------------------------------------------------------
# click_hwnd_sendinput / send_key_sendinput


def test_click_synthesises_a_mouse_click(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100)
    monkeypatch.setattr(si, "_bring_to_foreground", lambda *a, **k: None)
    result = click_hwnd_sendinput(_TARGET, _PIDS)
    assert result["backend"] == "sendinput"
    assert result["action"] == "click"
    assert result["foreground_pid"] == 100


def test_send_key_rejects_both_text_and_vk(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32())
    with pytest.raises(UiPidBoundaryError, match="not both"):
        send_key_sendinput(_TARGET, allowed_pids=_PIDS, text="a", vk=0x41)


def test_send_key_rejects_neither_text_nor_vk(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32())
    with pytest.raises(UiPidBoundaryError, match="provide text or vk"):
        send_key_sendinput(_TARGET, allowed_pids=_PIDS)


def test_send_key_types_unicode_text(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100)
    monkeypatch.setattr(si, "_bring_to_foreground", lambda *a, **k: None)
    result = send_key_sendinput(_TARGET, allowed_pids=_PIDS, text="Hi")
    assert result["action"] == "key"
    assert result["text"] == "Hi"


def test_send_key_rejects_empty_or_oversized_text(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100)
    monkeypatch.setattr(si, "_bring_to_foreground", lambda *a, **k: None)
    with pytest.raises(UiPidBoundaryError, match="at most 32 characters"):
        send_key_sendinput(_TARGET, allowed_pids=_PIDS, text="x" * 33)


def test_send_key_presses_a_virtual_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100)
    monkeypatch.setattr(si, "_bring_to_foreground", lambda *a, **k: None)
    result = send_key_sendinput(_TARGET, allowed_pids=_PIDS, vk=0x41)
    assert result["vk"] == 0x41
    assert result["action"] == "key"


def test_send_key_rejects_an_out_of_range_vk(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _FakeUser32(_Seq([_TARGET])), owner_pid=100)
    monkeypatch.setattr(si, "_bring_to_foreground", lambda *a, **k: None)
    with pytest.raises(UiPidBoundaryError, match="vk must be an integer"):
        send_key_sendinput(_TARGET, allowed_pids=_PIDS, vk=0)
