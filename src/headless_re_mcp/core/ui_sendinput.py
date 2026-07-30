"""SendInput UI fallback with foreground PID re-check."""

from __future__ import annotations

import ctypes
import os
import time
from typing import Any

from headless_re_mcp.core.ui_win32 import hwnd_owner_pid, require_allowed_hwnd
from headless_re_mcp.core.windows import UiPidBoundaryError

JsonObject = dict[str, Any]

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_ABSOLUTE = 0x8000
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
VK_MENU = 0x12
SM_CXSCREEN = 0
SM_CYSCREEN = 1


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = (
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    )


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = (
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    )


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = (
        ("uMsg", ctypes.c_ulong),
        ("wParamL", ctypes.c_ushort),
        ("wParamH", ctypes.c_ushort),
    )


class _INPUT_UNION(ctypes.Union):
    _fields_ = (
        ("mi", _MOUSEINPUT),
        ("ki", _KEYBDINPUT),
        ("hi", _HARDWAREINPUT),
    )


class _INPUT(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_ulong),
        ("union", _INPUT_UNION),
    )


class _RECT(ctypes.Structure):
    _fields_ = (
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    )


def _user32() -> Any:
    if os.name != "nt":
        raise UiPidBoundaryError(
            "capability_unavailable",
            "SendInput UI requires Windows",
        )
    return ctypes.windll.user32


def foreground_hwnd() -> int:
    return int(_user32().GetForegroundWindow() or 0)


def foreground_pid() -> int:
    hwnd = foreground_hwnd()
    if hwnd <= 0:
        return 0
    return hwnd_owner_pid(hwnd)


def require_foreground_allowed(allowed_pids: frozenset[int]) -> int:
    """Fail closed unless the current foreground window belongs to allowed PIDs."""
    hwnd = foreground_hwnd()
    if hwnd <= 0:
        raise UiPidBoundaryError(
            "permission_denied",
            "no foreground window for SendInput",
        )
    pid = hwnd_owner_pid(hwnd)
    if pid not in allowed_pids:
        raise UiPidBoundaryError(
            "permission_denied",
            "foreground window PID is not allowed for SendInput",
            foreground_hwnd=hwnd,
            foreground_pid=pid,
            allowed_pids=sorted(allowed_pids),
        )
    return pid


def _bring_to_foreground(hwnd: int, allowed_pids: frozenset[int]) -> None:
    user32 = _user32()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    require_allowed_hwnd(hwnd, allowed_pids)
    # SetForegroundWindow only accepts a top-level window. UI actions commonly
    # target a child Button/Edit HWND, so resolve its root before the focus dance.
    root = int(user32.GetAncestor(ctypes.c_void_p(int(hwnd)), 2) or hwnd)  # GA_ROOT
    require_allowed_hwnd(root, allowed_pids)
    # Best-effort focus; success is decided by the post-check below.
    user32.ShowWindow(ctypes.c_void_p(root), 9)  # SW_RESTORE
    user32.BringWindowToTop(ctypes.c_void_p(root))
    target = root
    current_tid = int(kernel32.GetCurrentThreadId())
    deadline = time.time() + 2.0
    while time.time() < deadline:
        fg = foreground_hwnd()
        if fg == target and hwnd_owner_pid(target) in allowed_pids:
            require_foreground_allowed(allowed_pids)
            return
        # A non-interactive launcher can temporarily leave the desktop without
        # any foreground HWND. In that state there is no foreground thread to
        # attach to, and SetForegroundWindow alone is commonly ignored. The
        # target root is already PID-authorized, so use the bounded Win32
        # activation path before the same fail-closed post-check.
        if fg <= 0:
            user32.SwitchToThisWindow(ctypes.c_void_p(target), True)
        # AttachThreadInput is often required when another app (e.g. Edge) owns FG.
        fg_tid = int(user32.GetWindowThreadProcessId(ctypes.c_void_p(fg), None)) if fg else 0
        tgt_tid = int(user32.GetWindowThreadProcessId(ctypes.c_void_p(target), None))
        attached_fg = False
        attached_tgt = False
        try:
            if fg_tid and fg_tid != current_tid:
                attached_fg = bool(user32.AttachThreadInput(current_tid, fg_tid, True))
            if tgt_tid and tgt_tid != current_tid:
                attached_tgt = bool(user32.AttachThreadInput(current_tid, tgt_tid, True))
            if fg <= 0:
                # Windows' foreground lock can reject activation when the
                # desktop currently has no foreground queue. A bounded Alt
                # press grants this input-initiated activation; no UI action is
                # emitted until the allowed-PID foreground post-check passes.
                user32.keybd_event(VK_MENU, 0, 0, 0)
            try:
                user32.SetForegroundWindow(ctypes.c_void_p(target))
            finally:
                if fg <= 0:
                    user32.keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0)
            if fg <= 0:
                user32.SetActiveWindow(ctypes.c_void_p(target))
                user32.SetFocus(ctypes.c_void_p(target))
        finally:
            if attached_tgt:
                user32.AttachThreadInput(current_tid, tgt_tid, False)
            if attached_fg:
                user32.AttachThreadInput(current_tid, fg_tid, False)
        time.sleep(0.05)
    require_foreground_allowed(allowed_pids)
    # Foreground may be a sibling owned by the same PID (acceptable).
    if hwnd_owner_pid(foreground_hwnd()) not in allowed_pids:
        raise UiPidBoundaryError(
            "permission_denied",
            "failed to bring target hwnd to foreground for SendInput",
            hwnd=hwnd,
            foreground_hwnd=foreground_hwnd(),
            foreground_pid=foreground_pid(),
        )


def _window_center(hwnd: int) -> tuple[int, int]:
    rect = _RECT()
    if not _user32().GetWindowRect(ctypes.c_void_p(int(hwnd)), ctypes.byref(rect)):
        raise UiPidBoundaryError(
            "backend_error",
            "GetWindowRect failed for SendInput click",
            hwnd=hwnd,
            winerror=ctypes.get_last_error(),
        )
    x = (int(rect.left) + int(rect.right)) // 2
    y = (int(rect.top) + int(rect.bottom)) // 2
    return x, y


def _abs_mouse(x: int, y: int) -> tuple[int, int]:
    user32 = _user32()
    width = max(int(user32.GetSystemMetrics(SM_CXSCREEN)), 1)
    height = max(int(user32.GetSystemMetrics(SM_CYSCREEN)), 1)
    ax = int(x * 65535 / width)
    ay = int(y * 65535 / height)
    return ax, ay


def _send_input(inputs: list[_INPUT]) -> None:
    user32 = _user32()
    arr = (_INPUT * len(inputs))(*inputs)
    sent = int(user32.SendInput(len(inputs), ctypes.byref(arr), ctypes.sizeof(_INPUT)))
    if sent != len(inputs):
        raise UiPidBoundaryError(
            "backend_error",
            "SendInput failed",
            expected=len(inputs),
            sent=sent,
            winerror=ctypes.get_last_error(),
        )


def click_hwnd_sendinput(
    hwnd: int,
    allowed_pids: frozenset[int],
) -> JsonObject:
    require_allowed_hwnd(hwnd, allowed_pids)
    _bring_to_foreground(hwnd, allowed_pids)
    require_foreground_allowed(allowed_pids)
    x, y = _window_center(hwnd)
    ax, ay = _abs_mouse(x, y)
    move = _INPUT(type=INPUT_MOUSE)
    move.union.mi = _MOUSEINPUT(ax, ay, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, 0, None)
    down = _INPUT(type=INPUT_MOUSE)
    down.union.mi = _MOUSEINPUT(ax, ay, 0, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE, 0, None)
    up = _INPUT(type=INPUT_MOUSE)
    up.union.mi = _MOUSEINPUT(ax, ay, 0, MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE, 0, None)
    require_foreground_allowed(allowed_pids)
    _send_input([move, down, up])
    require_foreground_allowed(allowed_pids)
    return {
        "hwnd": hwnd,
        "action": "click",
        "backend": "sendinput",
        "foreground_pid": foreground_pid(),
        "screen_x": x,
        "screen_y": y,
    }


def send_key_sendinput(
    hwnd: int,
    *,
    allowed_pids: frozenset[int],
    text: str | None = None,
    vk: int | None = None,
) -> JsonObject:
    require_allowed_hwnd(hwnd, allowed_pids)
    if text is not None and vk is not None:
        raise UiPidBoundaryError("invalid_params", "provide either text or vk, not both")
    if text is None and vk is None:
        raise UiPidBoundaryError("invalid_params", "provide text or vk")
    _bring_to_foreground(hwnd, allowed_pids)
    require_foreground_allowed(allowed_pids)
    inputs: list[_INPUT] = []
    if text is not None:
        if not isinstance(text, str) or not text or len(text) > 32:
            raise UiPidBoundaryError(
                "invalid_params",
                "text must be a non-empty string of at most 32 characters",
            )
        for ch in text:
            down = _INPUT(type=INPUT_KEYBOARD)
            down.union.ki = _KEYBDINPUT(0, ord(ch), KEYEVENTF_UNICODE, 0, None)
            up = _INPUT(type=INPUT_KEYBOARD)
            up.union.ki = _KEYBDINPUT(0, ord(ch), KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, None)
            inputs.extend((down, up))
        require_foreground_allowed(allowed_pids)
        _send_input(inputs)
        require_foreground_allowed(allowed_pids)
        return {
            "hwnd": hwnd,
            "action": "key",
            "text": text,
            "backend": "sendinput",
            "foreground_pid": foreground_pid(),
        }
    if type(vk) is not int or not 1 <= vk <= 0xFE:
        raise UiPidBoundaryError("invalid_params", "vk must be an integer in 1..254")
    down = _INPUT(type=INPUT_KEYBOARD)
    down.union.ki = _KEYBDINPUT(int(vk), 0, 0, 0, None)
    up = _INPUT(type=INPUT_KEYBOARD)
    up.union.ki = _KEYBDINPUT(int(vk), 0, KEYEVENTF_KEYUP, 0, None)
    require_foreground_allowed(allowed_pids)
    _send_input([down, up])
    require_foreground_allowed(allowed_pids)
    return {
        "hwnd": hwnd,
        "action": "key",
        "vk": vk,
        "backend": "sendinput",
        "foreground_pid": foreground_pid(),
    }
