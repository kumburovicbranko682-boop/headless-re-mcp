from __future__ import annotations

import ctypes
import os
from collections.abc import Sequence
from typing import Any

JsonObject = dict[str, Any]


class UiPidBoundaryError(ValueError):
    """Raised when UI targeting would escape the debuggee PID boundary."""

    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def blocked_ui_pids(*, debugger_pid: int | None, self_pid: int | None = None) -> set[int]:
    """PIDs that must never be UI-automation targets (analyzer / MCP host)."""
    blocked: set[int] = set()
    host = os.getpid() if self_pid is None else self_pid
    if host > 0:
        blocked.add(int(host))
    if isinstance(debugger_pid, int) and debugger_pid > 0:
        blocked.add(debugger_pid)
    return blocked


def resolve_allowed_ui_pids(
    *,
    debuggee_pid: int,
    debugger_pid: int | None,
    allow_child_pids: Sequence[int] = (),
    include_same_image_children: bool = False,
    self_pid: int | None = None,
) -> tuple[frozenset[int], frozenset[int]]:
    """Resolve allowed window-owner PIDs under the M10.1 boundary.

    Returns ``(allowed_pids, blocked_pids)``. Default allow-set is only the
    debuggee. Child PIDs require explicit authorization and still cannot
    include the headless debugger or the MCP host process.

    When ``include_same_image_children`` is True, direct children whose image
    path matches the debuggee are also allowed (PyInstaller-friendly opt-in).
    """
    if type(debuggee_pid) is not int or debuggee_pid <= 0:
        raise UiPidBoundaryError(
            "invalid_state",
            "no active debuggee; refuse UI window enumeration",
            debuggee_pid=debuggee_pid,
        )
    blocked = blocked_ui_pids(debugger_pid=debugger_pid, self_pid=self_pid)
    if debuggee_pid in blocked:
        raise UiPidBoundaryError(
            "permission_denied",
            "debuggee_pid collides with a blocked analyzer/host PID",
            debuggee_pid=debuggee_pid,
            blocked_pids=sorted(blocked),
        )
    allowed: set[int] = {debuggee_pid}
    extras: list[int] = list(allow_child_pids)
    if include_same_image_children:
        from headless_re_mcp.core.process_tree import (
            enumerate_direct_children,
            filter_same_image_pids,
        )

        extras.extend(filter_same_image_pids(debuggee_pid, enumerate_direct_children(debuggee_pid)))
    for raw in extras:
        if type(raw) is not int or raw <= 0:
            raise UiPidBoundaryError(
                "invalid_params",
                "allow_child_pids entries must be positive integers",
                value=raw,
            )
        if raw in blocked:
            raise UiPidBoundaryError(
                "permission_denied",
                "child pid is blocked (analyzer or MCP host)",
                child_pid=raw,
                blocked_pids=sorted(blocked),
            )
        allowed.add(raw)
    overlap = allowed & blocked
    if overlap:
        raise UiPidBoundaryError(
            "permission_denied",
            "allowed UI PIDs overlap blocked analyzer/host PIDs",
            overlap=sorted(overlap),
        )
    return frozenset(allowed), frozenset(blocked)


def list_process_windows(pid: int) -> list[JsonObject]:
    """Return structured top-level windows owned by ``pid`` (Windows only)."""
    if os.name != "nt" or type(pid) is not int or pid <= 0:
        return []

    user32 = ctypes.windll.user32
    windows: list[JsonObject] = []
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def callback(hwnd: int, _: int) -> bool:
        owner_pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
        if owner_pid.value != pid:
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        title = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, title, length + 1)
        class_name = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, class_name, len(class_name))
        visible = bool(user32.IsWindowVisible(hwnd))
        windows.append(
            {
                "hwnd": int(hwnd),
                "pid": int(owner_pid.value),
                "class_name": class_name.value,
                "title": title.value,
                "visible": visible,
            }
        )
        return True

    user32.EnumWindows(callback_type(callback), 0)
    windows.sort(key=lambda item: (item["pid"], item["hwnd"]))
    return windows


def list_windows_for_pids(pids: Sequence[int]) -> list[JsonObject]:
    """Enumerate top-level windows for each PID in ``pids`` (sorted)."""
    collected: list[JsonObject] = []
    for pid in sorted({int(item) for item in pids if type(item) is int and item > 0}):
        collected.extend(list_process_windows(pid))
    return collected


def is_pid_alive(pid: int) -> bool:
    """Best-effort check whether ``pid`` is still a live process (Windows)."""
    if type(pid) is not int or pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    kernel32 = ctypes.windll.kernel32
    process_query_limited_information = 0x1000
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) == 0:
            return False
        # STILL_ACTIVE == 259
        return int(exit_code.value) == 259
    finally:
        kernel32.CloseHandle(handle)


def describe_process_windows(pid: int) -> set[str]:
    """Return every top-level window owned by a process (legacy string form)."""
    return {
        f"0x{int(window['hwnd']):x}:{window['class_name']}:{window['title']}"
        for window in list_process_windows(pid)
    }
