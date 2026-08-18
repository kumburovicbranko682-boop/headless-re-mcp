"""Keep debuggee UI off the interactive desktop.

Creating the worker with ``STARTUPINFO.lpDesktop`` puts ordinary windows on
the hidden desktop. It does not stop ``MessageBox`` with
``MB_SERVICE_NOTIFICATION`` or ``MB_DEFAULT_DESKTOP_ONLY``: those flags open
the input desktop of WinSta0 and show there, which is how an anti-debug
dialog lands on the operator's session. A job with UI restrictions blocks
that handle/desktop switch; a poll on the input desktop hides anything that
still appears.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Iterable
from ctypes import wintypes
from typing import Any

from headless_re_mcp.core.windows import list_windows_for_pids

JsonObject = dict[str, Any]

_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_UI_RESTRICTIONS = 4
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001
_SW_HIDE = 0
_SWP_NOSIZE = 0x0001
_SWP_NOMOVE = 0x0002
_SWP_NOZORDER = 0x0004
_SWP_NOACTIVATE = 0x0010
_SWP_HIDEWINDOW = 0x0080

JOB_OBJECT_UILIMIT_HANDLES = 0x00000001
JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002
JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008
JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010
JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040
JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080

DESKTOP_UI_RESTRICTIONS = (
    JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
)


class _IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.POINTER(wintypes.ULONG)),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _UiRestrictions(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]


def _kernel32() -> Any:
    return ctypes.WinDLL("kernel32", use_last_error=True)


class DesktopIsolationJob:
    """Per-worker job that forbids switching onto the input desktop."""

    def __init__(self, handle: int) -> None:
        self._handle = handle

    @classmethod
    def create(cls) -> DesktopIsolationJob | None:
        if os.name != "nt":
            return None
        kernel32 = _kernel32()
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None
        try:
            limits = _ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                kernel32.CloseHandle(handle)
                return None
            ui = _UiRestrictions()
            ui.UIRestrictionsClass = DESKTOP_UI_RESTRICTIONS
            if not kernel32.SetInformationJobObject(
                handle,
                _JOB_OBJECT_BASIC_UI_RESTRICTIONS,
                ctypes.byref(ui),
                ctypes.sizeof(ui),
            ):
                kernel32.CloseHandle(handle)
                return None
            return cls(int(handle))
        except (OSError, AttributeError, ValueError):
            kernel32.CloseHandle(handle)
            return None

    def assign(self, pid: int) -> bool:
        if os.name != "nt" or type(pid) is not int or pid <= 0 or self._handle == 0:
            return False
        kernel32 = _kernel32()
        process = kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not process:
            return False
        try:
            return bool(kernel32.AssignProcessToJobObject(self._handle, process))
        finally:
            kernel32.CloseHandle(process)

    def close(self) -> None:
        handle = self._handle
        self._handle = 0
        if os.name != "nt" or handle == 0:
            return
        _kernel32().CloseHandle(handle)


def hide_input_desktop_windows_for_pids(pids: Iterable[int]) -> list[int]:
    """Hide top-level windows on the calling thread's desktop owned by ``pids``.

    The MCP process stays on the input desktop, so this is the leak surface
    ``MB_SERVICE_NOTIFICATION`` uses. Windows on the hidden desktop are not
    enumerated here. Hide only; do not dismiss, so an anti-debug MessageBox
    does not continue as if the operator clicked OK.
    """
    if os.name != "nt":
        return []
    allowed = {int(pid) for pid in pids if type(pid) is int and pid > 0}
    if not allowed:
        return []
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    hidden: list[int] = []
    flags = _SWP_NOSIZE | _SWP_NOMOVE | _SWP_NOZORDER | _SWP_NOACTIVATE | _SWP_HIDEWINDOW
    for row in list_windows_for_pids(sorted(allowed)):
        hwnd = int(row["hwnd"])
        user32.ShowWindow(hwnd, _SW_HIDE)
        user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, flags)
        hidden.append(hwnd)
    return hidden
