"""Process-tree helpers for UI child-PID discovery (Windows)."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Any

JsonObject = dict[str, Any]

_MAX_CHILD_PIDS = 16
_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    )


def process_image_path(pid: int) -> str | None:
    """Return the full image path for ``pid``, or None on failure."""
    if os.name != "nt" or type(pid) is not int or pid <= 0:
        return None
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        # QueryFullProcessImageNameW
        q = kernel32.QueryFullProcessImageNameW
        q.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        q.restype = wintypes.BOOL
        if not q(handle, 0, buf, ctypes.byref(size)):
            return None
        return buf.value or None
    finally:
        kernel32.CloseHandle(handle)


def enumerate_direct_children(parent_pid: int, *, max_pids: int = _MAX_CHILD_PIDS) -> list[int]:
    """Return direct child PIDs of ``parent_pid`` (bounded, Toolhelp32)."""
    if os.name != "nt" or type(parent_pid) is not int or parent_pid <= 0:
        return []
    limit = max(1, min(int(max_pids), _MAX_CHILD_PIDS))
    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1, 0xFFFFFFFF):
        return []
    children: list[int] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return []
        while True:
            if int(entry.th32ParentProcessID) == int(parent_pid):
                child = int(entry.th32ProcessID)
                if child > 0 and child != parent_pid:
                    children.append(child)
                    if len(children) >= limit:
                        break
            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    children.sort()
    return children


def filter_same_image_pids(debuggee_pid: int, candidates: list[int]) -> list[int]:
    """Keep candidates whose image path matches the debuggee (casefold)."""
    base = process_image_path(debuggee_pid)
    if not base:
        return []
    key = base.casefold()
    matched: list[int] = []
    for pid in candidates:
        path = process_image_path(pid)
        if path and path.casefold() == key:
            matched.append(int(pid))
    return matched


def probe_child_window_candidates(
    debuggee_pid: int,
    *,
    list_windows_fn: Any = None,
    max_pids: int = _MAX_CHILD_PIDS,
) -> list[JsonObject]:
    """Read-only: children that own top-level windows (not an allow grant)."""
    from headless_re_mcp.core.windows import list_process_windows

    window_lister = list_windows_fn or list_process_windows
    out: list[JsonObject] = []
    for child in enumerate_direct_children(debuggee_pid, max_pids=max_pids):
        windows = window_lister(child)
        visible = [w for w in windows if w.get("visible")]
        if not windows:
            continue
        out.append(
            {
                "pid": child,
                "image": process_image_path(child),
                "window_count": len(windows),
                "visible_count": len(visible),
                "titles": [str(w.get("title") or "") for w in visible[:8]],
                "same_image": bool(
                    (process_image_path(debuggee_pid) or "").casefold()
                    == (process_image_path(child) or "").casefold()
                ),
            }
        )
    return out
