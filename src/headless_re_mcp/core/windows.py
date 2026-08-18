from __future__ import annotations

import ctypes
import os
import queue
import threading
from collections.abc import Sequence
from contextlib import suppress
from ctypes import wintypes
from typing import Any

JsonObject = dict[str, Any]


def window_is_capturable(row: JsonObject) -> bool:
    """True when a snapshot row has a positive, non-minimized capture rectangle."""
    rect = row.get("rect") if isinstance(row.get("rect"), dict) else {}
    width = int(rect.get("width") or 0) if isinstance(rect, dict) else 0
    height = int(rect.get("height") or 0) if isinstance(rect, dict) else 0
    area = int(row.get("area") or (width * height) or 0)
    return (not bool(row.get("minimized"))) and area > 0 and width > 0 and height > 0


def window_capture_rank(row: JsonObject) -> tuple[int, int, int, int, int]:
    """Sort key for auto-select: capturable first, then visible, then area.

    A visible 0x0 HWND used to beat a larger hidden window, which made the
    console poll ``window has empty capture area`` every 800ms.
    """
    rect = row.get("rect") if isinstance(row.get("rect"), dict) else {}
    width = int(rect.get("width") or 0) if isinstance(rect, dict) else 0
    height = int(rect.get("height") or 0) if isinstance(rect, dict) else 0
    area = int(row.get("area") or (width * height) or 0)
    return (
        int(window_is_capturable(row)),
        int(bool(row.get("visible"))),
        int(not bool(row.get("minimized"))),
        area,
        int(bool(str(row.get("title") or "").strip())),
    )


def wnd_enum_callback_type() -> Any:
    """WNDENUMPROC: BOOL CALLBACK(HWND, LPARAM).

    ``ctypes.c_bool`` is 1 byte; Win32 BOOL is 4. Using ``c_bool`` as the
    EnumWindows / EnumDesktopWindows callback restype can abort enumeration
    after the first HWND, which looks like a process with no windows.
    """
    return ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


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
    callback_type = wnd_enum_callback_type()

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


class _RECT(ctypes.Structure):
    _fields_ = (
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    )


def list_input_desktop_windows(*, allowed_pids: frozenset[int] | None = None) -> list[JsonObject]:
    """Top-level windows on the current input desktop, optionally PID-bounded."""
    if os.name != "nt":
        return []
    user32 = ctypes.windll.user32
    rows: list[JsonObject] = []
    callback_type = wnd_enum_callback_type()

    def callback(hwnd: int, _: int) -> bool:
        owner = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        pid = int(owner.value)
        if allowed_pids is not None and pid not in allowed_pids:
            return True
        length = max(0, int(user32.GetWindowTextLengthW(hwnd)))
        title = ctypes.create_unicode_buffer(min(length, 4096) + 1)
        user32.GetWindowTextW(hwnd, title, len(title))
        class_name = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, class_name, len(class_name))
        rect = _RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        width = max(0, int(rect.right - rect.left))
        height = max(0, int(rect.bottom - rect.top))
        rows.append(
            {
                "hwnd": int(hwnd),
                "pid": pid,
                "title": title.value,
                "class_name": class_name.value,
                "visible": bool(user32.IsWindowVisible(hwnd)),
                "enabled": bool(user32.IsWindowEnabled(hwnd)),
                "minimized": bool(user32.IsIconic(hwnd)),
                "rect": {
                    "left": int(rect.left),
                    "top": int(rect.top),
                    "right": int(rect.right),
                    "bottom": int(rect.bottom),
                    "width": width,
                    "height": height,
                },
                "area": width * height,
            }
        )
        return True

    user32.EnumWindows(callback_type(callback), 0)
    rows.sort(key=window_capture_rank, reverse=True)
    return rows


def snapshot_input_desktop(*, allowed_pids: frozenset[int] | None = None) -> JsonObject:
    """Passive snapshot of the interactive desktop (when hidden desktop is off)."""
    if os.name != "nt":
        return {
            "available": False,
            "mode": "unavailable",
            "input_desktop": False,
            "window_count": 0,
            "desktop_window_count": 0,
            "windows": [],
        }
    all_rows = list_input_desktop_windows(allowed_pids=None)
    rows = (
        all_rows
        if allowed_pids is None
        else [row for row in all_rows if int(row["pid"]) in allowed_pids]
    )
    return {
        "available": True,
        "mode": "input_desktop",
        "name": r"WinSta0\Default",
        "input_desktop": True,
        "window_count": len(rows),
        "desktop_window_count": len(all_rows),
        "windows": rows,
    }


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


_PICK_LOCK = threading.Lock()
_OFN_EXPLORER = 0x00080000
_OFN_FILEMUSTEXIST = 0x00001000
_OFN_PATHMUSTEXIST = 0x00000800
_OFN_HIDEREADONLY = 0x00000004
_OFN_NOCHANGEDIR = 0x00000008
_COINIT_APARTMENTTHREADED = 0x2
_STA_READY = threading.Event()
_STA_JOBS: queue.Queue[tuple[str | None, queue.Queue[JsonObject]]] = queue.Queue()
_STA_GUARD = threading.Lock()
_STA_THREAD: threading.Thread | None = None


def _pick_unavailable() -> JsonObject:
    return {
        "path": None,
        "cancelled": False,
        "available": False,
        "busy": False,
        "error": None,
    }


def _show_open_file_dialog(title: str | None) -> JsonObject:
    """Must run on an STA thread. GetOpenFileNameW on an MTA worker often fails."""
    from ctypes import wintypes

    class OPENFILENAMEW(ctypes.Structure):
        _fields_ = [
            ("lStructSize", wintypes.DWORD),
            ("hwndOwner", wintypes.HWND),
            ("hInstance", wintypes.HINSTANCE),
            ("lpstrFilter", wintypes.LPCWSTR),
            ("lpstrCustomFilter", wintypes.LPWSTR),
            ("nMaxCustFilter", wintypes.DWORD),
            ("nFilterIndex", wintypes.DWORD),
            ("lpstrFile", wintypes.LPWSTR),
            ("nMaxFile", wintypes.DWORD),
            ("lpstrFileTitle", wintypes.LPWSTR),
            ("nMaxFileTitle", wintypes.DWORD),
            ("lpstrInitialDir", wintypes.LPCWSTR),
            ("lpstrTitle", wintypes.LPCWSTR),
            ("Flags", wintypes.DWORD),
            ("nFileOffset", wintypes.WORD),
            ("nFileExtension", wintypes.WORD),
            ("lpstrDefExt", wintypes.LPCWSTR),
            ("lCustData", wintypes.LPARAM),
            ("lpfnHook", ctypes.c_void_p),
            ("lpTemplateName", wintypes.LPCWSTR),
            ("pvReserved", ctypes.c_void_p),
            ("dwReserved", wintypes.DWORD),
            ("FlagsEx", wintypes.DWORD),
        ]

    buffer_chars = 32768
    file_buf = ctypes.create_unicode_buffer(buffer_chars)
    filter_buf = ctypes.create_unicode_buffer(
        "PE / dump (*.exe *.dll *.sys *.bin)\0*.exe;*.dll;*.sys;*.bin\0"
        "APK (*.apk)\0*.apk\0"
        "All files (*.*)\0*.*\0"
    )
    ofn = OPENFILENAMEW()
    ofn.lStructSize = ctypes.sizeof(OPENFILENAMEW)
    ofn.hwndOwner = ctypes.windll.user32.GetForegroundWindow()
    ofn.lpstrFilter = ctypes.cast(filter_buf, wintypes.LPCWSTR)
    ofn.nFilterIndex = 1
    ofn.lpstrFile = ctypes.cast(file_buf, wintypes.LPWSTR)
    ofn.nMaxFile = buffer_chars
    ofn.lpstrTitle = title or "Select a file to analyze"
    ofn.Flags = (
        _OFN_EXPLORER
        | _OFN_FILEMUSTEXIST
        | _OFN_PATHMUSTEXIST
        | _OFN_HIDEREADONLY
        | _OFN_NOCHANGEDIR
    )
    get_open = ctypes.windll.comdlg32.GetOpenFileNameW
    get_open.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
    get_open.restype = wintypes.BOOL
    comm_err = ctypes.windll.comdlg32.CommDlgExtendedError
    comm_err.restype = wintypes.DWORD
    ok = bool(get_open(ctypes.byref(ofn)))
    if ok:
        path = file_buf.value.strip()
        if path:
            return {
                "path": path,
                "cancelled": False,
                "available": True,
                "busy": False,
                "error": None,
            }
        return {
            "path": None,
            "cancelled": True,
            "available": True,
            "busy": False,
            "error": None,
        }
    extended = int(comm_err())
    if extended == 0:
        return {
            "path": None,
            "cancelled": True,
            "available": True,
            "busy": False,
            "error": None,
        }
    return {
        "path": None,
        "cancelled": False,
        "available": True,
        "busy": False,
        "error": f"commdlg_{extended}",
    }


def _sta_dialog_loop() -> None:
    with suppress(OSError):
        ctypes.windll.ole32.CoInitializeEx(None, _COINIT_APARTMENTTHREADED)
    _STA_READY.set()
    while True:
        title, reply = _STA_JOBS.get()
        try:
            reply.put(_show_open_file_dialog(title))
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            reply.put(
                {
                    "path": None,
                    "cancelled": False,
                    "available": True,
                    "busy": False,
                    "error": str(exc) or type(exc).__name__,
                }
            )


def _ensure_sta_dialog_thread() -> None:
    global _STA_THREAD
    with _STA_GUARD:
        if _STA_THREAD is not None and _STA_THREAD.is_alive():
            return
        _STA_READY.clear()
        _STA_THREAD = threading.Thread(
            target=_sta_dialog_loop,
            name="headless-re-file-dialog",
            daemon=True,
        )
        _STA_THREAD.start()
    if not _STA_READY.wait(timeout=5):
        raise RuntimeError("file dialog thread failed to start")


def pick_open_file_status(*, title: str | None = None) -> JsonObject:
    """Native file dialog with cancelled / busy / error distinguished.

    A ``<input type=file>`` cannot give IDA a real path. Returning ``None`` for
    lock contention used to look like the operator cancelled after picking a
    file, which left the Open Session button disabled.
    """
    if os.name != "nt":
        return _pick_unavailable()
    if not _PICK_LOCK.acquire(blocking=False):
        return {
            "path": None,
            "cancelled": False,
            "available": True,
            "busy": True,
            "error": None,
        }
    try:
        _ensure_sta_dialog_thread()
        reply: queue.Queue[JsonObject] = queue.Queue()
        _STA_JOBS.put((title, reply))
        try:
            result = reply.get(timeout=600)
        except queue.Empty:
            return {
                "path": None,
                "cancelled": False,
                "available": True,
                "busy": False,
                "error": "dialog_timeout",
            }
        if not isinstance(result, dict):
            return {
                "path": None,
                "cancelled": False,
                "available": True,
                "busy": False,
                "error": "dialog_invalid_result",
            }
        return result
    except RuntimeError as exc:
        return {
            "path": None,
            "cancelled": False,
            "available": True,
            "busy": False,
            "error": str(exc),
        }
    finally:
        _PICK_LOCK.release()


def pick_open_file(*, title: str | None = None) -> str | None:
    """Open a native file dialog; ``None`` means no path (cancel / busy / error)."""
    result = pick_open_file_status(title=title)
    path = result.get("path")
    return path if isinstance(path, str) and path.strip() else None
