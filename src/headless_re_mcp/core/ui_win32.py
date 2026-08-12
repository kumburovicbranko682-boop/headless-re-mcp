from __future__ import annotations

import ctypes
import os
import struct
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from headless_re_mcp.core.windows import UiPidBoundaryError

JsonObject = dict[str, Any]

WM_CLOSE = 0x0010
WM_SETTEXT = 0x000C
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_CHAR = 0x0102
WM_SYSCOMMAND = 0x0112
WM_COMMAND = 0x0111
WM_MOUSEMOVE = 0x0200
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_NCLBUTTONDOWN = 0x00A1
WM_NCLBUTTONUP = 0x00A2
BM_CLICK = 0x00F5
BN_CLICKED = 0
SC_CLOSE = 0xF060
HTCLOSE = 20
MK_LBUTTON = 0x0001
SMTO_NORMAL = 0x0000
SMTO_BLOCK = 0x0001
SMTO_ABORTIFHUNG = 0x0002
# Debugged UI threads often trip IsHungAppWindow even while debug.state==running.
# Prefer SMTO_NORMAL so cross-process marshaled messages can complete.
SMTO_NOTIMEOUTIFNOTHUNG = 0x0008
PW_CLIENTONLY = 0x00000001
PW_RENDERFULLCONTENT = 0x00000002
SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
BI_RGB = 0

_MAX_TEXT_CHARS = 4096
_MAX_TREE_NODES = 256
_MAX_TREE_DEPTH = 8
_MAX_WAIT_SECONDS = 30.0
_DEFAULT_SEND_TIMEOUT_MS = 5_000
_MAX_SCREENSHOT_EDGE = 8192
_MAX_SCREENSHOT_PIXELS = 16_777_216  # 4096*4096


class _RECT(ctypes.Structure):
    _fields_ = (
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    )


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = (
        ("biSize", ctypes.c_uint32),
        ("biWidth", ctypes.c_int32),
        ("biHeight", ctypes.c_int32),
        ("biPlanes", ctypes.c_uint16),
        ("biBitCount", ctypes.c_uint16),
        ("biCompression", ctypes.c_uint32),
        ("biSizeImage", ctypes.c_uint32),
        ("biXPelsPerMeter", ctypes.c_int32),
        ("biYPelsPerMeter", ctypes.c_int32),
        ("biClrUsed", ctypes.c_uint32),
        ("biClrImportant", ctypes.c_uint32),
    )

# Bounded Win32 messages allowed via ui.invoke (no arbitrary SendMessage).
# ``close`` is handled specially (background NC-click / WM_CLOSE); sentinel 0.
_INVOKE_WHITELIST: dict[str, int] = {
    "click": BM_CLICK,
    "bm_click": BM_CLICK,
    "set_text": WM_SETTEXT,
    "wm_settext": WM_SETTEXT,
    "command": WM_COMMAND,
    "wm_command": WM_COMMAND,
    "close": 0,
    "wm_close": 0,
}


def _user32() -> Any:
    if os.name != "nt":
        raise UiPidBoundaryError(
            "capability_unavailable",
            "Win32 UI automation requires Windows",
        )
    return ctypes.windll.user32


def hwnd_owner_pid(hwnd: int) -> int:
    user32 = _user32()
    owner_pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(int(hwnd), ctypes.byref(owner_pid))
    return int(owner_pid.value)


def require_allowed_hwnd(hwnd: int, allowed_pids: frozenset[int]) -> int:
    if type(hwnd) is not int or hwnd <= 0:
        raise UiPidBoundaryError("invalid_params", "hwnd must be a positive integer", hwnd=hwnd)
    user32 = _user32()
    if not user32.IsWindow(int(hwnd)):
        raise UiPidBoundaryError("not_found", "hwnd is not a valid window", hwnd=hwnd)
    pid = hwnd_owner_pid(hwnd)
    if pid not in allowed_pids:
        raise UiPidBoundaryError(
            "permission_denied",
            "hwnd is outside the allowed debuggee PID set",
            hwnd=hwnd,
            pid=pid,
            allowed_pids=sorted(allowed_pids),
        )
    return pid


def _window_text(hwnd: int) -> str:
    user32 = _user32()
    length = int(user32.GetWindowTextLengthW(int(hwnd)))
    buffer = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(int(hwnd), buffer, length + 1)
    return buffer.value


def _class_name(hwnd: int) -> str:
    user32 = _user32()
    buffer = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(int(hwnd), buffer, len(buffer))
    return buffer.value


def _control_id(hwnd: int) -> int:
    return int(_user32().GetDlgCtrlID(int(hwnd)))


def describe_hwnd(hwnd: int) -> JsonObject:
    user32 = _user32()
    pid = hwnd_owner_pid(hwnd)
    return {
        "hwnd": int(hwnd),
        "pid": pid,
        "class_name": _class_name(hwnd),
        "title": _window_text(hwnd),
        "visible": bool(user32.IsWindowVisible(int(hwnd))),
        "control_id": _control_id(hwnd),
        "enabled": bool(user32.IsWindowEnabled(int(hwnd))),
    }


def list_child_windows(parent_hwnd: int, allowed_pids: frozenset[int]) -> list[JsonObject]:
    require_allowed_hwnd(parent_hwnd, allowed_pids)
    user32 = _user32()
    children: list[JsonObject] = []
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def callback(hwnd: int, _: int) -> bool:
        pid = hwnd_owner_pid(hwnd)
        if pid not in allowed_pids:
            return True
        children.append(describe_hwnd(int(hwnd)))
        return True

    user32.EnumChildWindows(int(parent_hwnd), callback_type(callback), 0)
    children.sort(key=lambda item: item["hwnd"])
    return children


def build_window_tree(
    roots: Sequence[JsonObject],
    allowed_pids: frozenset[int],
    *,
    max_depth: int = 3,
    max_nodes: int = _MAX_TREE_NODES,
) -> JsonObject:
    if type(max_depth) is not int or not 0 <= max_depth <= _MAX_TREE_DEPTH:
        raise UiPidBoundaryError(
            "invalid_params",
            f"max_depth must be between 0 and {_MAX_TREE_DEPTH}",
            max_depth=max_depth,
        )
    if type(max_nodes) is not int or not 1 <= max_nodes <= _MAX_TREE_NODES:
        raise UiPidBoundaryError(
            "invalid_params",
            f"max_nodes must be between 1 and {_MAX_TREE_NODES}",
            max_nodes=max_nodes,
        )
    nodes = 0
    truncated = False

    def walk(node: JsonObject, depth: int) -> JsonObject:
        nonlocal nodes, truncated
        nodes += 1
        item = dict(node)
        item["children"] = []
        if nodes >= max_nodes:
            truncated = True
            return item
        if depth >= max_depth:
            return item
        hwnd = int(node["hwnd"])
        for child in list_child_windows(hwnd, allowed_pids):
            if nodes >= max_nodes:
                truncated = True
                break
            item["children"].append(walk(child, depth + 1))
        return item

    tree = [walk(dict(root), 0) for root in roots if nodes < max_nodes]
    return {
        "nodes": tree,
        "count": nodes,
        "max_depth": max_depth,
        "max_nodes": max_nodes,
        "truncated": truncated,
    }


def resolve_hwnd(
    allowed_pids: frozenset[int],
    *,
    hwnd: int | None = None,
    parent_hwnd: int | None = None,
    class_name: str | None = None,
    title: str | None = None,
    title_contains: str | None = None,
    control_id: int | None = None,
) -> JsonObject:
    if hwnd is not None:
        require_allowed_hwnd(hwnd, allowed_pids)
        return describe_hwnd(hwnd)

    candidates: list[JsonObject]
    if parent_hwnd is not None:
        candidates = list_child_windows(parent_hwnd, allowed_pids)
    else:
        from headless_re_mcp.core.windows import list_windows_for_pids

        candidates = list_windows_for_pids(sorted(allowed_pids))

    matched: list[JsonObject] = []
    for item in candidates:
        if class_name is not None and item.get("class_name") != class_name:
            continue
        if title is not None and item.get("title") != title:
            continue
        if title_contains is not None and title_contains not in str(item.get("title") or ""):
            continue
        if control_id is not None and int(item.get("control_id") or 0) != control_id:
            continue
        # When resolving children without filters beyond parent, still require at least
        # one selector besides parent to avoid ambiguous full dumps via resolve.
        matched.append(item)

    selectors = [class_name, title, title_contains, control_id]
    if parent_hwnd is None and all(value is None for value in selectors):
        raise UiPidBoundaryError(
            "invalid_params",
            "resolve requires hwnd or at least one of class_name/title/title_contains/control_id",
        )
    if parent_hwnd is not None and all(value is None for value in selectors):
        raise UiPidBoundaryError(
            "invalid_params",
            "child resolve requires class_name, title, title_contains, or control_id",
        )
    if not matched:
        raise UiPidBoundaryError("not_found", "no window matched the resolve selectors")
    if len(matched) > 1:
        raise UiPidBoundaryError(
            "ambiguous",
            "multiple windows matched the resolve selectors",
            matches=[
                {
                    "hwnd": m["hwnd"],
                    "class_name": m["class_name"],
                    "title": m["title"],
                }
                for m in matched[:8]
            ],
            count=len(matched),
        )
    return matched[0]


def _send_timeout(
    hwnd: int,
    message: int,
    wparam: int,
    lparam: int | ctypes.Array[Any] | ctypes.c_wchar_p,
    timeout_ms: int,
) -> int:
    user32 = _user32()
    result = ctypes.c_size_t(0)
    send = user32.SendMessageTimeoutW
    send.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    send.restype = ctypes.c_size_t
    if isinstance(lparam, int):
        lp = ctypes.c_void_p(int(lparam))
    else:
        lp = ctypes.cast(lparam, ctypes.c_void_p)
    ok = send(
        ctypes.c_void_p(int(hwnd)),
        ctypes.c_uint(int(message)),
        ctypes.c_size_t(int(wparam)),
        lp,
        ctypes.c_uint(SMTO_NORMAL),
        ctypes.c_uint(int(timeout_ms)),
        ctypes.byref(result),
    )
    if not ok:
        raise UiPidBoundaryError(
            "timeout",
            "SendMessageTimeout failed or timed out",
            hwnd=hwnd,
            win32_message=message,
            winerror=ctypes.get_last_error(),
        )
    return int(result.value)



def _post_message(
    hwnd: int,
    message: int,
    wparam: int,
    lparam: int,
) -> None:
    user32 = _user32()
    post = user32.PostMessageW
    post.restype = ctypes.c_int
    ok = post(
        ctypes.c_void_p(int(hwnd)),
        ctypes.c_uint(int(message)),
        ctypes.c_size_t(int(wparam)),
        ctypes.c_size_t(int(lparam)),
    )
    if not ok:
        raise UiPidBoundaryError(
            "backend_error",
            "PostMessageW failed",
            hwnd=hwnd,
            win32_message=message,
            winerror=ctypes.get_last_error(),
        )


def _makelparam(x: int, y: int) -> int:
    return (int(y) << 16) | (int(x) & 0xFFFF)


def click_hwnd(
    hwnd: int,
    allowed_pids: frozenset[int],
    *,
    timeout_ms: int = _DEFAULT_SEND_TIMEOUT_MS,
) -> JsonObject:
    """Click via PostMessage — no foreground / no cursor move / no injection.

    ``timeout_ms`` is retained for API compatibility; BM_CLICK is queued asynchronously.
    """
    _ = timeout_ms
    require_allowed_hwnd(hwnd, allowed_pids)
    # SendMessage(BM_CLICK) waits for the button handler to finish. If that handler
    # hits a debugger breakpoint, the host and debuggee deadlock. PostMessage returns
    # immediately and lets the UI drive event loop observe the breakpoint hit.
    _post_message(hwnd, BM_CLICK, 0, 0)
    return {
        "hwnd": hwnd,
        "action": "click",
        "backend": "win32_postmessage",
        "foreground_required": False,
        "injection_required": False,
    }


def click_hwnd_at(
    hwnd: int,
    allowed_pids: frozenset[int],
    *,
    x: int,
    y: int,
    timeout_ms: int = _DEFAULT_SEND_TIMEOUT_MS,
) -> JsonObject:
    """Background client-area click via posted mouse messages (no SetForegroundWindow)."""
    _ = timeout_ms
    if type(x) is not int or type(y) is not int or x < 0 or y < 0 or x > 65535 or y > 65535:
        raise UiPidBoundaryError(
            "invalid_params",
            "x/y must be integers in 0..65535 (client coordinates)",
            x=x,
            y=y,
        )
    require_allowed_hwnd(hwnd, allowed_pids)
    lp = _makelparam(x, y)
    _post_message(hwnd, WM_MOUSEMOVE, 0, lp)
    _post_message(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp)
    _post_message(hwnd, WM_LBUTTONUP, 0, lp)
    return {
        "hwnd": hwnd,
        "action": "click_at",
        "x": x,
        "y": y,
        "backend": "win32_postmessage_client",
        "foreground_required": False,
        "injection_required": False,
    }


def close_hwnd(
    hwnd: int,
    allowed_pids: frozenset[int],
    *,
    method: str = "nc_close",
    timeout_ms: int = _DEFAULT_SEND_TIMEOUT_MS,
    show_noactivate: bool = True,
) -> JsonObject:
    """Close a top-level window without bringing it to the foreground.

    Methods (all message-based, no injection, no SetCursorPos / SetForegroundWindow):
    - ``nc_close``: post WM_NCLBUTTON* on HTCLOSE (simulate title-bar X), then SC_CLOSE/WM_CLOSE
    - ``syscommand``: WM_SYSCOMMAND SC_CLOSE
    - ``wm_close``: WM_CLOSE only

    When ``show_noactivate`` is True and the window looks cloaked/off-screen,
    ``ShowWindow(SW_SHOWNOACTIVATE)`` is used first so the message pump can see it
    without stealing focus. Some CEF/SDL apps (e.g. Steam) still ignore these
    messages; that is an app limitation, not a foreground requirement.
    """
    require_allowed_hwnd(hwnd, allowed_pids)
    key = (method or "nc_close").strip().casefold()
    if key not in {"nc_close", "syscommand", "wm_close", "close"}:
        raise UiPidBoundaryError(
            "invalid_params",
            "close method must be nc_close|syscommand|wm_close",
            method=method,
        )
    user32 = _user32()
    rect = _RECT()
    if not user32.GetWindowRect(ctypes.c_void_p(int(hwnd)), ctypes.byref(rect)):
        raise UiPidBoundaryError(
            "backend_error",
            "GetWindowRect failed",
            hwnd=hwnd,
            winerror=ctypes.get_last_error(),
        )
    width = int(rect.right) - int(rect.left)
    height = int(rect.bottom) - int(rect.top)
    cloaked = width <= 0 or height <= 0 or abs(int(rect.left)) > 10000 or abs(int(rect.top)) > 10000
    shown_noactivate = False
    if show_noactivate and cloaked:
        # 4 = SW_SHOWNOACTIVATE — restore visibility without activation.
        user32.ShowWindow(ctypes.c_void_p(int(hwnd)), 4)
        shown_noactivate = True
        user32.GetWindowRect(ctypes.c_void_p(int(hwnd)), ctypes.byref(rect))

    # Prefer SendMessageTimeout for close: some Chromium/CEF UIs ignore posted
    # WM_CLOSE while still handling synchronous close without needing foreground.
    if key in {"nc_close", "close"}:
        screen_x = int(rect.right) - 22
        screen_y = int(rect.top) + 12
        lp = _makelparam(screen_x, screen_y)
        _post_message(hwnd, WM_NCLBUTTONDOWN, HTCLOSE, lp)
        _post_message(hwnd, WM_NCLBUTTONUP, HTCLOSE, lp)
        _send_timeout(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0, timeout_ms)
        _send_timeout(hwnd, WM_CLOSE, 0, 0, timeout_ms)
        backend = "win32_nc_close_sendmessage"
    elif key == "syscommand":
        _send_timeout(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0, timeout_ms)
        backend = "win32_syscommand_close"
    else:
        _send_timeout(hwnd, WM_CLOSE, 0, 0, timeout_ms)
        backend = "win32_wm_close"
    return {
        "hwnd": hwnd,
        "action": "close",
        "method": key if key != "close" else "nc_close",
        "backend": backend,
        "shown_noactivate": shown_noactivate,
        "foreground_required": False,
        "injection_required": False,
    }


def set_window_text(
    hwnd: int,
    text: str,
    allowed_pids: frozenset[int],
    *,
    timeout_ms: int = _DEFAULT_SEND_TIMEOUT_MS,
) -> JsonObject:
    if not isinstance(text, str):
        raise UiPidBoundaryError("invalid_params", "text must be a string")
    if len(text) > _MAX_TEXT_CHARS:
        raise UiPidBoundaryError(
            "invalid_params",
            f"text exceeds {_MAX_TEXT_CHARS} characters",
            length=len(text),
        )
    require_allowed_hwnd(hwnd, allowed_pids)
    buffer = ctypes.create_unicode_buffer(text)
    # SMTO_NORMAL (not ABORTIFHUNG): debugger-attached UI threads often trip
    # IsHungAppWindow even while debug.state==running. Pair with headless.ini
    # TlsCallbacks=0 so the message pump can complete.
    _send_timeout(hwnd, WM_SETTEXT, 0, buffer, timeout_ms)
    return {
        "hwnd": hwnd,
        "action": "text.set",
        "text": text,
        "backend": "win32_sendmessage",
    }


def get_window_text(hwnd: int, allowed_pids: frozenset[int]) -> str:
    require_allowed_hwnd(hwnd, allowed_pids)
    return _window_text(hwnd)


def send_key(
    hwnd: int,
    *,
    allowed_pids: frozenset[int],
    text: str | None = None,
    vk: int | None = None,
    timeout_ms: int = _DEFAULT_SEND_TIMEOUT_MS,
) -> JsonObject:
    require_allowed_hwnd(hwnd, allowed_pids)
    if text is not None and vk is not None:
        raise UiPidBoundaryError("invalid_params", "provide either text or vk, not both")
    if text is None and vk is None:
        raise UiPidBoundaryError("invalid_params", "provide text or vk")
    if text is not None:
        if not isinstance(text, str) or not text or len(text) > 32:
            raise UiPidBoundaryError(
                "invalid_params",
                "text must be a non-empty string of at most 32 characters",
            )
        for ch in text:
            _send_timeout(hwnd, WM_CHAR, ord(ch), 0, timeout_ms)
        return {"hwnd": hwnd, "action": "key", "text": text, "backend": "win32_wm_char"}
    if type(vk) is not int or not 1 <= vk <= 0xFE:
        raise UiPidBoundaryError("invalid_params", "vk must be an integer in 1..254")
    _send_timeout(hwnd, WM_KEYDOWN, vk, 0, timeout_ms)
    _send_timeout(hwnd, WM_KEYUP, vk, 0, timeout_ms)
    return {"hwnd": hwnd, "action": "key", "vk": vk, "backend": "win32_wm_key"}


def invoke_hwnd(
    hwnd: int,
    allowed_pids: frozenset[int],
    *,
    action: str = "click",
    text: str | None = None,
    control_id: int | None = None,
    timeout_ms: int = _DEFAULT_SEND_TIMEOUT_MS,
) -> JsonObject:
    require_allowed_hwnd(hwnd, allowed_pids)
    key = action.strip().casefold()
    if key not in _INVOKE_WHITELIST:
        raise UiPidBoundaryError(
            "invalid_params",
            "invoke action not in whitelist",
            action=action,
            allowed=sorted(_INVOKE_WHITELIST),
        )
    if key in {"close", "wm_close"}:
        return close_hwnd(
            hwnd,
            allowed_pids,
            method="wm_close" if key == "wm_close" else "nc_close",
            timeout_ms=timeout_ms,
        )
    win32_message = _INVOKE_WHITELIST[key]
    if win32_message == BM_CLICK:
        return click_hwnd(hwnd, allowed_pids, timeout_ms=timeout_ms)
    if win32_message == WM_SETTEXT:
        if text is None:
            raise UiPidBoundaryError("invalid_params", "set_text invoke requires text")
        return set_window_text(hwnd, text, allowed_pids, timeout_ms=timeout_ms)
    # WM_COMMAND: notify parent about child control (BN_CLICKED).
    if control_id is None:
        control_id = _control_id(hwnd)
    parent = int(_user32().GetParent(int(hwnd)))
    if parent == 0:
        parent = hwnd
    require_allowed_hwnd(parent, allowed_pids)
    wparam = (BN_CLICKED << 16) | (int(control_id) & 0xFFFF)
    _send_timeout(parent, WM_COMMAND, wparam, int(hwnd), timeout_ms)
    return {
        "hwnd": hwnd,
        "parent_hwnd": parent,
        "action": "invoke",
        "message": "wm_command",
        "control_id": int(control_id),
        "backend": "win32_sendmessage",
    }


def _window_capture_size(hwnd: int, *, client_only: bool) -> tuple[int, int]:
    user32 = _user32()
    rect = _RECT()
    if client_only:
        if not user32.GetClientRect(ctypes.c_void_p(int(hwnd)), ctypes.byref(rect)):
            raise UiPidBoundaryError(
                "capability_unavailable",
                "GetClientRect failed",
                hwnd=hwnd,
                winerror=ctypes.get_last_error(),
            )
        width = int(rect.right - rect.left)
        height = int(rect.bottom - rect.top)
    else:
        if not user32.GetWindowRect(ctypes.c_void_p(int(hwnd)), ctypes.byref(rect)):
            raise UiPidBoundaryError(
                "capability_unavailable",
                "GetWindowRect failed",
                hwnd=hwnd,
                winerror=ctypes.get_last_error(),
            )
        width = int(rect.right - rect.left)
        height = int(rect.bottom - rect.top)
    if width <= 0 or height <= 0:
        raise UiPidBoundaryError(
            "invalid_state",
            "window has empty capture area",
            hwnd=hwnd,
            width=width,
            height=height,
        )
    if width > _MAX_SCREENSHOT_EDGE or height > _MAX_SCREENSHOT_EDGE:
        raise UiPidBoundaryError(
            "invalid_params",
            f"screenshot exceeds max edge {_MAX_SCREENSHOT_EDGE}",
            hwnd=hwnd,
            width=width,
            height=height,
        )
    if width * height > _MAX_SCREENSHOT_PIXELS:
        raise UiPidBoundaryError(
            "invalid_params",
            f"screenshot exceeds max pixels {_MAX_SCREENSHOT_PIXELS}",
            hwnd=hwnd,
            width=width,
            height=height,
        )
    return width, height


def _write_bmp_bgr(path: Path, width: int, height: int, pixels: bytes) -> int:
    row_stride = ((width * 3 + 3) // 4) * 4
    expected = row_stride * height
    if len(pixels) != expected:
        raise UiPidBoundaryError(
            "capability_unavailable",
            "screenshot pixel buffer size mismatch",
            expected=expected,
            actual=len(pixels),
        )
    file_header_size = 14
    info_size = 40
    offset = file_header_size + info_size
    file_size = offset + expected
    header = struct.pack(
        "<2sIHHI",
        b"BM",
        file_size,
        0,
        0,
        offset,
    )
    info = struct.pack(
        "<IiiHHIIiiII",
        info_size,
        width,
        height,  # bottom-up DIB
        1,
        24,
        BI_RGB,
        expected,
        0,
        0,
        0,
        0,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(header)
        handle.write(info)
        handle.write(pixels)
    return file_size


def _estimate_capture_uniformity(
    pixels: bytes,
    width: int,
    height: int,
    row_stride: int,
    *,
    max_samples: int = 4096,
    dark_threshold: int = 24,
    dark_ratio_degraded: float = 0.995,
) -> JsonObject:
    """Detect blank/uniform captures without switching or re-capturing.

    GPU/DirectX/Chromium surfaces frequently return an all-black or single-color
    frame to ``PrintWindow``. Callers surface ``degraded`` so the operator can
    tell a real window apart from an unrenderable one, instead of silently
    falling back to the input desktop. Sampling is bounded so large captures
    stay cheap, and the scan is read-only.
    """
    total = width * height
    if total <= 0 or not pixels:
        return {
            "degraded": True,
            "degraded_reason": "empty_capture",
            "sampled_pixels": 0,
            "uniform_ratio": 1.0,
            "dark_ratio": 1.0,
        }
    step = max(1, total // max_samples)
    sampled = 0
    same = 0
    dark = 0
    first: tuple[int, int, int] | None = None
    for index in range(0, total, step):
        row = index // width
        col = index % width
        offset = row * row_stride + col * 3
        if offset + 3 > len(pixels):
            continue
        pixel = (pixels[offset], pixels[offset + 1], pixels[offset + 2])
        if first is None:
            first = pixel
        if pixel == first:
            same += 1
        if pixel[0] + pixel[1] + pixel[2] <= dark_threshold:
            dark += 1
        sampled += 1
    if sampled == 0 or first is None:
        return {
            "degraded": True,
            "degraded_reason": "empty_capture",
            "sampled_pixels": 0,
            "uniform_ratio": 1.0,
            "dark_ratio": 1.0,
        }
    uniform = same == sampled
    dark_ratio = dark / sampled
    mostly_black = dark_ratio >= dark_ratio_degraded
    degraded = uniform or mostly_black
    reason: str | None = None
    if degraded:
        if sum(first) <= dark_threshold:
            reason = "blank_capture"
        elif uniform:
            reason = "uniform_capture"
        else:
            reason = "mostly_black_capture"
    return {
        "degraded": degraded,
        "degraded_reason": reason,
        "sampled_pixels": sampled,
        "uniform_ratio": round(same / sampled, 4),
        "dark_ratio": round(dark_ratio, 4),
    }


def capture_hwnd_screenshot(
    hwnd: int,
    allowed_pids: frozenset[int],
    output_path: str | Path,
    *,
    client_only: bool = False,
) -> JsonObject:
    """Capture a PID-bounded hwnd into a BMP artifact via PrintWindow/BitBlt.

    Never touches windows outside ``allowed_pids``. Does not use SendInput or
    change foreground focus.
    """
    path = Path(output_path)
    if path.suffix.casefold() != ".bmp":
        raise UiPidBoundaryError(
            "invalid_params",
            "screenshot output_path must end with .bmp",
            output_path=str(path),
        )
    pid = require_allowed_hwnd(hwnd, allowed_pids)
    width, height = _window_capture_size(hwnd, client_only=client_only)

    # Use private WinDLL handles with explicit pointer prototypes so UIA/comtypes
    # cannot poison global ctypes.windll.gdi32 argtypes (OverflowError on HDC).
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    hwnd_ptr = ctypes.c_void_p(int(hwnd))
    for fn_name, restype, argtypes in (
        ("GetWindowDC", ctypes.c_void_p, [ctypes.c_void_p]),
        ("GetDC", ctypes.c_void_p, [ctypes.c_void_p]),
        ("ReleaseDC", ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p]),
        ("PrintWindow", ctypes.c_bool, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]),
    ):
        fn = getattr(user32, fn_name)
        fn.restype = restype
        fn.argtypes = argtypes
    for fn_name, restype, argtypes in (
        ("CreateCompatibleDC", ctypes.c_void_p, [ctypes.c_void_p]),
        ("CreateCompatibleBitmap", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]),
        ("SelectObject", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p]),
        ("BitBlt", ctypes.c_bool, [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint]),
        ("DeleteDC", ctypes.c_bool, [ctypes.c_void_p]),
        ("DeleteObject", ctypes.c_bool, [ctypes.c_void_p]),
        ("GetDIBits", ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]),
    ):
        fn = getattr(gdi32, fn_name)
        fn.restype = restype
        fn.argtypes = argtypes

    window_dc = user32.GetWindowDC(hwnd_ptr) if not client_only else user32.GetDC(hwnd_ptr)
    if not window_dc:
        raise UiPidBoundaryError(
            "capability_unavailable",
            "failed to obtain window DC",
            hwnd=hwnd,
            winerror=ctypes.get_last_error(),
        )
    window_dc = ctypes.c_void_p(int(window_dc))
    mem_dc = gdi32.CreateCompatibleDC(window_dc)
    bitmap = gdi32.CreateCompatibleBitmap(window_dc, width, height)
    old_obj = gdi32.SelectObject(mem_dc, bitmap) if mem_dc and bitmap else 0
    backend = "win32_printwindow"
    try:
        if not mem_dc or not bitmap:
            raise UiPidBoundaryError(
                "capability_unavailable",
                "failed to allocate capture bitmap",
                hwnd=hwnd,
                winerror=ctypes.get_last_error(),
            )
        flags = PW_RENDERFULLCONTENT
        if client_only:
            flags |= PW_CLIENTONLY
        printed = bool(user32.PrintWindow(hwnd_ptr, mem_dc, ctypes.c_uint(flags)))
        if not printed:
            # Fallback for hosts that ignore PrintWindow: BitBlt visible pixels.
            backend = "win32_bitblt"
            if not gdi32.BitBlt(mem_dc, 0, 0, width, height, window_dc, 0, 0, SRCCOPY):
                raise UiPidBoundaryError(
                    "capability_unavailable",
                    "PrintWindow and BitBlt both failed",
                    hwnd=hwnd,
                    winerror=ctypes.get_last_error(),
                )

        # Re-check ownership after capture to close TOCTOU against hwnd reuse.
        require_allowed_hwnd(hwnd, allowed_pids)

        bmi = _BITMAPINFOHEADER()
        bmi.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
        bmi.biWidth = width
        bmi.biHeight = height
        bmi.biPlanes = 1
        bmi.biBitCount = 24
        bmi.biCompression = BI_RGB
        row_stride = ((width * 3 + 3) // 4) * 4
        buffer = (ctypes.c_ubyte * (row_stride * height))()
        got = gdi32.GetDIBits(
            mem_dc,
            bitmap,
            0,
            height,
            ctypes.byref(buffer),
            ctypes.byref(bmi),
            DIB_RGB_COLORS,
        )
        if got != height:
            raise UiPidBoundaryError(
                "capability_unavailable",
                "GetDIBits failed for screenshot",
                hwnd=hwnd,
                got=int(got),
                height=height,
                winerror=ctypes.get_last_error(),
            )
        pixels = bytes(buffer)
        byte_count = _write_bmp_bgr(path, width, height, pixels)
    finally:
        if mem_dc and old_obj:
            gdi32.SelectObject(mem_dc, old_obj)
        if bitmap:
            gdi32.DeleteObject(bitmap)
        if mem_dc:
            gdi32.DeleteDC(mem_dc)
        if client_only:
            user32.ReleaseDC(hwnd_ptr, window_dc)
        else:
            user32.ReleaseDC(hwnd_ptr, window_dc)

    uniformity = _estimate_capture_uniformity(pixels, width, height, row_stride)
    return {
        "hwnd": int(hwnd),
        "pid": pid,
        "action": "screenshot",
        "backend": backend,
        "format": "bmp",
        "width": width,
        "height": height,
        "client_only": bool(client_only),
        "artifact": str(path.resolve()),
        "path": str(path.resolve()),
        "artifact_bytes": byte_count,
        "degraded": bool(uniformity["degraded"]),
        "degraded_reason": uniformity["degraded_reason"],
        "capture_quality": {
            "sampled_pixels": uniformity["sampled_pixels"],
            "uniform_ratio": uniformity["uniform_ratio"],
            "dark_ratio": uniformity["dark_ratio"],
        },
    }


def wait_for_window(
    allowed_pids: frozenset[int],
    *,
    timeout: float = 10.0,
    poll_interval: float = 0.1,
    class_name: str | None = None,
    title: str | None = None,
    title_contains: str | None = None,
    control_id: int | None = None,
    parent_hwnd: int | None = None,
) -> JsonObject:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < float(timeout) <= _MAX_WAIT_SECONDS
    ):
        raise UiPidBoundaryError(
            "invalid_params",
            f"timeout must be > 0 and <= {_MAX_WAIT_SECONDS}",
            timeout=timeout,
        )
    deadline = time.monotonic() + float(timeout)
    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            found = resolve_hwnd(
                allowed_pids,
                parent_hwnd=parent_hwnd,
                class_name=class_name,
                title=title,
                title_contains=title_contains,
                control_id=control_id,
            )
            return {
                "matched": True,
                "window": found,
                "waited_ms": int((float(timeout) - (deadline - time.monotonic())) * 1000),
            }
        except UiPidBoundaryError as exc:
            if exc.code not in {"not_found", "ambiguous"}:
                raise
            last_error = exc.message
            time.sleep(max(0.05, float(poll_interval)))
    raise UiPidBoundaryError(
        "timeout",
        "timed out waiting for window",
        last_error=last_error,
        timeout=timeout,
    )
