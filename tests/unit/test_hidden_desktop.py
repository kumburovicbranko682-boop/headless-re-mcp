"""Unit coverage for hidden-desktop capture heuristics and lifecycle.

The capture-degradation heuristic is pure and runs on every platform; the
desktop lifecycle / process-launch checks require the Win32 desktop APIs and
are skipped elsewhere.
"""

from __future__ import annotations

import os
import sys

import pytest

from headless_re_mcp.core.ui_win32 import _estimate_capture_uniformity, _prefer_capture_uniformity

WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="requires Win32 desktop APIs")


def _stride(width: int) -> int:
    return ((width * 3 + 3) // 4) * 4


def _solid(width: int, height: int, color: tuple[int, int, int]) -> tuple[bytes, int]:
    stride = _stride(width)
    row = bytearray()
    for _ in range(width):
        row += bytes(color)
    row += bytes(stride - width * 3)
    return bytes(row) * height, stride


def test_snapshot_input_desktop_is_empty_off_windows(monkeypatch) -> None:
    monkeypatch.setattr("headless_re_mcp.core.windows.os.name", "posix")
    from headless_re_mcp.core.windows import snapshot_input_desktop

    snapshot = snapshot_input_desktop(allowed_pids=frozenset({1}))
    assert snapshot["available"] is False
    assert snapshot["windows"] == []
    assert snapshot["window_count"] == 0
    assert snapshot["desktop_window_count"] == 0


def test_openfilename_file_buffer_casts_to_lpwstr() -> None:
    """GetOpenFileNameW used to raise TypeError on the file buffer itself."""
    import ctypes
    from ctypes import wintypes

    file_buf = ctypes.create_unicode_buffer(32)
    filter_buf = ctypes.create_unicode_buffer("All\0*.*\0")

    class OPENFILENAMEW(ctypes.Structure):
        _fields_ = [
            ("lpstrFilter", wintypes.LPCWSTR),
            ("lpstrFile", wintypes.LPWSTR),
        ]

    ofn = OPENFILENAMEW()
    ofn.lpstrFilter = ctypes.cast(filter_buf, wintypes.LPCWSTR)
    ofn.lpstrFile = ctypes.cast(file_buf, wintypes.LPWSTR)
    file_buf.value = "C:\\sample.exe"
    assert ofn.lpstrFile == "C:\\sample.exe"


def test_black_capture_flagged_blank() -> None:
    width, height = 48, 48
    pixels, stride = _solid(width, height, (0, 0, 0))
    result = _estimate_capture_uniformity(pixels, width, height, stride)
    assert result["degraded"] is True
    assert result["degraded_reason"] == "blank_capture"


def test_uniform_nonblack_flagged_uniform() -> None:
    width, height = 48, 48
    pixels, stride = _solid(width, height, (255, 255, 255))
    result = _estimate_capture_uniformity(pixels, width, height, stride)
    assert result["degraded"] is True
    assert result["degraded_reason"] == "uniform_capture"


def test_varied_capture_not_degraded() -> None:
    width, height = 64, 64
    stride = _stride(width)
    buffer = bytearray()
    for y in range(height):
        for x in range(width):
            value = (x * 4 + y * 4) % 256
            buffer += bytes(((value + 30) % 256, (value + 90) % 256, (value + 150) % 256))
        buffer += bytes(stride - width * 3)
    result = _estimate_capture_uniformity(bytes(buffer), width, height, stride)
    assert result["degraded"] is False
    assert result["degraded_reason"] is None
    assert result["uniform_ratio"] < 1.0


def test_empty_capture_flagged() -> None:
    result = _estimate_capture_uniformity(b"", 0, 0, 0)
    assert result["degraded"] is True
    assert result["degraded_reason"] == "empty_capture"
    assert result["sampled_pixels"] == 0


def test_prefer_capture_picks_less_black_frame() -> None:
    blank = {"degraded": True, "dark_ratio": 1.0}
    varied = {"degraded": False, "dark_ratio": 0.1}
    assert _prefer_capture_uniformity(blank, varied) is True
    assert _prefer_capture_uniformity(varied, blank) is False


def test_window_capture_rank_prefers_nonzero_area() -> None:
    from headless_re_mcp.core.service_ui import _select_desktop_window
    from headless_re_mcp.core.windows import window_capture_rank, window_is_capturable

    empty = {
        "hwnd": 1,
        "visible": True,
        "minimized": False,
        "area": 0,
        "title": "ghost",
        "rect": {"width": 0, "height": 0},
    }
    hidden = {
        "hwnd": 2,
        "visible": False,
        "minimized": False,
        "area": 800 * 600,
        "title": "x64dbg",
        "rect": {"width": 800, "height": 600},
    }
    assert window_is_capturable(empty) is False
    assert window_is_capturable(hidden) is True
    assert window_capture_rank(hidden) > window_capture_rank(empty)
    assert _select_desktop_window([empty, hidden], None)["hwnd"] == 2


def test_pick_open_file_status_is_unavailable_off_windows(monkeypatch) -> None:
    monkeypatch.setattr("headless_re_mcp.core.windows.os.name", "posix")
    from headless_re_mcp.core.windows import pick_open_file, pick_open_file_status

    result = pick_open_file_status()
    assert result["available"] is False
    assert result["path"] is None
    assert result["busy"] is False
    assert pick_open_file() is None


def test_pick_open_file_status_busy_does_not_look_like_cancel(monkeypatch) -> None:
    from headless_re_mcp.core import windows as winmod

    monkeypatch.setattr(winmod.os, "name", "nt")
    assert winmod._PICK_LOCK.acquire(blocking=False)
    try:
        result = winmod.pick_open_file_status()
        assert result["busy"] is True
        assert result["cancelled"] is False
        assert result["path"] is None
        assert result["available"] is True
    finally:
        winmod._PICK_LOCK.release()


@WINDOWS_ONLY
def test_hidden_desktop_lifecycle_is_isolated() -> None:
    from headless_re_mcp.core.hidden_desktop import HiddenDesktop

    desktop = HiddenDesktop.create(prefix="HeadlessRE-Test")
    try:
        assert desktop.name.startswith("HeadlessRE-Test-")
        assert desktop.qualified_name == rf"WinSta0\{desktop.name}"
        snapshot = desktop.snapshot()
        assert snapshot["available"] is True
        assert snapshot["input_desktop"] is False
        assert isinstance(snapshot["windows"], list)
    finally:
        desktop.close()
    desktop.close()  # idempotent


@WINDOWS_ONLY
def test_process_spawns_on_hidden_desktop() -> None:
    from headless_re_mcp.core.hidden_desktop import HiddenDesktop

    desktop = HiddenDesktop.create(prefix="HeadlessRE-Test")
    try:
        process = desktop.spawn([sys.executable, "-c", "import sys; sys.exit(7)"])
        try:
            assert process.wait(timeout=30) == 7
        finally:
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
    finally:
        desktop.close()


@WINDOWS_ONLY
def test_wnd_enum_callback_uses_win32_bool() -> None:
    import ctypes
    from ctypes import wintypes

    from headless_re_mcp.core.windows import wnd_enum_callback_type

    proto = wnd_enum_callback_type()
    assert ctypes.sizeof(proto._restype_) == 4
    assert proto._restype_ is not ctypes.c_bool
    assert proto._restype_ is wintypes.BOOL
    assert list(proto._argtypes_) == [wintypes.HWND, wintypes.LPARAM]


def test_paused_debuggee_with_zero_windows_is_named() -> None:
    from headless_re_mcp.core.service_ui import _annotate_virtual_desktop_snapshot

    payload = _annotate_virtual_desktop_snapshot(
        {
            "available": True,
            "windows": [],
            "window_count": 0,
            "desktop_window_count": 4,
        },
        session_id="s1",
        state={"state": "paused", "process_id": 55884},
        allowed=frozenset({55884}),
        debuggee_pid=55884,
        debugger_pid=99,
    )
    assert payload["hint"] == "paused_before_gui"
    assert payload["debuggee_state"] == "paused"
    assert payload["desktop_window_count"] == 4
    assert payload["window_count"] == 0
    assert "dynamic.resume" in str(payload["suggestion"])


def test_desktop_monitor_pids_accepts_string_process_id(monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp.core import service_ui

    monkeypatch.setattr(service_ui, "is_pid_alive", lambda pid: pid == 55884)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.enumerate_direct_children",
        lambda _pid: [],
    )
    allowed, debuggee = service_ui._desktop_monitor_pids(
        {"process_id": "55884", "state": "paused"}
    )
    assert debuggee == 55884
    assert allowed == frozenset({55884})
