"""Unit coverage for hidden-desktop capture heuristics and lifecycle.

The capture-degradation heuristic is pure and runs on every platform; the
desktop lifecycle / process-launch checks require the Win32 desktop APIs and
are skipped elsewhere.
"""

from __future__ import annotations

import os
import sys

import pytest

from headless_re_mcp.core.ui_win32 import _estimate_capture_uniformity

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
