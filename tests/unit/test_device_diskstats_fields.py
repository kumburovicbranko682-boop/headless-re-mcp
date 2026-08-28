"""device.diskstats decodes /proc/diskstats and converts sectors honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_DISKSTATS = "\n".join(
    [
        "   8       0 sda 12345 100 987654 5000 6789 200 543210 3000 0 4000 8000",
        "   8       1 sda1 1000 10 20000 500 500 20 10000 300 0 700 800",
        " 254       0 dm-0 50 0 400 10 60 0 480 20 0 30 30",
        # Too few columns to be a diskstats row -- must be skipped.
        "cat: /proc/diskstats: truncated",
    ]
)


def _tool_docstring(name: str) -> str:
    source = Path(build_device_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _FakeDev:
    def __init__(self, body: str) -> None:
        self._body = body

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        command = args if isinstance(args, str) else " ".join(args)
        assert command == "cat /proc/diskstats"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_columns_decode_and_bytes_are_sectors_times_512() -> None:
    """The headline read_bytes/write_bytes come from the 512-byte sector unit.

    /proc/diskstats always counts 512-byte sectors regardless of the device's
    physical block size, so multiplying by the physical size instead would
    overstate the transfer.
    """
    payload = _backend(_FakeDev(_DISKSTATS)).diskstats("emulator-5554")
    devices = {entry["name"]: entry for entry in payload["devices"]}
    assert payload["count"] == 3
    assert payload["has_more"] is False
    assert set(devices) == {"sda", "sda1", "dm-0"}
    sda = devices["sda"]
    assert sda["major"] == 8
    assert sda["minor"] == 0
    assert sda["reads_completed"] == 12345
    assert sda["sectors_read"] == 987654
    assert sda["read_ms"] == 5000
    assert sda["writes_completed"] == 6789
    assert sda["sectors_written"] == 543210
    assert sda["write_ms"] == 3000
    assert sda["ios_in_progress"] == 0
    assert sda["io_ms"] == 4000
    assert sda["read_bytes"] == 987654 * 512
    assert sda["write_bytes"] == 543210 * 512
    assert set(sda) == {
        "name",
        "major",
        "minor",
        "reads_completed",
        "sectors_read",
        "read_ms",
        "writes_completed",
        "sectors_written",
        "write_ms",
        "ios_in_progress",
        "io_ms",
        "read_bytes",
        "write_bytes",
    }


def test_zero_devices_is_a_backend_error() -> None:
    """A live device always has block devices, so empty means the read failed."""
    dev = _FakeDev("cat: /proc/diskstats: No such file or directory")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).diskstats("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_cap_flags_has_more() -> None:
    """Filling the cap sets has_more and does not spill past the limit."""
    rows = [
        f"   7       {index} loop{index} 1 0 2 0 0 0 0 0 0 0 0"
        for index in range(0, 5)
    ]
    payload = _backend(_FakeDev("\n".join(rows))).diskstats("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.diskstats")
    assert "devices" in doc
    assert "read_bytes" in doc
    assert "has_more" in doc
