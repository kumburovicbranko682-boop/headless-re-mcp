"""device.meminfo must report kB fields honestly and stay bounded.

Only kB-labelled fields are kept (one unit, no guessing), the values are exact
integers, a capped map says has_more, and a read yielding no fields is an
error rather than a bare empty map.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_MEMINFO = "\n".join(
    [
        "MemTotal:        8047856 kB",
        "MemFree:          123456 kB",
        "MemAvailable:    4000000 kB",
        "SwapTotal:       2097148 kB",
        "HugePages_Total:       0",
        "HugePages_Free:        0",
        "Hugepagesize:       2048 kB",
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
    def __init__(self, output: str) -> None:
        self._output = output

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        command = args if isinstance(args, str) else " ".join(args)
        assert command.endswith("/proc/meminfo"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_kb_fields_kept_counts_dropped() -> None:
    """Only kB-labelled fields appear; values are exact ints.

    Measured against AdbBackend.meminfo: the five kB lines are kept with their
    integer kilobyte values, while the unitless HugePages_Total / HugePages_Free
    counts are dropped so every value shares one unit. has_more is False.
    """
    payload = _backend(_MEMINFO).meminfo("emulator-5554")
    assert payload["has_more"] is False
    meminfo = payload["meminfo"]
    assert meminfo["MemTotal"] == 8047856
    assert meminfo["MemAvailable"] == 4000000
    assert meminfo["Hugepagesize"] == 2048
    assert "HugePages_Total" not in meminfo
    assert "HugePages_Free" not in meminfo
    assert payload["count"] == 5


def test_capped_map_says_has_more() -> None:
    """A full map reports has_more instead of posing as every field."""
    lines = [f"Field{index}:  {index} kB" for index in range(300)]
    payload = _backend("\n".join(lines)).meminfo("emulator-5554")
    assert payload["count"] == 256
    assert payload["has_more"] is True


def test_no_fields_is_an_error() -> None:
    """A read with no kB fields is backend_error, never an empty map."""
    with pytest.raises(AdbError) as excinfo:
        _backend("HugePages_Total:  0\n(nothing in kB here)").meminfo("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.meminfo")
    assert "meminfo" in doc
    assert "kilobytes" in doc
    assert "has_more" in doc
