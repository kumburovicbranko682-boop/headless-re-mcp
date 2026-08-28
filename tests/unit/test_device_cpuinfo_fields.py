"""device.cpuinfo must parse /proc/cpuinfo block-by-block and stay honest.

Blocks are preserved verbatim across architectures, the core count ignores a
trailing summary block, oversized values are cut and flagged, a capped list
says has_more, and a read yielding no blocks is an error.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    _MAX_CPU_VALUE,
    AdbBackend,
    AdbError,
)
from headless_re_mcp.tools.device import build_device_tools

_ARM = "\n".join(
    [
        "processor\t: 0",
        "BogoMIPS\t: 38.40",
        "Features\t: fp asimd aes pmull sha1 sha2 crc32",
        "CPU implementer\t: 0x51",
        "CPU architecture: 8",
        "",
        "processor\t: 1",
        "BogoMIPS\t: 38.40",
        "Features\t: fp asimd aes pmull sha1 sha2 crc32",
        "CPU implementer\t: 0x51",
        "",
        "Hardware\t: Qualcomm Technologies, Inc SDM845",
        "Revision\t: 0000",
        "",
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
        assert command.endswith("/proc/cpuinfo"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_arm_blocks_and_core_count() -> None:
    """ARM cpuinfo: two cores plus a trailing Hardware block.

    Measured against AdbBackend.cpuinfo: three blocks parse, but processors is
    2 -- only the blocks with a processor key count, so the Hardware summary is
    not miscounted as a core. The Features string is preserved verbatim.
    """
    payload = _backend(_ARM).cpuinfo("emulator-5554")
    assert payload["count"] == 3
    assert payload["processors"] == 2
    assert payload["has_more"] is False
    assert "value_truncated" not in payload
    blocks = payload["blocks"]
    assert blocks[0]["processor"] == "0"
    assert "aes" in blocks[0]["Features"]
    assert blocks[0]["CPU architecture"] == "8"
    assert blocks[2]["Hardware"].startswith("Qualcomm")
    assert "processor" not in blocks[2]


def test_oversized_value_is_cut_and_flagged() -> None:
    """A pathologically long flags line is cut and value_truncated is set."""
    long_flags = "flags\t: " + " ".join(f"f{index}" for index in range(4000))
    payload = _backend(f"processor\t: 0\n{long_flags}\n").cpuinfo("emulator-5554")
    assert payload["value_truncated"] is True
    assert len(payload["blocks"][0]["flags"]) == _MAX_CPU_VALUE


def test_no_blocks_is_an_error() -> None:
    """A read with no parseable blocks is backend_error, never an empty list."""
    with pytest.raises(AdbError) as excinfo:
        _backend("\n\n   \n").cpuinfo("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.cpuinfo")
    assert "blocks" in doc
    assert "processors" in doc
    assert "has_more" in doc
