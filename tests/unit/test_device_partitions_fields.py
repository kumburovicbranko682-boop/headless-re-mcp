"""device.partitions must parse /proc/partitions honestly.

The header and error text are skipped by requiring integer major/minor/blocks,
size_bytes is blocks x 1024, a capped list says has_more, and a read yielding no
partitions is an error.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_PARTITIONS = "\n".join(
    [
        "major minor  #blocks  name",
        "",
        "179        0  15267840 mmcblk0",
        "179       48     65536 mmcblk0p48",
        "254        0    524288 dm-0",
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
        assert command.endswith("/proc/partitions"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_partitions_parse_with_size_bytes() -> None:
    """Rows parse; the header/blank are skipped and size_bytes is blocks x 1024.

    Measured against AdbBackend.partitions: count 3, has_more False. The whole
    disk and a partition both appear with integer major/minor/blocks, and
    size_bytes is the 1024-byte block count times 1024.
    """
    payload = _backend(_PARTITIONS).partitions("emulator-5554")
    assert payload["count"] == 3
    assert payload["has_more"] is False
    parts = payload["partitions"]
    assert parts[0] == {
        "name": "mmcblk0",
        "major": 179,
        "minor": 0,
        "blocks": 15267840,
        "size_bytes": 15267840 * 1024,
    }
    assert parts[1]["name"] == "mmcblk0p48"
    assert parts[2]["name"] == "dm-0"


def test_error_text_is_not_a_partition() -> None:
    """A permission-denied line has no integer columns, so it yields an error.

    'cat: /proc/partitions: Permission denied' has four tokens but non-numeric
    major/minor, so nothing parses and the call is backend_error rather than a
    bogus partition.
    """
    with pytest.raises(AdbError) as excinfo:
        _backend("cat: /proc/partitions: Permission denied").partitions("x")
    assert excinfo.value.code == "backend_error"


def test_header_only_is_an_error() -> None:
    """A header with no rows is backend_error (a live device always has some)."""
    with pytest.raises(AdbError) as excinfo:
        _backend("major minor  #blocks  name\n\n").partitions("x")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.partitions")
    assert "partitions" in doc
    assert "size_bytes" in doc
    assert "has_more" in doc
