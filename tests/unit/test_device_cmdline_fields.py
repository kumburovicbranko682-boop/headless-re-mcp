"""device.cmdline must split the boot command line honestly.

key=value tokens become params (last duplicate wins), bare tokens become flags,
the raw line is preserved, an over-long line is marked truncated, and an empty
read is an error.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    _MAX_CMDLINE_RAW,
    AdbBackend,
    AdbError,
)
from headless_re_mcp.tools.device import build_device_tools

_CMDLINE = (
    "console=ttyMSM0,115200n8 androidboot.hardware=qcom "
    "androidboot.verifiedbootstate=orange androidboot.veritymode=enforcing "
    "quiet androidboot.slot_suffix=_a androidboot.verifiedbootstate=green"
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
        assert command.endswith("/proc/cmdline"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_params_flags_and_last_duplicate_wins() -> None:
    """Tokens split into params/flags; a repeated key takes the last value.

    Measured against AdbBackend.cmdline: androidboot.* and console land in
    params, the bare 'quiet' lands in flags, and verifiedbootstate -- given
    twice -- resolves to the last value (green), matching how the kernel reads
    the command line. raw preserves the exact input.
    """
    payload = _backend(_CMDLINE + "\n").cmdline("emulator-5554")
    params = payload["params"]
    assert params["androidboot.hardware"] == "qcom"
    assert params["androidboot.veritymode"] == "enforcing"
    assert params["androidboot.verifiedbootstate"] == "green"
    assert params["console"] == "ttyMSM0,115200n8"
    assert payload["flags"] == ["quiet"]
    assert payload["raw"] == _CMDLINE
    assert "truncated" not in payload


def test_over_long_line_is_marked_truncated() -> None:
    """A raw line past the cap is cut and flagged truncated."""
    big = " ".join(f"k{index}=v" for index in range(6000))
    payload = _backend(big).cmdline("emulator-5554")
    assert payload["truncated"] is True
    assert len(payload["raw"]) <= _MAX_CMDLINE_RAW


def test_empty_read_is_an_error() -> None:
    """An empty command line is backend_error, never empty params."""
    with pytest.raises(AdbError) as excinfo:
        _backend("   \n").cmdline("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.cmdline")
    assert "params" in doc
    assert "flags" in doc
    assert "raw" in doc
