"""device.loadavg parses the scheduler snapshot and fails honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools


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
        assert command == "cat /proc/loadavg"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_loads_runqueue_and_last_pid_parse() -> None:
    """The run-queue splits on '/', loads are floats, last_pid is an int."""
    payload = _backend(_FakeDev("0.52 0.58 0.59 2/1234 15678")).loadavg("emulator-5554")
    assert payload == {
        "load1": 0.52,
        "load5": 0.58,
        "load15": 0.59,
        "running_entities": 2,
        "total_entities": 1234,
        "last_pid": 15678,
    }


def test_host_error_is_a_backend_error() -> None:
    """An adb host-error reply is a read failure, not an empty reading."""
    dev = _FakeDev("error: device offline")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).loadavg("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_malformed_line_is_a_backend_error() -> None:
    """A line missing the running/total field does not parse to a reading."""
    dev = _FakeDev("0.10 0.20 0.30 nofield 42")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).loadavg("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.loadavg")
    assert "running_entities" in doc
    assert "last_pid" in doc
