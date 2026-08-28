"""device.uptime parses /proc/uptime and stays honest when it cannot.

/proc/uptime is a single line of two floats -- seconds since boot and the
sum of idle seconds across every CPU. It is always present on a live kernel,
so an unreadable or unparseable reply is a backend failure, not an empty
snapshot. These tests pin the field names, float typing, and that host-error
or garbage output raises backend_error instead of a hollow success.
"""

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
    def __init__(self, output: str) -> None:
        self._output = output

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        assert args == "cat /proc/uptime"
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_uptime_parses_two_floats() -> None:
    payload = _backend("605.85 3752.87\n").uptime("emulator-5554")
    assert payload == {"uptime_seconds": 605.85, "idle_seconds": 3752.87}
    assert isinstance(payload["uptime_seconds"], float)
    assert isinstance(payload["idle_seconds"], float)


def test_idle_may_exceed_uptime_on_multicore() -> None:
    # Eight cores idle since boot: idle far exceeds wall-clock uptime.
    payload = _backend("100.00 780.50").uptime("emulator-5554")
    assert payload["uptime_seconds"] == 100.0
    assert payload["idle_seconds"] == 780.5


def test_extra_columns_are_ignored() -> None:
    payload = _backend("12.5 34.5 99.9\n").uptime("emulator-5554")
    assert payload == {"uptime_seconds": 12.5, "idle_seconds": 34.5}


def test_host_error_output_raises_backend_error() -> None:
    backend = _backend("error: device offline\n")
    with pytest.raises(AdbError) as excinfo:
        backend.uptime("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_single_field_raises_backend_error() -> None:
    # A lone value is not a valid /proc/uptime line; do not fabricate idle.
    backend = _backend("605.85\n")
    with pytest.raises(AdbError) as excinfo:
        backend.uptime("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_non_numeric_output_raises_backend_error() -> None:
    backend = _backend("/proc/uptime: No such file or directory\n")
    with pytest.raises(AdbError) as excinfo:
        backend.uptime("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_empty_output_raises_backend_error() -> None:
    backend = _backend("")
    with pytest.raises(AdbError) as excinfo:
        backend.uptime("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_the_fields_and_honesty_contract() -> None:
    doc = _tool_docstring("device.uptime")
    assert "uptime_seconds" in doc
    assert "idle_seconds" in doc
    assert "backend_error" in doc
