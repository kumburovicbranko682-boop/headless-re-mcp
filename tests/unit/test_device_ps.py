"""device.ps must list the process table honestly and filter by name."""

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
    def __init__(self, text: str) -> None:
        self._text = text

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return self._text


def _backend(text: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True  # type: ignore[attr-defined]
    backend._device = lambda serial: _FakeDev(text)  # type: ignore[method-assign]
    return backend


_PS = """USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME
root             1     0   10800   1234 0                   0 S init
root           678     1   20000   2345 0                   0 S zygote64
u0_a123      12345   678 1234567  45678 0                   0 S com.example.app
shell        23456   789    9000    900 0                   0 R frida-server
"""


def test_ps_parses_columns_and_skips_the_header() -> None:
    payload = _backend(_PS).processes("emulator-5554")
    assert payload["total"] == 4
    assert payload["count"] == 4
    assert payload["offset"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    first = payload["processes"][0]
    assert first == {"user": "root", "pid": 1, "ppid": 0, "name": "init"}
    # sorted by pid ascending
    pids = [row["pid"] for row in payload["processes"]]
    assert pids == sorted(pids)
    names = {row["name"] for row in payload["processes"]}
    assert "com.example.app" in names
    assert "frida-server" in names


def test_name_filter_is_case_insensitive_substring_and_echoes_back() -> None:
    payload = _backend(_PS).processes("emulator-5554", name_filter="FRIDA")
    assert payload["count"] == 1
    assert payload["total"] == 1
    assert payload["processes"][0]["name"] == "frida-server"
    assert payload["processes"][0]["pid"] == 23456
    assert payload["name_filter"] == "FRIDA"


def test_paging_reports_has_more() -> None:
    first = _backend(_PS).processes("emulator-5554", offset=0, limit=2)
    assert first["count"] == 2
    assert first["total"] == 4
    assert first["has_more"] is True
    tail = _backend(_PS).processes("emulator-5554", offset=2, limit=2)
    assert tail["count"] == 2
    assert tail["offset"] == 2
    assert tail["has_more"] is False


def test_no_name_filter_key_when_not_given() -> None:
    payload = _backend(_PS).processes("emulator-5554")
    assert "name_filter" not in payload


def test_host_error_output_is_a_backend_error() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("error: device offline\n").processes("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_the_fields() -> None:
    doc = _tool_docstring("device.ps")
    assert "processes" in doc
    assert "name_filter" in doc
    assert "has_more" in doc
