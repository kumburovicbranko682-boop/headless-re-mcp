"""device.routes must decode /proc/net/route addresses exactly and stay honest.

Little-endian hex words become dotted IPv4, the default route surfaces the
gateway, an empty table is a real result, and a read missing the header is an
error.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    AdbBackend,
    AdbError,
    _hex_le_ipv4,
)
from headless_re_mcp.tools.device import build_device_tools

_HEADER = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask"
    "\t\tMTU\tWindow\tIRTT"
)
_ROUTES = "\n".join(
    [
        _HEADER,
        "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0",
        "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0",
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
        assert command.endswith("/proc/net/route"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_le_hex_decoding_is_exact() -> None:
    """Little-endian hex words decode to the right dotted IPv4."""
    assert _hex_le_ipv4("0101A8C0") == "192.168.1.1"
    assert _hex_le_ipv4("00000000") == "0.0.0.0"
    assert _hex_le_ipv4("00FFFFFF") == "255.255.255.0"
    assert _hex_le_ipv4("zzzz") is None


def test_default_route_and_subnet() -> None:
    """The default route surfaces the gateway; the subnet route its mask.

    Measured against AdbBackend.routes: two routes parse, has_more False. The
    default route has destination 0.0.0.0 and gateway 192.168.1.1; the on-link
    subnet route has destination 192.168.1.0, a 0.0.0.0 gateway and a
    255.255.255.0 mask. The raw flags hex is preserved.
    """
    payload = _backend(_ROUTES).routes("emulator-5554")
    assert payload["count"] == 2
    assert payload["has_more"] is False
    routes = payload["routes"]
    assert routes[0] == {
        "iface": "wlan0",
        "destination": "0.0.0.0",
        "gateway": "192.168.1.1",
        "mask": "0.0.0.0",
        "flags": "0003",
    }
    assert routes[1]["destination"] == "192.168.1.0"
    assert routes[1]["mask"] == "255.255.255.0"


def test_empty_table_is_not_an_error() -> None:
    """A header with no routes is an honest empty table, not a failure."""
    payload = _backend(_HEADER + "\n").routes("emulator-5554")
    assert payload["count"] == 0
    assert payload["routes"] == []


def test_missing_header_is_an_error() -> None:
    """A denied / missing read (no header) is backend_error."""
    with pytest.raises(AdbError) as excinfo:
        _backend("cat: /proc/net/route: Permission denied").routes("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.routes")
    assert "routes" in doc
    assert "gateway" in doc
    assert "has_more" in doc
