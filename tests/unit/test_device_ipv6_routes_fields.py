"""device.ipv6_routes decodes /proc/net/ipv6_route and keeps outcomes distinct."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

# default route via fe80::1 on wlan0, an on-link 2001:db8::/64, and ::1/128 on lo.
_IPV6_ROUTE = "\n".join(
    [
        "00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00 "
        "fe800000000000000000000000000001 00000400 00000000 00000000 00000003 wlan0",
        "20010db8000000000000000000000000 40 "
        "00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000100 00000000 00000000 00000001 wlan0",
        "00000000000000000000000000000001 80 "
        "00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000000 00000000 00000000 80200001 lo",
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
        assert command == "cat /proc/net/ipv6_route"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_routes_decode_network_order_straight() -> None:
    """Addresses are network-order hex, prefix/flags are hex, next_hop :: is on-link.

    The default route is the all-zero destination with prefix 0; getting the
    reversal wrong (as tcp6 needs) would corrupt the gateway address.
    """
    payload = _backend(_FakeDev(_IPV6_ROUTE)).ipv6_routes("emulator-5554")
    routes = payload["routes"]
    assert payload["available"] is True
    assert payload["count"] == 3
    assert payload["has_more"] is False
    assert routes[0] == {
        "destination": "::",
        "prefix_len": 0,
        "next_hop": "fe80::1",
        "flags": 0x3,
        "device": "wlan0",
    }
    assert routes[1]["destination"] == "2001:db8::"
    assert routes[1]["prefix_len"] == 64
    assert routes[1]["next_hop"] == "::"
    assert routes[2]["destination"] == "::1"
    assert routes[2]["prefix_len"] == 128
    assert routes[2]["flags"] == 0x80200001
    assert routes[2]["device"] == "lo"


def test_ipv6_disabled_is_available_false_not_an_error() -> None:
    """A missing file (IPv6 off / locked down) is a real state, not a failure."""
    dev = _FakeDev("cat: /proc/net/ipv6_route: No such file or directory")
    payload = _backend(dev).ipv6_routes("emulator-5554")
    assert payload["available"] is False
    assert payload["routes"] == []
    assert payload["count"] == 0


def test_offline_device_is_a_backend_error() -> None:
    """An adb host-error reply is transport death, distinct from IPv6-off."""
    dev = _FakeDev("error: device offline")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).ipv6_routes("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_unrecognized_output_is_not_guessed_empty() -> None:
    """Non-error output we cannot parse is an error, never a false empty."""
    dev = _FakeDev("this is clearly not an ipv6 route table")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).ipv6_routes("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_cap_flags_has_more() -> None:
    """Filling the cap sets has_more and does not spill past the limit."""
    payload = _backend(_FakeDev(_IPV6_ROUTE)).ipv6_routes("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True
    assert payload["available"] is True


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.ipv6_routes")
    assert "routes" in doc
    assert "available" in doc
    assert "next_hop" in doc
