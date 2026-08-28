"""device.net_snmp6 reads the flat if_snmp6 table and keeps outcomes distinct."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_SNMP6 = "\n".join(
    [
        "Ip6InReceives                       12345",
        "Ip6InHdrErrors                      0",
        "Ip6OutRequests                      9000",
        "Icmp6InMsgs                         10",
        "Icmp6InErrors                       0",
        "Udp6InDatagrams                     500",
        "Udp6NoPorts                         3",
        "Udp6InErrors                        1",
        # A malformed line (not exactly name + integer) must be skipped.
        "GarbageLineWithoutValue",
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
        assert command == "cat /proc/net/snmp6"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_flat_counters_parse() -> None:
    """Each Name Value line becomes one counter; a valueless line is dropped."""
    payload = _backend(_FakeDev(_SNMP6)).net_snmp6("emulator-5554")
    counters = payload["counters"]
    assert payload["available"] is True
    assert payload["count"] == 8
    assert payload["has_more"] is False
    assert counters["Ip6InReceives"] == 12345
    assert counters["Udp6NoPorts"] == 3
    assert counters["Udp6InErrors"] == 1
    assert "GarbageLineWithoutValue" not in counters


def test_ipv6_disabled_is_available_false_not_an_error() -> None:
    """A missing file (IPv6 off / locked down) is a real state, not a failure."""
    dev = _FakeDev("cat: /proc/net/snmp6: No such file or directory")
    payload = _backend(dev).net_snmp6("emulator-5554")
    assert payload["available"] is False
    assert payload["counters"] == {}
    assert payload["count"] == 0


def test_offline_device_is_a_backend_error() -> None:
    """An adb host-error reply is transport death, distinct from IPv6-off."""
    dev = _FakeDev("error: device offline")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).net_snmp6("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_unrecognized_output_is_not_guessed_empty() -> None:
    """Non-error output we cannot parse is an error, never a false empty."""
    dev = _FakeDev("this is not the snmp6 table at all")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).net_snmp6("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.net_snmp6")
    assert "counters" in doc
    assert "available" in doc
    assert "IPv6" in doc
