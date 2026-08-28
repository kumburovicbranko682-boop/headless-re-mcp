"""device.ipv6_addrs decodes if_inet6 and keeps three outcomes distinct."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

# lo ::1/128 host, wlan0 link-local fe80::.../64, wlan0 global 2001:db8::1/64.
_IF_INET6 = "\n".join(
    [
        "00000000000000000000000000000001 01 80 10 80       lo",
        "fe80000000000000027c86fffe010203 03 40 20 80    wlan0",
        "20010db8000000000000000000000001 04 40 00 80    wlan0",
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
        assert command == "cat /proc/net/if_inet6"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_addresses_decode_straight_with_scope() -> None:
    """if_inet6 stores bytes in network order, so decoding is reversal-free.

    ::1 is host scope, fe80:: is link-local, and 2001:db8::1 is global -- the
    scope column is what tells a routable address from a link-local one.
    """
    payload = _backend(_FakeDev(_IF_INET6)).ipv6_addrs("emulator-5554")
    assert payload["available"] is True
    assert payload["count"] == 3
    assert payload["has_more"] is False
    entries = payload["addresses"]
    assert entries[0] == {
        "name": "lo",
        "address": "::1",
        "prefix_len": 128,
        "scope": "host",
    }
    assert entries[1]["address"] == "fe80::27c:86ff:fe01:203"
    assert entries[1]["scope"] == "link"
    assert entries[1]["prefix_len"] == 64
    assert entries[2]["address"] == "2001:db8::1"
    assert entries[2]["scope"] == "global"


def test_ipv6_disabled_is_available_false_not_an_error() -> None:
    """A missing file (IPv6 off / locked down) is a real state, not a failure."""
    dev = _FakeDev("cat: /proc/net/if_inet6: No such file or directory")
    payload = _backend(dev).ipv6_addrs("emulator-5554")
    assert payload["available"] is False
    assert payload["addresses"] == []
    assert payload["count"] == 0


def test_offline_device_is_a_backend_error() -> None:
    """An adb host-error reply is transport death, distinct from IPv6-off."""
    dev = _FakeDev("error: device offline")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).ipv6_addrs("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_clean_empty_file_is_available_true_empty() -> None:
    """A readable but empty table means IPv6 present with no addresses."""
    payload = _backend(_FakeDev("")).ipv6_addrs("emulator-5554")
    assert payload["available"] is True
    assert payload["addresses"] == []
    assert payload["count"] == 0


def test_unrecognized_output_is_not_guessed_empty() -> None:
    """Non-error output we cannot parse is an error, never a false empty."""
    dev = _FakeDev("some unexpected banner\nanother unexpected line")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).ipv6_addrs("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_cap_flags_has_more() -> None:
    """Filling the cap sets has_more and does not spill past the limit."""
    rows = [
        f"200104860000000000000000000000{index:02x} 03 40 00 80    wlan0"
        for index in range(1, 6)
    ]
    payload = _backend(_FakeDev("\n".join(rows))).ipv6_addrs("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True
    assert payload["available"] is True


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.ipv6_addrs")
    assert "addresses" in doc
    assert "available" in doc
    assert "IPv6-only" in doc
