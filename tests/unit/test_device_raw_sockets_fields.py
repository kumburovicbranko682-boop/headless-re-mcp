"""device.raw_sockets parses /proc/net/raw[6] and stays honest per family.

A raw (SOCK_RAW) socket carries an IP protocol number in the local_address
"port" slot, not a port; these tests pin that decoding, the host-endian
IPv4/IPv6 address conversion, and the availability contract that tells a
disabled/denied family (families entry false) apart from a readable-empty
one and from an offline device (backend_error).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_RAW_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode ref pointer drops"
)
_RAW6_HEADER = (
    "  sl  local_address                         remote_address                  "
    "      st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"
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
    """Serve canned text for the two raw-socket reads by path."""

    def __init__(self, raw: str, raw6: str) -> None:
        self._by_path = {
            "cat /proc/net/raw": raw,
            "cat /proc/net/raw6": raw6,
        }

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        return self._by_path[args]


def _backend(raw: str, raw6: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(raw, raw6)  # type: ignore[method-assign]
    return backend


def test_parses_ipv4_and_ipv6_rows_with_protocol_not_port() -> None:
    raw = "\n".join(
        [
            _RAW_HEADER,
            "   0: 00000000:0001 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000     0        0 12345 2 0000000000000000 0",
            "   1: 0100007F:0006 0800000A:0000 01 00000000:00000000 "
            "00:00000000 00000000 10133        0 45678 2 0000000000000000 0",
        ]
    )
    raw6 = "\n".join(
        [
            _RAW6_HEADER,
            "   0: 00000000000000000000000001000000:003A "
            "00000000000000000000000000000000:0000 07 00000000:00000000 "
            "00:00000000 00000000     0        0 55555 2 0000000000000000 0",
        ]
    )
    payload = _backend(raw, raw6).raw_sockets("emulator-5554")
    assert payload["families"] == {"ipv4": True, "ipv6": True}
    assert payload["count"] == 3
    assert payload["has_more"] is False

    icmp, tcp_like, v6 = payload["sockets"]
    assert icmp == {
        "family": "ipv4",
        "local_ip": "0.0.0.0",
        "protocol": 1,
        "protocol_name": "icmp",
        "remote_ip": "0.0.0.0",
        "state": 7,
        "uid": 0,
        "inode": 12345,
    }
    # local_address hex is host-endian: 0100007F -> 127.0.0.1, 0800000A -> 10.0.0.8.
    assert tcp_like["local_ip"] == "127.0.0.1"
    assert tcp_like["remote_ip"] == "10.0.0.8"
    assert tcp_like["protocol"] == 6
    assert tcp_like["protocol_name"] == "tcp"
    assert tcp_like["uid"] == 10133
    assert tcp_like["inode"] == 45678
    # raw6 loopback ::1 with ICMPv6 (0x3A = 58).
    assert v6["family"] == "ipv6"
    assert v6["local_ip"] == "::1"
    assert v6["protocol"] == 58
    assert v6["protocol_name"] == "ipv6-icmp"
    assert v6["inode"] == 55555


def test_ipv6_disabled_is_family_false_not_error() -> None:
    raw = _RAW_HEADER + "\n"
    raw6 = "cat: /proc/net/raw6: No such file or directory\n"
    payload = _backend(raw, raw6).raw_sockets("emulator-5554")
    assert payload["families"] == {"ipv4": True, "ipv6": False}
    assert payload["sockets"] == []
    assert payload["count"] == 0


def test_both_denied_returns_empty_not_error() -> None:
    denied = "cat: {}: Permission denied\n"
    payload = _backend(
        denied.format("/proc/net/raw"), denied.format("/proc/net/raw6")
    ).raw_sockets("emulator-5554")
    assert payload["families"] == {"ipv4": False, "ipv6": False}
    assert payload["sockets"] == []
    assert payload["has_more"] is False


def test_host_error_on_both_raises_backend_error() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("error: device offline\n", "error: device offline\n").raw_sockets(
            "emulator-5554"
        )
    assert excinfo.value.code == "backend_error"


def test_unknown_protocol_number_falls_back_to_digits() -> None:
    raw = "\n".join(
        [
            _RAW_HEADER,
            "   0: 00000000:00FD 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000  1000        0 321 2 0000000000000000 0",
        ]
    )
    payload = _backend(raw, _RAW_HEADER + "\n").raw_sockets("emulator-5554")
    row = payload["sockets"][0]
    assert row["protocol"] == 253
    assert row["protocol_name"] == "253"


def test_malformed_rows_are_skipped() -> None:
    raw = "\n".join(
        [
            _RAW_HEADER,
            "   0: short row",  # too few columns
            "   1: ZZZZZZZZ:0001 00000000:0000 07 x x x x x 999",  # bad hex ip
            "   2: 00000000:0001 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000     0        0 777 2 0000000000000000 0",  # valid
        ]
    )
    payload = _backend(raw, _RAW_HEADER + "\n").raw_sockets("emulator-5554")
    assert payload["count"] == 1
    assert payload["sockets"][0]["inode"] == 777


def test_limit_caps_and_flags_has_more() -> None:
    rows = [_RAW_HEADER] + [
        f"   {i}: 00000000:0001 00000000:0000 07 00000000:00000000 "
        f"00:00000000 00000000     0        0 {1000 + i} 2 0000000000000000 0"
        for i in range(4)
    ]
    payload = _backend("\n".join(rows), _RAW_HEADER + "\n").raw_sockets(
        "emulator-5554", limit=2
    )
    assert payload["count"] == 2
    assert payload["has_more"] is True
    # ipv6 was still probed for availability even though the page filled on ipv4.
    assert payload["families"] == {"ipv4": True, "ipv6": True}


def test_docstring_names_fields_and_family_contract() -> None:
    doc = _tool_docstring("device.raw_sockets")
    assert "protocol" in doc
    assert "families" in doc
    assert "CAP_NET_RAW" in doc
