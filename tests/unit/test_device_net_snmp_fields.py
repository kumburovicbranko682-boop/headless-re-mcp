"""device.net_snmp pairs header/value lines and fails honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_SNMP = "\n".join(
    [
        "Ip: Forwarding DefaultTTL InReceives InHdrErrors InDelivers OutRequests",
        "Ip: 2 64 12345 0 12000 9000",
        "Icmp: InMsgs InErrors InDestUnreachs",
        "Icmp: 10 1 3",
        "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens "
        "AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs OutRsts",
        "Tcp: 1 200 120000 -1 100 50 2 3 5 9999 8888 12 7",
        "Udp: InDatagrams NoPorts InErrors OutDatagrams",
        "Udp: 500 3 1 400",
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
        assert command == "cat /proc/net/snmp"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_header_value_pairs_zip_per_protocol() -> None:
    """Names and values zip by column; signed counters keep their sign.

    Tcp.MaxConn is -1 in every kernel, so treating the column as unsigned or
    dropping the minus would silently corrupt it.
    """
    payload = _backend(_FakeDev(_SNMP)).net_snmp("emulator-5554")
    protocols = payload["protocols"]
    assert payload["count"] == 4
    assert payload["has_more"] is False
    assert set(protocols) == {"Ip", "Icmp", "Tcp", "Udp"}
    assert protocols["Ip"]["InReceives"] == 12345
    assert protocols["Tcp"]["MaxConn"] == -1
    assert protocols["Tcp"]["CurrEstab"] == 5
    assert protocols["Tcp"]["RetransSegs"] == 12
    assert protocols["Tcp"]["OutRsts"] == 7
    assert protocols["Udp"]["NoPorts"] == 3
    assert protocols["Udp"]["InErrors"] == 1


def test_value_line_without_header_is_skipped() -> None:
    """A values row with no preceding names row is dropped, not guessed."""
    body = "\n".join(
        [
            "Ip: Forwarding DefaultTTL InReceives",
            "Ip: 2 64 100",
            "Orphan: 5 6 7",
        ]
    )
    payload = _backend(_FakeDev(body)).net_snmp("emulator-5554")
    assert set(payload["protocols"]) == {"Ip"}
    assert payload["count"] == 1


def test_duplicate_protocol_block_keeps_the_first() -> None:
    """A repeated protocol block does not overwrite the captured one."""
    body = "\n".join(
        [
            "Tcp: ActiveOpens RetransSegs",
            "Tcp: 100 12",
            "Tcp: ActiveOpens RetransSegs",
            "Tcp: 999 88",
        ]
    )
    payload = _backend(_FakeDev(body)).net_snmp("emulator-5554")
    assert payload["protocols"]["Tcp"] == {"ActiveOpens": 100, "RetransSegs": 12}


def test_zero_protocols_is_a_backend_error() -> None:
    """A missing or refused file is a read failure, not an empty map."""
    dev = _FakeDev("cat: /proc/net/snmp: No such file or directory")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).net_snmp("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.net_snmp")
    assert "protocols" in doc
    assert "has_more" in doc
    assert "negative" in doc
