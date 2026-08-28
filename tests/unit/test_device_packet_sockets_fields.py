"""device.packet_sockets parses /proc/net/packet and stays honest.

AF_PACKET sockets read raw link-layer frames; one bound to ETH_P_ALL
(0x0003) is capturing everything -- the tcpdump/sniffer signature. These
tests pin the field decoding (type, ethertype, capture_all, uid, inode),
the bounded page, and the availability contract that distinguishes a
SELinux/no-CONFIG_PACKET denial (available false) from a readable-but-empty
file (available true) and from an offline device (backend_error).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_HEADER = "sk               RefCnt Type Proto  Iface R Rmem   User   Inode"


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
        assert args == "cat /proc/net/packet"
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_parses_sniffer_and_regular_rows() -> None:
    output = "\n".join(
        [
            _HEADER,
            "0000000000000000 3      3    0003   2     1 0      1000   45678",
            "0000000000000000 2      2    0800   0     0 0      0      12345",
            "",
        ]
    )
    payload = _backend(output).packet_sockets("emulator-5554")
    assert payload["available"] is True
    assert payload["count"] == 2
    assert payload["has_more"] is False
    sniffer, regular = payload["sockets"]
    assert sniffer == {
        "type": 3,
        "type_name": "raw",
        "protocol": 0x0003,
        "protocol_hex": "0x0003",
        "capture_all": True,
        "iface_index": 2,
        "uid": 1000,
        "inode": 45678,
    }
    assert regular["capture_all"] is False
    assert regular["protocol"] == 0x0800
    assert regular["protocol_hex"] == "0x0800"
    assert regular["type_name"] == "datagram"
    assert regular["uid"] == 0
    assert regular["inode"] == 12345


def test_unknown_type_number_falls_back_to_its_digits() -> None:
    output = "\n".join(
        [
            _HEADER,
            "0000000000000000 1      9    0003   1     0 0      2000   999",
        ]
    )
    payload = _backend(output).packet_sockets("emulator-5554")
    assert payload["sockets"][0]["type_name"] == "9"


def test_header_only_is_available_and_empty() -> None:
    payload = _backend(_HEADER + "\n").packet_sockets("emulator-5554")
    assert payload == {
        "available": True,
        "sockets": [],
        "count": 0,
        "has_more": False,
    }


def test_permission_denied_is_available_false_not_error() -> None:
    payload = _backend("cat: /proc/net/packet: Permission denied\n").packet_sockets(
        "emulator-5554"
    )
    assert payload["available"] is False
    assert "Permission denied" in payload["reason"]
    assert payload["sockets"] == []
    assert payload["count"] == 0


def test_no_such_file_is_available_false() -> None:
    payload = _backend("cat: /proc/net/packet: No such file or directory\n").packet_sockets(
        "emulator-5554"
    )
    assert payload["available"] is False
    assert payload["sockets"] == []


def test_host_error_raises_backend_error() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("error: device offline\n").packet_sockets("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_output_without_header_raises_backend_error() -> None:
    # Real content but no recognizable header: refuse rather than invent rows.
    with pytest.raises(AdbError) as excinfo:
        _backend("garbage line one\ngarbage line two\n").packet_sockets("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_malformed_rows_are_skipped_not_fatal() -> None:
    output = "\n".join(
        [
            _HEADER,
            "0000000000000000 3      3",  # too few columns
            "0000000000000000 x      y    zzzz   q     0 0      0      1",  # non-numeric
            "0000000000000000 2      2    0800   0     0 0      0      777",  # valid
        ]
    )
    payload = _backend(output).packet_sockets("emulator-5554")
    assert payload["count"] == 1
    assert payload["sockets"][0]["inode"] == 777


def test_limit_caps_page_and_flags_has_more() -> None:
    rows = [_HEADER] + [
        f"0000000000000000 1      3    0003   1     0 0      0      {i}" for i in range(5)
    ]
    payload = _backend("\n".join(rows)).packet_sockets("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_docstring_names_fields_and_availability_contract() -> None:
    doc = _tool_docstring("device.packet_sockets")
    assert "capture_all" in doc
    assert "ETH_P_ALL" in doc
    assert "available" in doc
