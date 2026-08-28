"""device.protocols parses /proc/net/protocols and stays honest.

Each row is a kernel protocol handler with its live socket count. These
tests pin the field decoding (including the -1 "not tracked" memory value),
the bounded page, and the availability contract that tells a SELinux/absent
denial (available false) apart from a readable file and an offline device
(backend_error).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_HEADER = "protocol size sockets memory press maxhdr slab module"


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
        assert args == "cat /proc/net/protocols"
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_parses_rows_with_socket_counts_and_negative_memory() -> None:
    output = "\n".join(
        [
            _HEADER,
            # name size sockets memory press maxhdr slab module <flags...>
            "PACKET 1344 2 -1 NI 0 no kernel n n n n n n n",
            "RAWv6 1112 1 -1 NI 0 yes kernel y y y n y y n",
            "TCPv6 2504 12 17 yes 1472 yes kernel y y y y y y y",
            "NETLINK 1040 8 -1 NI 0 no kernel n n n n n n n",
        ]
    )
    payload = _backend(output).protocols("emulator-5554")
    assert payload["available"] is True
    assert payload["count"] == 4
    assert payload["has_more"] is False

    packet, rawv6, tcpv6, netlink = payload["protocols"]
    assert packet == {
        "name": "PACKET",
        "size": 1344,
        "sockets": 2,
        "memory": -1,
        "module": "kernel",
    }
    assert rawv6["name"] == "RAWv6"
    assert rawv6["sockets"] == 1
    assert tcpv6["name"] == "TCPv6"
    assert tcpv6["sockets"] == 12
    assert tcpv6["memory"] == 17
    assert netlink["sockets"] == 8


def test_module_backed_protocol_keeps_module_name() -> None:
    output = "\n".join(
        [
            _HEADER,
            "SCTP 1500 3 -1 NI 0 yes sctp y y y n y y n",
        ]
    )
    row = _backend(output).protocols("emulator-5554")["protocols"][0]
    assert row["module"] == "sctp"


def test_permission_denied_is_available_false() -> None:
    payload = _backend("cat: /proc/net/protocols: Permission denied\n").protocols(
        "emulator-5554"
    )
    assert payload["available"] is False
    assert "Permission denied" in payload["reason"]
    assert payload["protocols"] == []
    assert payload["count"] == 0


def test_no_such_file_is_available_false() -> None:
    payload = _backend("cat: /proc/net/protocols: No such file or directory\n").protocols(
        "emulator-5554"
    )
    assert payload["available"] is False
    assert payload["protocols"] == []


def test_host_error_raises_backend_error() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("error: device offline\n").protocols("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_output_without_header_raises_backend_error() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("garbage one\ngarbage two\n").protocols("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_header_only_is_available_and_empty() -> None:
    payload = _backend(_HEADER + "\n").protocols("emulator-5554")
    assert payload == {
        "available": True,
        "protocols": [],
        "count": 0,
        "has_more": False,
    }


def test_malformed_rows_are_skipped() -> None:
    output = "\n".join(
        [
            _HEADER,
            "TRUNCATED 1000 5",  # too few columns
            "BADSIZE x 5 -1 NI 0 no kernel n",  # non-numeric size
            "UNIX 1024 42 -1 NI 0 yes kernel y y",  # valid
        ]
    )
    payload = _backend(output).protocols("emulator-5554")
    assert payload["count"] == 1
    assert payload["protocols"][0]["name"] == "UNIX"
    assert payload["protocols"][0]["sockets"] == 42


def test_limit_caps_page_and_flags_has_more() -> None:
    rows = [_HEADER] + [
        f"PROTO{i} 1000 {i} -1 NI 0 no kernel n" for i in range(5)
    ]
    payload = _backend("\n".join(rows)).protocols("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_docstring_names_fields_and_contract() -> None:
    doc = _tool_docstring("device.protocols")
    assert "sockets" in doc
    assert "module" in doc
    assert "available" in doc
