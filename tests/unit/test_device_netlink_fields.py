"""device.netlink parses /proc/net/netlink and stays honest.

Netlink sockets connect userspace to the kernel; the "Eth" column is the
netlink protocol family (not an ethertype) and a nonzero groups mask marks a
multicast event subscriber. These tests pin the field decoding, the protocol
naming, the bounded page, and the availability contract that separates a
SELinux/absent denial (available false) from a readable file and from an
offline device (backend_error).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_HEADER = (
    "sk               Eth Pid        Groups   Rmem     Wmem     Dump  "
    "Locks     Drops     Inode"
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
        assert args == "cat /proc/net/netlink"
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_parses_kernel_and_subscriber_rows() -> None:
    output = "\n".join(
        [
            _HEADER,
            # Columns: ptr Eth Pid Groups Rmem Wmem Dump Locks Drops Inode.
            "0000000000000000 0 0 00000000 0 0 0 2 0 0",
            "0000000000000000 0 1234 00000001 0 0 0 2 0 45678",
            "0000000000000000 15 4321 00000002 256 0 0 3 5 99999",
        ]
    )
    payload = _backend(output).netlink("emulator-5554")
    assert payload["available"] is True
    assert payload["count"] == 3
    assert payload["has_more"] is False

    kernel, route_user, uevent = payload["sockets"]
    assert kernel == {
        "protocol": 0,
        "protocol_name": "route",
        "portid": 0,
        "groups": 0,
        "groups_hex": "0x00000000",
        "rmem": 0,
        "wmem": 0,
        "drops": 0,
        "inode": 0,
    }
    assert route_user["portid"] == 1234
    assert route_user["groups"] == 1
    assert route_user["groups_hex"] == "0x00000001"
    assert route_user["inode"] == 45678
    # protocol 15 is NETLINK_KOBJECT_UEVENT -- device hotplug monitoring.
    assert uevent["protocol"] == 15
    assert uevent["protocol_name"] == "kobject_uevent"
    assert uevent["groups"] == 2
    assert uevent["rmem"] == 256
    assert uevent["drops"] == 5
    assert uevent["inode"] == 99999


def test_unknown_protocol_falls_back_to_digits() -> None:
    output = "\n".join(
        [
            _HEADER,
            "0000000000000000 99 5 00000000 0 0 0 2 0 7",
        ]
    )
    row = _backend(output).netlink("emulator-5554")["sockets"][0]
    assert row["protocol"] == 99
    assert row["protocol_name"] == "99"


def test_permission_denied_is_available_false() -> None:
    payload = _backend("cat: /proc/net/netlink: Permission denied\n").netlink("emulator-5554")
    assert payload["available"] is False
    assert "Permission denied" in payload["reason"]
    assert payload["sockets"] == []
    assert payload["count"] == 0


def test_no_such_file_is_available_false() -> None:
    payload = _backend("cat: /proc/net/netlink: No such file or directory\n").netlink(
        "emulator-5554"
    )
    assert payload["available"] is False
    assert payload["sockets"] == []


def test_host_error_raises_backend_error() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("error: device offline\n").netlink("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_output_without_header_raises_backend_error() -> None:
    with pytest.raises(AdbError) as excinfo:
        _backend("garbage one\ngarbage two\n").netlink("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_header_only_is_available_and_empty() -> None:
    payload = _backend(_HEADER + "\n").netlink("emulator-5554")
    assert payload == {
        "available": True,
        "sockets": [],
        "count": 0,
        "has_more": False,
    }


def test_malformed_rows_are_skipped() -> None:
    output = "\n".join(
        [
            _HEADER,
            "0000000000000000 0",  # too few columns
            "0000000000000000 x y zz 0 0 0 2 0 1",  # non-numeric fields
            "0000000000000000 0 7 00000000 0 0 0 2 0 333",  # valid
        ]
    )
    payload = _backend(output).netlink("emulator-5554")
    assert payload["count"] == 1
    assert payload["sockets"][0]["inode"] == 333


def test_limit_caps_page_and_flags_has_more() -> None:
    rows = [_HEADER] + [
        f"0000000000000000 0 {i} 00000000 0 0 0 2 0 {i}" for i in range(5)
    ]
    payload = _backend("\n".join(rows)).netlink("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_docstring_names_fields_and_contract() -> None:
    doc = _tool_docstring("device.netlink")
    assert "protocol_name" in doc
    assert "portid" in doc
    assert "groups" in doc
    assert "available" in doc
