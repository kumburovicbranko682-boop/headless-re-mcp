"""device.connections must decode /proc/net exactly and stay honest when cut.

Hex addresses are reconstructed byte-for-byte, an address family the device
refuses is named under unavailable rather than dropped, both families failing
is an error, and a capped page says has_more instead of pretending to be every
socket.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    AdbError,
    _decode_hex_endpoint,
    _hex_to_ip,
)
from headless_re_mcp.tools.device import build_device_tools

_TCP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode"
)
_TCP6_HEADER = (
    "  sl  local_address                         "
    "remote_address                        st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode"
)
_TCP_ROWS = [
    _TCP_HEADER,
    "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 "
    "00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0",
    "   1: 0100007F:CF32 0100007F:1F90 01 00000000:00000000 00:00000000 "
    "00000000 10088        0 67890 1 0000000000000000 20 4 30 10 -1",
]
_TCP6_ROWS = [
    _TCP6_HEADER,
    "   0: 00000000000000000000000000000000:1F90 "
    "00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 "
    "00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0",
    "   1: 00000000000000000000000001000000:0035 "
    "00000000000000000000000001000000:D431 01 00000000:00000000 00:00000000 "
    "00000000 10099        0 33333 1 0000000000000000 20 4 30 10 -1",
]


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
    """Serves canned /proc/net text; a source in ``fail`` is refused."""

    def __init__(
        self, tcp: str | None = None, tcp6: str | None = None
    ) -> None:
        self._tcp = tcp
        self._tcp6 = tcp6

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        command = args if isinstance(args, str) else " ".join(args)
        if command.endswith("/proc/net/tcp6"):
            if self._tcp6 is None:
                return "cat: /proc/net/tcp6: No such file or directory"
            return self._tcp6
        if command.endswith("/proc/net/tcp"):
            if self._tcp is None:
                return "cat: /proc/net/tcp: Permission denied"
            return self._tcp
        raise AssertionError(f"unexpected command: {command!r}")


def _backend(dev: _FakeDev) -> Any:
    from headless_re_mcp.backends.adb.client import AdbBackend

    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_hex_address_decoding_is_exact() -> None:
    """The kernel stores each 32-bit word little-endian; decoding is exact.

    Measured against _hex_to_ip / _decode_hex_endpoint: 0100007F is 127.0.0.1,
    the all-zero IPv6 word group is ::, the loopback group is ::1, and the
    IPv4-mapped group is ::ffff:127.0.0.1. Reading these as raw hex would name
    the wrong host.
    """
    assert _hex_to_ip("0100007F") == "127.0.0.1"
    assert _hex_to_ip("00000000000000000000000000000000") == "::"
    assert _hex_to_ip("00000000000000000000000001000000") == "::1"
    assert _hex_to_ip("0000000000000000FFFF00000100007F") == "::ffff:127.0.0.1"
    assert _decode_hex_endpoint("0100007F:1F90") == ("127.0.0.1", 8080)
    assert _decode_hex_endpoint("garbage") is None


def test_both_families_decode_and_bracket_ipv6() -> None:
    """Both /proc/net files parse; IPv6 endpoints are bracketed.

    Measured against AdbBackend.connections over canned tcp and tcp6: four
    sockets, no unavailable, has_more False. The IPv6 rows render as [::]:8080
    and [::1]:53 so the port never fuses onto the address, and each row carries
    proto, local, remote, decoded state, uid and inode.
    """
    dev = _FakeDev(tcp="\n".join(_TCP_ROWS), tcp6="\n".join(_TCP6_ROWS))
    payload = _backend(dev).connections("emulator-5554", limit=500)
    assert payload["count"] == 4
    assert payload["has_more"] is False
    assert "unavailable" not in payload
    conns = payload["connections"]
    assert conns[0] == {
        "proto": "tcp",
        "local": "127.0.0.1:8080",
        "remote": "0.0.0.0:0",
        "state": "LISTEN",
        "uid": 1000,
        "inode": 12345,
    }
    assert conns[1] == {
        "proto": "tcp",
        "local": "127.0.0.1:53042",
        "remote": "127.0.0.1:8080",
        "state": "ESTABLISHED",
        "uid": 10088,
        "inode": 67890,
    }
    assert conns[2]["proto"] == "tcp6"
    assert conns[2]["local"] == "[::]:8080"
    assert conns[2]["state"] == "LISTEN"
    assert conns[3]["local"] == "[::1]:53"
    assert conns[3]["remote"] == "[::1]:54321"
    assert conns[3]["uid"] == 10099


def test_a_refused_family_is_named_not_dropped() -> None:
    """IPv6 off (no such file) is unavailable, not silently empty.

    Measured against AdbBackend.connections when tcp6 answers with a cat
    error: the two IPv4 sockets come back, tcp6 lands in unavailable, and the
    call is not an error. Dropping it would read as a device with no IPv6
    sockets.
    """
    dev = _FakeDev(tcp="\n".join(_TCP_ROWS), tcp6=None)
    payload = _backend(dev).connections("emulator-5554", limit=500)
    assert payload["count"] == 2
    assert payload["unavailable"] == ["tcp6"]
    assert all(row["proto"] == "tcp" for row in payload["connections"])


def test_both_families_refused_is_an_error() -> None:
    """Both files refused (SELinux) is backend_error, never an empty list.

    Measured against AdbBackend.connections when both cat calls are denied:
    it raises AdbError(backend_error). Returning an empty connections list
    would read as a device with no open sockets.
    """
    dev = _FakeDev(tcp=None, tcp6=None)
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).connections("emulator-5554", limit=500)
    assert excinfo.value.code == "backend_error"


def test_capped_page_says_has_more_and_skips_second_family() -> None:
    """A full page reports has_more and does not read tcp6.

    Measured against AdbBackend.connections with 600 IPv4 rows and limit 5:
    count is 5, has_more True, and because the page filled on tcp the tcp6
    read never happens, so unavailable is absent. Ignoring has_more would treat
    the page as every socket.
    """
    rows = [_TCP_HEADER]
    for index in range(600):
        rows.append(
            f" {index:3d}: 0100007F:{index + 4096:04X} 00000000:0000 0A "
            "00000000:00000000 00:00000000 00000000  1000        0 "
            f"{index} 1 0000000000000000 100 0 0 10 0"
        )
    dev = _FakeDev(tcp="\n".join(rows), tcp6="\n".join(_TCP6_ROWS))
    payload = _backend(dev).connections("emulator-5554", limit=5)
    assert payload["count"] == 5
    assert payload["has_more"] is True
    assert "unavailable" not in payload


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.connections")
    assert "connections" in doc
    assert "unavailable" in doc
    assert "has_more" in doc
