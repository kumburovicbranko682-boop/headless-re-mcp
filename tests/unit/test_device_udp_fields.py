"""device.udp decodes /proc/net/udp honestly, without inventing TCP state."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_UDP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode ref pointer drops"
)
_UDP6_HEADER = (
    "  sl  local_address                         remote_address"
    "                        st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode ref pointer drops"
)
# 0.0.0.0:5353 (mDNS, wildcard remote) and 127.0.0.1:53 owned by uid 0.
_UDP_ROWS = [
    "  464: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 "
    "00000000  1000        0 12345 2 0000000000000000 0",
    "  465: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 "
    "00000000     0        0 23456 2 0000000000000000 0",
]
# [::]:5353 (wildcard) and [::1]:53 in the kernel's word-reversed hex form.
_UDP6_ROWS = [
    "   10: 00000000000000000000000000000000:14E9 "
    "00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 "
    "00000000  1000        0 34567 2 0000000000000000 0",
    "   11: 00000000000000000000000001000000:0035 "
    "00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 "
    "00000000     0        0 45678 2 0000000000000000 0",
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
    """Answers each ``cat /proc/net/udp{,6}`` with canned text (or an error)."""

    def __init__(self, udp: str | None, udp6: str | None) -> None:
        self._udp = udp
        self._udp6 = udp6

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        command = args if isinstance(args, str) else " ".join(args)
        if command == "cat /proc/net/udp":
            body = self._udp
        elif command == "cat /proc/net/udp6":
            body = self._udp6
        else:  # pragma: no cover - the method only reads these two files
            raise AssertionError(f"unexpected command: {command!r}")
        if body is None:
            return "cat: /proc/net/udp: No such file or directory"
        return body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_endpoints_decode_across_both_families() -> None:
    """Both families parse; addresses decode little-endian and IPv6 is bracketed.

    A UDP receiver keeps a wildcard remote (0.0.0.0:0 / [::]:0), so the tool
    must report that faithfully rather than pretending the socket is
    connected. There is no state field because UDP has no TCP state machine.
    """
    dev = _FakeDev(
        udp="\n".join([_UDP_HEADER, *_UDP_ROWS]),
        udp6="\n".join([_UDP6_HEADER, *_UDP6_ROWS]),
    )
    payload = _backend(dev).udp("emulator-5554")
    entries = payload["udp"]
    assert payload["count"] == 4
    assert payload["has_more"] is False
    assert "unavailable" not in payload
    assert all("state" not in entry for entry in entries)
    by_local = {entry["local"]: entry for entry in entries}
    assert by_local["0.0.0.0:5353"]["proto"] == "udp"
    assert by_local["0.0.0.0:5353"]["remote"] == "0.0.0.0:0"
    assert by_local["0.0.0.0:5353"]["uid"] == 1000
    assert by_local["0.0.0.0:5353"]["inode"] == 12345
    assert by_local["127.0.0.1:53"]["uid"] == 0
    assert by_local["[::]:5353"]["proto"] == "udp6"
    assert by_local["[::]:5353"]["remote"] == "[::]:0"
    assert by_local["[::1]:53"]["inode"] == 45678


def test_one_missing_family_is_named_not_dropped() -> None:
    """A refused /proc/net/udp6 is reported in unavailable, udp still parses."""
    dev = _FakeDev(udp="\n".join([_UDP_HEADER, *_UDP_ROWS]), udp6=None)
    payload = _backend(dev).udp("emulator-5554")
    assert payload["count"] == 2
    assert payload["unavailable"] == ["udp6"]
    assert {entry["proto"] for entry in payload["udp"]} == {"udp"}


def test_both_families_failing_is_an_error() -> None:
    """Neither file readable is a backend_error, not an empty socket list."""
    dev = _FakeDev(udp=None, udp6=None)
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).udp("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_empty_but_readable_table_is_zero_not_an_error() -> None:
    """A header with no rows is a real zero-socket result, not a failure."""
    dev = _FakeDev(udp=_UDP_HEADER, udp6=_UDP6_HEADER)
    payload = _backend(dev).udp("emulator-5554")
    assert payload["count"] == 0
    assert payload["udp"] == []
    assert payload["has_more"] is False
    assert "unavailable" not in payload


def test_cap_flags_has_more_and_stops() -> None:
    """Filling the cap sets has_more and does not spill past the limit."""
    rows = [
        f"  {index}: 00000000:{index:04X} 00000000:0000 07 00000000:00000000 "
        "00:00000000 00000000  1000        0 "
        f"{10000 + index} 2 0000000000000000 0"
        for index in range(1, 6)
    ]
    dev = _FakeDev(udp="\n".join([_UDP_HEADER, *rows]), udp6="\n".join([_UDP6_HEADER]))
    payload = _backend(dev).udp("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True
    assert {entry["proto"] for entry in payload["udp"]} == {"udp"}


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.udp")
    assert "udp" in doc
    assert "has_more" in doc
    assert "unavailable" in doc
