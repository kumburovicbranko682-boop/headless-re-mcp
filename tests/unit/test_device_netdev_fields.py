"""device.netdev names interfaces, decodes counters, and fails honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_NETDEV = "\n".join(
    [
        "Inter-|   Receive                                                |  Transmit",
        " face |bytes    packets errs drop fifo frame compressed multicast|"
        "bytes    packets errs drop fifo colls carrier compressed",
        "    lo: 1234567    8901    0    0    0     0          0         0  "
        "1234567    8901    0    0    0     0       0          0",
        "  wlan0:  987654    4321    1    2    0     0          0        10   "
        "123456     789    3    4    0     0       0          0",
        "  rmnet0:       0       0    0    0    0     0          0         0        "
        "0       0    0    0    0     0       0          0",
        # A truncated row (fewer than the kernel's 16 columns) must be skipped.
        "  eth9:  10  20  30",
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
        assert command == "cat /proc/net/dev"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_interfaces_and_counters_decode() -> None:
    """Both header lines and the truncated row drop out; counters map by column.

    The receive block is the first eight columns and the transmit block the
    next eight, so tx_bytes is column 8 -- getting that offset wrong would
    report a receive counter as a transmit one.
    """
    payload = _backend(_FakeDev(_NETDEV)).netdev("emulator-5554")
    ifaces = {entry["name"]: entry for entry in payload["interfaces"]}
    assert payload["count"] == 3
    assert payload["has_more"] is False
    assert set(ifaces) == {"lo", "wlan0", "rmnet0"}
    wlan = ifaces["wlan0"]
    assert wlan["rx_bytes"] == 987654
    assert wlan["rx_packets"] == 4321
    assert wlan["rx_errs"] == 1
    assert wlan["rx_drop"] == 2
    assert wlan["tx_bytes"] == 123456
    assert wlan["tx_packets"] == 789
    assert wlan["tx_errs"] == 3
    assert wlan["tx_drop"] == 4
    assert set(wlan) == {
        "name",
        "rx_bytes",
        "rx_packets",
        "rx_errs",
        "rx_drop",
        "tx_bytes",
        "tx_packets",
        "tx_errs",
        "tx_drop",
    }
    assert ifaces["rmnet0"]["rx_bytes"] == 0


def test_zero_interfaces_is_a_backend_error() -> None:
    """A live kernel always has lo, so an empty parse is a read failure."""
    dev = _FakeDev("cat: /proc/net/dev: No such file or directory")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).netdev("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_cap_flags_has_more() -> None:
    """Filling the cap sets has_more and does not spill past the limit."""
    rows = [
        f"  if{index}: {index}    {index}    0    0    0    0    0    0    "
        f"{index}    {index}    0    0    0    0    0    0"
        for index in range(1, 6)
    ]
    payload = _backend(_FakeDev("\n".join(rows))).netdev("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.netdev")
    assert "interfaces" in doc
    assert "has_more" in doc
    assert "lo" in doc
