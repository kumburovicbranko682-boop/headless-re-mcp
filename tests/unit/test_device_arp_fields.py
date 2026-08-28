"""device.arp must parse /proc/net/arp honestly.

Complete and incomplete entries are distinguished, an empty table is a real
result rather than an error, and a read that never returns the header (denied
or missing) is an error.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_HEADER = "IP address       HW type     Flags       HW address            Mask     Device"
_ARP = "\n".join(
    [
        _HEADER,
        "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0",
        "192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        wlan0",
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
    def __init__(self, output: str) -> None:
        self._output = output

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        command = args if isinstance(args, str) else " ".join(args)
        assert command.endswith("/proc/net/arp"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_complete_and_incomplete_entries() -> None:
    """Two neighbours parse; the ATF_COM bit distinguishes complete ones.

    Measured against AdbBackend.arp: the header is skipped, count is 2,
    has_more False. The 0x2 entry is complete with a real MAC; the 0x0 entry is
    incomplete with the placeholder MAC. Both carry the interface.
    """
    payload = _backend(_ARP).arp("emulator-5554")
    assert payload["count"] == 2
    assert payload["has_more"] is False
    arp = payload["arp"]
    assert arp[0] == {
        "ip": "192.168.1.1",
        "mac": "aa:bb:cc:dd:ee:ff",
        "flags": "0x2",
        "complete": True,
        "device": "wlan0",
    }
    assert arp[1]["complete"] is False
    assert arp[1]["mac"] == "00:00:00:00:00:00"


def test_empty_table_is_not_an_error() -> None:
    """A header with no rows is an honest empty table, not a failure."""
    payload = _backend(_HEADER + "\n").arp("emulator-5554")
    assert payload["count"] == 0
    assert payload["arp"] == []
    assert payload["has_more"] is False


def test_missing_header_is_an_error() -> None:
    """A denied / missing read (no header) is backend_error."""
    with pytest.raises(AdbError) as excinfo:
        _backend("cat: /proc/net/arp: Permission denied").arp("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.arp")
    assert "arp" in doc
    assert "complete" in doc
    assert "has_more" in doc
