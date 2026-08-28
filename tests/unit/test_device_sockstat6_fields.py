"""device.sockstat6 parses the IPv6 summary and keeps outcomes distinct."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_SOCKSTAT6 = "\n".join(
    [
        "TCP6: inuse 2",
        "UDP6: inuse 1",
        "UDPLITE6: inuse 0",
        "RAW6: inuse 0",
        "FRAG6: inuse 0 memory 0",
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
        assert command == "cat /proc/net/sockstat6"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_labels_decode_into_counter_maps() -> None:
    """Each IPv6 protocol line becomes a per-label counter map."""
    payload = _backend(_FakeDev(_SOCKSTAT6)).sockstat6("emulator-5554")
    stats = payload["stats"]
    assert payload["available"] is True
    assert payload["count"] == 5
    assert payload["has_more"] is False
    assert stats["TCP6"] == {"inuse": 2}
    assert stats["UDP6"] == {"inuse": 1}
    assert stats["FRAG6"] == {"inuse": 0, "memory": 0}


def test_ipv6_disabled_is_available_false_not_an_error() -> None:
    """A missing file (IPv6 off / locked down) is a real state, not a failure."""
    dev = _FakeDev("cat: /proc/net/sockstat6: No such file or directory")
    payload = _backend(dev).sockstat6("emulator-5554")
    assert payload["available"] is False
    assert payload["stats"] == {}
    assert payload["count"] == 0


def test_offline_device_is_a_backend_error() -> None:
    """An adb host-error reply is transport death, distinct from IPv6-off."""
    dev = _FakeDev("error: device offline")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).sockstat6("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_unrecognized_output_is_not_guessed_empty() -> None:
    """Non-error output we cannot parse is an error, never a false empty."""
    dev = _FakeDev("this is definitely not the sockstat6 table")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).sockstat6("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.sockstat6")
    assert "stats" in doc
    assert "available" in doc
    assert "IPv6" in doc
