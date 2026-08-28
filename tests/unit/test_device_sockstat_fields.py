"""device.sockstat parses the per-label counter table and fails honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_SOCKSTAT = "\n".join(
    [
        "sockets: used 234",
        "TCP: inuse 5 orphan 0 tw 2 alloc 10 mem 3",
        "UDP: inuse 3 mem 1",
        "UDPLITE: inuse 0",
        "RAW: inuse 0",
        "FRAG: inuse 0 memory 0",
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
        assert command == "cat /proc/net/sockstat"
        return self._body


def _backend(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_labels_decode_into_counter_maps() -> None:
    """Each Label: name value ... line becomes a per-label counter map.

    The leading 'sockets: used N' line is parsed by the same rule as the
    protocol lines, so it lands as {'sockets': {'used': 234}} rather than
    being special-cased or dropped.
    """
    payload = _backend(_FakeDev(_SOCKSTAT)).sockstat("emulator-5554")
    stats = payload["stats"]
    assert payload["count"] == 6
    assert payload["has_more"] is False
    assert stats["sockets"] == {"used": 234}
    assert stats["TCP"] == {"inuse": 5, "orphan": 0, "tw": 2, "alloc": 10, "mem": 3}
    assert stats["UDP"] == {"inuse": 3, "mem": 1}
    assert stats["FRAG"] == {"inuse": 0, "memory": 0}


def test_zero_labels_is_a_backend_error() -> None:
    """A missing or refused file is a read failure, not an empty map."""
    dev = _FakeDev("cat: /proc/net/sockstat: No such file or directory")
    with pytest.raises(AdbError) as excinfo:
        _backend(dev).sockstat("emulator-5554")
    assert excinfo.value.code == "backend_error"


def test_label_with_unparsable_values_is_skipped() -> None:
    """A label whose value columns are not integers contributes nothing."""
    body = "\n".join(
        [
            "sockets: used 12",
            "BOGUS: alpha beta gamma delta",
        ]
    )
    payload = _backend(_FakeDev(body)).sockstat("emulator-5554")
    assert set(payload["stats"]) == {"sockets"}
    assert payload["count"] == 1


def test_docstring_states_the_honesty_contract() -> None:
    doc = _tool_docstring("device.sockstat")
    assert "stats" in doc
    assert "has_more" in doc
    assert "TIME_WAIT" in doc
