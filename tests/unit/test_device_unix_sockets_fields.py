"""device.unix_sockets must return the named IPC surface honestly.

Named sockets (filesystem and abstract @) are kept with decoded type, anonymous
sockets are omitted, and a read missing the header is an error.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.tools.device import build_device_tools

_HEADER = "Num       RefCount Protocol Flags    Type St Inode Path"
_UNIX = "\n".join(
    [
        _HEADER,
        "0000000000000000: 00000002 00000000 00010000 0001 01 12345 /dev/socket/logd",
        "0000000000000000: 00000002 00000000 00010000 0002 01 12346 @jdwp-control",
        "0000000000000000: 00000002 00000000 00010000 0001 03 12347",
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
        assert command.endswith("/proc/net/unix"), command
        return self._output


def _backend(output: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_named_sockets_kept_anonymous_dropped() -> None:
    """Two named sockets parse with decoded type; the anonymous one is dropped.

    Measured against AdbBackend.unix_sockets: count 2, has_more False. The
    filesystem socket keeps its /dev/socket path and STREAM type; the abstract
    socket keeps its @-prefixed name and DGRAM type; the pathless third row is
    omitted so the result is the real IPC surface.
    """
    payload = _backend(_UNIX).unix_sockets("emulator-5554")
    assert payload["count"] == 2
    assert payload["has_more"] is False
    sockets = payload["unix_sockets"]
    assert sockets[0] == {
        "path": "/dev/socket/logd",
        "type": "STREAM",
        "state": "01",
        "inode": 12345,
    }
    assert sockets[1]["path"] == "@jdwp-control"
    assert sockets[1]["type"] == "DGRAM"
    assert all(sock["path"] for sock in sockets)


def test_header_only_is_empty_not_error() -> None:
    """A header with only anonymous rows yields an honest empty list."""
    payload = _backend(_HEADER + "\n0000: 1 0 0 0001 01 5\n").unix_sockets("x")
    assert payload["count"] == 0
    assert payload["unix_sockets"] == []


def test_missing_header_is_an_error() -> None:
    """A denied / missing read (no header) is backend_error."""
    with pytest.raises(AdbError) as excinfo:
        _backend("cat: /proc/net/unix: Permission denied").unix_sockets("x")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_payload_and_honesty() -> None:
    doc = _tool_docstring("device.unix_sockets")
    assert "unix_sockets" in doc
    assert "path" in doc
    assert "has_more" in doc
