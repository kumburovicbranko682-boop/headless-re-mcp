"""frida.memory.read must report how many bytes it actually got.

Frida's Memory.readByteArray returns null for a range that is not fully mapped,
which the client turns into empty bytes. Reporting the requested ``size`` while
``data`` is short (or empty) would read as a full read of a page of zeros, and
an unattended agent draws conclusions from exactly that. These pin the honest
shape: ``size`` is the request, ``bytes`` is what came back, and ``truncated``
marks a range that could not be fully read.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.frida.client import FridaClient
from headless_re_mcp.tools.frida import build_frida_tools


class _Exports:
    def __init__(self, payload: list[int]) -> None:
        self._payload = payload

    def read(self, address: int, size: int) -> list[int]:
        assert address >= 0 and size >= 1
        return self._payload


class _Script:
    def __init__(self, payload: list[int]) -> None:
        self.exports_sync = _Exports(payload)

    def load(self) -> None:
        return None


class _Session:
    def __init__(self, payload: list[int]) -> None:
        self._payload = payload
        self.detached = False

    def create_script(self, source: str) -> _Script:
        assert source
        return _Script(self._payload)

    def detach(self) -> None:
        self.detached = True


def _client(monkeypatch: Any, payload: list[int]) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()  # only availability is checked before the attach
    monkeypatch.setattr(client, "_attach_local", lambda pid, **_: _Session(payload))
    return client


def _tool_docstring(name: str) -> str:
    source = Path(build_frida_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_a_full_read_reports_bytes_equal_to_size_and_no_truncation(monkeypatch: Any) -> None:
    client = _client(monkeypatch, list(range(16)))
    out = client.memory_read(4242, 0x1000, 16, allowed_pid=4242)
    assert out["size"] == 16
    assert out["bytes"] == 16
    assert out["encoding"] == "hex"
    assert out["data"] == bytes(range(16)).hex()
    assert "truncated" not in out


def test_an_unreadable_range_is_marked_not_silently_empty(monkeypatch: Any) -> None:
    # readByteArray returned null -> no bytes. The old shape said size=256 with
    # empty data, indistinguishable from a genuine read that returned nothing.
    client = _client(monkeypatch, [])
    out = client.memory_read(4242, 0x1000, 256, allowed_pid=4242)
    assert out["size"] == 256
    assert out["bytes"] == 0
    assert out["data"] == ""
    assert out["truncated"] is True


def test_a_short_read_reports_the_actual_bytes(monkeypatch: Any) -> None:
    # A guard page partway through the range: fewer bytes than requested.
    client = _client(monkeypatch, [1, 2, 3, 4])
    out = client.memory_read(4242, 0x1000, 64, allowed_pid=4242)
    assert out["size"] == 64
    assert out["bytes"] == 4
    assert out["data"] == bytes([1, 2, 3, 4]).hex()
    assert out["truncated"] is True


def test_the_probe_session_is_detached(monkeypatch: Any) -> None:
    session = _Session(list(range(8)))
    client = FridaClient()
    client._available = True
    client._frida = object()
    monkeypatch.setattr(client, "_attach_local", lambda pid, **_: session)
    client.memory_read(4242, 0x1000, 8, allowed_pid=4242)
    assert session.detached is True


def test_docstring_names_bytes_and_truncated() -> None:
    doc = _tool_docstring("frida.memory.read")
    assert "bytes" in doc
    assert "truncated" in doc
