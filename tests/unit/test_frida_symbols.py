"""frida.symbols must page the symbol table and tell empty from unavailable."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.frida.client import _ENUM_SCRIPT, FridaClient
from headless_re_mcp.tools.frida import build_frida_tools


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


def _client_over(api: object) -> FridaClient:
    script = type("_S", (), {"exports_sync": api, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()
    frida = type("_F", (), {"attach": lambda self, pid: session})()
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


class _SymbolsApi:
    def symbols(self, name: str, count: int) -> dict[str, Any]:
        return {
            "found": True,
            "module": name,
            "base": "0x1000",
            "total": 42,
            "available": True,
            "symbols": [
                {
                    "name": f"s{index}",
                    "address": "0x2000",
                    "type": "function" if index % 2 == 0 else "variable",
                    "global": index % 2 == 0,
                    "section": ".text",
                }
                for index in range(int(count))
            ],
        }


def test_frida_symbols_pages_and_maps_every_field() -> None:
    """The catalog named symbols with name/address/type/global/section.

    Measured: 11 symbols requested for a page of 10 -> count 10, has_more
    True, and each item keeps the permission-ish global flag and section.
    A page that filled the limit with no has_more reads as the whole table.
    """
    client = _client_over(_SymbolsApi())
    payload = client.symbols(1, "libnative.so", allowed_pid=1, limit=10)
    assert payload["found"] is True
    assert payload["module"] == "libnative.so"
    assert payload["count"] == 10
    assert len(payload["symbols"]) == 10
    assert payload["has_more"] is True
    first = payload["symbols"][0]
    assert set(first) == {"name", "address", "type", "global", "section"}
    assert first["type"] == "function"
    assert first["global"] is True
    assert first["section"] == ".text"
    # A loaded, enumerable module carries no `available` field at all.
    assert "available" not in payload
    doc = _tool_docstring("frida.symbols")
    assert "has_more" in doc
    assert "Module.enumerateSymbols" in doc


class _NotLoadedApi:
    def symbols(self, name: str, count: int) -> dict[str, Any]:
        del name, count
        return {"found": False, "symbols": []}


def test_frida_symbols_reports_a_module_that_is_not_loaded_as_not_found() -> None:
    """found false means the module never resolved, not "it has no symbols"."""
    client = _client_over(_NotLoadedApi())
    payload = client.symbols(1, "libghost.so", allowed_pid=1, limit=10)
    assert payload["found"] is False
    assert payload["symbols"] == []
    assert payload["count"] == 0
    assert payload["has_more"] is False
    assert "available" not in payload


class _UnavailableApi:
    def symbols(self, name: str, count: int) -> dict[str, Any]:
        del count
        return {
            "found": True,
            "module": name,
            "base": "0x1000",
            "symbols": [],
            "available": False,
            "error": "enumerateSymbols: not yet implemented",
        }


def test_frida_symbols_distinguishes_unavailable_from_a_stripped_module() -> None:
    """An empty table can mean 'stripped' or 'the target cannot enumerate'.

    When the script reports available false, pass it through with the error so
    an empty list is not read as a loaded module whose symbol table is empty.
    """
    client = _client_over(_UnavailableApi())
    payload = client.symbols(1, "libnative.so", allowed_pid=1, limit=10)
    assert payload["found"] is True
    assert payload["symbols"] == []
    assert payload["available"] is False
    assert "not yet implemented" in payload["error"]
    doc = _tool_docstring("frida.symbols")
    assert "available" in doc


def test_symbols_rpc_uses_enumerate_symbols_and_emits_its_fields() -> None:
    """Frida's native runtime cannot run in CI, so pin the RPC script text.

    The symbols export must resolve the module and call enumerateSymbols, and
    it must emit isGlobal and section, or a caller keying on global/section
    reads a table that never carried them.
    """
    assert "symbols: function" in _ENUM_SCRIPT
    assert "enumerateSymbols()" in _ENUM_SCRIPT
    assert "findModuleByName" in _ENUM_SCRIPT
    assert "isGlobal" in _ENUM_SCRIPT
    assert "section" in _ENUM_SCRIPT
    assert "available: false" in _ENUM_SCRIPT
