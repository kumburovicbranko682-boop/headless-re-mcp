"""r2.function_refs returns a function's outgoing references, both ends mapped."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Error, _require_allowed_command
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.r2 import build_r2_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _pe(tmp_path: Path) -> Path:
    pe = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(image))
    return pe


def test_function_refs_map_both_endpoints(tmp_path: Path) -> None:
    """Each afxj row maps its from site and to target to {va, rva, module}.

    afxj answers "what does this function reference": a call to a callee and a
    data read of a global. Both from (the site inside the function) and to (the
    target) become Address objects, so a caller can walk callees and data
    dependencies without a second pass.
    """
    payload = enrich_r2_payload(
        {
            "raw": json.dumps(
                [
                    {"type": "call", "from": 0x140001020, "to": 0x140001100},
                    {"type": "data", "from": 0x140001030, "to": 0x140003000},
                ]
            ),
            "commands": ["afxj @ 0x140001000"],
            "address": 0x140001000,
        },
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["count"] == 2
    call = payload["items"][0]
    assert call["type"] == "call"
    assert call["from"] == 0x140001020
    assert call["to"] == 0x140001100
    assert call["from_address"]["rva"] == 0x1020
    assert call["to_address"]["rva"] == 0x1100
    # The item's own address maps from the from site.
    assert call["address"]["va"] == 0x140001020
    data = payload["items"][1]
    assert data["type"] == "data"
    assert data["to_address"]["rva"] == 0x3000
    # The queried function address is echoed as an integer.
    assert payload["address_va"] == 0x140001000
    assert type(payload["address"]) is not int


def test_function_refs_empty_when_no_function(tmp_path: Path) -> None:
    """A function that references nothing (or no function) is an honest empty."""
    payload = enrich_r2_payload(
        {"raw": "[]", "commands": ["afxj @ 0x140001000"], "address": 0x140001000},
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["items"] == []
    assert payload["count"] == 0
    assert payload["parsed"] is True


def test_afxj_command_is_whitelisted() -> None:
    """afxj at a hex or decimal address is allowed; opaque forms are refused."""
    _require_allowed_command("afxj @ 0x140001000")
    _require_allowed_command("afxj @ 4096")
    for bad in ("afxj", "afxj @ sym.main", "afxj @ 0x10; iI", "afxj@0x10", "afx @ 0x10"):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_function_refs_schema_and_docstring() -> None:
    """The tool rejects negative addresses in-schema and names its fields."""
    bindings = build_r2_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    assert "r2.function_refs" in named
    props = input_schema_for(named["r2.function_refs"])["properties"]
    assert props["address"]["minimum"] == 0

    doc = _tool_docstring("r2.function_refs")
    for token in ("from_address", "to_address", "outgoing", "xrefs_to", "address_va"):
        assert token in doc
