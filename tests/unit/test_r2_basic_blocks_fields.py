"""r2.basic_blocks returns a function's control-flow graph with mapped addresses."""

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


def test_basic_blocks_map_addr_and_keep_edge_vas(tmp_path: Path) -> None:
    """Each block's addr becomes an Address; jump/fail stay raw target VAs.

    afbj gives the CFG r2.disasm's linear listing flattens: block boundaries
    and the taken (jump) / fall-through (fail) edges. The block address is
    mapped to {va, rva, module}; the edge targets are left as integers to
    follow, and the requested function address lands in address_va.
    """
    payload = enrich_r2_payload(
        {
            "raw": json.dumps(
                [
                    {
                        "addr": 0x140001100,
                        "size": 0x20,
                        "ninstr": 8,
                        "jump": 0x140001140,
                        "fail": 0x140001120,
                    },
                    {"addr": 0x140001120, "size": 0x10, "ninstr": 4},
                ]
            ),
            "commands": ["afbj @ 0x140001100"],
            "address": 0x140001100,
        },
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["count"] == 2
    first = payload["items"][0]
    assert first["address"]["va"] == 0x140001100
    assert first["address"]["rva"] == 0x1100
    assert type(first["address"]) is not int
    # Edge targets are preserved as raw VAs to follow.
    assert first["jump"] == 0x140001140
    assert first["fail"] == 0x140001120
    assert first["ninstr"] == 8
    # The requested function address is echoed as an integer in address_va.
    assert payload["address_va"] == 0x140001100
    assert type(payload["address"]) is not int


def test_basic_blocks_empty_when_no_function(tmp_path: Path) -> None:
    """afbj over an address with no function yields an empty, honest list."""
    payload = enrich_r2_payload(
        {"raw": "[]", "commands": ["afbj @ 0x140009999"], "address": 0x140009999},
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["items"] == []
    assert payload["count"] == 0
    assert payload["parsed"] is True


def test_afbj_command_is_whitelisted() -> None:
    """afbj at a hex or decimal address is allowed; a bare/opaque form is not."""
    _require_allowed_command("afbj @ 0x140001100")
    _require_allowed_command("afbj @ 4096")
    for bad in ("afbj", "afbj @ main", "afbj @ 0x10; #cmd", "afbj@0x10"):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_basic_blocks_schema_and_docstring() -> None:
    """The tool rejects negative addresses in-schema and names its fields."""
    bindings = build_r2_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    assert "r2.basic_blocks" in named
    props = input_schema_for(named["r2.basic_blocks"])["properties"]
    assert props["address"]["minimum"] == 0

    doc = _tool_docstring("r2.basic_blocks")
    for token in ("items", "jump", "fail", "ninstr", "address_va"):
        assert token in doc
    assert "no integer address" in doc.replace("\n", " ")
