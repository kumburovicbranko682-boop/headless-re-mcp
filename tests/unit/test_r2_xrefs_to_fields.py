"""r2.xrefs_to returns references TO an address, scoped and with mapped sites."""

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


def test_xrefs_to_maps_the_referencing_site(tmp_path: Path) -> None:
    """Each ref's from site becomes an Address; the queried address is echoed.

    axtj answers "who references this": the from site, the opcode that makes
    the reference and the function it sits in. from is mapped to
    {va, rva, module} (as address and from_address); the requested target
    lands in address_va.
    """
    payload = enrich_r2_payload(
        {
            "raw": json.dumps(
                [
                    {
                        "from": 0x140002018,
                        "type": "CALL",
                        "opcode": "call 0x140001100",
                        "fcn_addr": 0x140002000,
                        "fcn_name": "entry0",
                        "refname": "sym.target",
                    }
                ]
            ),
            "commands": ["axtj @ 0x140001100"],
            "address": 0x140001100,
        },
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["count"] == 1
    item = payload["items"][0]
    assert item["from"] == 0x140002018
    assert item["from_address"]["va"] == 0x140002018
    assert item["from_address"]["rva"] == 0x2018
    assert item["address"]["va"] == 0x140002018
    assert item["opcode"] == "call 0x140001100"
    assert item["fcn_name"] == "entry0"
    # The queried target is echoed as an integer, not folded into item edges.
    assert payload["address_va"] == 0x140001100
    assert type(payload["address"]) is not int


def test_xrefs_to_empty_when_nothing_references(tmp_path: Path) -> None:
    """A target nothing references yields an empty, honest list (not a failure)."""
    payload = enrich_r2_payload(
        {"raw": "[]", "commands": ["axtj @ 0x140001100"], "address": 0x140001100},
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["items"] == []
    assert payload["count"] == 0
    assert payload["parsed"] is True


def test_axtj_command_is_whitelisted() -> None:
    """axtj at a hex or decimal address is allowed; opaque forms are refused."""
    _require_allowed_command("axtj @ 0x140001100")
    _require_allowed_command("axtj @ 4096")
    for bad in ("axtj", "axtj @ sym.main", "axtj @ 0x10; iI", "axtj@0x10"):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_xrefs_to_schema_and_docstring() -> None:
    """The tool rejects negative addresses in-schema and names its fields."""
    bindings = build_r2_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    assert "r2.xrefs_to" in named
    props = input_schema_for(named["r2.xrefs_to"])["properties"]
    assert props["address"]["minimum"] == 0

    doc = _tool_docstring("r2.xrefs_to")
    for token in ("from_address", "opcode", "fcn_name", "address_va"):
        assert token in doc
    assert "no integer address" in doc.replace("\n", " ")
