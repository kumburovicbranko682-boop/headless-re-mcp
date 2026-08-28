"""r2.disasm must name the address object it actually returns."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
from headless_re_mcp.core.models import Architecture
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


def test_r2_disasm_puts_the_request_va_in_address_va_not_address(
    tmp_path: Path,
) -> None:
    """The catalog said address and meant the integer the caller passed.

    Measured: enrich_r2_payload replaces address with {va, rva, module} and
    puts the integer in address_va. Looking for an integer address after a
    successful disasm reads as radare2 returning nothing usable, so the
    overnight pass retries pdj or skips the next xref.
    """
    pe = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(image))
    payload = enrich_r2_payload(
        {
            "raw": json.dumps([{"offset": 0x140001000, "opcode": "nop"}]),
            "commands": ["pdj"],
            "address": 0x140001000,
            "count": 1,
        },
        binary=pe,
        architecture=Architecture.X64,
    )
    assert payload["address"] == {
        "module": "demo64.exe",
        "rva": 0x1000,
        "va": 0x140001000,
        "architecture": "x64",
    }
    assert payload["address_va"] == 0x140001000
    assert type(payload["address"]) is not int
    described = _tool_docstring("r2.disasm")
    assert "Answers with items" in described
    assert "address_va" in described
    assert "no integer address" in described.replace("\n", " ")
    # The input address is an integer, but r2.functions/items carry a field
    # also named address that is a (va/rva/module) object -- the wrong thing to
    # pass back. The doc must name the integer source (offset from r2.functions)
    # so the collision does not send an object into an int param.
    assert "offset" in described
    assert "r2.functions" in described
