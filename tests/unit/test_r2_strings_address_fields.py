"""r2.strings must name the address object on each recovered string."""

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


def test_r2_strings_puts_the_string_va_under_address_object(tmp_path: Path) -> None:
    """The catalog said address and meant a VA integer.

    Measured: enrich_r2_payload puts {va, rva, module} on each item.address
    while vaddr stays the integer VA. Looking for an integer address after a
    successful string list reads as radare2 returning no string VA.
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
            "raw": json.dumps(
                [
                    {
                        "string": "kernel32",
                        "vaddr": 0x140001000,
                        "section": ".rdata",
                        "type": "ascii",
                    }
                ]
            ),
            "commands": ["izj"],
        },
        binary=pe,
        architecture=Architecture.X64,
    )
    assert payload["items"][0]["address"]["va"] == 0x140001000
    assert payload["items"][0]["address"]["rva"] == 0x1000
    assert payload["items"][0]["vaddr"] == 0x140001000
    assert type(payload["items"][0]["address"]) is not int
    described = _tool_docstring("r2.strings")
    assert "Answers with items" in described
    assert "va/rva/module" in described
    assert "no integer address" in described.replace("\n", " ")
