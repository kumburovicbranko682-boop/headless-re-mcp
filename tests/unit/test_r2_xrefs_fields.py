"""r2.xrefs must name the address object it actually returns."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import enrich_xrefs_payload
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


def test_r2_xrefs_puts_the_request_va_in_address_va_not_address(
    tmp_path: Path,
) -> None:
    """The catalog named item edges and never named the request address.

    Measured: enrich_xrefs_payload replaces the requested address with
    {va, rva, module} and puts the integer in address_va. Looking for an
    integer address after a successful xref list reads as radare2
    returning no request coordinate.
    """
    payload = enrich_xrefs_payload(
        {
            # The axtj array (refs to the address) then the axfj array (refs
            # from it), exactly as the two-command script emits them.
            "raw": json.dumps([{"from": 0x140002000, "type": "CODE"}]) + "\n[]",
            "commands": ["axtj @ 5368713216", "axfj @ 5368713216"],
            "address": 0x140001000,
        },
        binary=_pe(tmp_path),
        address=0x140001000,
        architecture=Architecture.X64,
    )
    assert payload["address"]["va"] == 0x140001000
    assert payload["address_va"] == 0x140001000
    assert type(payload["address"]) is not int
    assert payload["items"][0]["from_address"]["va"] == 0x140002000
    assert payload["items"][0]["direction"] == "to"
    assert payload["items"][0]["to_address"]["va"] == 0x140001000
    described = _tool_docstring("r2.xrefs")
    assert "from_address" in described
    assert "address_va" in described
    assert "direction" in described
    assert "no integer address" in described.replace("\n", " ")


def test_r2_address_schemas_match_the_client_non_negative_check() -> None:
    """The catalog accepted negative addresses on both r2 address tools.

    Measured: R2Client.disasm and R2Client.xrefs both raise invalid_params for
    a negative address, but only after the tool resolved a session and spawned
    radare2 with `aa`. The input schemas carry no minimum, so the analysis pass
    is paid before the refusal.
    """
    from headless_re_mcp.backends.r2.client import R2Client
    from headless_re_mcp.tools.binding import input_schema_for

    source = Path(R2Client.disasm.__code__.co_filename).read_text(encoding="utf-8")
    assert source.count('"address must be a non-negative int"') >= 2

    bindings = build_r2_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    for name in ("r2.disasm", "r2.xrefs"):
        props = input_schema_for(named[name])["properties"]
        assert props["address"]["minimum"] == 0, name
