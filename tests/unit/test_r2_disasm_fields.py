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


def test_r2_disasm_counts_undecodable_bytes_as_invalid(tmp_path: Path) -> None:
    """invalid_count must tally the rows radare2 could not decode.

    Pointed at data or unmapped memory, pdj returns one type "invalid" row per
    byte -- structurally identical to a decoded run. disasm() surfaces how many
    of the returned rows were undecodable so a caller can tell code from bytes
    without walking every item; invalid_count == count means "not code".
    """
    from headless_re_mcp.backends.r2.client import R2Client

    pe = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(image))

    client = R2Client(executable=pe)  # never launched; run is stubbed below

    def _fake_run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict:
        del binary, commands, timeout
        entries = [
            {"offset": 0x140001000, "opcode": "nop", "type": "nop", "bytes": "90", "size": 1},
            {"offset": 0x140001001, "type": "invalid", "bytes": "ff", "size": 1},
            {"offset": 0x140001002, "type": "invalid", "bytes": "ff", "size": 1},
        ]
        return {"raw": json.dumps(entries), "commands": ["aa", "pdj 3 @ 0"]}

    client.run = _fake_run  # type: ignore[method-assign]

    payload = client.disasm(pe, 0x140001000, count=3)
    assert payload["invalid_count"] == 2  # two of three rows were undecodable
    assert len(payload["items"]) == 3

    # An all-invalid run (data/unmapped) must report invalid_count == count.
    def _all_invalid(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict:
        del binary, commands, timeout
        entries = [{"offset": i, "type": "invalid", "bytes": "ff", "size": 1} for i in range(4)]
        return {"raw": json.dumps(entries), "commands": ["aa", "pdj 4 @ 0"]}

    client.run = _all_invalid  # type: ignore[method-assign]
    bytes_payload = client.disasm(pe, 0x0, count=4)
    assert bytes_payload["invalid_count"] == len(bytes_payload["items"]) == 4

    described = _tool_docstring("r2.disasm")
    assert "invalid_count" in described
