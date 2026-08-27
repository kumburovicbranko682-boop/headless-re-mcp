"""r2.disasm must name the address object it actually returns."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

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


def _disasm_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, instrs: list[dict]):
    import headless_re_mcp.backends.r2.client as r2_module
    from headless_re_mcp.backends.common.bounded_run import Completed
    from headless_re_mcp.backends.r2.client import R2Client

    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")

    def fake_run(cmd: list[str], **kwargs: object) -> Completed:
        del kwargs
        return Completed(0, json.dumps(instrs).encode("utf-8"), b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    return R2Client(executable), binary


def test_r2_disasm_counts_invalid_instructions_from_a_bad_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unmapped address does not fail: r2 returns 0xff filler typed invalid.

    Verified against radare2 5.5.0: pdj at 0xdeadbeef returns `count`
    instructions each {"bytes": "ff", "type": "invalid"}. Without a count of
    those, the filler reads as a real disassembly and an unattended pass records
    invalid bytes as code. invalid_count == count is the "nothing decodable
    here" signal.
    """
    instrs = [
        {"offset": 0xDEAD0000 + i, "size": 1, "bytes": "ff", "type": "invalid"}
        for i in range(3)
    ]
    client, binary = _disasm_client(tmp_path, monkeypatch, instrs)
    result = client.disasm(binary, 0xDEAD0000, count=3)
    assert result["count"] == 3
    assert result["invalid_count"] == 3


def test_r2_disasm_invalid_count_is_zero_for_real_instructions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Decoded code (including a valid "null"-typed opcode) is not counted."""
    instrs = [
        {"offset": 0x401000, "size": 4, "opcode": "endbr64", "type": "null"},
        {"offset": 0x401004, "size": 1, "opcode": "push rbp", "type": "rpush"},
        {"offset": 0x401005, "size": 3, "opcode": "mov rbp, rsp", "type": "mov"},
    ]
    client, binary = _disasm_client(tmp_path, monkeypatch, instrs)
    result = client.disasm(binary, 0x401000, count=3)
    assert result["count"] == 3
    assert result["invalid_count"] == 0


def test_r2_disasm_docstring_explains_invalid_count() -> None:
    doc = _tool_docstring("r2.disasm").replace("\n", " ")
    assert "invalid_count" in doc
    assert "unmapped" in doc
    assert "invalid_count == count" in doc
