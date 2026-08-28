"""r2.disasm_function must map a whole function's ops and keep the resolved text."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import (
    R2Client,
    R2Error,
    _require_allowed_command,
)
from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS
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


def _canned(payload: Any) -> Any:
    """A fake R2Client.run returning ``payload`` as the pdfj raw JSON."""

    def run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        raw = json.dumps(payload) if payload is not None else ""
        return {"raw": raw, "commands": commands}

    return run


def test_disasm_function_maps_ops_and_keeps_resolved_disasm(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A pdfj function must come back named, sized, and with each op mapped.

    The whole reason to disassemble a function (not a linear window) is the
    resolved view: the call op must keep its ``call sym.re_mcp_triple`` disasm
    text and its ``call`` type, every op must be address-mapped for a pivot, and
    r2's per-op internals (esil, ...) must be dropped so the listing stays lean.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    pdfj = {
        "name": "main",
        "addr": 0x1150,
        "size": 54,
        "ops": [
            {
                "addr": 0x1150,
                "opcode": "push rbp",
                "disasm": "push rbp",
                "bytes": "55",
                "type": "rpush",
                "size": 1,
                "esil": "rbp,8,rsp,-=,rsp,=[8]",
            },
            {
                "addr": 0x1155,
                "opcode": "call 0x1139",
                "disasm": "call sym.re_mcp_triple",
                "bytes": "e8dfffffff",
                "type": "call",
                "size": 5,
                "esil": "...",
            },
        ],
    }
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(pdfj))
    out = client.disasm_function(binary, 0x1150)
    assert out["parsed"] is True
    assert out["name"] == "main"
    assert out["size"] == 54
    assert out["address_va"] == 0x1150
    assert isinstance(out.get("address"), dict)
    assert out["address"].get("va") == 0x1150
    assert out["count"] == 2
    assert out["invalid_count"] == 0
    call = out["ops"][1]
    assert call["type"] == "call"
    assert call["disasm"] == "call sym.re_mcp_triple"
    assert call["addr"] == 0x1155
    assert call["address"].get("va") == 0x1155
    # The op-level internals r2 emits are dropped; only the reading fields remain.
    assert "esil" not in call
    assert set(call) >= {"addr", "opcode", "disasm", "bytes", "type", "size", "address"}
    doc = _tool_docstring("r2.disasm_function")
    assert "disasm" in doc
    assert "invalid_count" in doc
    assert "ops_truncated" in doc


def test_disasm_function_non_function_address_is_clean_empty(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """pdfj at a non-function address must be an empty op list, not an error.

    r2 prints nothing when there is no function at the address, so the reader
    reports parsed False with zero ops rather than raising -- the same fail-soft
    the other r2 readers give an address that resolves to nothing.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(None))  # empty raw
    out = client.disasm_function(binary, 0x1)
    assert out["parsed"] is False
    assert out["ops"] == []
    assert out["count"] == 0
    assert out["invalid_count"] == 0
    assert "name" not in out


def test_disasm_function_counts_invalid_ops(tmp_path: Path, monkeypatch: Any) -> None:
    """An undecodable op inside the function must be counted, not hidden.

    r2 tags a byte it cannot decode ``type: invalid`` (5.x) or ``ill`` (6.x);
    invalid_count surfaces "some of this is not really code" the same way
    r2.disasm does.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    pdfj = {
        "name": "f",
        "addr": 0x2000,
        "size": 3,
        "ops": [
            {"addr": 0x2000, "opcode": "nop", "disasm": "nop", "type": "nop", "size": 1},
            {"addr": 0x2001, "opcode": "invalid", "disasm": "invalid", "type": "ill", "size": 1},
        ],
    }
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(pdfj))
    out = client.disasm_function(binary, 0x2000)
    assert out["count"] == 2
    assert out["invalid_count"] == 1


def test_disasm_function_discloses_a_capped_listing(tmp_path: Path, monkeypatch: Any) -> None:
    """A function longer than the op cap must be flagged, not silently ended."""
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    ops = [
        {"addr": 0x3000 + i, "opcode": "nop", "disasm": "nop", "type": "nop", "size": 1}
        for i in range(_MAX_ITEMS + 3)
    ]
    pdfj = {"name": "big", "addr": 0x3000, "size": _MAX_ITEMS + 3, "ops": ops}
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(pdfj))
    out = client.disasm_function(binary, 0x3000)
    assert out["count"] == _MAX_ITEMS
    assert len(out["ops"]) == _MAX_ITEMS
    assert out["ops_truncated"] is True
    assert out["ops_total"] == _MAX_ITEMS + 3
    assert out["ops_limit"] == _MAX_ITEMS


def test_disasm_function_rejects_a_bad_address(tmp_path: Path) -> None:
    """A negative address is a caller error, refused before any r2 spawn."""
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    client = R2Client(executable=Path("/nonexistent-r2"))
    with pytest.raises(R2Error) as info:
        client.disasm_function(binary, -1)
    assert info.value.code == "invalid_params"


def test_pdfj_whitelist_requires_an_integer_address() -> None:
    """The whitelist gates pdfj to an int/hex address, refusing a symbol name.

    r2.disasm_function always builds ``pdfj @ <int>``, but the whitelist is the
    last gate: an integer/hex seek passes, a symbol expression or a bare pdfj is
    refused so no unbounded or expression-bearing command can slip through.
    """
    _require_allowed_command("pdfj @ 0x1150")
    _require_allowed_command("pdfj @ 4432")
    with pytest.raises(R2Error):
        _require_allowed_command("pdfj @ sym.main")
    with pytest.raises(R2Error):
        _require_allowed_command("pdfj")
