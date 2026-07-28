"""Unit tests for r2 Address mapping (no live r2 required)."""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    address_dict,
    enrich_r2_payload,
    parse_r2_json,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture


def _minimal_pe(tmp_path: Path, *, x64: bool = True) -> Path:
    # Tiny fake PE with MZ + PE + optional header image base.
    path = tmp_path / ("demo64.exe" if x64 else "demo32.exe")
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    # SizeOfOptionalHeader
    optional_size = 0xF0 if x64 else 0xE0
    data[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    optional_off = pe_offset + 24
    if x64:
        data[optional_off : optional_off + 2] = (0x20B).to_bytes(2, "little")
        image_base = 0x140000000
        data[optional_off + 24 : optional_off + 32] = image_base.to_bytes(8, "little")
    else:
        data[optional_off : optional_off + 2] = (0x10B).to_bytes(2, "little")
        image_base = 0x400000
        data[optional_off + 28 : optional_off + 32] = image_base.to_bytes(4, "little")
    # SizeOfImage
    data[optional_off + 56 : optional_off + 60] = (0x10000).to_bytes(4, "little")
    path.write_bytes(bytes(data))
    return path


def test_parse_r2_json_trailing_array() -> None:
    raw = "warning stuff\n" + json.dumps([{"offset": 0x140001000, "name": "entry0", "size": 16}])
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, list)
    assert parsed[0]["name"] == "entry0"


def test_address_dict_with_rva() -> None:
    mapped = address_dict(
        0x140001000,
        module="demo64.exe",
        image_base=0x140000000,
        architecture=Architecture.X64,
    )
    assert mapped == {
        "module": "demo64.exe",
        "rva": 0x1000,
        "va": 0x140001000,
        "architecture": "x64",
    }


def test_enrich_functions_payload(tmp_path: Path) -> None:
    binary = _minimal_pe(tmp_path, x64=True)
    arch, base = pe_preferred_base(binary)
    assert arch is Architecture.X64
    assert base == 0x140000000
    raw = json.dumps(
        [
            {"offset": 0x140001000, "name": "entry0", "size": 32},
            {"offset": 0x140002000, "name": "f1", "size": 8},
        ]
    )
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["aa", "aflj"]},
        binary=binary,
        architecture=Architecture.X64,
    )
    assert enriched["parsed"] is True
    assert enriched["count"] == 2
    assert enriched["items"][0]["address"]["rva"] == 0x1000
    assert enriched["items"][0]["address"]["module"] == "demo64.exe"
    assert enriched["items"][1]["address"]["va"] == 0x140002000


def test_enrich_disasm_request_address(tmp_path: Path) -> None:
    binary = _minimal_pe(tmp_path, x64=True)
    raw = json.dumps([{"offset": 0x140001000, "opcode": "nop"}])
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["pdj"], "address": 0x140001000, "count": 1},
        binary=binary,
    )
    assert enriched["address"]["rva"] == 0x1000
    assert enriched["address_va"] == 0x140001000
    assert enriched["items"][0]["address"]["module"] == binary.name
