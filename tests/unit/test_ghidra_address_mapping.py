"""Ghidra payload enrichment: string addresses gain the r2-style Address object.

enrich_ghidra_payload is additive -- it never drops or rewrites the original
address strings ExportJson.py emits, it only attaches a companion
``{module, rva, va, architecture}`` object beside each, matching the shape the
r2 backend produces so the two engines report ELF coordinates identically.
These tests pin that: the base/arch come from the binary header, each mode's
address fields are enriched under the documented companion key, the original
strings survive untouched, and an address outside the load image (EXTERNAL)
degrades to va-only rather than a bogus rva.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.mapping import _to_int, enrich_ghidra_payload


def _write_elf(path: Path, *, machine: int = 0x3E, base: int = 0x400000) -> Path:
    phentsize, phoff = 56, 64
    data = bytearray(phoff + phentsize)
    data[:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little-endian
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<Q", data, 0x20, phoff)
    struct.pack_into("<H", data, 0x36, phentsize)
    struct.pack_into("<H", data, 0x38, 1)
    struct.pack_into("<I", data, phoff, 1)  # PT_LOAD
    struct.pack_into("<Q", data, phoff + 16, base)  # p_vaddr
    path.write_bytes(bytes(data))
    return path


def _write_pe64(path: Path, image_base: int = 0x140000000) -> Path:
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_off = 0x80
    data[0x3C:0x40] = pe_off.to_bytes(4, "little")
    data[pe_off : pe_off + 4] = b"PE\0\0"
    data[pe_off + 20 : pe_off + 22] = (0xF0).to_bytes(2, "little")
    opt = pe_off + 24
    data[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    data[opt + 24 : opt + 32] = image_base.to_bytes(8, "little")
    path.write_bytes(bytes(data))
    return path


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0040114e", 0x40114E),
        ("0x40114e", 0x40114E),
        ("ram:0040114e", 0x40114E),
        ("EXTERNAL:00000001", 1),
        ("not-an-address", None),
        (None, None),
    ],
)
def test_to_int_parses_ghidra_address_strings(text: object, expected: int | None) -> None:
    assert _to_int(text) == expected


def test_enrich_functions_attaches_entry_address_and_keeps_entry(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "a.out")
    payload = {
        "mode": "functions",
        "items": [{"name": "crackme_check", "entry": "0040114e", "body_size": 40}],
        "count": 1,
    }
    out = enrich_ghidra_payload(payload, binary=binary)

    assert out["module"] == "a.out"
    assert out["image_base"] == 0x400000
    assert out["architecture"] == "x64"
    item = out["items"][0]
    # Original fields untouched.
    assert item["entry"] == "0040114e"
    assert item["body_size"] == 40
    # Companion object with rva relative to the ELF load base.
    assert item["entry_address"] == {
        "module": "a.out",
        "rva": 0x114E,
        "va": 0x40114E,
        "architecture": "x64",
    }


def test_enrich_xrefs_attaches_both_endpoints_like_r2(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "a.out")
    payload = {
        "mode": "xrefs",
        "items": [{"from": "00401183", "to": "00401136", "type": "UNCONDITIONAL_CALL"}],
        "count": 1,
    }
    out = enrich_ghidra_payload(payload, binary=binary)
    item = out["items"][0]
    assert item["from"] == "00401183" and item["to"] == "00401136"
    assert item["from_address"]["rva"] == 0x1183
    assert item["from_address"]["module"] == "a.out"
    assert item["to_address"]["rva"] == 0x1136


def test_enrich_symbols_uses_address_detail_and_degrades_outside_image(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "a.out")
    payload = {
        "mode": "symbols",
        "items": [
            {"name": "crackme_check", "address": "0040114e", "type": "Function"},
            {"name": "puts", "address": "EXTERNAL:00000001", "type": "Function"},
        ],
        "count": 2,
    }
    out = enrich_ghidra_payload(payload, binary=binary)
    named, external = out["items"]
    # The string field keeps its name; the object rides under address_detail.
    assert named["address"] == "0040114e"
    assert named["address_detail"]["rva"] == 0x114E
    assert named["address_detail"]["module"] == "a.out"
    # An address below the load base (EXTERNAL space) has no rva, so it is
    # va-only with no module -- never a fabricated rva.
    assert external["address_detail"] == {"va": 1, "architecture": "x64"}


def test_enrich_decompile_attaches_top_level_entry_address(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "a.out")
    payload = {
        "mode": "decompile",
        "function": "crackme_check",
        "entry": "0040114e",
        "decompiled": "int crackme_check(void){...}",
        "truncated": False,
    }
    out = enrich_ghidra_payload(payload, binary=binary)
    assert out["entry"] == "0040114e"
    assert out["entry_address"]["rva"] == 0x114E
    assert out["entry_address"]["va"] == 0x40114E


def test_enrich_pe_addresses_use_pe_image_base(tmp_path: Path) -> None:
    # A PE must keep PE ImageBase semantics; the ELF fallback never runs for it.
    binary = _write_pe64(tmp_path / "demo64.exe")
    payload = {
        "mode": "functions",
        "items": [{"name": "entry0", "entry": "140001000", "body_size": 16}],
        "count": 1,
    }
    out = enrich_ghidra_payload(payload, binary=binary)
    assert out["image_base"] == 0x140000000
    assert out["items"][0]["entry_address"]["rva"] == 0x1000
    assert out["items"][0]["entry_address"]["module"] == "demo64.exe"


def test_enrich_is_a_noop_shape_for_empty_items(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "a.out")
    out = enrich_ghidra_payload({"mode": "functions", "items": [], "count": 0}, binary=binary)
    assert out["items"] == []
    assert out["module"] == "a.out"
