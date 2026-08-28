"""Guard-path coverage for the r2 payload/address mapping helpers.

``test_r2_address_mapping.py`` pins the happy paths (a well-formed PE, a
functions listing, a disasm request address). This file drives the fail-closed
edges of ``backends/r2/mapping.py``: the PE header reader bailing on a corrupt
image, ``address_dict`` refusing an inconsistent coordinate, ``parse_r2_json``
skipping a bracket that does not begin JSON, ``_item_va`` recovering from a
string offset that will not parse, and ``enrich_r2_payload`` tolerating
non-dict rows / an object payload / an unmappable request address. None of this
needs a live radare2 -- the helpers work on bytes and dicts.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    _item_va,
    _needed_header_bytes,
    address_dict,
    enrich_r2_payload,
    parse_r2_json,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture


def _pe(
    tmp_path: Path,
    name: str = "mod.exe",
    *,
    pe_sig: bytes = b"PE\0\0",
    magic: int = 0x20B,
    size_of_optional_header: int = 0xF0,
    image_base: int = 0x140000000,
    total: int = 0x200,
) -> Path:
    data = bytearray(total)
    data[0:2] = b"MZ"
    pe_off = 0x80
    data[0x3C:0x40] = pe_off.to_bytes(4, "little")
    data[pe_off : pe_off + 4] = pe_sig
    data[pe_off + 20 : pe_off + 22] = size_of_optional_header.to_bytes(2, "little")
    opt = pe_off + 24
    data[opt : opt + 2] = magic.to_bytes(2, "little")
    if magic == 0x20B:
        data[opt + 24 : opt + 32] = image_base.to_bytes(8, "little")
    else:
        data[opt + 28 : opt + 32] = (image_base & 0xFFFFFFFF).to_bytes(4, "little")
    data[opt + 56 : opt + 60] = (0x10000).to_bytes(4, "little")
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return path


# --- pe_preferred_base header guards --------------------------------------


def test_preferred_base_bails_on_a_truncated_optional_header(tmp_path: Path) -> None:
    binary = _pe(tmp_path, size_of_optional_header=40)
    assert pe_preferred_base(binary) == (None, None)


def test_preferred_base_bails_on_an_unknown_optional_magic(tmp_path: Path) -> None:
    binary = _pe(tmp_path, magic=0x1FF)
    assert pe_preferred_base(binary) == (None, None)


def test_preferred_base_reports_architecture_but_no_base_when_base_is_zero(
    tmp_path: Path,
) -> None:
    binary = _pe(tmp_path, image_base=0)
    assert pe_preferred_base(binary) == (Architecture.X64, None)


def test_preferred_base_rejects_a_bad_pe_signature(tmp_path: Path) -> None:
    binary = _pe(tmp_path, pe_sig=b"XX\0\0")
    assert pe_preferred_base(binary) == (None, None)


def test_needed_header_bytes_returns_none_for_a_bad_signature() -> None:
    head = bytearray(0x200)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    head[0x80:0x84] = b"XX\0\0"
    assert _needed_header_bytes(bytes(head)) is None


# --- address_dict inconsistent-coordinate guard ---------------------------


def test_address_dict_returns_none_for_an_unmappable_coordinate() -> None:
    """An RVA with no module is not a valid Address, so mapping fails closed.

    ``address_dict`` computes an RVA when the VA sits above the image base, then
    builds an ``Address``; that model rejects an RVA without a module. An empty
    module name (a Path with no basename would produce one) must yield ``None``
    rather than letting the pydantic ValueError escape into the r2 payload.
    """
    assert address_dict(0x1000, module="", image_base=0x1000, architecture=Architecture.X64) is None


# --- parse_r2_json bracket-that-is-not-json -------------------------------


def test_parse_r2_json_skips_a_bracket_that_does_not_start_json() -> None:
    raw = "[not json here\n" + json.dumps([{"offset": 0x1000, "name": "f"}])
    parsed = parse_r2_json(raw)
    assert isinstance(parsed, list)
    assert parsed[0]["name"] == "f"


# --- _item_va string parsing ----------------------------------------------


def test_item_va_parses_a_hex_string_offset() -> None:
    assert _item_va({"offset": "0x1000"}, ("offset",)) == 0x1000


def test_item_va_skips_an_unparseable_string_and_tries_the_next_key() -> None:
    assert _item_va({"offset": "not-a-number", "vaddr": 0x2000}, ("offset", "vaddr")) == 0x2000


# --- enrich_r2_payload tolerant rows / shapes -----------------------------


def test_enrich_skips_non_dict_rows_in_the_array(tmp_path: Path) -> None:
    binary = _pe(tmp_path)
    raw = json.dumps([{"offset": 0x140001000, "name": "f0"}, "stray", 42])
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    assert enriched["parsed"] is True
    assert enriched["count"] == 1
    assert enriched["items"][0]["name"] == "f0"


def test_enrich_keeps_a_row_without_any_address_field(tmp_path: Path) -> None:
    binary = _pe(tmp_path)
    raw = json.dumps([{"name": "no_address_here"}])
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    assert enriched["count"] == 1
    assert "address" not in enriched["items"][0]
    assert enriched["items"][0]["name"] == "no_address_here"


def test_enrich_stores_an_object_payload_as_info(tmp_path: Path) -> None:
    binary = _pe(tmp_path)
    raw = json.dumps({"format": "pe", "bits": 64})
    enriched = enrich_r2_payload({"raw": raw, "commands": ["ij"]}, binary=binary)
    assert enriched["parsed"] is True
    assert enriched["info"] == {"format": "pe", "bits": 64}
    assert "items" not in enriched


def test_enrich_does_not_annotate_an_unmappable_request_address(tmp_path: Path) -> None:
    """A request address that will not map is left raw, never turned into junk.

    ``enrich_r2_payload`` copies the caller's dict, then only overwrites
    ``out['address']`` (and adds ``out['address_va']``) when the coordinate
    maps. A value ``address_dict`` rejects -- here a negative VA -- must exercise
    the skip branch: the original raw value stays put, no ``Address`` dict is
    substituted, and no ``address_va`` is fabricated. It must not crash.
    """
    binary = _pe(tmp_path)
    raw = json.dumps([{"offset": 0x140001000, "opcode": "nop"}])
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["pdj"], "address": -1},
        binary=binary,
    )
    assert enriched["address"] == -1
    assert not isinstance(enriched["address"], dict)
    assert "address_va" not in enriched
