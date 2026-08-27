"""Enrichment-path coverage for the r2/rizin payload mapper.

``enrich_r2_payload`` runs on every r2 tool result: it reads the PE preferred
base without spawning r2, extracts the first JSON value from banner-prefixed
output, and maps raw offsets to unified Address fields. These are the header
shapes and payload shapes that decide whether a caller gets a usable rva or a
bare va -- exercised directly, with crafted bytes, no live r2.
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


def _build_pe(
    path: Path,
    *,
    magic: int = 0x20B,
    optional_size: int = 0xF0,
    image_base: int = 0x140000000,
    pe_sig: bytes = b"PE\0\0",
    pe_offset: int = 0x80,
) -> Path:
    total = max(0x200, pe_offset + 24 + optional_size + 8)
    data = bytearray(total)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = pe_sig
    data[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    off = pe_offset + 24
    if optional_size >= 2:
        data[off : off + 2] = magic.to_bytes(2, "little")
    if magic == 0x10B:
        data[off + 28 : off + 32] = int(image_base).to_bytes(4, "little")
    elif magic == 0x20B:
        data[off + 24 : off + 32] = int(image_base).to_bytes(8, "little")
    path.write_bytes(bytes(data))
    return path


# ---------------------------------------------------------------------------
# pe_preferred_base


def test_preferred_base_reads_a_32bit_image_base(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "x86.exe", magic=0x10B, optional_size=0xE0, image_base=0x400000)

    arch, base = pe_preferred_base(binary)

    assert arch is Architecture.X86
    assert base == 0x400000


def test_preferred_base_returns_nothing_for_a_non_pe(tmp_path: Path) -> None:
    plain = tmp_path / "note.txt"
    plain.write_bytes(b"not a portable executable at all")

    assert pe_preferred_base(plain) == (None, None)


def test_preferred_base_swallows_an_unreadable_path(tmp_path: Path) -> None:
    # A directory cannot be opened for reading; the read must fail closed.
    assert pe_preferred_base(tmp_path) == (None, None)


def test_preferred_base_rejects_a_bad_pe_signature(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "bad.exe", pe_sig=b"XXXX")

    assert pe_preferred_base(binary) == (None, None)


def test_preferred_base_rejects_a_truncated_optional_header(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "tiny.exe", optional_size=40)

    assert pe_preferred_base(binary) == (None, None)


def test_preferred_base_rejects_an_unknown_optional_magic(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "weird.exe", magic=0x999)

    assert pe_preferred_base(binary) == (None, None)


def test_preferred_base_reports_arch_without_a_zero_image_base(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "zero.exe", magic=0x20B, image_base=0)

    arch, base = pe_preferred_base(binary)

    assert arch is Architecture.X64
    assert base is None


def test_preferred_base_rereads_when_the_stub_outruns_the_window(tmp_path: Path) -> None:
    """A DOS stub longer than the initial 64 KiB window forces a second read."""
    binary = _build_pe(tmp_path / "bigstub.exe", pe_offset=0x11000, image_base=0x140000000)

    arch, base = pe_preferred_base(binary)

    assert arch is Architecture.X64
    assert base == 0x140000000


def test_needed_header_bytes_rejects_a_bad_signature() -> None:
    head = bytearray(0x200)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    head[0x80:0x84] = b"XXXX"

    assert _needed_header_bytes(bytes(head)) is None


# ---------------------------------------------------------------------------
# parse_r2_json


def test_parse_json_skips_a_bracket_that_does_not_decode() -> None:
    raw = 'banner [not-json-here {"info": 1} trailing'

    assert parse_r2_json(raw) == {"info": 1}


def test_parse_json_returns_none_when_there_is_no_json() -> None:
    assert parse_r2_json("just a warning line, no json") is None


# ---------------------------------------------------------------------------
# _item_va


def test_item_va_parses_a_hex_string() -> None:
    assert _item_va({"offset": "0x140001000"}, ("offset",)) == 0x140001000


def test_item_va_skips_an_unparseable_string() -> None:
    assert _item_va({"offset": "not-a-number"}, ("offset",)) is None


def test_item_va_returns_none_when_no_key_matches() -> None:
    assert _item_va({"name": "x"}, ("offset", "vaddr")) is None


# ---------------------------------------------------------------------------
# address_dict


def test_address_dict_rejects_a_non_integer_va() -> None:
    assert address_dict(None, module="m", image_base=None, architecture=None) is None


def test_address_dict_returns_none_when_the_model_rejects_it() -> None:
    # rva present with a blank module violates the Address invariant.
    assert address_dict(0x2000, module="", image_base=0x1000, architecture=None) is None


# ---------------------------------------------------------------------------
# enrich_r2_payload


def test_enrich_marks_a_dict_payload_as_info(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "d.exe")

    out = enrich_r2_payload({"raw": json.dumps({"arch": "x64", "bits": 64})}, binary=binary)

    assert out["parsed"] is True
    assert out["info"] == {"arch": "x64", "bits": 64}
    assert "items" not in out


def test_enrich_marks_unparseable_output_as_not_parsed(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "d.exe")

    out = enrich_r2_payload({"raw": "warning: nothing here"}, binary=binary)

    assert out["parsed"] is False


def test_enrich_skips_non_object_entries_in_a_list(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "d.exe", image_base=0x140000000)
    raw = json.dumps([123, "str", {"offset": 0x140001000, "name": "f"}])

    out = enrich_r2_payload({"raw": raw}, binary=binary, architecture=Architecture.X64)

    assert out["count"] == 1
    assert out["items"][0]["name"] == "f"


def test_enrich_keeps_an_item_without_a_mappable_address(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "d.exe")
    raw = json.dumps([{"name": "no-address-here"}])

    out = enrich_r2_payload({"raw": raw}, binary=binary, architecture=Architecture.X64)

    assert out["count"] == 1
    assert "address" not in out["items"][0]


def test_enrich_ignores_a_negative_request_address(tmp_path: Path) -> None:
    binary = _build_pe(tmp_path / "d.exe")
    raw = json.dumps([{"offset": 0x140001000}])

    out = enrich_r2_payload(
        {"raw": raw, "address": -1}, binary=binary, architecture=Architecture.X64
    )

    # A negative address maps to nothing, so no Address is attached to it.
    assert "address_va" not in out
    assert out["address"] == -1
