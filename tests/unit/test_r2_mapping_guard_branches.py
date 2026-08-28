"""Guard and shape branches of the r2 payload mapping helper.

The existing mapping tests pin the request-address rewrite and the truncation
contracts on well-formed PE input. This file fills in the branches those step
over: the PE header reader's re-read, short-header, x86, zero-base and
non-PE / unreadable paths; the Address builder's reject path; the lenient JSON
extraction; the per-item hex/int coercion; and the enrichment branches for an
unmappable request address, a non-dict item, an unmappable item, a bare JSON
object and unparsable output. Each test pins one branch; no radare2 is needed.
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
    magic: int,
    image_base: int,
    *,
    optional_size: int = 0xF0,
    pe_offset: int = 0x80,
    size: int = 0x200,
) -> bytes:
    image = bytearray(size)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    image[pe_offset + 24 : pe_offset + 26] = magic.to_bytes(2, "little")
    if magic == 0x20B:
        image[pe_offset + 48 : pe_offset + 56] = image_base.to_bytes(8, "little")
    else:
        image[pe_offset + 52 : pe_offset + 56] = image_base.to_bytes(4, "little")
    return bytes(image)


# ---------------------------------------------------------------------------
# pe_preferred_base / _needed_header_bytes.
# ---------------------------------------------------------------------------
def test_pe_preferred_base_reads_x64(tmp_path: Path) -> None:
    p = tmp_path / "a.exe"
    p.write_bytes(_pe(0x20B, 0x140000000))
    assert pe_preferred_base(p) == (Architecture.X64, 0x140000000)


def test_pe_preferred_base_reads_x86(tmp_path: Path) -> None:
    p = tmp_path / "a.exe"
    p.write_bytes(_pe(0x10B, 0x400000))
    assert pe_preferred_base(p) == (Architecture.X86, 0x400000)


def test_pe_preferred_base_rejects_an_unknown_magic(tmp_path: Path) -> None:
    p = tmp_path / "a.exe"
    p.write_bytes(_pe(0x999, 0x400000))
    assert pe_preferred_base(p) == (None, None)


def test_pe_preferred_base_reports_no_base_when_zero(tmp_path: Path) -> None:
    """A PE whose ImageBase is zero still names its architecture."""
    p = tmp_path / "a.exe"
    p.write_bytes(_pe(0x20B, 0))
    assert pe_preferred_base(p) == (Architecture.X64, None)


def test_pe_preferred_base_rejects_a_short_optional_header(tmp_path: Path) -> None:
    p = tmp_path / "a.exe"
    p.write_bytes(_pe(0x20B, 0x400000, optional_size=10))
    assert pe_preferred_base(p) == (None, None)


def test_pe_preferred_base_returns_none_for_a_non_pe(tmp_path: Path) -> None:
    p = tmp_path / "a.bin"
    p.write_bytes(b"not a pe file at all, definitely not, no MZ here")
    assert pe_preferred_base(p) == (None, None)


def test_pe_preferred_base_handles_an_unreadable_path(tmp_path: Path) -> None:
    """A directory (or any path open() rejects) reads as "no header", not a crash."""
    assert pe_preferred_base(tmp_path) == (None, None)


def test_pe_preferred_base_rereads_past_the_header_window(tmp_path: Path) -> None:
    """A PE header past the initial 64 KiB window forces a bounded second read.

    The reader takes a window first, and only re-reads when the file header says
    the optional header runs further; this exercises that re-read on a header
    deliberately placed beyond the first window.
    """
    pe_offset = 0x10000
    size = pe_offset + 0x200
    image = bytearray(size)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 20 : pe_offset + 22] = (0xF0).to_bytes(2, "little")
    image[pe_offset + 24 : pe_offset + 26] = (0x20B).to_bytes(2, "little")
    image[pe_offset + 48 : pe_offset + 56] = (0x140000000).to_bytes(8, "little")
    p = tmp_path / "big.exe"
    p.write_bytes(bytes(image))
    assert pe_preferred_base(p) == (Architecture.X64, 0x140000000)


def test_needed_header_bytes_rejects_a_bad_pe_signature() -> None:
    head = bytearray(0x100)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    head[0x80:0x84] = b"XXXX"
    assert _needed_header_bytes(bytes(head)) is None


# ---------------------------------------------------------------------------
# address_dict.
# ---------------------------------------------------------------------------
def test_address_dict_maps_a_va_over_the_image_base() -> None:
    mapped = address_dict(
        0x2000, module="m", image_base=0x1000, architecture=Architecture.X64
    )
    assert mapped == {
        "module": "m",
        "rva": 0x1000,
        "va": 0x2000,
        "architecture": "x64",
    }


def test_address_dict_omits_rva_below_the_image_base() -> None:
    assert address_dict(0x500, module="m", image_base=0x1000, architecture=None) == {
        "va": 0x500
    }


def test_address_dict_rejects_a_non_int_or_negative_va() -> None:
    assert address_dict("0x10", module="m", image_base=None, architecture=None) is None  # type: ignore[arg-type]
    assert address_dict(-1, module="m", image_base=None, architecture=None) is None


def test_address_dict_rejects_an_rva_without_a_module() -> None:
    """An rva needs a module; a blank one makes Address reject it, not raise out.

    address_dict swallows the Address ValueError and returns None so a mapping
    with an unusable module degrades to no address rather than a crash.
    """
    assert address_dict(0x2000, module="", image_base=0x1000, architecture=None) is None


# ---------------------------------------------------------------------------
# parse_r2_json / _item_va.
# ---------------------------------------------------------------------------
def test_parse_r2_json_skips_a_false_bracket() -> None:
    """A `[` inside a banner is not the root value; the reader keeps scanning."""
    assert parse_r2_json('banner [not json {"a": 1}') == {"a": 1}
    assert parse_r2_json("") is None
    assert parse_r2_json("no json here") is None


def test_item_va_reads_ints_and_hex_strings() -> None:
    assert _item_va({"offset": 0x1000}, ("offset",)) == 0x1000
    assert _item_va({"offset": "0x2000"}, ("offset",)) == 0x2000
    # A non-numeric string is skipped so the next key can answer.
    assert _item_va({"offset": "nope", "vaddr": 0x30}, ("offset", "vaddr")) == 0x30
    assert _item_va({"offset": "nope"}, ("offset",)) is None
    assert _item_va({}, ("offset",)) is None


# ---------------------------------------------------------------------------
# enrich_r2_payload branches.
# ---------------------------------------------------------------------------
def test_enrich_skips_an_unmappable_request_address(tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    out = enrich_r2_payload(
        {"raw": "[]", "commands": [], "address": -1}, binary=binary
    )
    assert "address_va" not in out
    assert out["parsed"] is True


def test_enrich_skips_non_dict_and_unmappable_items(tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    raw = json.dumps([123, {"name": "no_address_here"}, {"offset": 4096}])
    out = enrich_r2_payload({"raw": raw, "commands": []}, binary=binary)
    assert out["count"] == 2
    items = out["items"]
    assert "address" not in items[0]
    assert items[1]["address"] == {"va": 4096}


def test_enrich_reports_a_json_object_as_info(tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    out = enrich_r2_payload(
        {"raw": json.dumps({"arch": "x86"}), "commands": []}, binary=binary
    )
    assert out["parsed"] is True
    assert out["info"] == {"arch": "x86"}


def test_enrich_reports_unparsable_output(tmp_path: Path) -> None:
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00")
    out = enrich_r2_payload({"raw": "not json", "commands": []}, binary=binary)
    assert out["parsed"] is False
