"""Guard, refusal, and layout-branch coverage for the PE rebuild helpers.

The happy remap/rebuild flows are covered elsewhere; these drive the fail-closed
guards (bad alignments, malformed headers, oversized sections, unresolved import
entries, header-room refusals) and the 32-bit and in-place layout branches by
calling the module helpers directly with crafted byte buffers.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.unpack.pe_rebuild import (
    PeRebuildError,
    _align,
    _rva_to_file_offset,
    _usable_alignment,
    parse_runtime_headers,
    rebuild_imports,
    remap_dump_to_file,
    write_rebuilt_pe,
)


def _make_runtime_dump(*, pe32_plus: bool = True) -> bytearray:
    image = bytearray(0x3000)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    machine = 0x8664 if pe32_plus else 0x14C
    optional_size = 0xF0 if pe32_plus else 0xE0
    struct.pack_into("<HHIIIHH", image, file_header, machine, 1, 0, 0, 0, optional_size, 0x22)
    optional = file_header + 20
    magic = 0x20B if pe32_plus else 0x10B
    struct.pack_into("<HBB", image, optional, magic, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    if pe32_plus:
        struct.pack_into("<Q", image, optional + 24, 0x140000000)
    else:
        struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x400)
    struct.pack_into("<HH", image, optional + 68, 3, 0)
    dir_count_off = optional + (108 if pe32_plus else 92)
    struct.pack_into("<I", image, dir_count_off, 16)
    section = optional + optional_size
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0, 0)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x1000:0x1002] = b"\xc3\x90"
    return image


def _api(module: str, name: str, **extra: Any) -> dict[str, Any]:
    entry = {"kind": "api", "module": module, "name": name, "ordinal": 0}
    entry.update(extra)
    return entry


# --------------------------------------------------------------------------- #
# _usable_alignment / _align
# --------------------------------------------------------------------------- #
def test_usable_alignment_rejects_a_non_integer() -> None:
    with pytest.raises(PeRebuildError, match="not a number"):
        _usable_alignment("nope", floor=0x200, ceiling=0x10000, what="FileAlignment")


def test_usable_alignment_rejects_a_value_above_the_ceiling() -> None:
    with pytest.raises(PeRebuildError, match="exceeds"):
        _usable_alignment(0x20000, floor=0x200, ceiling=0x10000, what="FileAlignment")


def test_usable_alignment_rejects_a_non_power_of_two() -> None:
    with pytest.raises(PeRebuildError, match="power of two"):
        _usable_alignment(0x300, floor=0x200, ceiling=0x10000, what="FileAlignment")


def test_align_rejects_a_non_positive_alignment() -> None:
    with pytest.raises(PeRebuildError, match="alignment must be positive"):
        _align(0x100, 0)


# --------------------------------------------------------------------------- #
# _rva_to_file_offset
# --------------------------------------------------------------------------- #
def test_rva_to_file_offset_rejects_a_bad_range() -> None:
    with pytest.raises(PeRebuildError, match="usable file offset"):
        _rva_to_file_offset({"sections": []}, -1, length=8, image=b"")


def test_rva_to_file_offset_skips_zero_raw_size_and_fails_closed() -> None:
    headers = {"sections": [{"virtual_address": 0x1000, "raw_size": 0, "raw_offset": 0x400}]}
    with pytest.raises(PeRebuildError, match="not a writable file range"):
        _rva_to_file_offset(headers, 0x1000, length=8, image=b"\0" * 0x2000)


def test_rva_to_file_offset_skips_a_range_beyond_the_image() -> None:
    headers = {"sections": [{"virtual_address": 0x1000, "raw_size": 0x200, "raw_offset": 0x4000}]}
    # va<=rva<=va+raw_size matches, but raw_offset is past the short image.
    with pytest.raises(PeRebuildError, match="not a writable file range"):
        _rva_to_file_offset(headers, 0x1000, length=8, image=b"\0" * 0x100)


def test_rva_to_file_offset_returns_the_mapped_offset() -> None:
    headers = {"sections": [{"virtual_address": 0x1000, "raw_size": 0x200, "raw_offset": 0x400}]}
    assert _rva_to_file_offset(headers, 0x1010, length=8, image=b"\0" * 0x1000) == 0x410


# --------------------------------------------------------------------------- #
# parse_runtime_headers
# --------------------------------------------------------------------------- #
def test_parse_rejects_a_bad_dos_header() -> None:
    with pytest.raises(PeRebuildError, match="valid DOS header"):
        parse_runtime_headers(b"ZZ" + b"\0" * 0x80)


def test_parse_rejects_a_pe_offset_inside_the_dos_stub() -> None:
    image = bytearray(0x80)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x10)  # < 0x40
    with pytest.raises(PeRebuildError, match="PE header offset"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_a_bad_pe_signature() -> None:
    image = bytearray(0x80)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"XX\0\0"
    with pytest.raises(PeRebuildError, match="valid PE signature"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_a_truncated_optional_header() -> None:
    image = bytearray(0x80)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    file_header = 0x44
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 0, 0, 0, 0, 0x400, 0x22)
    with pytest.raises(PeRebuildError, match="optional header is truncated"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_an_unsupported_optional_magic() -> None:
    dump = _make_runtime_dump()
    optional = 0x80 + 4 + 20
    struct.pack_into("<H", dump, optional, 0x999)
    with pytest.raises(PeRebuildError, match="unsupported optional magic"):
        parse_runtime_headers(bytes(dump))


def test_parse_rejects_a_truncated_section_table() -> None:
    dump = _make_runtime_dump()
    # Claim four sections but hand over a buffer too small to hold the table.
    struct.pack_into("<H", dump, 0x80 + 4 + 2, 4)
    with pytest.raises(PeRebuildError, match="section table is truncated"):
        parse_runtime_headers(bytes(dump[:0x1A0]))


# --------------------------------------------------------------------------- #
# remap_dump_to_file
# --------------------------------------------------------------------------- #
def test_remap_rejects_a_dump_without_sections() -> None:
    dump = _make_runtime_dump()
    struct.pack_into("<H", dump, 0x80 + 4 + 2, 0)  # NumberOfSections = 0
    with pytest.raises(PeRebuildError, match="no sections to remap"):
        remap_dump_to_file(bytes(dump))


def test_remap_truncates_a_section_larger_than_the_dump() -> None:
    dump = _make_runtime_dump()
    optional = 0x80 + 4 + 20
    section = optional + 0xF0
    struct.pack_into("<I", dump, section + 8, 0x900000)  # VirtualSize >> dump
    _rebuilt, report = remap_dump_to_file(bytes(dump))
    assert any("larger than" in w for w in report.warnings)
    assert any("not trusted" in u for u in report.unfixed)


def test_remap_zero_fills_a_section_mapped_beyond_the_dump() -> None:
    dump = _make_runtime_dump()
    optional = 0x80 + 4 + 20
    section = optional + 0xF0
    struct.pack_into("<I", dump, section + 12, 0x900000)  # VirtualAddress past the dump
    _rebuilt, report = remap_dump_to_file(bytes(dump))
    assert any("beyond dump" in w for w in report.warnings)
    assert any("missing runtime bytes" in u for u in report.unfixed)


def test_remap_skips_directory_indexes_past_the_count() -> None:
    dump = _make_runtime_dump()
    optional = 0x80 + 4 + 20
    # Only six data directories, so the bound-import slot (index 11) is skipped.
    struct.pack_into("<I", dump, optional + 108, 6)
    _rebuilt, _report = remap_dump_to_file(bytes(dump))


def test_remap_refuses_an_oversized_section_table() -> None:
    dump = _make_runtime_dump()
    optional = 0x80 + 4 + 20
    section = optional + 0xF0
    struct.pack_into("<H", dump, 0x80 + 4 + 2, 6)  # NumberOfSections = 6
    # Six sections each declaring more than the whole dump sum past the 4x cap.
    for index in range(6):
        off = section + index * 40
        dump[off : off + 8] = f".sec{index}\0\0\0".encode()[:8].ljust(8, b"\0")
        struct.pack_into("<IIII", dump, off + 8, 0x900000, 0x1000 + index * 0x1000, 0, 0)
        struct.pack_into("<I", dump, off + 36, 0x60000020)
    with pytest.raises(PeRebuildError, match="more than 4x"):
        remap_dump_to_file(bytes(dump))


def test_remap_rejects_a_negative_entry_point() -> None:
    dump = _make_runtime_dump()
    with pytest.raises(PeRebuildError, match="non-negative integer"):
        remap_dump_to_file(bytes(dump), entry_point_rva=-1)


def test_remap_clears_stale_volatile_directories() -> None:
    dump = _make_runtime_dump()
    optional = 0x80 + 4 + 20
    dir_off = optional + 112
    struct.pack_into("<II", dump, dir_off + 5 * 8, 0x5000, 0x100)  # BASERELOC dir set
    _rebuilt, report = remap_dump_to_file(bytes(dump))
    assert any("cleared data directory" in c for c in report.changes)


# --------------------------------------------------------------------------- #
# rebuild_imports: entry classification
# --------------------------------------------------------------------------- #
def _remapped(*, pe32_plus: bool = True) -> bytes:
    rebuilt, _ = remap_dump_to_file(bytes(_make_runtime_dump(pe32_plus=pe32_plus)))
    return rebuilt


def test_rebuild_imports_classifies_unresolved_entries() -> None:
    remapped = _remapped()
    entries: list[Any] = [
        "not-a-dict",
        {"kind": "reloc", "thunk_rva": 0x2000},
        _api("", "NoModule"),
        _api("kernel32.dll", "VirtualAlloc"),
    ]
    _rebuilt, report = rebuild_imports(remapped, entries)
    assert any("reloc" in u for u in report.unfixed)
    assert any("missing module name" in u for u in report.unfixed)


def test_rebuild_imports_recovers_and_defaults_ordinals() -> None:
    remapped = _remapped()
    entries = [
        _api("user32.dll", "ordinal_7"),  # parsed from the name
        _api("user32.dll", "ordinal_"),  # unparseable -> defaults to 0
        _api("user32.dll", "MessageBoxW"),
    ]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert any(".himps" in c for c in report.changes)


def test_rebuild_imports_refuses_without_resolved_apis() -> None:
    remapped = _remapped()
    entries = [{"kind": "null", "thunk_va": 0}, {"kind": "reloc", "thunk_rva": 1}]
    with pytest.raises(PeRebuildError, match="no resolved API entries"):
        rebuild_imports(remapped, entries)


def test_rebuild_imports_handles_by_ordinal_and_duplicate_names() -> None:
    remapped = _remapped()
    entries = [
        _api("ws2_32.dll", "", ordinal=5),  # by-ordinal thunk
        _api("kernel32.dll", "VirtualAlloc"),
        _api("kernel32.dll", "VirtualAlloc"),  # duplicate name -> reused offset
    ]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert any(".himps" in c for c in report.changes)


# --------------------------------------------------------------------------- #
# rebuild_imports: 32-bit and in-place layout branches
# --------------------------------------------------------------------------- #
def test_rebuild_imports_appends_a_32bit_iat() -> None:
    remapped = _remapped(pe32_plus=False)
    entries = [_api("kernel32.dll", "VirtualAlloc"), {"kind": "null"}]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert any(".himps" in c for c in report.changes)
    assert any("original IAT bytes" in u for u in report.unfixed)


def test_rebuild_imports_patches_a_32bit_iat_in_place() -> None:
    remapped = _remapped(pe32_plus=False)
    entries = [_api("kernel32.dll", "VirtualAlloc"), {"kind": "null"}]
    rebuilt, report = rebuild_imports(remapped, entries, iat_rva=0x1000)
    assert any("in-place" in c for c in report.changes)


def test_rebuild_imports_pads_to_file_alignment() -> None:
    remapped = _remapped()
    entries = [_api("kernel32.dll", "VirtualAlloc"), {"kind": "null"}]
    # An unaligned input length forces the appended section to start past it.
    rebuilt, _ = rebuild_imports(remapped + b"\x00", entries)
    assert len(rebuilt) % 0x200 == 0


def test_rebuild_imports_refuses_without_header_room() -> None:
    remapped = bytearray(_remapped())
    struct.pack_into("<I", remapped, 0x80 + 24 + 60, 0x100)  # tiny SizeOfHeaders
    entries = [_api("kernel32.dll", "VirtualAlloc"), {"kind": "null"}]
    with pytest.raises(PeRebuildError, match="SizeOfHeaders has no room"):
        rebuild_imports(bytes(remapped), entries)


def test_rebuild_imports_refuses_too_few_data_directories() -> None:
    remapped = bytearray(_remapped())
    struct.pack_into("<I", remapped, 0x80 + 24 + 108, 8)  # NumberOfRvaAndSizes = 8
    entries = [_api("kernel32.dll", "VirtualAlloc"), {"kind": "null"}]
    with pytest.raises(PeRebuildError, match="needs at least 13"):
        rebuild_imports(bytes(remapped), entries)


# --------------------------------------------------------------------------- #
# write_rebuilt_pe
# --------------------------------------------------------------------------- #
def test_write_rebuilt_pe_removes_stale_partials(tmp_path: Path) -> None:
    target = tmp_path / "rebuilt.exe"
    stale = tmp_path / "rebuilt.exe.partial"
    stale.write_bytes(b"leftover")

    sha = write_rebuilt_pe(target, b"MZ" + b"\0" * 64)

    assert len(sha) == 64
    assert target.exists()
    assert not stale.exists()


def test_write_rebuilt_pe_unlinks_a_surviving_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "rebuilt.exe"

    def copy_replace(self: Path, dst: Any) -> None:
        # Publish by copy so the partial survives into the finally block.
        Path(dst).write_bytes(self.read_bytes())

    monkeypatch.setattr(Path, "replace", copy_replace)

    sha = write_rebuilt_pe(target, b"MZ" + b"\0" * 64)

    assert len(sha) == 64
    assert target.exists()
    assert list(tmp_path.glob("*.partial")) == []
