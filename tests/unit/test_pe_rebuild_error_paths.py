"""Refusal and edge-branch coverage for the PE remap / IAT rebuild helpers.

Every field these read comes out of a dump the target wrote, so the module's
contract is that a malformed header produces a named ``PeRebuildError`` rather
than a struct fault or a runaway allocation. These craft dumps with one field
poisoned at a time to exercise each guard, plus the import-entry classification
branches and the write helper's stale-partial cleanup.
"""

from __future__ import annotations

import struct
from pathlib import Path

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
from tests.unit.test_pe_rebuild import _make_runtime_dump


def _offsets(dump: bytes) -> tuple[int, int, int, int, int]:
    pe = struct.unpack_from("<I", dump, 0x3C)[0]
    file_header = pe + 4
    optional = file_header + 20
    optional_size = struct.unpack_from("<H", dump, file_header + 16)[0]
    return pe, file_header, optional, optional_size, optional + optional_size


# --- parse_runtime_headers refusals -----------------------------------------


def test_parse_rejects_a_missing_dos_header() -> None:
    with pytest.raises(PeRebuildError, match="valid DOS header"):
        parse_runtime_headers(b"MZ")


def test_parse_rejects_a_pe_offset_outside_the_image() -> None:
    dump = bytearray(_make_runtime_dump())
    struct.pack_into("<I", dump, 0x3C, 0)  # pe_offset < 0x40
    with pytest.raises(PeRebuildError, match="PE header offset is outside"):
        parse_runtime_headers(bytes(dump))


def test_parse_rejects_a_bad_pe_signature() -> None:
    dump = bytearray(_make_runtime_dump())
    pe = struct.unpack_from("<I", dump, 0x3C)[0]
    dump[pe : pe + 4] = b"XX\0\0"
    with pytest.raises(PeRebuildError, match="valid PE signature"):
        parse_runtime_headers(bytes(dump))


def test_parse_rejects_an_optional_header_that_overruns_the_image() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, file_header, _opt, _osz, _st = _offsets(dump)
    struct.pack_into("<H", dump, file_header + 16, 0xFFF0)  # SizeOfOptionalHeader
    with pytest.raises(PeRebuildError, match="optional header is truncated"):
        parse_runtime_headers(bytes(dump))


def test_parse_rejects_an_image_that_ends_before_the_optional_magic() -> None:
    pe_offset = 0x40
    image = bytearray(pe_offset + 25)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    # SizeOfOptionalHeader stays 0, so optional+size fits, but optional+2 overruns.
    with pytest.raises(PeRebuildError, match="optional header is truncated"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_an_optional_header_that_stops_before_the_directory_count() -> None:
    pe_offset = 0x40
    image = bytearray(100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<H", image, file_header + 16, 2)  # SizeOfOptionalHeader
    optional = file_header + 20
    struct.pack_into("<H", image, optional, 0x20B)  # PE32+ magic
    # dir_count_off (optional + 108) + 4 lands past the 100-byte image.
    with pytest.raises(PeRebuildError, match="optional header is truncated"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_a_directory_array_that_overruns_the_image() -> None:
    pe_offset = 0x40
    image = bytearray(210)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<H", image, file_header + 16, 2)  # SizeOfOptionalHeader
    optional = file_header + 20
    struct.pack_into("<H", image, optional, 0x20B)  # PE32+ magic
    struct.pack_into("<I", image, optional + 108, 16)  # NumberOfRvaAndSizes
    # The count fits, but 16 directory entries run past the 210-byte image.
    with pytest.raises(PeRebuildError, match="optional header is truncated"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_an_unsupported_optional_magic() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, _fh, optional, _osz, _st = _offsets(dump)
    struct.pack_into("<H", dump, optional, 0x0999)
    with pytest.raises(PeRebuildError, match="unsupported optional magic"):
        parse_runtime_headers(bytes(dump))


def test_parse_rejects_a_truncated_section_table() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, file_header, _opt, _osz, _st = _offsets(dump)
    struct.pack_into("<H", dump, file_header + 2, 40)  # NumberOfSections
    truncated = bytes(dump[:512])
    with pytest.raises(PeRebuildError, match="section table is truncated"):
        parse_runtime_headers(truncated)


# --- alignment / offset helpers ----------------------------------------------


def test_usable_alignment_rejects_a_non_integer() -> None:
    with pytest.raises(PeRebuildError, match="is not a number"):
        _usable_alignment("nope", floor=0x200, ceiling=0x10000, what="FileAlignment")


def test_align_rejects_a_non_positive_alignment() -> None:
    with pytest.raises(PeRebuildError, match="alignment must be positive"):
        _align(10, 0)


def test_rva_to_file_offset_rejects_a_bad_range_and_an_unmapped_rva() -> None:
    remapped, _ = remap_dump_to_file(_make_runtime_dump(), entry_point_rva=0x1000)
    headers = parse_runtime_headers(remapped)
    with pytest.raises(PeRebuildError, match="usable file offset"):
        _rva_to_file_offset(headers, -1, length=8, image=remapped)
    with pytest.raises(PeRebuildError, match="not a writable file range"):
        _rva_to_file_offset(headers, 0x00FFFFFF, length=8, image=remapped)


# --- remap_dump_to_file refusals and best-effort branches --------------------


def test_remap_rejects_an_out_of_range_file_alignment() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, _fh, optional, _osz, _st = _offsets(dump)
    struct.pack_into("<I", dump, optional + 36, 0x20000)  # > MAX_FILE_ALIGNMENT
    with pytest.raises(PeRebuildError, match="exceeds"):
        remap_dump_to_file(bytes(dump))


def test_remap_rejects_a_file_alignment_that_is_not_a_power_of_two() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, _fh, optional, _osz, _st = _offsets(dump)
    struct.pack_into("<I", dump, optional + 36, 0x300)
    with pytest.raises(PeRebuildError, match="not a power of two"):
        remap_dump_to_file(bytes(dump))


def test_remap_rejects_a_dump_with_no_sections() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, file_header, _opt, _osz, _st = _offsets(dump)
    struct.pack_into("<H", dump, file_header + 2, 0)  # NumberOfSections = 0
    with pytest.raises(PeRebuildError, match="no sections to remap"):
        remap_dump_to_file(bytes(dump))


def test_remap_rejects_a_negative_entry_point() -> None:
    with pytest.raises(PeRebuildError, match="non-negative integer"):
        remap_dump_to_file(_make_runtime_dump(), entry_point_rva=-1)


def test_remap_truncates_a_section_that_claims_more_than_the_dump() -> None:
    dump = bytearray(_make_runtime_dump())
    *_rest, section_table = _offsets(dump)
    struct.pack_into("<I", dump, section_table + 8, 0x7FFFFFFF)  # VirtualSize
    _rebuilt, report = remap_dump_to_file(bytes(dump), entry_point_rva=0x1000)
    assert any("larger than" in warning for warning in report.warnings)
    assert any("not trusted" in item for item in report.unfixed)


def test_remap_zero_fills_a_section_mapped_beyond_the_dump() -> None:
    dump = bytearray(_make_runtime_dump())
    *_rest, section_table = _offsets(dump)
    struct.pack_into("<I", dump, section_table + 12, 0x00999000)  # VirtualAddress
    _rebuilt, report = remap_dump_to_file(bytes(dump), entry_point_rva=0x1000)
    assert any("beyond dump" in warning for warning in report.warnings)
    assert any("missing runtime bytes" in item for item in report.unfixed)


def test_remap_clears_a_stale_volatile_directory() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, _fh, optional, _osz, _st = _offsets(dump)
    dir_off = optional + 112
    struct.pack_into("<II", dump, dir_off + 5 * 8, 0x1234, 0x40)  # BASERELOC directory
    _rebuilt, report = remap_dump_to_file(bytes(dump), entry_point_rva=0x1000)
    assert any("cleared data directory[5]" in change for change in report.changes)


# --- rebuild_imports classification and layout branches ----------------------


def test_rebuild_imports_classifies_unusual_entries() -> None:
    remapped, _ = remap_dump_to_file(_make_runtime_dump(), entry_point_rva=0x1000)
    entries = [
        "not-a-dict",
        {"kind": "reloc", "thunk_va": 0x1},
        {"kind": "api", "name": "X", "module": ""},
        {"kind": "api", "module": "kernel32.dll", "name": "ordinal_9"},
        {"kind": "api", "module": "kernel32.dll", "name": "ordinal_bad"},
        {"kind": "api", "module": "kernel32.dll", "name": "VirtualAlloc", "thunk_va": 0x140002000},
        {"kind": "null", "thunk_va": 0x140002008, "value": 0},
    ]
    _rebuilt, report = rebuild_imports(remapped, entries)  # type: ignore[arg-type]
    assert any("reloc" in item for item in report.unfixed)
    assert any("missing module name" in item for item in report.unfixed)
    assert any(".himps" in change for change in report.changes)


def test_rebuild_imports_deduplicates_a_repeated_named_api() -> None:
    remapped, _ = remap_dump_to_file(_make_runtime_dump(), entry_point_rva=0x1000)
    entries = [
        {"kind": "api", "module": "kernel32.dll", "name": "VirtualAlloc", "thunk_va": 0x140002000},
        {"kind": "api", "module": "kernel32.dll", "name": "VirtualAlloc", "thunk_va": 0x140002008},
        {"kind": "null", "thunk_va": 0x140002010, "value": 0},
    ]
    rebuilt, report = rebuild_imports(remapped, entries)
    # The name is written once even though two thunks reference it.
    assert rebuilt.count(b"VirtualAlloc") == 1
    assert any(".himps" in change for change in report.changes)


def test_rebuild_imports_rejects_a_directory_array_too_short() -> None:
    dump = bytearray(_make_runtime_dump())
    _pe, _fh, optional, _osz, _st = _offsets(dump)
    struct.pack_into("<I", dump, optional + 108, 5)  # NumberOfRvaAndSizes
    remapped, _ = remap_dump_to_file(bytes(dump), entry_point_rva=0x1000)
    entries = [
        {"kind": "api", "module": "kernel32.dll", "name": "VirtualAlloc", "thunk_va": 0x140002000},
    ]
    with pytest.raises(PeRebuildError, match="at least 13"):
        rebuild_imports(remapped, entries)


def test_rebuild_imports_handles_x86_ordinal_and_named_thunks() -> None:
    remapped, _ = remap_dump_to_file(
        _make_runtime_dump(pe32_plus=False), entry_point_rva=0x1000
    )
    entries = [
        {"kind": "api", "module": "user32.dll", "name": "MessageBoxA", "thunk_va": 0x402000},
        {"kind": "api", "module": "user32.dll", "name": "", "ordinal": 7},
        {"kind": "null", "thunk_va": 0x402010, "value": 0},
    ]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert parse_runtime_headers(rebuilt)["architecture"] == "x86"
    assert any(".himps" in change for change in report.changes)


def test_rebuild_imports_patches_x86_iat_in_place() -> None:
    remapped, _ = remap_dump_to_file(
        _make_runtime_dump(pe32_plus=False), entry_point_rva=0x1000
    )
    entries = [
        {"kind": "api", "module": "user32.dll", "name": "MessageBoxA", "thunk_va": 0x402000},
        {"kind": "null", "thunk_va": 0x402008, "value": 0},
    ]
    _rebuilt, report = rebuild_imports(remapped, entries, iat_rva=0x1000)
    assert any("in-place" in change for change in report.changes)


# --- write_rebuilt_pe housekeeping -------------------------------------------


def test_write_rebuilt_pe_clears_a_stale_partial_first(tmp_path: Path) -> None:
    target = tmp_path / "out.exe"
    stale = tmp_path / "out.exe.partial"
    stale.write_bytes(b"leftover from a crashed write")
    sha = write_rebuilt_pe(target, b"MZ" + b"\0" * 64)
    assert len(sha) == 64
    assert target.read_bytes().startswith(b"MZ")
    assert list(tmp_path.glob("*.partial")) == []
