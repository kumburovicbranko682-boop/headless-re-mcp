"""Unit tests for PE dump remap and IAT rebuild helpers."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.detection.pe import scan_pe
from headless_re_mcp.unpack.pe_rebuild import (
    MAX_SECTION_COUNT,
    PeRebuildError,
    parse_runtime_headers,
    rebuild_imports,
    remap_dump_to_file,
    write_rebuilt_pe,
)


def _make_runtime_dump(*, pe32_plus: bool = True) -> bytes:
    """Build a minimal memory-style PE image (sections at VA offsets)."""
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
    struct.pack_into("<I", image, optional + 16, 0x1000)  # EP
    if pe32_plus:
        struct.pack_into("<Q", image, optional + 24, 0x140000000)
    else:
        struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x400)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<HH", image, optional + 68, 3, 0)
    dir_count_off = optional + (108 if pe32_plus else 92)
    struct.pack_into("<I", image, dir_count_off, 16)
    section = optional + optional_size
    image[section : section + 8] = b".text\0\0\0"
    # VirtualSize, VA, RawSize, RawOffset — raw fields intentionally wrong (memory style)
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0, 0)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x1000:0x1002] = b"\xC3\x90"
    return bytes(image)


def test_parse_and_remap_runtime_dump(tmp_path: Path) -> None:
    dump = _make_runtime_dump()
    headers = parse_runtime_headers(dump)
    assert headers["architecture"] == "x64"
    assert headers["entry_point_rva"] == 0x1000

    rebuilt, report = remap_dump_to_file(dump, entry_point_rva=0x1000)
    report_dict = report.to_dict()
    assert report_dict["claims_universal_unpack"] is False
    assert any("checksum" in item.lower() for item in report_dict["unfixed"])
    out = tmp_path / "remapped.exe"
    sha = write_rebuilt_pe(out, rebuilt)
    assert len(sha) == 64
    pe = scan_pe(out)
    assert pe.architecture == "x64"
    assert pe.pe.entry_point_rva == 0x1000
    assert pe.pe.sections[0].raw_size > 0


def test_rebuild_imports_adds_himps_section(tmp_path: Path) -> None:
    dump = _make_runtime_dump()
    remapped, _ = remap_dump_to_file(dump, entry_point_rva=0x1000)
    entries = [
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualAlloc",
            "ordinal": 0,
            "thunk_va": 0x140002000,
        },
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualProtect",
            "ordinal": 0,
            "thunk_va": 0x140002008,
        },
        {"kind": "null", "thunk_va": 0x140002010, "value": 0},
    ]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert any(".himps" in change for change in report.changes)
    report_dict = report.to_dict()
    assert report_dict["claims_universal_unpack"] is False
    assert any("checksum" in item.lower() for item in report_dict["unfixed"])
    out = tmp_path / "imports.exe"
    write_rebuilt_pe(out, rebuilt)
    pe = scan_pe(out)
    assert pe.pe.imports.function_count >= 2
    assert any(section.name.startswith(".himps") for section in pe.pe.sections)


def test_rebuild_imports_tolerates_a_non_ascii_api_name(tmp_path: Path) -> None:
    """A packer can leave a non-ASCII byte in a resolved import name.

    The DLL-name path encodes with "replace", but the API-name path used
    "strict" and raised UnicodeEncodeError out of the whole rebuild, so one odd
    byte aborted an otherwise recoverable import table. It must degrade instead.
    """
    dump = _make_runtime_dump()
    remapped, _ = remap_dump_to_file(dump, entry_point_rva=0x1000)
    entries = [
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "Bad\u00e9Name",
            "ordinal": 0,
            "thunk_va": 0x140002000,
        },
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualAlloc",
            "ordinal": 0,
            "thunk_va": 0x140002008,
        },
        {"kind": "null", "thunk_va": 0x140002010, "value": 0},
    ]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert any(".himps" in change for change in report.changes)
    # The non-ASCII byte becomes '?' (ascii/replace); the rest of the name and
    # the neighbouring clean import both survive into the rebuilt name table.
    assert b"Bad?Name\x00" in rebuilt
    assert b"VirtualAlloc\x00" in rebuilt
    out = tmp_path / "imports-nonascii.exe"
    write_rebuilt_pe(out, rebuilt)
    pe = scan_pe(out)
    assert pe.pe.imports.function_count >= 2


def test_pe_rebuild_report_always_lists_checksum_unfixed() -> None:
    dump = _make_runtime_dump()
    _, remap_report = remap_dump_to_file(dump, entry_point_rva=0x1000)
    remap_dict = remap_report.to_dict()
    assert remap_dict["claims_universal_unpack"] is False
    assert any("checksum" in item.lower() for item in remap_dict["unfixed"])

    remapped, _ = remap_dump_to_file(dump, entry_point_rva=0x1000)
    entries = [
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualAlloc",
            "ordinal": 0,
            "thunk_va": 0x140002000,
        },
        {"kind": "null", "thunk_va": 0x140002008, "value": 0},
    ]
    _, import_report = rebuild_imports(remapped, entries)
    import_dict = import_report.to_dict()
    assert import_dict["claims_universal_unpack"] is False
    assert any("checksum" in item.lower() for item in import_dict["unfixed"])
    assert any("original IAT bytes" in item for item in import_dict["unfixed"])


def _make_runtime_dump_with_rdata() -> bytes:
    image = bytearray(0x3000)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x400)
    struct.pack_into("<HH", image, optional + 68, 3, 0)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0, 0)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[section + 40 : section + 48] = b".rdata\0\0"
    struct.pack_into("<IIII", image, section + 48, 0x200, 0x2000, 0, 0)
    struct.pack_into("<I", image, section + 76, 0x40000040)
    image[0x1000:0x1002] = b"\xC3\x90"
    image[0x2000:0x2018] = b"\xAA" * 0x18
    return bytes(image)


def test_rebuild_imports_patches_the_original_iat_when_rva_is_known() -> None:
    dump = _make_runtime_dump_with_rdata()
    remapped, _ = remap_dump_to_file(dump, entry_point_rva=0x1000)
    entries = [
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualAlloc",
            "ordinal": 0,
            "thunk_va": 0x140002000,
        },
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualProtect",
            "ordinal": 0,
            "thunk_va": 0x140002008,
        },
        {"kind": "null", "thunk_va": 0x140002010, "value": 0},
    ]
    rebuilt, report = rebuild_imports(remapped, entries, iat_rva=0x2000)
    assert any("in-place" in change for change in report.changes)
    assert not any("original IAT bytes" in item for item in report.unfixed)
    headers = parse_runtime_headers(rebuilt)
    iat_dir = headers["directories"][12]
    assert iat_dir["rva"] == 0x2000
    offset = None
    for section in headers["sections"]:
        if int(section["virtual_address"]) == 0x2000:
            offset = int(section["raw_offset"])
            break
    assert offset is not None
    assert rebuilt[offset : offset + 8] != b"\xAA" * 8
    first_thunk = struct.unpack_from("<Q", rebuilt, offset)[0]
    assert first_thunk != 0


def _file_offset_for_rva(image: bytes, rva: int, *, length: int = 1) -> int:
    headers = parse_runtime_headers(image)
    for section in headers["sections"]:
        va = int(section["virtual_address"])
        raw_size = int(section["raw_size"])
        raw_offset = int(section["raw_offset"])
        if raw_size <= 0:
            continue
        if va <= rva and rva + length <= va + raw_size:
            return raw_offset + (rva - va)
    raise AssertionError(f"RVA {rva:#x} size {length} is not in the rebuilt file")


def _ascii_at_rva(image: bytes, rva: int) -> str:
    offset = _file_offset_for_rva(image, rva)
    end = image.index(b"\0", offset)
    return image[offset:end].decode("ascii")


def test_rebuild_imports_in_place_names_sit_at_published_rvas() -> None:
    dump = _make_runtime_dump_with_rdata()
    remapped, _ = remap_dump_to_file(dump, entry_point_rva=0x1000)
    entries = [
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualAlloc",
            "ordinal": 0,
            "thunk_va": 0x140002000,
        },
        {
            "kind": "api",
            "module": "kernel32.dll",
            "name": "VirtualProtect",
            "ordinal": 0,
            "thunk_va": 0x140002008,
        },
        {"kind": "null", "thunk_va": 0x140002010, "value": 0},
    ]
    rebuilt, report = rebuild_imports(remapped, entries, iat_rva=0x2000)
    assert any("in-place" in change for change in report.changes)

    headers = parse_runtime_headers(rebuilt)
    import_dir = headers["directories"][1]
    desc_off = _file_offset_for_rva(rebuilt, int(import_dir["rva"]), length=20)
    original_first_thunk, _ts, _fc, name_rva, first_thunk = struct.unpack_from(
        "<IIIII", rebuilt, desc_off
    )
    assert name_rva != 0
    assert _ascii_at_rva(rebuilt, name_rva) == "kernel32.dll"

    expected = ("VirtualAlloc", "VirtualProtect")
    ilt_rva = original_first_thunk
    iat_rva = first_thunk
    for api_name in expected:
        ilt_off = _file_offset_for_rva(rebuilt, ilt_rva, length=8)
        iat_off = _file_offset_for_rva(rebuilt, iat_rva, length=8)
        hint_name_rva = struct.unpack_from("<Q", rebuilt, ilt_off)[0]
        iat_name_rva = struct.unpack_from("<Q", rebuilt, iat_off)[0]
        assert hint_name_rva == iat_name_rva
        assert hint_name_rva != 0
        assert _ascii_at_rva(rebuilt, hint_name_rva + 2) == api_name
        ilt_rva += 8
        iat_rva += 8


def test_hostile_number_of_sections_is_refused_before_header_growth() -> None:
    dump = bytearray(_make_runtime_dump())
    pe_offset = struct.unpack_from("<I", dump, 0x3C)[0]
    # 200 section-table slots still fit inside this 0x3000 dump, so a missing
    # cap would parse them and grow SizeOfHeaders by (200+1)*40 before failing.
    struct.pack_into("<H", dump, pe_offset + 6, MAX_SECTION_COUNT + 104)
    with pytest.raises(PeRebuildError, match="NumberOfSections") as caught:
        remap_dump_to_file(bytes(dump))
    assert str(MAX_SECTION_COUNT) in str(caught.value)


def test_write_rebuilt_pe_deletes_partial_when_publish_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "rebuilt.exe"

    def fail_replace(self: Path, _dst: Path) -> Path:
        raise OSError("simulated publish failure")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated publish failure"):
        write_rebuilt_pe(target, b"MZ" + b"\0" * 64)
    assert not target.exists()
    assert list(tmp_path.glob("*.partial")) == []
