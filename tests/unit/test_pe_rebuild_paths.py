"""Branch coverage for the PE remap / IAT rebuild helpers.

These build synthetic memory-style PE images (x86 and x64) in-process, so the
hostile-input and error arms run without the optional on-disk fixture that
gates the sibling suite. The focus is the guard and reporting paths: alignment
and RVA validation, malformed headers, oversized/absent sections, entry
handling in the import rebuild, the 32-bit thunk path, the header-room and
directory-count refusals, and the atomic writer's cleanup arms.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.unpack import pe_rebuild as mod
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


def _make_dump(*, pe32_plus: bool = True, with_rdata: bool = False) -> bytearray:
    """A minimal memory-style PE image; raw fields left zero as in a dump."""
    image = bytearray(0x3000)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    machine = 0x8664 if pe32_plus else 0x14C
    optional_size = 0xF0 if pe32_plus else 0xE0
    section_count = 2 if with_rdata else 1
    struct.pack_into(
        "<HHIIIHH", image, file_header, machine, section_count, 0, 0, 0, optional_size, 0x22
    )
    optional = file_header + 20
    magic = 0x20B if pe32_plus else 0x10B
    struct.pack_into("<HBB", image, optional, magic, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)  # EP
    if pe32_plus:
        struct.pack_into("<Q", image, optional + 24, 0x140000000)
    else:
        struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)  # Section/FileAlignment
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x400)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<HH", image, optional + 68, 3, 0)
    dir_count_off = optional + (108 if pe32_plus else 92)
    struct.pack_into("<I", image, dir_count_off, 16)
    section = optional + optional_size
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0, 0)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    if with_rdata:
        image[section + 40 : section + 48] = b".rdata\0\0"
        struct.pack_into("<IIII", image, section + 48, 0x200, 0x2000, 0, 0)
        struct.pack_into("<I", image, section + 76, 0x40000040)
        image[0x2000:0x2018] = b"\xaa" * 0x18
    image[0x1000:0x1002] = b"\xc3\x90"
    return image


def _optional_offset(image: bytes | bytearray) -> int:
    pe_offset = int(struct.unpack_from("<I", image, 0x3C)[0])
    return pe_offset + 4 + 20


def _named(module: str, name: str) -> dict[str, Any]:
    return {"kind": "api", "module": module, "name": name, "ordinal": 0}


# ---------------------------------------------------------------------------
# _usable_alignment / _align / _rva_to_file_offset
# ---------------------------------------------------------------------------


def test_usable_alignment_rejects_bad_values() -> None:
    with pytest.raises(PeRebuildError, match="not a number"):
        _usable_alignment("x", floor=0x200, ceiling=0x10000, what="FileAlignment")
    with pytest.raises(PeRebuildError, match="not a number"):
        _usable_alignment(True, floor=0x200, ceiling=0x10000, what="FileAlignment")
    with pytest.raises(PeRebuildError, match="exceeds"):
        _usable_alignment(0x20000, floor=0x200, ceiling=0x10000, what="FileAlignment")
    with pytest.raises(PeRebuildError, match="power of two"):
        _usable_alignment(0x600, floor=0x200, ceiling=0x10000, what="FileAlignment")
    assert _usable_alignment(0, floor=0x200, ceiling=0x10000, what="FileAlignment") == 0x200


def test_align_rejects_a_nonpositive_alignment() -> None:
    assert _align(0x201, 0x200) == 0x400
    with pytest.raises(PeRebuildError, match="alignment must be positive"):
        _align(10, 0)


def test_rva_to_file_offset_validation_and_search() -> None:
    with pytest.raises(PeRebuildError, match="usable file offset"):
        _rva_to_file_offset({"sections": []}, -1, length=8, image=b"\0" * 64)

    headers = {
        "sections": [
            {"virtual_address": 0x1000, "raw_size": 0, "raw_offset": 0},
            {"virtual_address": 0x2000, "raw_size": 0x100, "raw_offset": 0x50},
        ]
    }
    # The empty section is skipped; the second matches the RVA but its file
    # range runs off the end of a tiny image, so no offset is returned.
    with pytest.raises(PeRebuildError, match="not a writable file range"):
        _rva_to_file_offset(headers, 0x2000, length=8, image=b"\0" * 0x40)

    ok = _rva_to_file_offset(headers, 0x2000, length=8, image=b"\0" * 0x200)
    assert ok == 0x50


# ---------------------------------------------------------------------------
# parse_runtime_headers guards
# ---------------------------------------------------------------------------


def test_parse_rejects_a_missing_dos_header() -> None:
    with pytest.raises(PeRebuildError, match="valid DOS header"):
        parse_runtime_headers(b"MZ" + b"\0" * 8)
    not_mz = _make_dump()
    not_mz[:2] = b"ZZ"
    with pytest.raises(PeRebuildError, match="valid DOS header"):
        parse_runtime_headers(bytes(not_mz))


def test_parse_rejects_a_bad_pe_offset_and_signature() -> None:
    bad_offset = _make_dump()
    struct.pack_into("<I", bad_offset, 0x3C, 0x10)
    with pytest.raises(PeRebuildError, match="PE header offset"):
        parse_runtime_headers(bytes(bad_offset))

    bad_sig = _make_dump()
    pe_offset = struct.unpack_from("<I", bad_sig, 0x3C)[0]
    bad_sig[pe_offset : pe_offset + 4] = b"XXXX"
    with pytest.raises(PeRebuildError, match="valid PE signature"):
        parse_runtime_headers(bytes(bad_sig))


def test_parse_rejects_truncated_optional_and_bad_magic() -> None:
    truncated = _make_dump()
    file_header = struct.unpack_from("<I", truncated, 0x3C)[0] + 4
    struct.pack_into("<H", truncated, file_header + 16, 0xFFF0)
    with pytest.raises(PeRebuildError, match="optional header is truncated"):
        parse_runtime_headers(bytes(truncated))

    bad_magic = _make_dump()
    optional = _optional_offset(bad_magic)
    struct.pack_into("<H", bad_magic, optional, 0x999)
    with pytest.raises(PeRebuildError, match="unsupported optional magic"):
        parse_runtime_headers(bytes(bad_magic))


def test_parse_rejects_a_truncated_section_table() -> None:
    dump = _make_dump()
    # Passes the optional-header bound but the single section entry runs past
    # the shortened image.
    with pytest.raises(PeRebuildError, match="section table is truncated"):
        parse_runtime_headers(bytes(dump[:0x190]))


# ---------------------------------------------------------------------------
# remap_dump_to_file
# ---------------------------------------------------------------------------


def test_remap_enforces_its_own_section_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    # parse_runtime_headers already caps NumberOfSections, so drive remap's own
    # loader-ceiling guard directly with a parser that hands back too many.
    fake_headers = {
        "pe_offset": 0x80,
        "file_alignment": 0x200,
        "section_alignment": 0x1000,
        "architecture": "x64",
        "sections": [
            {"name": f"s{i}", "virtual_address": 0x1000, "virtual_size": 0x10, "raw_size": 0}
            for i in range(mod.MAX_SECTION_COUNT + 1)
        ],
    }
    monkeypatch.setattr(mod, "parse_runtime_headers", lambda image: fake_headers)
    with pytest.raises(PeRebuildError, match="the loader accepts"):
        remap_dump_to_file(bytes(_make_dump()))


def test_remap_rejects_a_dump_with_no_sections() -> None:
    dump = _make_dump()
    file_header = struct.unpack_from("<I", dump, 0x3C)[0] + 4
    struct.pack_into("<H", dump, file_header + 2, 0)
    with pytest.raises(PeRebuildError, match="no sections to remap"):
        remap_dump_to_file(bytes(dump))


def test_remap_truncates_a_section_larger_than_the_dump() -> None:
    dump = _make_dump()
    optional = _optional_offset(dump)
    section = optional + 0xF0
    struct.pack_into("<I", dump, section + 8, 0x7FFFFFFF)  # VirtualSize
    rebuilt, report = remap_dump_to_file(bytes(dump))
    assert len(rebuilt) < 4 * len(dump)
    assert any("larger than" in warning for warning in report.warnings)
    assert any("not trusted" in item for item in report.unfixed)


def test_remap_zero_fills_a_section_mapped_beyond_the_dump() -> None:
    dump = _make_dump(with_rdata=True)
    optional = _optional_offset(dump)
    section = optional + 0xF0
    # Second section's virtual address sits past the end of the dump, so its
    # runtime bytes are absent and it is filled with zeroes and reported.
    struct.pack_into("<IIII", dump, section + 48, 0x10, 0x40000, 0, 0)
    rebuilt, report = remap_dump_to_file(bytes(dump))
    assert any("beyond dump" in warning for warning in report.warnings)
    assert any("missing runtime bytes" in item for item in report.unfixed)
    assert len(rebuilt) > 0


def test_remap_rejects_a_negative_entry_point() -> None:
    with pytest.raises(PeRebuildError, match="entry_point_rva"):
        remap_dump_to_file(bytes(_make_dump()), entry_point_rva=-1)


def test_remap_clears_only_populated_volatile_directories() -> None:
    dump = _make_dump()
    optional = _optional_offset(dump)
    dir_count_off = optional + 108
    dir_off = optional + 112
    # Six directories: the base-reloc entry (index 5) carries data and is
    # cleared, while the bound-import entry (index 11) sits past the count and
    # is skipped entirely.
    struct.pack_into("<I", dump, dir_count_off, 6)
    struct.pack_into("<II", dump, dir_off + 5 * 8, 0x1000, 0x40)
    rebuilt, report = remap_dump_to_file(bytes(dump))
    assert any("cleared data directory[5]" in change for change in report.changes)
    headers = parse_runtime_headers(rebuilt)
    assert headers["directories"][5]["rva"] == 0


# ---------------------------------------------------------------------------
# rebuild_imports entry handling
# ---------------------------------------------------------------------------


def test_rebuild_imports_reports_every_unresolved_entry_shape() -> None:
    remapped, _ = remap_dump_to_file(bytes(_make_dump()), entry_point_rva=0x1000)
    entries: list[Any] = [
        "not-a-dict",
        {"kind": "null", "thunk_va": 0x10},
        {"kind": "stub", "thunk_va": 0x18},
        {"kind": "api", "name": "NoModule"},
        {"kind": "api", "module": "user32.dll", "name": "ordinal_5"},
        {"kind": "api", "module": "user32.dll", "name": "ordinal_bad"},
        _named("kernel32.dll", "VirtualAlloc"),
        _named("kernel32.dll", "VirtualAlloc"),
    ]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert any("stub" in item for item in report.unfixed)
    assert any("missing module name" in item for item in report.unfixed)
    assert any("modules=2" in change for change in report.changes)
    headers = parse_runtime_headers(rebuilt)
    assert any(section["name"].startswith(".himps") for section in headers["sections"])


def test_rebuild_imports_needs_at_least_one_resolved_api() -> None:
    remapped, _ = remap_dump_to_file(bytes(_make_dump()), entry_point_rva=0x1000)
    junk_entries: list[Any] = [{"kind": "stub"}, "junk"]
    with pytest.raises(PeRebuildError, match="no resolved API entries"):
        rebuild_imports(remapped, junk_entries)


def test_rebuild_imports_pads_when_the_image_is_not_aligned() -> None:
    remapped, _ = remap_dump_to_file(bytes(_make_dump()), entry_point_rva=0x1000)
    # A trailing byte makes len(out) fall off the file alignment, taking the
    # padding arm that grows the image up to the new section's raw offset.
    rebuilt, _report = rebuild_imports(remapped + b"\x7f", [_named("kernel32.dll", "Sleep")])
    headers = parse_runtime_headers(rebuilt)
    assert any(section["name"].startswith(".himps") for section in headers["sections"])


def test_rebuild_imports_rejects_headers_with_no_room_for_a_section() -> None:
    remapped = bytearray(remap_dump_to_file(bytes(_make_dump()), entry_point_rva=0x1000)[0])
    pe_offset = struct.unpack_from("<I", remapped, 0x3C)[0]
    optional_size = struct.unpack_from("<H", remapped, pe_offset + 20)[0]
    sections_offset = pe_offset + 24 + optional_size
    struct.pack_into("<I", remapped, pe_offset + 24 + 60, sections_offset)  # SizeOfHeaders
    with pytest.raises(PeRebuildError, match="no room for an additional section"):
        rebuild_imports(bytes(remapped), [_named("kernel32.dll", "Sleep")])


def test_rebuild_imports_rejects_too_few_data_directories() -> None:
    remapped = bytearray(remap_dump_to_file(bytes(_make_dump()), entry_point_rva=0x1000)[0])
    pe_offset = struct.unpack_from("<I", remapped, 0x3C)[0]
    struct.pack_into("<I", remapped, pe_offset + 24 + 108, 5)  # NumberOfRvaAndSizes
    with pytest.raises(PeRebuildError, match="at least 13"):
        rebuild_imports(bytes(remapped), [_named("kernel32.dll", "Sleep")])


def test_rebuild_imports_writes_32bit_thunks_in_section_and_in_place() -> None:
    # Section-resident IAT (no iat_rva) on a 32-bit image.
    remapped, _ = remap_dump_to_file(bytes(_make_dump(pe32_plus=False)), entry_point_rva=0x1000)
    section_rebuilt, report = rebuild_imports(remapped, [_named("kernel32.dll", "GetProcAddress")])
    assert parse_runtime_headers(section_rebuilt)["architecture"] == "x86"
    assert any("original IAT bytes" in item for item in report.unfixed)

    # In-place IAT patch on a 32-bit image with a real .rdata to write into.
    rdata = _make_dump(pe32_plus=False, with_rdata=True)
    remapped_rdata, _ = remap_dump_to_file(bytes(rdata), entry_point_rva=0x1000)
    in_place, in_place_report = rebuild_imports(
        remapped_rdata,
        [_named("kernel32.dll", "VirtualAlloc"), _named("kernel32.dll", "VirtualProtect")],
        iat_rva=0x2000,
    )
    assert any("in-place" in change for change in in_place_report.changes)
    assert parse_runtime_headers(in_place)["architecture"] == "x86"


# ---------------------------------------------------------------------------
# write_rebuilt_pe cleanup arms
# ---------------------------------------------------------------------------


def test_write_rebuilt_pe_sweeps_stale_partial_files(tmp_path: Path) -> None:
    target = tmp_path / "out.exe"
    stale = tmp_path / "out.exe.partial"
    stale.write_bytes(b"leftover")
    sha = write_rebuilt_pe(target, b"MZ" + b"\0" * 64)
    assert len(sha) == 64
    assert target.read_bytes().startswith(b"MZ")
    assert not stale.exists()


def test_write_rebuilt_pe_finally_unlinks_a_surviving_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out.exe"

    def copy_instead_of_move(self: Path, dst: Path) -> Path:
        # Leave the .partial in place so both files exist entering ``finally``.
        Path(dst).write_bytes(self.read_bytes())
        return Path(dst)

    monkeypatch.setattr(Path, "replace", copy_instead_of_move)
    sha = write_rebuilt_pe(target, b"MZ" + b"\0" * 64)
    assert len(sha) == 64
    assert target.exists()
    assert list(tmp_path.glob("*.partial")) == []
