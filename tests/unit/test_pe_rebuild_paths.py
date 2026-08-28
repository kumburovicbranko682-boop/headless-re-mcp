"""Coverage for pe_rebuild guard, parse-error, import-edge, and write arms.

The module is pure byte manipulation, so most arms are reached by handing the
helpers crafted PE images (built on the shared runtime-dump shape) or by calling
the small validators directly.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.unpack import pe_rebuild
from headless_re_mcp.unpack.pe_rebuild import (
    PeRebuildError,
    parse_runtime_headers,
    rebuild_imports,
    remap_dump_to_file,
    write_rebuilt_pe,
)


def _runtime_dump(*, pe32_plus: bool = True, with_rdata: bool = False) -> bytearray:
    """A minimal memory-style PE image; sections live at their VA offsets."""
    image = bytearray(0x3000)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    machine = 0x8664 if pe32_plus else 0x14C
    optional_size = 0xF0 if pe32_plus else 0xE0
    nsections = 2 if with_rdata else 1
    struct.pack_into(
        "<HHIIIHH", image, file_header, machine, nsections, 0, 0, 0, optional_size, 0x22
    )
    optional = file_header + 20
    magic = 0x20B if pe32_plus else 0x10B
    struct.pack_into("<HBB", image, optional, magic, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)  # AddressOfEntryPoint
    if pe32_plus:
        struct.pack_into("<Q", image, optional + 24, 0x140000000)
    else:
        struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)  # section/file align
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x400)  # SizeOfImage/Headers
    struct.pack_into("<HH", image, optional + 68, 3, 0)
    struct.pack_into("<I", image, optional + (108 if pe32_plus else 92), 16)  # dir count
    section = optional + optional_size
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0, 0)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x1000:0x1002] = b"\xC3\x90"
    if with_rdata:
        image[section + 40 : section + 48] = b".rdata\0\0"
        struct.pack_into("<IIII", image, section + 48, 0x200, 0x2000, 0, 0)
        struct.pack_into("<I", image, section + 76, 0x40000040)
        image[0x2000:0x2018] = b"\xAA" * 0x18
    return image


def _api(module: str, name: str, **extra: Any) -> dict[str, Any]:
    return {"kind": "api", "module": module, "name": name, **extra}


# ---------------------------------------------------------------------------
# small validators, called directly
# ---------------------------------------------------------------------------


def test_usable_alignment_rejects_bad_values() -> None:
    with pytest.raises(PeRebuildError, match="is not a number"):
        pe_rebuild._usable_alignment("nope", floor=0x200, ceiling=0x10000, what="FileAlignment")
    with pytest.raises(PeRebuildError, match="is not a number"):
        pe_rebuild._usable_alignment(True, floor=0x200, ceiling=0x10000, what="FileAlignment")
    with pytest.raises(PeRebuildError, match="exceeds"):
        pe_rebuild._usable_alignment(
            0x20000000, floor=0x200, ceiling=0x10000, what="FileAlignment"
        )
    with pytest.raises(PeRebuildError, match="power of two"):
        pe_rebuild._usable_alignment(0x300, floor=0x200, ceiling=0x10000, what="FileAlignment")
    assert pe_rebuild._usable_alignment(0, floor=0x200, ceiling=0x10000, what="x") == 0x200


def test_align_rejects_a_non_positive_alignment() -> None:
    with pytest.raises(PeRebuildError, match="alignment must be positive"):
        pe_rebuild._align(10, 0)


def test_rva_to_file_offset_arms() -> None:
    with pytest.raises(PeRebuildError, match="not a usable file offset"):
        pe_rebuild._rva_to_file_offset({"sections": []}, -1, length=4, image=b"")

    # A zero-raw-size section is skipped, so a matching RVA still refuses.
    zero_raw = {"sections": [{"virtual_address": 0, "raw_size": 0, "raw_offset": 0}]}
    with pytest.raises(PeRebuildError, match="not a writable file range"):
        pe_rebuild._rva_to_file_offset(zero_raw, 0x10, length=4, image=b"\0" * 0x40)

    # The range fits the section's VA window but points past the image bytes.
    past_end = {
        "sections": [{"virtual_address": 0x1000, "raw_size": 0x1000, "raw_offset": 0x9000}]
    }
    with pytest.raises(PeRebuildError, match="not a writable file range"):
        pe_rebuild._rva_to_file_offset(past_end, 0x1000, length=4, image=b"\0" * 0x100)


# ---------------------------------------------------------------------------
# parse_runtime_headers error arms
# ---------------------------------------------------------------------------


def test_parse_rejects_a_bad_dos_header() -> None:
    with pytest.raises(PeRebuildError, match="valid DOS header"):
        parse_runtime_headers(b"MZ")  # too short
    with pytest.raises(PeRebuildError, match="valid DOS header"):
        parse_runtime_headers(b"ZZ" + b"\0" * 0x80)  # wrong magic


def test_parse_rejects_a_pe_offset_outside_the_image() -> None:
    image = bytearray(0x100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x20)  # below the 0x40 floor
    with pytest.raises(PeRebuildError, match="PE header offset is outside"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_a_bad_pe_signature() -> None:
    image = bytearray(0x100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"XXXX"
    with pytest.raises(PeRebuildError, match="valid PE signature"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_a_truncated_optional_header() -> None:
    image = bytearray(0x100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84 + 16, 0x1000)  # SizeOfOptionalHeader
    with pytest.raises(PeRebuildError, match="optional header is truncated"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_an_unsupported_optional_magic() -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84 + 16, 0x60)  # SizeOfOptionalHeader
    struct.pack_into("<H", image, 0x98, 0x999)  # optional magic
    with pytest.raises(PeRebuildError, match="unsupported optional magic"):
        parse_runtime_headers(bytes(image))


def test_parse_rejects_a_truncated_section_table() -> None:
    image = bytearray(0x130)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84 + 2, 2)  # NumberOfSections
    struct.pack_into("<H", image, 0x84 + 16, 0x60)  # SizeOfOptionalHeader
    struct.pack_into("<H", image, 0x98, 0x10B)  # PE32 magic
    with pytest.raises(PeRebuildError, match="section table is truncated"):
        parse_runtime_headers(bytes(image))


# ---------------------------------------------------------------------------
# remap_dump_to_file arms
# ---------------------------------------------------------------------------


def test_remap_rejects_a_dump_with_no_sections() -> None:
    dump = _runtime_dump()
    struct.pack_into("<H", dump, 0x84 + 2, 0)  # NumberOfSections
    with pytest.raises(PeRebuildError, match="no sections to remap"):
        remap_dump_to_file(bytes(dump))


def test_remap_truncates_a_section_larger_than_the_dump() -> None:
    dump = _runtime_dump()
    section = 0x98 + 0xF0
    struct.pack_into("<I", dump, section + 8, 0x100000)  # VirtualSize past the dump
    _out, report = remap_dump_to_file(bytes(dump))
    assert any("larger than" in warning for warning in report.warnings)
    assert any("declared size not trusted" in item for item in report.unfixed)


def test_remap_zero_fills_a_section_beyond_the_dump() -> None:
    dump = _runtime_dump()
    section = 0x98 + 0xF0
    struct.pack_into("<I", dump, section + 12, 0x5000)  # VirtualAddress past the dump
    _out, report = remap_dump_to_file(bytes(dump))
    assert any("beyond dump" in warning for warning in report.warnings)
    assert any("missing runtime bytes" in item for item in report.unfixed)


def test_remap_rejects_a_negative_entry_point() -> None:
    dump = _runtime_dump()
    with pytest.raises(PeRebuildError, match="non-negative integer"):
        remap_dump_to_file(bytes(dump), entry_point_rva=-1)


def test_remap_clears_a_stale_volatile_directory() -> None:
    dump = _runtime_dump()
    optional = 0x98
    struct.pack_into("<I", dump, optional + 108, 5)  # NumberOfRvaAndSizes
    # Security directory (index 4) carries a stale certificate pointer.
    struct.pack_into("<II", dump, optional + 112 + 4 * 8, 0x100, 0x40)
    _out, report = remap_dump_to_file(bytes(dump))
    assert any("cleared data directory[4]" in change for change in report.changes)


# ---------------------------------------------------------------------------
# rebuild_imports entry-classification arms
# ---------------------------------------------------------------------------


def _remapped(**kwargs: bool) -> bytes:
    out, _report = remap_dump_to_file(bytes(_runtime_dump(**kwargs)), entry_point_rva=0x1000)
    return out


def test_rebuild_imports_classifies_unusable_entries() -> None:
    remapped = _remapped()
    entries: list[object] = [
        "not-a-dict",  # skipped
        {"kind": "reloc", "thunk_rva": 0x10},  # non-api -> unresolved
        _api("", "Foo"),  # missing module -> unresolved
        _api("user32.dll", "ordinal_7", ordinal=0),  # name-derived ordinal
        _api("user32.dll", "MessageBoxA"),
        _api("user32.dll", "MessageBoxA"),  # duplicate name -> deduped
        _api("user32.dll", "", ordinal=9),  # by-ordinal import
        {"kind": "null"},
    ]
    rebuilt, report = rebuild_imports(remapped, entries)  # type: ignore[arg-type]
    assert any("unresolved_thunks" in change for change in report.changes)
    headers = parse_runtime_headers(rebuilt)
    assert any(str(s["name"]).startswith(".himps") for s in headers["sections"])


def test_rebuild_imports_recovers_an_unparsable_ordinal_name() -> None:
    remapped = _remapped()
    entries = [_api("user32.dll", "ordinal_xx", ordinal=0), {"kind": "null"}]
    rebuilt, _report = rebuild_imports(remapped, entries)
    assert isinstance(rebuilt, bytes)


def test_rebuild_imports_refuses_when_no_api_entries_resolve() -> None:
    remapped = _remapped()
    with pytest.raises(PeRebuildError, match="no resolved API entries"):
        rebuild_imports(remapped, [{"kind": "reloc"}, {"kind": "null"}])


def test_rebuild_imports_handles_a_32bit_image() -> None:
    remapped = _remapped(pe32_plus=False)
    entries = [_api("user32.dll", "MessageBoxA"), _api("user32.dll", "", ordinal=3)]
    rebuilt, report = rebuild_imports(remapped, entries)
    assert any(".himps" in change for change in report.changes)
    assert any("original IAT bytes" in item for item in report.unfixed)


def test_rebuild_imports_patches_a_32bit_iat_in_place() -> None:
    remapped = _remapped(pe32_plus=False, with_rdata=True)
    entries = [_api("user32.dll", "MessageBoxA"), _api("user32.dll", "MessageBoxW")]
    rebuilt, report = rebuild_imports(remapped, entries, iat_rva=0x2000)
    assert any("in-place" in change for change in report.changes)
    headers = parse_runtime_headers(rebuilt)
    assert headers["directories"][12]["rva"] == 0x2000


def test_rebuild_imports_pads_an_unaligned_image() -> None:
    remapped = _remapped() + b"\x01"  # nudge the length off the file alignment
    rebuilt, _report = rebuild_imports(remapped, [_api("user32.dll", "MessageBoxA")])
    assert len(rebuilt) % 0x200 == 0


def test_rebuild_imports_refuses_when_headers_have_no_room() -> None:
    remapped = bytearray(_remapped())
    pe_offset = struct.unpack_from("<I", remapped, 0x3C)[0]
    struct.pack_into("<I", remapped, pe_offset + 24 + 60, 0x80)  # tiny SizeOfHeaders
    with pytest.raises(PeRebuildError, match="no room for an additional section"):
        rebuild_imports(bytes(remapped), [_api("user32.dll", "MessageBoxA")])


def test_rebuild_imports_requires_enough_data_directories() -> None:
    dump = _runtime_dump()
    struct.pack_into("<I", dump, 0x98 + 108, 10)  # NumberOfRvaAndSizes below 13
    remapped, _report = remap_dump_to_file(bytes(dump), entry_point_rva=0x1000)
    with pytest.raises(PeRebuildError, match="at least 13"):
        rebuild_imports(remapped, [_api("user32.dll", "MessageBoxA")])


# ---------------------------------------------------------------------------
# write_rebuilt_pe cleanup arms
# ---------------------------------------------------------------------------


def test_write_rebuilt_pe_sweeps_a_stale_partial(tmp_path: Path) -> None:
    target = tmp_path / "out.exe"
    stale = tmp_path / "out.exe.stale.partial"
    stale.write_bytes(b"leftover")
    sha = write_rebuilt_pe(target, b"MZ" + b"\0" * 62)
    assert len(sha) == 64
    assert not stale.exists()
    assert target.read_bytes().startswith(b"MZ")


def test_write_rebuilt_pe_cleans_a_lingering_partial_after_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out.exe"
    target.write_bytes(b"old")

    def noop_replace(self: Path, _dst: Path) -> Path:
        return self

    monkeypatch.setattr(Path, "replace", noop_replace)
    sha = write_rebuilt_pe(target, b"MZ" + b"\0" * 62)
    assert len(sha) == 64
    assert list(tmp_path.glob("*.partial")) == []
