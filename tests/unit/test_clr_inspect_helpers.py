"""Cover the CLR metadata helpers directly with synthetic buffers: kind
classification, metadata-root parsing guards, and #~/#Strings table walking."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import headless_re_mcp.dotnet.clr_inspect as clr
from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    DotnetKind,
    MetadataStats,
    _classify_kind,
    _decode_flags,
    _parse_metadata_root,
    _parse_tables_and_names,
    inspect_dotnet,
)

_FLAG_ILONLY = 0x00000001
_FLAG_NATIVE_ENTRYPOINT = 0x00000010


def test_metadata_stats_to_dict_names_every_count() -> None:
    stats = MetadataStats(
        type_count=3,
        method_count=9,
        field_count=4,
        resource_count=1,
        strings_heap_bytes=100,
        us_heap_bytes=8,
    )
    payload = stats.to_dict()
    assert payload["type_count"] == 3
    assert payload["method_count"] == 9
    assert payload["source"] == "metadata_tables"


def test_classify_kind_covers_hint_mixed_and_pure() -> None:
    assert _classify_kind(verified=False, flags=_FLAG_ILONLY) is DotnetKind.CLR_HINT
    assert (
        _classify_kind(verified=True, flags=_FLAG_NATIVE_ENTRYPOINT)
        is DotnetKind.MIXED_MODE
    )
    assert _classify_kind(verified=True, flags=0) is DotnetKind.MIXED_MODE
    assert _classify_kind(verified=True, flags=_FLAG_ILONLY) is DotnetKind.PURE_MANAGED


def test_decode_flags_lists_set_bits() -> None:
    decoded = _decode_flags(_FLAG_ILONLY | _FLAG_NATIVE_ENTRYPOINT)
    assert "ILONLY" in decoded
    assert "NATIVE_ENTRYPOINT" in decoded


# --- _parse_metadata_root guards ----------------------------------------------


def test_parse_metadata_root_rejects_short_or_unsigned() -> None:
    assert _parse_metadata_root(b"BSJB") == (None, [], None, None, None)
    assert _parse_metadata_root(b"XXXX" + bytes(20)) == (None, [], None, None, None)


def test_parse_metadata_root_rejects_an_overlong_version_length() -> None:
    meta = b"BSJB" + bytes(8) + struct.pack("<I", 1000)
    assert _parse_metadata_root(meta) == (None, [], None, None, None)


def test_parse_metadata_root_stops_before_the_stream_count() -> None:
    meta = b"BSJB" + bytes(8) + struct.pack("<I", 4) + b"v1\x00\x00"
    version, streams, module, asm, stats = _parse_metadata_root(meta)
    assert version == "v1"
    assert streams == []


def test_parse_metadata_root_stops_on_a_truncated_stream_header() -> None:
    meta = (
        b"BSJB" + bytes(8) + struct.pack("<I", 4) + b"v1\x00\x00"
        + struct.pack("<HH", 0, 1)
    )
    version, streams, *_rest = _parse_metadata_root(meta)
    assert version == "v1"
    assert streams == []


def test_parse_metadata_root_stops_on_an_unterminated_stream_name() -> None:
    meta = (
        b"BSJB" + bytes(8) + struct.pack("<I", 4) + b"v1\x00\x00"
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 0, 0)
        + b"NAMEWITHOUTNULL"
    )
    version, streams, *_rest = _parse_metadata_root(meta)
    assert version == "v1"
    assert streams == []


def test_parse_metadata_root_wraps_table_parse_failures(
    monkeypatch: Any,
) -> None:
    meta = (
        b"BSJB" + bytes(8) + struct.pack("<I", 4) + b"v1\x00\x00"
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 0, 0)
        + b"#~\x00\x00"
    )

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("table walk fell over")

    monkeypatch.setattr(clr, "_parse_tables_and_names", boom)
    version, streams, module, asm, stats = _parse_metadata_root(meta)
    assert version == "v1"
    assert streams == ["#~"]
    assert module is None and asm is None and stats is None


# --- _parse_tables_and_names --------------------------------------------------


def _build_tables_two_byte_indexes() -> tuple[bytes, dict[str, tuple[int, int]]]:
    strings = b"\x00ModuleName\x00AsmName\x00"  # len 20
    tables = bytearray(64)
    tables[4] = 2  # major version
    tables[6] = 0  # heap_sizes: all 2-byte indexes
    struct.pack_into("<Q", tables, 8, (1 << 0) | (1 << 32))  # Module + Assembly
    struct.pack_into("<I", tables, 24, 1)  # Module row count
    struct.pack_into("<I", tables, 28, 1)  # Assembly row count
    struct.pack_into("<H", tables, 34, 1)  # Module.Name -> "ModuleName"
    struct.pack_into("<H", tables, 60, 12)  # Assembly.Name -> "AsmName"
    meta = strings + bytes(tables)
    stream_map = {"#Strings": (0, len(strings)), "#~": (len(strings), 64), "#US": (0, 8)}
    return meta, stream_map


def test_parse_tables_reads_module_and_assembly_names() -> None:
    meta, stream_map = _build_tables_two_byte_indexes()
    module, asm, stats = _parse_tables_and_names(meta, stream_map)
    assert module == "ModuleName"
    assert asm == "AsmName"
    assert stats is not None
    assert stats.strings_heap_bytes == 20
    assert stats.us_heap_bytes == 8


def test_parse_tables_returns_nothing_without_a_tables_stream() -> None:
    assert _parse_tables_and_names(b"", {"#Strings": (0, 0)}) == (None, None, None)


def test_parse_tables_rejects_a_short_tables_header() -> None:
    meta = b"\x00" * 10
    stream_map = {"#~": (0, 10)}
    assert _parse_tables_and_names(meta, stream_map) == (None, None, None)


def test_parse_tables_stops_when_row_counts_are_truncated() -> None:
    tables = bytearray(24)
    struct.pack_into("<Q", tables, 8, 1 << 0)  # a table is present, but no room
    stream_map = {"#~": (0, 24)}
    assert _parse_tables_and_names(bytes(tables), stream_map) == (None, None, None)


def test_parse_tables_returns_stats_only_without_a_strings_heap() -> None:
    tables = bytearray(32)
    tables[6] = 0
    struct.pack_into("<Q", tables, 8, 1 << 0)  # Module present
    struct.pack_into("<I", tables, 24, 1)  # one Module row
    stream_map = {"#~": (0, 32)}
    module, asm, stats = _parse_tables_and_names(bytes(tables), stream_map)
    assert module is None
    assert asm is None
    assert stats is not None


def test_parse_tables_reads_four_byte_string_indexes() -> None:
    strings = b"\x00WideName\x00"  # "WideName" at index 1
    tables = bytearray(40)
    tables[6] = 0x01  # heap_sizes: 4-byte string index
    struct.pack_into("<Q", tables, 8, 1 << 0)  # Module only
    struct.pack_into("<I", tables, 24, 1)
    # One row count read leaves the cursor at 28; Module.Name sits at cursor+2.
    struct.pack_into("<I", tables, 30, 1)  # 4-byte Module.Name index
    meta = strings + bytes(tables)
    stream_map = {"#Strings": (0, len(strings)), "#~": (len(strings), 40)}
    module, _asm, _stats = _parse_tables_and_names(meta, stream_map)
    assert module == "WideName"


def test_parse_tables_stops_at_an_unhandled_table() -> None:
    strings = b"\x00ModuleName\x00"
    tables = bytearray(48)
    tables[6] = 0
    struct.pack_into("<Q", tables, 8, (1 << 0) | (1 << 2))  # Module + TypeDef
    struct.pack_into("<I", tables, 24, 1)  # Module row count
    struct.pack_into("<I", tables, 28, 1)  # TypeDef row count
    struct.pack_into("<H", tables, 34, 1)  # Module.Name -> "ModuleName"
    meta = strings + bytes(tables)
    stream_map = {"#Strings": (0, len(strings)), "#~": (len(strings), 48)}
    module, asm, stats = _parse_tables_and_names(meta, stream_map)
    assert module == "ModuleName"
    assert asm is None
    assert stats is not None
    assert stats.type_count == 1


def test_string_at_handles_zero_and_unterminated_indexes() -> None:
    # A Module.Name index of 0 resolves to None (the reserved empty string).
    strings = b"\x00Only"  # no trailing null after "Only"
    tables = bytearray(64)
    tables[6] = 0
    struct.pack_into("<Q", tables, 8, (1 << 0) | (1 << 32))
    struct.pack_into("<I", tables, 24, 1)
    struct.pack_into("<I", tables, 28, 1)
    struct.pack_into("<H", tables, 34, 0)  # Module.Name index 0 -> None
    struct.pack_into("<H", tables, 60, 1)  # Assembly.Name index 1 -> "Only" (no null)
    meta = strings + bytes(tables)
    stream_map = {"#Strings": (0, len(strings)), "#~": (len(strings), 64)}
    module, asm, _stats = _parse_tables_and_names(meta, stream_map)
    assert module is None
    assert asm == "Only"


# --- inspect_dotnet CLR-hint / metadata branches ------------------------------


def _clr_image(
    *, com_rva: int = 0x1100, meta_rva: int = 0x1200, meta_sig: bytes = b"BSJB"
) -> bytearray:
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, com_rva, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, meta_rva, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    image[meta_off : meta_off + 4] = meta_sig
    version = b"v4.0.30319\0"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off + 16 : meta_off + 16 + len(padded)] = padded
    cursor = meta_off + 16 + len(padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    return image


def test_inspect_reports_a_hint_when_the_cor20_header_is_unreadable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "hint.exe"
    path.write_bytes(_clr_image(com_rva=0x7FFFFFFF))
    report = inspect_dotnet(path)
    assert report.is_dotnet is True
    assert report.kind is DotnetKind.CLR_HINT
    assert report.verified_clr is False
    try:
        inspect_dotnet(path, require_verified=True)
        raise AssertionError("expected DotnetInspectError")
    except DotnetInspectError as exc:
        assert exc.code == "clr_unverified"


def test_inspect_notes_metadata_that_is_not_bsjb(tmp_path: Path) -> None:
    path = tmp_path / "notbsjb.exe"
    path.write_bytes(_clr_image(meta_sig=b"XXXX"))
    report = inspect_dotnet(path)
    assert report.verified_clr is False
    assert "BSJB" in report.note


def test_inspect_notes_unmappable_metadata(tmp_path: Path) -> None:
    path = tmp_path / "unmappable.exe"
    path.write_bytes(_clr_image(meta_rva=0x7FFFFFFF))
    report = inspect_dotnet(path)
    assert report.verified_clr is False
    assert "not mappable" in report.note
