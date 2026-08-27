"""CLR inspection paths: hint fallbacks, metadata-root and #~ table parsing.

Complements test_dotnet_inspect.py: this file drives the COR20-unreadable and
MetaData-unmappable hint paths, mixed-mode classification, and the byte-level
metadata parsers (stream walking, Module/Assembly name extraction, string-heap
edge cases) with handcrafted blobs -- no real .NET assembly is needed.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

import headless_re_mcp.dotnet.clr_inspect as clr_inspect
from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    DotnetKind,
    MetadataStats,
    _parse_metadata_root,
    _parse_tables_and_names,
    inspect_dotnet,
)


def _tables_stream(
    *,
    heap_sizes: int,
    module_idx: int,
    assembly_idx: int,
) -> bytes:
    """A #~ stream with one Module row and one Assembly row."""
    str_size = 4 if heap_sizes & 0x01 else 2
    guid_size = 4 if heap_sizes & 0x02 else 2
    blob_size = 4 if heap_sizes & 0x04 else 2
    header = bytearray(24)
    header[6] = heap_sizes
    struct.pack_into("<Q", header, 8, (1 << 0x00) | (1 << 0x20))
    counts = struct.pack("<II", 1, 1)
    module_row = (
        (0).to_bytes(2, "little")
        + module_idx.to_bytes(str_size, "little")
        + (0).to_bytes(guid_size, "little") * 3
    )
    assembly_row = (
        (0x8004).to_bytes(4, "little")
        + (1).to_bytes(2, "little") * 4
        + (0).to_bytes(4, "little")
        + (0).to_bytes(blob_size, "little")
        + assembly_idx.to_bytes(str_size, "little")
        + (0).to_bytes(str_size, "little")
    )
    return bytes(header) + counts + module_row + assembly_row


def _metadata_root(streams: dict[bytes, bytes]) -> bytes:
    """A BSJB metadata root whose stream headers point at appended payloads."""
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - len(version) % 4) % 4)
    headers_len = 0
    for name in streams:
        headers_len += 8 + ((len(name) + 1 + 3) & ~3)
    data_offset = 16 + len(version_padded) + 4 + headers_len
    blob = bytearray()
    blob += b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", len(version))
    blob += version_padded
    blob += struct.pack("<HH", 0, len(streams))
    payload = b""
    for name, data in streams.items():
        blob += struct.pack("<II", data_offset + len(payload), len(data))
        name_bytes = name + b"\0"
        blob += name_bytes + b"\0" * ((4 - len(name_bytes) % 4) % 4)
        payload += data
    return bytes(blob) + payload


def _write_clr_pe(
    path: Path,
    *,
    com_rva: int = 0x1100,
    meta_rva: int = 0x1200,
    meta_size: int = 0x40,
    flags: int = 0x1,
    meta_blob: bytes | None = None,
) -> None:
    image = bytearray(0x1000)
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
    struct.pack_into("<IIII", image, section + 8, 0x800, 0x1000, 0x800, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, meta_rva, meta_size)
    struct.pack_into("<I", image, cor_off + 16, flags)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)

    if meta_blob is not None:
        image[0x400 : 0x400 + len(meta_blob)] = meta_blob
    path.write_bytes(image)


def test_an_unreadable_cor20_header_is_a_hint_only(tmp_path: Path) -> None:
    path = tmp_path / "hint.exe"
    _write_clr_pe(path, com_rva=0x7000)

    report = inspect_dotnet(path)

    assert report.is_dotnet is True
    assert report.kind is DotnetKind.CLR_HINT
    assert report.verified_clr is False
    assert "COR20 header unreadable" in report.note

    with pytest.raises(DotnetInspectError) as caught:
        inspect_dotnet(path, require_verified=True)
    assert caught.value.code == "clr_unverified"
    assert caught.value.details["kind"] == "clr_directory_hint"


def test_a_metadata_rva_that_is_not_bsjb_stays_unverified(tmp_path: Path) -> None:
    path = tmp_path / "nobsjb.exe"
    _write_clr_pe(path, meta_rva=0x1300)

    report = inspect_dotnet(path)

    assert report.verified_clr is False
    assert report.kind is DotnetKind.CLR_HINT
    assert report.note == "COR20 MetaData RVA does not point at BSJB"


def test_an_unmappable_metadata_rva_stays_unverified(tmp_path: Path) -> None:
    path = tmp_path / "unmappable.exe"
    _write_clr_pe(path, meta_rva=0x7000)

    report = inspect_dotnet(path)

    assert report.verified_clr is False
    assert report.note == "COR20 MetaData RVA not mappable"


@pytest.mark.parametrize("flags", [0x10 | 0x1, 0x0])
def test_native_entrypoint_or_missing_ilonly_is_mixed_mode(
    tmp_path: Path, flags: int
) -> None:
    blob = _metadata_root({})
    path = tmp_path / "mixed.exe"
    _write_clr_pe(path, flags=flags, meta_size=len(blob), meta_blob=blob)

    report = inspect_dotnet(path)

    assert report.verified_clr is True
    assert report.kind is DotnetKind.MIXED_MODE


def test_a_full_metadata_root_yields_names_and_stats(tmp_path: Path) -> None:
    strings = b"\0App.exe\0App\0"
    tables = _tables_stream(heap_sizes=0, module_idx=1, assembly_idx=9)
    blob = _metadata_root({b"#~": tables, b"#Strings": strings, b"#US": b"\0\0"})
    path = tmp_path / "named.exe"
    _write_clr_pe(path, meta_size=len(blob), meta_blob=blob)

    report = inspect_dotnet(path)

    assert report.verified_clr is True
    assert report.module_name == "App.exe"
    assert report.assembly_name == "App"
    assert report.streams == ("#~", "#Strings", "#US")
    stats = report.to_dict()["metadata_stats"]
    assert stats["strings_heap_bytes"] == len(strings)
    assert stats["us_heap_bytes"] == 2
    assert stats["source"] == "metadata_tables"


def test_wide_heap_indexes_are_decoded_too() -> None:
    strings = b"\0Wide.exe\0Wide\0"
    tables = _tables_stream(heap_sizes=0x07, module_idx=1, assembly_idx=10)
    meta = _metadata_root({b"#~": tables, b"#Strings": strings})

    version, streams, module_name, assembly_name, stats = _parse_metadata_root(meta)

    assert version == "v4.0.30319"
    assert streams == ["#~", "#Strings"]
    assert module_name == "Wide.exe"
    assert assembly_name == "Wide"
    assert stats is not None
    assert stats.us_heap_bytes is None


def test_metadata_root_rejects_short_or_unsigned_blobs() -> None:
    assert _parse_metadata_root(b"BSJB") == (None, [], None, None, None)
    assert _parse_metadata_root(b"NOPE" + b"\0" * 32) == (None, [], None, None, None)


def test_metadata_root_rejects_a_version_longer_than_the_blob() -> None:
    blob = b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", 0xFFFF)

    assert _parse_metadata_root(blob) == (None, [], None, None, None)


def test_metadata_root_truncated_before_the_stream_count() -> None:
    version = b"v2\0\0"
    blob = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", len(version))
        + version
    )

    assert _parse_metadata_root(blob) == ("v2", [], None, None, None)


def test_metadata_root_stops_at_a_truncated_stream_header() -> None:
    version = b"v2\0\0"
    blob = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", len(version))
        + version
        + struct.pack("<HH", 0, 2)
        + b"\0\0\0\0"
    )

    version_out, streams, *_ = _parse_metadata_root(blob)

    assert version_out == "v2"
    assert streams == []


def test_metadata_root_stops_at_an_unterminated_stream_name() -> None:
    version = b"v2\0\0"
    blob = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", len(version))
        + version
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 0, 0)
        + b"#~"
    )

    version_out, streams, *_ = _parse_metadata_root(blob)

    assert version_out == "v2"
    assert streams == []


def test_metadata_root_swallows_a_table_parser_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exploding(meta: bytes, stream_map: dict) -> tuple:
        raise RuntimeError("hostile tables")

    monkeypatch.setattr(clr_inspect, "_parse_tables_and_names", exploding)
    meta = _metadata_root({b"#~": _tables_stream(heap_sizes=0, module_idx=1, assembly_idx=1)})

    version, streams, module_name, assembly_name, stats = _parse_metadata_root(meta)

    assert version == "v4.0.30319"
    assert streams == ["#~"]
    assert module_name is None
    assert assembly_name is None
    assert stats is None


def test_tables_shorter_than_the_header_yield_nothing() -> None:
    meta = b"\0" * 8

    assert _parse_tables_and_names(meta, {"#~": (0, 8)}) == (None, None, None)


def test_tables_truncated_inside_the_row_counts_yield_nothing() -> None:
    tables = bytearray(24)
    struct.pack_into("<Q", tables, 8, 1)

    assert _parse_tables_and_names(bytes(tables), {"#~": (0, 24)}) == (None, None, None)


def test_tables_without_a_strings_heap_still_report_stats() -> None:
    tables = _tables_stream(heap_sizes=0, module_idx=1, assembly_idx=1)

    module_name, assembly_name, stats = _parse_tables_and_names(
        tables, {"#~": (0, len(tables))}
    )

    assert module_name is None
    assert assembly_name is None
    assert stats is not None
    assert stats.strings_heap_bytes is None


def test_out_of_heap_string_indexes_yield_no_names() -> None:
    strings = b"\0App\0"
    tables = _tables_stream(heap_sizes=0, module_idx=0, assembly_idx=9999)
    meta = tables + strings

    module_name, assembly_name, stats = _parse_tables_and_names(
        meta, {"#~": (0, len(tables)), "#Strings": (len(tables), len(strings))}
    )

    assert module_name is None
    assert assembly_name is None
    assert stats is not None


def test_an_unterminated_heap_string_runs_to_the_end_of_the_heap() -> None:
    strings = b"\0App"
    tables = _tables_stream(heap_sizes=0, module_idx=1, assembly_idx=1)
    meta = tables + strings

    module_name, assembly_name, _stats = _parse_tables_and_names(
        meta, {"#~": (0, len(tables)), "#Strings": (len(tables), len(strings))}
    )

    assert module_name == "App"
    assert assembly_name == "App"


def test_name_walking_stops_at_the_first_unknown_table() -> None:
    """Row sizes of tables other than Module/Assembly are unknown; walking on
    with a wrong stride would read garbage string indexes, so the walk stops."""
    tables = bytearray(24 + 4)
    tables[6] = 0
    struct.pack_into("<Q", tables, 8, 1 << 0x02)
    struct.pack_into("<I", tables, 24, 5)
    strings = b"\0App\0"
    meta = bytes(tables) + strings

    module_name, assembly_name, stats = _parse_tables_and_names(
        meta, {"#~": (0, len(tables)), "#Strings": (len(tables), len(strings))}
    )

    assert module_name is None
    assert assembly_name is None
    assert stats is not None
    assert stats.type_count == 5


def test_metadata_stats_serialize_every_field() -> None:
    stats = MetadataStats(type_count=3, method_count=7)

    as_dict = stats.to_dict()

    assert as_dict["type_count"] == 3
    assert as_dict["method_count"] == 7
    assert as_dict["field_count"] is None
    assert as_dict["source"] == "metadata_tables"
