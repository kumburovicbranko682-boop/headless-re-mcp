"""Guard and edge-branch coverage for the .NET metadata parsers.

``test_dotnet_metadata_enum`` / ``test_dotnet_inspect`` cover the happy paths;
these drive the fail-closed and edge branches of ``metadata_enum`` (unterminated
strings heap, wide heap indexes, truncated stream/table headers, method bodies
past EOF) and ``clr_inspect`` (metadata-root parse failures, truncated table
headers, wide string indexes, invalid/unterminated names) with hand-built
metadata contexts and crafted CLR images.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.detection import pe as pe_mod
from headless_re_mcp.dotnet import clr_inspect
from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    _parse_metadata_root,
    _parse_tables_and_names,
)
from headless_re_mcp.dotnet.metadata_enum import (
    _iter_strings_heap,
    _load_metadata_context,
    _MetaCtx,
    _read_index,
    _read_method_body,
    _rows_the_stream_can_hold,
    _string_at,
)


def _ctx(**over: Any) -> _MetaCtx:
    base: dict[str, Any] = dict(
        path=Path("x"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=b"",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={},
        table_data_offset=0,
    )
    base.update(over)
    return _MetaCtx(**base)


# --------------------------------------------------------------------------- #
# metadata_enum small helpers (direct)
# --------------------------------------------------------------------------- #
def test_string_at_reads_to_the_heap_end_when_unterminated() -> None:
    assert _string_at(_ctx(strings=b"\x00hello"), 1) == "hello"


def test_read_index_reads_a_four_byte_index() -> None:
    assert _read_index(b"\x2a\x00\x00\x00", 0, 4) == (42, 4)


def test_rows_the_stream_can_hold_is_zero_for_bad_inputs() -> None:
    ctx = _ctx(tables=b"abcd")
    assert _rows_the_stream_can_hold(ctx, 0, 0) == 0  # row_size <= 0
    assert _rows_the_stream_can_hold(ctx, 4, 2) == 0  # offset at/after the stream end


def test_iter_strings_heap_reads_an_unterminated_tail() -> None:
    rows = list(_iter_strings_heap(_ctx(strings=b"\x00abc")))
    assert rows == [{"index": 1, "value": "abc"}]


def test_iter_strings_heap_skips_empty_entries() -> None:
    rows = list(_iter_strings_heap(_ctx(strings=b"\x00\x00abc\x00")))
    assert rows == [{"index": 2, "value": "abc"}]


def test_iter_strings_heap_is_bounded_at_ten_thousand() -> None:
    rows = list(_iter_strings_heap(_ctx(strings=b"\x00" + b"a\x00" * 10_001)))
    assert len(rows) == 10_000


def test_read_method_body_rejects_an_offset_past_the_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pe_mod, "_rva_to_offset", lambda *a, **k: 5)
    with pytest.raises(DotnetInspectError, match="out of file"):
        _read_method_body(_ctx(pe_data=b"abc"), 0x2000, max_bytes=16)


# --------------------------------------------------------------------------- #
# metadata_enum _load_metadata_context (crafted CLR images)
# --------------------------------------------------------------------------- #
def _clr_pe(path: Path, meta_blob: bytes, *, meta_size: int | None = None) -> None:
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
    struct.pack_into("<II", image, optional + 112 + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, meta_size or len(meta_blob))
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    image[meta_off : meta_off + len(meta_blob)] = meta_blob
    path.write_bytes(bytes(image))


def _meta_root(stream_count: int, size: int) -> bytearray:
    blob = bytearray(size)
    blob[0:4] = b"BSJB"
    struct.pack_into("<HH", blob, 4, 1, 1)
    struct.pack_into("<I", blob, 12, 2)  # version length
    blob[16:20] = b"v\0\0\0"
    struct.pack_into("<HH", blob, 20, 0, stream_count)  # reserved, stream count
    return blob


def test_load_metadata_stops_when_a_stream_header_does_not_fit(tmp_path: Path) -> None:
    blob = _meta_root(2, 40)
    struct.pack_into("<II", blob, 24, 0, 0)  # first stream header
    blob[32:35] = b"#X\0"  # first stream name; second header would start at 44 > 40
    path = tmp_path / "short-streams.dll"
    _clr_pe(path, bytes(blob), meta_size=40)
    ctx = _load_metadata_context(path)
    assert list(ctx.stream_map) == ["#X"]


def test_load_metadata_stops_on_an_unterminated_stream_name(tmp_path: Path) -> None:
    blob = _meta_root(1, 40)
    struct.pack_into("<II", blob, 24, 0, 0)
    blob[32:40] = b"\xaa" * 8  # name with no NUL before the metadata ends
    path = tmp_path / "bad-stream-name.dll"
    _clr_pe(path, bytes(blob), meta_size=40)
    ctx = _load_metadata_context(path)
    assert ctx.stream_map == {}


def test_load_metadata_stops_when_row_counts_run_past_the_stream(tmp_path: Path) -> None:
    blob = _meta_root(1, 62)
    struct.pack_into("<II", blob, 24, 36, 26)  # #~ stream at offset 36, size 26
    blob[32:35] = b"#~\0"
    struct.pack_into("<I", blob, 36 + 8, 1)  # tables Valid bitmask: bit 0 set
    path = tmp_path / "short-tables.dll"
    _clr_pe(path, bytes(blob), meta_size=62)
    ctx = _load_metadata_context(path)
    assert ctx.row_counts == {}


# --------------------------------------------------------------------------- #
# clr_inspect metadata parsing
# --------------------------------------------------------------------------- #
def test_parse_metadata_root_swallows_a_table_parse_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise ValueError("table parse failed")

    monkeypatch.setattr(clr_inspect, "_parse_tables_and_names", boom)
    blob = bytes(_meta_root(0, 24))
    version, streams, module_name, assembly_name, stats = _parse_metadata_root(blob)
    assert version == "v"
    assert streams == []
    assert module_name is None
    assert assembly_name is None
    assert stats is None


def test_parse_tables_stops_when_row_counts_run_past_the_stream() -> None:
    tables = bytearray(26)
    struct.pack_into("<I", tables, 8, 1)  # Valid: bit 0 set, but only 26 bytes
    assert _parse_tables_and_names(bytes(tables), {"#~": (0, 26)}) == (None, None, None)


def _tables_and_strings(tables: bytes, strings: bytes) -> tuple[bytes, dict[str, tuple[int, int]]]:
    meta = bytearray(64 + len(strings))
    meta[0 : len(tables)] = tables
    meta[64 : 64 + len(strings)] = strings
    stream_map = {"#~": (0, len(tables)), "#Strings": (64, len(strings))}
    return bytes(meta), stream_map


def test_parse_tables_reads_a_wide_string_index_and_unterminated_name() -> None:
    tables = bytearray(40)
    tables[6] = 0x01  # HeapSizes: 4-byte string indexes
    struct.pack_into("<I", tables, 8, 1)  # Valid: Module (bit 0)
    struct.pack_into("<I", tables, 24, 1)  # Module row count
    struct.pack_into("<I", tables, 30, 1)  # Module.Name index -> strings[1]
    meta, stream_map = _tables_and_strings(bytes(tables), b"\x00abc")  # no trailing NUL
    module_name, _assembly, _stats = _parse_tables_and_names(meta, stream_map)
    assert module_name == "abc"


def test_parse_tables_returns_no_name_for_a_zero_string_index() -> None:
    tables = bytearray(40)
    struct.pack_into("<I", tables, 8, 1)  # Valid: Module (bit 0)
    struct.pack_into("<I", tables, 24, 1)  # Module row count
    struct.pack_into("<H", tables, 30, 0)  # Module.Name index 0 -> None
    meta, stream_map = _tables_and_strings(bytes(tables), b"\x00X\x00")
    module_name, _assembly, _stats = _parse_tables_and_names(meta, stream_map)
    assert module_name is None
