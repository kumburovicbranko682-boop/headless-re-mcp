"""End-to-end proof that the AssemblyRef row-shape fix corrects real enumeration.

Companion to ``test_metadata_memberref_enumeration_offset``. AssemblyRef (0x23)
was sized as a copy of the Assembly (0x20) row -- a leading HashAlgId(4) and no
trailing HashValue blob -- which is 22 bytes at 2-byte indexes, where the correct
II.22.5 shape is 20. That two-byte error shifts the start of every later table,
so the name column of ManifestResource (0x28) is read from the wrong offset. The
buffer below is laid out so ``_iter_resources`` resolves the real name only when
AssemblyRef is 20 bytes; the old 22-byte shape reads two bytes further on and
comes back ``None``. Unlike the coded-index cases, this difference shows up at
default (2-byte) index widths, so no giant synthetic table is needed.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import _iter_resources, _MetaCtx


def _ctx(tables: bytes, strings: bytes, row_counts: dict[int, int]) -> _MetaCtx:
    return _MetaCtx(
        path=Path("."),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=tables,
        strings=strings,
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts=dict(row_counts),
        table_data_offset=0,
    )


def test_manifestresource_name_is_read_past_a_correctly_sized_assemblyref_row() -> None:
    # One AssemblyRef row: correct II.22.5 shape is 20 bytes at 2-byte indexes.
    assembly_ref_row = b"\x00" * 20
    # ManifestResource row (starts at byte 20 when AssemblyRef is 20): Offset(4) +
    # Flags(4) + Name(str,2) + Implementation(coded,2). Name at byte 28 = #Strings
    # index 1. Trailing bytes 30-33 are zero, so the old 22-byte AssemblyRef would
    # place the row at byte 22 and read the name at byte 30 -> index 0 -> None.
    manifest_resource_region = (
        b"\x00" * 8 + (1).to_bytes(2, "little") + b"\x00" * 4
    )  # bytes 20..33
    tables = assembly_ref_row + manifest_resource_region
    strings = b"\x00netmodule\x00"

    meta = _ctx(tables, strings, {0x23: 1, 0x28: 1})
    rows = list(_iter_resources(meta))

    assert len(rows) == 1
    assert rows[0]["name"] == "netmodule"
    assert rows[0]["token"] == 0x28000001
