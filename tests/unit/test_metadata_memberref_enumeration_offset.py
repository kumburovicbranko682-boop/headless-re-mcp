"""End-to-end proof that the row-width fix corrects real table enumeration.

``test_metadata_table_row_widths_ecma`` pins the arithmetic in ``_table_row_size``
and ``_table_start``. This file goes one step further and reads an actual row: a
mis-sized ``InterfaceImpl`` (0x09) row shifts the start of every later table, so
the name column of the next table -- ``MemberRef`` (0x0A) -- would be read from
the middle of the InterfaceImpl row and come back wrong. The buffer below is laid
out byte-for-byte so ``_iter_memberrefs`` yields the real symbol only when 0x09 is
sized as ``TypeDef index + TypeDefOrRef coded index`` (6 bytes); the old
``TypeDef + MethodDef`` shape (4 bytes) reads the name two bytes short and yields
``None``.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import _iter_memberrefs, _MetaCtx


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


def test_memberref_name_is_read_past_a_correctly_sized_interfaceimpl_row() -> None:
    # TypeSpec (0x1B) declares 2**14 rows so the TypeDefOrRef coded index widens to
    # 4 bytes: with the fix InterfaceImpl (0x09) is 2 + 4 = 6 bytes, so MemberRef
    # (0x0A) starts at byte 6. The same TypeSpec count widens MemberRefParent to 4
    # bytes, so a MemberRef row is Class(4) + Name(str,2) + Signature(blob,2) = 8.
    interface_impl_row = (1).to_bytes(2, "little") + (2).to_bytes(4, "little")  # 6 bytes
    # Class coded index = 0, Name = #Strings index 1, Signature blob index = 0.
    memberref_row = (
        (0).to_bytes(4, "little") + (1).to_bytes(2, "little") + (0).to_bytes(2, "little")
    )  # 8 bytes
    tables = interface_impl_row + memberref_row
    # #Strings: a leading NUL, then the symbol at index 1.
    strings = b"\x00CreateFileW\x00"

    meta = _ctx(tables, strings, {0x09: 1, 0x0A: 1, 0x1B: 1 << 14})
    rows = list(_iter_memberrefs(meta))

    assert len(rows) == 1
    # Read at the correct 6-byte offset the name resolves; the old 4-byte row would
    # have read bytes 8-9 (inside the MemberRef class column, value 0) and returned
    # None, so this assertion regresses loudly if 0x09 is ever mis-sized again.
    assert rows[0]["name"] == "CreateFileW"
    assert rows[0]["token"] == 0x0A000001
