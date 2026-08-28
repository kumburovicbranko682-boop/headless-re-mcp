"""ECMA-335 II.22 row-size regressions for four columns that used the wrong index.

Each case picks row counts that push exactly one coded index across the 2-vs-4
byte boundary while the sibling simple index stays at 2 bytes, so the corrected
column width differs from what the previous (wrong) formula produced. That gap
is the whole point: table row sizes feed ``_table_start``/row striding, so a
column that is two bytes too wide or too narrow silently misaligns every table
parsed afterwards on real-world assemblies (small fixtures keep every index at
2 bytes and never expose it).
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import _MetaCtx, _table_row_size

# Table ids (ECMA-335 II.22).
_TYPEDEF = 0x02
_TYPEREF = 0x01
_METHODDEF = 0x06
_MEMBERREF = 0x0A
_ASSEMBLYREF = 0x23
_INTERFACEIMPL = 0x09
_METHODSEMANTICS = 0x18
_NESTEDCLASS = 0x29


def _ctx(row_counts: dict[int, int]) -> _MetaCtx:
    # Only row_counts and the three heap index sizes affect _table_row_size;
    # everything else is placeholder. Small heaps (2 bytes) isolate the
    # divergence to the coded indexes under test.
    return _MetaCtx(
        path=Path("stub.dll"),
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
        row_counts=row_counts,
        table_data_offset=0,
    )


def test_interface_impl_interface_is_a_typedeforref_coded_index() -> None:
    # TypeRef at the 2-tag-bit threshold makes TypeDefOrRef 4 bytes while the
    # (wrongly used) MethodDef simple index stays 2. Correct row = 2 + 4 = 6;
    # the old MethodDef-index formula gave 2 + 2 = 4.
    meta = _ctx({_TYPEDEF: 10, _TYPEREF: 1 << 14, _METHODDEF: 10})
    assert _table_row_size(meta, _INTERFACEIMPL) == 6


def test_method_semantics_method_is_a_plain_methoddef_index() -> None:
    # MemberRef at the 1-tag-bit threshold widens MethodDefOrRef to 4 bytes,
    # but the Method column is a plain MethodDef index that must stay 2.
    # Correct row = 2 + 2 + 2 = 6; the old coded-index formula gave 2 + 4 + 2 = 8.
    meta = _ctx({_METHODDEF: 10, _MEMBERREF: 1 << 15})
    assert _table_row_size(meta, _METHODSEMANTICS) == 6


def test_assembly_ref_has_no_hashalgid_and_a_trailing_hashvalue_blob() -> None:
    # AssemblyRef is 4 fixed 2-byte version fields + Flags(4) + blob + str + str
    # + a trailing HashValue blob = 12 + 2*blob + 2*str. With 2-byte heaps that
    # is 20. Sizing it like Assembly (0x20) gave 16 + blob + 2*str = 22.
    meta = _ctx({})
    assert _table_row_size(meta, _ASSEMBLYREF) == 20


def test_nested_class_enclosing_is_a_typedef_index_not_implementation() -> None:
    # AssemblyRef at the 2-tag-bit threshold widens the Implementation coded
    # index to 4 bytes, but EnclosingClass is a plain TypeDef index (2 bytes).
    # Correct row = 2 + 2 = 4; the old Implementation formula gave 2 + 4 = 6.
    meta = _ctx({_TYPEDEF: 10, _ASSEMBLYREF: 1 << 14})
    assert _table_row_size(meta, _NESTEDCLASS) == 4


def test_all_four_columns_are_correct_under_one_hostile_row_count() -> None:
    # A single assembly can trip all four at once: wide TypeRef, MemberRef, and
    # AssemblyRef counts widen the coded indexes while TypeDef/MethodDef stay
    # narrow. Pins that each fix reads its own column, not a neighbour's.
    meta = _ctx(
        {
            _TYPEDEF: 10,
            _METHODDEF: 10,
            _TYPEREF: 1 << 14,
            _MEMBERREF: 1 << 15,
            _ASSEMBLYREF: 1 << 14,
        }
    )
    assert _table_row_size(meta, _INTERFACEIMPL) == 6
    assert _table_row_size(meta, _METHODSEMANTICS) == 6
    assert _table_row_size(meta, _ASSEMBLYREF) == 20
    assert _table_row_size(meta, _NESTEDCLASS) == 4
