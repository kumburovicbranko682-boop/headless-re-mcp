"""InterfaceImpl (0x09) and NestedClass (0x29) row sizes use the right index kinds.

Both tables have a second column whose index kind the sizing table originally
got wrong -- InterfaceImpl.Interface is a TypeDefOrRef coded index (not a
MethodDef simple index) and NestedClass.EnclosingClass is a TypeDef simple index
(not an Implementation coded index) per ECMA-335 II.22.23 / II.22.32. The two
kinds are indistinguishable while every index is 2 bytes, which is why a small
crafted fixture cannot catch the mistake; they diverge only once a table crosses
the coded-index widening threshold (2^14 rows for a 2-bit tag) while the simple
index it was confused with stays 2 bytes (< 2^16 rows). ``table_row_size`` takes
raw row counts, so these pin the divergent-width case directly without building a
whole PE. InterfaceImpl in particular sits before the Assembly table, so an
undercount there desyncs the walk that reads assembly_name on large assemblies.
"""

from __future__ import annotations

from headless_re_mcp.dotnet.metadata_enum import table_row_size

# A 2-bit coded index widens to 4 bytes at 2^14 rows; a simple index stays
# 2 bytes until 2^16. Pick a count between the two so exactly one widens.
_WIDE = 20000  # >= 2**14 (16384), < 2**16 (65536)


def _size(table: int, row_counts: dict[int, int]) -> int:
    return table_row_size(
        row_counts,
        table,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
    )


def test_interfaceimpl_interface_is_a_typedeforref_coded_index() -> None:
    # TypeDef at _WIDE widens TypeDefOrRef to 4 bytes but keeps the MethodDef
    # simple index at 2. Class (TypeDef simple) is 2, Interface (coded) is 4.
    size = _size(0x09, {0x02: _WIDE, 0x06: 100})
    assert size == 2 + 4  # not 2 + 2, which the MethodDef-index bug produced


def test_nestedclass_enclosing_is_a_typedef_index_not_implementation() -> None:
    # AssemblyRef at _WIDE widens the Implementation coded index to 4 bytes,
    # while TypeDef stays a 2-byte simple index. Both columns are TypeDef.
    size = _size(0x29, {0x23: _WIDE, 0x02: 100})
    assert size == 2 + 2  # not 2 + 4, which the Implementation-index bug produced


def test_both_columns_stay_two_bytes_on_a_small_assembly() -> None:
    # The common case every existing fixture exercises: nothing has widened, so
    # both corrected rows are 4 bytes total -- the fix changes only large inputs.
    assert _size(0x09, {0x02: 10, 0x06: 10}) == 4
    assert _size(0x29, {0x23: 10, 0x02: 10}) == 4
