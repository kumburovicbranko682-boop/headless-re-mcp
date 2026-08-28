"""ECMA-335 II.22 row-size fidelity for the .NET metadata table walker.

``_table_row_size`` feeds ``_table_start``, which sums the byte width of every
table ahead of the one being read. A single wrong width silently shifts the
read cursor for all later tables (MemberRef 0x0A, ManifestResource 0x28, ...),
so a row size that merely *coincides* with the truth on a small assembly (where
every index is 2 bytes) still corrupts enumeration on a large one.

Each case forces the one coded/simple index the bug got wrong to a width that
differs from what the buggy formula would have produced, so the assertion fails
against the pre-fix code and passes only against the ECMA-335 layout. Row counts
are chosen against the documented index-size thresholds: a simple index is
4 bytes at >= 65536 rows; a coded index with ``t`` tag bits is 4 bytes once the
largest of its tables reaches ``1 << (16 - t)`` rows (TypeDefOrRef t=2 -> 16384;
MethodDefOrRef / HasSemantics t=1 -> 32768).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.dotnet.metadata_enum import _MetaCtx, _table_row_size


def _ctx(row_counts: dict[int, int], *, s: int = 2, b: int = 2, g: int = 2) -> _MetaCtx:
    """A metadata context carrying only what ``_table_row_size`` reads."""
    return _MetaCtx(
        path=Path("dummy"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=b"",
        heap_sizes=0,
        string_index_size=s,
        blob_index_size=b,
        guid_index_size=g,
        row_counts=dict(row_counts),
        table_data_offset=0,
    )


def test_interface_impl_interface_is_a_typedeforref_coded_index() -> None:
    # InterfaceImpl (0x09) II.22.23: Class(TypeDef idx) + Interface(TypeDefOrRef).
    # 16384 TypeRefs push TypeDefOrRef to 4 bytes while MethodDef stays small, so
    # the buggy "+ simple(MethodDef)" gives 2+2=4 where the truth is 2+4=6.
    assert _table_row_size(_ctx({0x01: 16384}), 0x09) == 6


def test_method_semantics_method_is_a_plain_methoddef_index() -> None:
    # MethodSemantics (0x18) II.22.28: Semantics(2) + Method(MethodDef idx) +
    # Association(HasSemantics). 32768 MemberRefs push the *MethodDefOrRef* coded
    # index to 4 bytes, but Method is a plain MethodDef index (small -> 2 bytes),
    # so the buggy coded form gives 2+4+2=8 where the truth is 2+2+2=6.
    assert _table_row_size(_ctx({0x0A: 32768}), 0x18) == 6


def test_assembly_ref_has_no_hashalgid_and_a_trailing_hashvalue_blob() -> None:
    # AssemblyRef (0x23) II.22.5 differs from Assembly (0x20): no leading
    # HashAlgId(4), plus a trailing HashValue(blob). With 2-byte heaps the truth
    # is 2+2+2+2+4 + blob + str + str + blob = 20; the Assembly-shaped copy was 22.
    assert _table_row_size(_ctx({}), 0x23) == 20


def test_file_hashvalue_is_a_blob_not_a_coded_index() -> None:
    # File (0x26) II.22.19: Flags(4) + Name(str) + HashValue(blob). 16384
    # AssemblyRefs push the Implementation coded index to 4 bytes while the blob
    # heap stays 2, so the buggy "+ implementation" gives 4+2+4=10 vs truth 4+2+2=8.
    assert _table_row_size(_ctx({0x23: 16384}), 0x26) == 8


def test_nested_class_enclosing_is_a_plain_typedef_index() -> None:
    # NestedClass (0x29) II.22.32: NestedClass(TypeDef idx) + EnclosingClass
    # (TypeDef idx). 16384 AssemblyRefs push Implementation to 4 bytes, so the
    # buggy "+ implementation" gives 2+4=6 where both columns are TypeDef -> 2+2=4.
    assert _table_row_size(_ctx({0x23: 16384}), 0x29) == 4


def test_method_spec_and_generic_param_constraint_are_not_swapped() -> None:
    # 0x2B is MethodSpec II.22.29: Method(MethodDefOrRef) + Instantiation(blob).
    # 32768 MemberRefs push MethodDefOrRef to 4 bytes -> 4 + blob(2) = 6. The
    # GenericParamConstraint shape that used to sit here would read 2 + 2 = 4.
    assert _table_row_size(_ctx({0x0A: 32768}), 0x2B) == 6

    # 0x2C is GenericParamConstraint II.22.21: Owner(GenericParam idx) +
    # Constraint(TypeDefOrRef). 16384 TypeRefs push TypeDefOrRef to 4 bytes ->
    # 2 + 4 = 6. The MethodSpec shape that used to sit here would read 2 + 2 = 4.
    assert _table_row_size(_ctx({0x01: 16384}), 0x2C) == 6


@pytest.mark.parametrize(
    ("table", "row_counts", "expected"),
    [
        (0x09, {0x01: 16384}, 6),
        (0x18, {0x0A: 32768}, 6),
        (0x23, {}, 20),
        (0x26, {0x23: 16384}, 8),
        (0x29, {0x23: 16384}, 4),
        (0x2B, {0x0A: 32768}, 6),
        (0x2C, {0x01: 16384}, 6),
    ],
)
def test_row_sizes_match_ecma(table: int, row_counts: dict[int, int], expected: int) -> None:
    assert _table_row_size(_ctx(row_counts), table) == expected
