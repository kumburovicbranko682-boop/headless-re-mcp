"""ECMA-335 II.22 metadata table row-size regression tests.

``metadata_enum`` materialises a table by first walking every lower-numbered
table and summing ``_table_row_size`` * rows to find where the wanted table
starts. A wrong size for *any* table below the one being read shifts that start
offset, so every subsequent row is decoded from the wrong bytes -- names,
tokens, RVAs and resource offsets all come back confidently wrong.

Several row sizes were miscomputed:

* AssemblyRef (0x23) was given the *Assembly* (0x20) layout -- a phantom leading
  HashAlgId and no trailing HashValue blob. With the common 2-byte blob heap
  that overstates the row by 2 bytes. AssemblyRef sits below ManifestResource
  (0x28) and is present in virtually every assembly, so the resource listing
  read past its real rows and dropped them. This is the one that bit real,
  ordinary inputs; the rest below are masked whenever the coded/simple index
  sizes happen to coincide at 2 bytes, which is why nothing caught them.
* InterfaceImpl (0x09) read its Interface column as a simple MethodDef index
  instead of a TypeDefOrRef coded index.
* MethodSemantics (0x18) read its Method column as a MethodDefOrRef coded index
  instead of a simple MethodDef index.
* File (0x26) read its HashValue column as an Implementation coded index
  instead of a Blob index.
* MethodSpec (0x2B) and GenericParamConstraint (0x2C) had their layouts
  swapped.

Each test picks row counts that force the buggy and correct formulas apart, so
it fails against the old code rather than merely restating it.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import (
    _iter_resources,
    _MetaCtx,
    _table_row_size,
    _table_start,
)


def _ctx(
    row_counts: dict[int, int],
    *,
    heap_sizes: int = 0,
    tables: bytes = b"",
    strings: bytes = b"",
    table_data_offset: int = 0,
) -> _MetaCtx:
    """Build a metadata context directly, bypassing PE loading.

    ``heap_sizes`` follows the ECMA header bit layout: bit0 -> 4-byte #Strings
    index, bit1 -> 4-byte #GUID index, bit2 -> 4-byte #Blob index. Zero means
    every heap index is 2 bytes, the common small-assembly case.
    """
    string_index_size = 4 if (heap_sizes & 0x01) else 2
    guid_index_size = 4 if (heap_sizes & 0x02) else 2
    blob_index_size = 4 if (heap_sizes & 0x04) else 2
    return _MetaCtx(
        path=Path("synthetic"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=tables,
        strings=strings,
        heap_sizes=heap_sizes,
        string_index_size=string_index_size,
        blob_index_size=blob_index_size,
        guid_index_size=guid_index_size,
        row_counts=row_counts,
        table_data_offset=table_data_offset,
    )


def test_assembly_ref_row_size_is_not_the_assembly_layout() -> None:
    # AssemblyRef = 4x uint16 version + Flags(4) + PublicKeyOrToken(blob) +
    # Name(str) + Culture(str) + HashValue(blob) = 8 + 4 + 2 + 2 + 2 + 2 = 20
    # with 2-byte heaps. The old code produced 22 (Assembly's layout).
    assert _table_row_size(_ctx({0x23: 3}), 0x23) == 20


def test_assembly_ref_offset_no_longer_drops_the_resource_table() -> None:
    # Two AssemblyRef rows (20 bytes each) precede one ManifestResource row.
    # ManifestResource = Offset(4) + Flags(4) + Name(2-byte string index).
    strings = b"\x00Res\x00"  # index 1 -> "Res"
    resource_row = (
        (0x11111111).to_bytes(4, "little")
        + (0x00000002).to_bytes(4, "little")
        + (1).to_bytes(2, "little")
    )
    tables = b"\xee" * 40 + resource_row + b"\x00" * 4
    ctx = _ctx(
        {0x23: 2, 0x28: 1},
        tables=tables,
        strings=strings,
    )
    # Old code summed 22*2 = 44 and read off the end, yielding no resources.
    assert _table_start(ctx, 0x28) == 40
    assert list(_iter_resources(ctx)) == [
        {
            "token": 0x28000001,
            "rid": 1,
            "name": "Res",
            "offset": 0x11111111,
            "flags": 0x00000002,
        }
    ]


def test_interface_impl_interface_column_is_a_coded_index() -> None:
    # TypeDef=20000 forces the TypeDefOrRef coded index to 4 bytes while the
    # MethodDef simple index the old code used stays 2. Class(TypeDef simple)=2
    # + Interface(TypeDefOrRef)=4 => 6; the bug gave 4.
    assert _table_row_size(_ctx({0x02: 20000, 0x06: 100}), 0x09) == 6


def test_method_semantics_method_column_is_a_simple_index() -> None:
    # MemberRef=40000 forces MethodDefOrRef (the coded index the old code used)
    # to 4 bytes while the MethodDef simple index stays 2. Semantics(2) +
    # Method(MethodDef simple)=2 + Association(HasSemantics)=2 => 6; bug gave 8.
    assert _table_row_size(_ctx({0x06: 100, 0x0A: 40000}), 0x18) == 6


def test_file_hash_value_column_is_a_blob_index() -> None:
    # AssemblyRef=20000 forces the Implementation coded index (the old code's
    # choice) to 4 bytes while the blob heap index stays 2. Flags(4) + Name(2)
    # + HashValue(blob)=2 => 8; the bug gave 10.
    assert _table_row_size(_ctx({0x23: 20000}), 0x26) == 8


def test_method_spec_and_generic_param_constraint_are_not_swapped() -> None:
    # MemberRef=40000 forces MethodDefOrRef to 4 bytes. MethodSpec (0x2B) =
    # Method(MethodDefOrRef)=4 + Instantiation(blob)=2 => 6. GenericParam-
    # Constraint (0x2C) = Owner(GenericParam simple)=2 + Constraint(TypeDefOrRef)=2
    # => 4. The old code had these two formulas swapped (0x2B=4, 0x2C=6).
    ctx = _ctx({0x0A: 40000, 0x2A: 100})
    assert _table_row_size(ctx, 0x2B) == 6
    assert _table_row_size(ctx, 0x2C) == 4
