"""ECMA-335 II.22 table row widths, and what a wrong one does downstream.

``_table_row_size`` is the ruler the enumerator lays end to end to find where a
table starts: ``_table_start(target)`` sums the widths of every table before
``target``. A single column typed wrong -- a coded index where the spec says a
simple one, or a formula copied from the neighbouring table -- shifts every
later table's offset, so ``dotnet.enumerate kind=resources`` and ``dotnet.xrefs``
read their rows from the wrong bytes and report the wrong name (or, when the
miscount runs a table past the end of its stream, drop it entirely).

The widths were verified column-by-column against ECMA-335 6th edition II.22 and
the saferwall/pe table definitions. Small honest assemblies hid the errors: at
two-byte heap indexes a coded and a simple index are both two bytes, so the
wrong ones only diverge once a row count crosses the index-size threshold -- and
the empty-tables fixture the other tests use has no rows at all. These pin the
widths directly instead.
"""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import (
    _MetaCtx,
    _table_row_size,
    enumerate_metadata,
)

# Row counts large enough to push a table's index columns to four bytes:
# > 2**16 forces a simple index wide, and the coded-index thresholds are lower
# still, so these make a mis-typed column observably the wrong width.
_WIDE = 70_000
_WIDE_CODED = 40_000


def _ctx(row_counts: dict[int, int]) -> _MetaCtx:
    """A context carrying only what ``_table_row_size`` reads: the row counts
    and the (two-byte) heap index sizes."""
    return _MetaCtx(
        path=Path("unused"),
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
        row_counts=dict(row_counts),
        table_data_offset=0,
    )


def test_interface_impl_interface_column_is_a_typedeforref_coded_index() -> None:
    """InterfaceImpl (0x09): Class=TypeDef index, Interface=TypeDefOrRef coded.

    The second column was sized as a simple MethodDef index. With many
    MethodDefs but few types the simple index is four bytes while the correct
    coded index stays two, so every MemberRef after it (dotnet.xrefs) shifted.
    """
    meta = _ctx({0x06: _WIDE, 0x02: 4})
    # Class: simple TypeDef (2) + Interface: TypeDefOrRef coded, few types (2).
    assert _table_row_size(meta, 0x09) == 4


def test_method_semantics_method_column_is_a_simple_methoddef_index() -> None:
    """MethodSemantics (0x18): Method=MethodDef index, Association=HasSemantics.

    The Method column was sized as a MethodDefOrRef coded index. With many
    MemberRefs the coded index is four bytes while the simple MethodDef index
    the spec asks for stays two.
    """
    meta = _ctx({0x0A: _WIDE_CODED})
    # Semantics(2) + Method simple MethodDef(2) + Association HasSemantics(2).
    assert _table_row_size(meta, 0x18) == 6


def test_assembly_ref_is_not_the_assembly_row_shape() -> None:
    """AssemblyRef (0x23) had the Assembly (0x20) formula copied onto it.

    AssemblyRef has no leading HashAlgId and carries a trailing HashValue blob
    that Assembly does not. At two-byte heaps that is a two-byte overcount on
    every AssemblyRef row -- and nearly every assembly references another.
    """
    meta = _ctx({})
    # Major/Minor/Build/Rev(2*4) + Flags(4) + PublicKeyOrToken(b) + Name(s)
    # + Culture(s) + HashValue(b) = 12 + 2 + 2 + 2 + 2 = 20.
    assert _table_row_size(meta, 0x23) == 20


def test_file_hash_value_column_is_a_blob_index() -> None:
    """File (0x26): Flags(4) + Name(String) + HashValue(Blob).

    The HashValue column was sized as an Implementation coded index. Give the
    Implementation set (File/AssemblyRef/ExportedType) enough rows and that
    coded index widens to four bytes while the real Blob index stays two.
    """
    meta = _ctx({0x23: 20_000})
    assert _table_row_size(meta, 0x26) == 8


def test_nested_class_both_columns_are_simple_typedef_indexes() -> None:
    """NestedClass (0x29): NestedClass=TypeDef index, EnclosingClass=TypeDef.

    The second column was an Implementation coded index; both are simple
    TypeDef indexes.
    """
    meta = _ctx({0x23: 20_000})
    assert _table_row_size(meta, 0x29) == 4


def test_method_spec_and_generic_param_constraint_are_not_swapped() -> None:
    """0x2B is MethodSpec, 0x2C is GenericParamConstraint -- their formulas had
    been exchanged (the stray ``# MethodSpec`` comment sat on 0x2C)."""
    # MethodSpec (0x2B): Method(MethodDefOrRef coded) + Instantiation(Blob).
    method_spec = _ctx({0x0A: _WIDE_CODED})
    assert _table_row_size(method_spec, 0x2B) == 6  # coded 4 + blob 2
    # GenericParamConstraint (0x2C): Owner(GenericParam index) + Constraint
    # (TypeDefOrRef coded).
    gpc = _ctx({0x01: 20_000})
    assert _table_row_size(gpc, 0x2C) == 6  # simple 2 + coded 4


def test_enc_tables_are_sizeable_so_a_later_table_can_be_reached() -> None:
    """ENCLog (0x1E) and ENCMap (0x1F) are fixed-width uint columns.

    They were absent from the size table, so an assembly carrying them made
    ``_table_start`` abort with ``unsupported_metadata`` before it could reach
    ManifestResource -- even though those tables are trivially sizeable.
    """
    meta = _ctx({})
    assert _table_row_size(meta, 0x1E) == 8  # Token(4) + FuncCode(4)
    assert _table_row_size(meta, 0x1F) == 4  # Token(4)


def _write_clr_with_assembly_ref_and_resource(path: Path) -> None:
    """A minimal managed image whose #~ stream holds one AssemblyRef row
    followed by one ManifestResource row named ``myresource``.

    ManifestResource (0x28) sits after AssemblyRef (0x23), so its offset is
    found by adding AssemblyRef's row width. When that width is overcounted the
    resource row is read two bytes late -- which here runs it past the end of
    the #~ stream, so the enumerator reports zero resources instead of one.
    """
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
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)

    # --- metadata root, laid out relative to its own start ---
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    strings_heap = b"\0myresource\0"  # index 1 -> "myresource"

    tilde = bytearray()
    tilde += struct.pack("<I", 0)  # reserved
    tilde += struct.pack("<BB", 2, 0)  # major, minor
    tilde += struct.pack("<B", 0)  # heap sizes: all two-byte
    tilde += struct.pack("<B", 1)  # reserved
    valid = (1 << 0x23) | (1 << 0x28)  # AssemblyRef + ManifestResource
    tilde += struct.pack("<Q", valid)
    tilde += struct.pack("<Q", 0)  # sorted
    tilde += struct.pack("<I", 1)  # AssemblyRef rows (ascending table order)
    tilde += struct.pack("<I", 1)  # ManifestResource rows
    tilde += b"\0" * 20  # one AssemblyRef row (correct width at 2-byte heaps)
    tilde += struct.pack("<II", 0, 0)  # ManifestResource Offset, Flags
    tilde += struct.pack("<H", 1)  # Name -> #Strings index 1
    tilde += struct.pack("<H", 0)  # Implementation coded index

    fixed = bytearray()
    fixed += b"BSJB"
    fixed += struct.pack("<HH", 1, 1)
    fixed += struct.pack("<I", 0)
    fixed += struct.pack("<I", len(version))
    fixed += version_padded
    fixed += struct.pack("<HH", 0, 2)  # flags, stream count

    def _stream_header(offset: int, size: int, name: bytes) -> bytes:
        padded = name + b"\0"
        padded += b"\0" * ((4 - (len(padded) % 4)) % 4)
        return struct.pack("<II", offset, size) + padded

    header_len = len(_stream_header(0, 0, b"#Strings")) + len(
        _stream_header(0, 0, b"#~")
    )
    data_start = len(fixed) + header_len
    strings_off = data_start
    tilde_off = strings_off + len(strings_heap)

    md = bytearray(fixed)
    md += _stream_header(strings_off, len(strings_heap), b"#Strings")
    md += _stream_header(tilde_off, len(tilde), b"#~")
    md += strings_heap
    md += bytes(tilde)

    meta_off = 0x400
    image[meta_off : meta_off + len(md)] = md
    struct.pack_into("<I", image, cor_off + 8, 0x1200, )  # metadata RVA
    struct.pack_into("<I", image, cor_off + 12, len(md))  # metadata size
    path.write_bytes(image)


def test_resource_enumeration_survives_a_preceding_assembly_ref(
    tmp_path: Path,
) -> None:
    """End to end: the resource is found only when AssemblyRef is sized right.

    With the old width AssemblyRef overcounts by two bytes, the ManifestResource
    row is placed past the end of the #~ stream, and enumeration reports no
    resources at all. Correctly sized, the one resource comes back by name.
    """
    binary = tmp_path / "with_resource.dll"
    _write_clr_with_assembly_ref_and_resource(binary)

    page = enumerate_metadata(binary, "resources", limit=10)

    assert page.total == 1
    assert page.items[0]["name"] == "myresource"
