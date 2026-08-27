"""M6.4 metadata enumeration unit tests."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.metadata_enum import (
    CAPABILITY,
    _coded_index_size,
    _disassemble_il,
    _MetaCtx,
    _simple_index_size,
    _table_row_size,
    enumerate_metadata,
)


def _write_minimal_clr(path: Path) -> None:
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
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


@pytest.mark.parametrize(
    ("rows", "expected"),
    [(0, 2), (65535, 2), (65536, 4), (100000, 4)],
)
def test_simple_index_widens_to_four_bytes_at_two_to_the_sixteen(rows: int, expected: int) -> None:
    """A simple table index is 2 bytes until the table needs a 17th bit.

    Every row offset in the #~ stream is a sum of table-row sizes, and a row
    size is a sum of index widths. Get this boundary wrong by one and every
    table after the first is read at the wrong offset, so the whole enumeration
    silently returns garbage rather than failing.
    """
    assert _simple_index_size({0x02: rows}, 0x02) == expected


@pytest.mark.parametrize(
    ("tables", "tag_bits", "rows", "expected"),
    [
        # TypeDefOrRef: 2 tag bits, so the row number keeps 14 bits -> 2**14.
        ((0x02, 0x01, 0x1B), 2, 16383, 2),
        ((0x02, 0x01, 0x1B), 2, 16384, 4),
        # HasCustomAttribute-style: 5 tag bits -> 11-bit row number -> 2**11.
        ((0x06, 0x0A), 5, 2047, 2),
        ((0x06, 0x0A), 5, 2048, 4),
    ],
)
def test_coded_index_width_follows_the_tag_bit_budget(
    tables: tuple[int, ...], tag_bits: int, rows: int, expected: int
) -> None:
    """A coded index steals tag_bits from its 16, so it widens sooner.

    The more tables a coded index can point into, the more tag bits it spends,
    and the fewer rows fit before it has to grow to 4 bytes. The threshold is
    2**(16 - tag_bits), not 2**16.
    """
    assert _coded_index_size({tables[0]: rows}, tables, tag_bits) == expected


def test_coded_index_width_is_driven_by_the_largest_referenced_table() -> None:
    """One big table in the union forces the width for all of them.

    The index has to address the largest table it can point into, so a small
    MethodDef next to a huge MemberRef is still a 4-byte index -- reading it as
    2 would misalign every following column in the row.
    """
    assert _coded_index_size({0x06: 1, 0x0A: 5000}, (0x06, 0x0A), 5) == 4


def test_enumerate_empty_tables_is_ok(tmp_path: Path) -> None:
    binary = tmp_path / "empty_tables.exe"
    _write_minimal_clr(binary)
    page = enumerate_metadata(binary, "types", limit=10)
    assert page.capability == CAPABILITY
    assert page.total == 0
    assert page.backend == "dotnet_metadata"
    assert page.claims_universal_unpack is False


def test_il_branch_and_constant_operands_are_signed() -> None:
    """A backward branch is a negative offset, not a four-billion one.

    ldc.i4 and both branch widths carry signed operands in ECMA-335. Only the
    short branches were decoded signed, so a long ``br`` to a target ten bytes
    back printed as 4294967286 and a ``ldc.i4 -1`` as 4294967295 -- the value an
    agent reads to follow a loop was its two's-complement bit pattern instead.
    """
    il = (
        bytes([0x38])
        + (-10).to_bytes(4, "little", signed=True)  # br -10 (long, backward)
        + bytes([0x20])
        + (-1).to_bytes(4, "little", signed=True)  # ldc.i4 -1
        + bytes([0x2B])
        + (-2).to_bytes(1, "little", signed=True)  # br.s -2 (short, was already signed)
        + bytes([0x28])
        + (0x0A000001).to_bytes(4, "little")  # call token stays unsigned
    )

    instructions, partial = _disassemble_il(il, max_insns=16)

    decoded = [(insn["mnemonic"], insn["operand"]) for insn in instructions]
    assert decoded == [
        ("br", -10),
        ("ldc.i4", -1),
        ("br.s", -2),
        ("call", 0x0A000001),
    ]
    assert partial is False


def test_service_enumerate_and_xrefs_surface(tmp_path: Path) -> None:
    binary = tmp_path / "empty_tables.exe"
    _write_minimal_clr(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    enumerated = service.dotnet_enumerate(session_id, "strings", limit=5)
    assert enumerated.ok
    assert enumerated.data is not None
    assert enumerated.data["not_ida_idalib"] is True
    xrefs = service.dotnet_xrefs(session_id, limit=5)
    assert xrefs.ok
    assert xrefs.data is not None
    assert xrefs.data["kind"] == "xrefs"


def _ctx(row_counts: dict[int, int], *, heap_sizes: int = 0) -> _MetaCtx:
    """A metadata context carrying only what ``_table_row_size`` reads."""
    return _MetaCtx(
        path=Path("x"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=b"",
        heap_sizes=heap_sizes,
        string_index_size=4 if heap_sizes & 0x01 else 2,
        blob_index_size=4 if heap_sizes & 0x04 else 2,
        guid_index_size=4 if heap_sizes & 0x02 else 2,
        row_counts=dict(row_counts),
        table_data_offset=0,
    )


def test_interfaceimpl_interface_column_is_a_coded_typedeforref_index() -> None:
    """InterfaceImpl.Interface is a TypeDefOrRef coded index, not a MethodDef one.

    The two widths only diverge past 2^14 rows, so a small assembly hides it: with
    20,000 TypeRefs the TypeDefOrRef coded index is 4 bytes while MethodDef stays a
    2-byte simple index. Sizing Interface as MethodDef would give 2 + 2 = 4; the
    spec-correct row is Class(TypeDef, 2) + Interface(TypeDefOrRef, 4) = 6. A wrong
    row here shifts every table after 0x09 -- MemberRef xrefs and IL token
    resolution among them -- for exactly the large assemblies worth enumerating.
    """
    meta = _ctx({0x01: 20000})  # TypeRef count forces TypeDefOrRef to 4 bytes.
    assert _table_row_size(meta, 0x09) == 6


def test_nestedclass_both_columns_are_plain_typedef_indexes() -> None:
    """NestedClass and EnclosingClass are both simple TypeDef indexes.

    The buggy row sized EnclosingClass as an Implementation coded index. Pushing
    the File table past 2^14 makes that coded index 4 bytes while the TypeDef
    simple index stays 2, so the mistake would read 2 + 4 = 6; the spec-correct
    row is TypeDef(2) + TypeDef(2) = 4.
    """
    meta = _ctx({0x26: 20000})  # File count forces the Implementation index to 4.
    assert _table_row_size(meta, 0x29) == 4


def test_small_row_counts_keep_every_index_two_bytes() -> None:
    """Calibration: with small counts both fixed tables collapse to 2 + 2 = 4.

    This is why the coding error stayed invisible on ordinary assemblies, and it
    guards the fix from over-correcting the common case into a wider row.
    """
    meta = _ctx({0x02: 10, 0x01: 10, 0x06: 10, 0x26: 10})
    assert _table_row_size(meta, 0x09) == 4
    assert _table_row_size(meta, 0x29) == 4


def test_methodsemantics_method_column_is_a_simple_methoddef_index() -> None:
    """MethodSemantics.Method indexes MethodDef directly, not MethodDefOrRef.

    The two widths diverge past 2^15 combined MethodDef+MemberRef rows. With
    40,000 MemberRefs and few MethodDefs the MethodDefOrRef coded index is 4 bytes
    while the simple MethodDef index stays 2, so sizing Method as the coded index
    gives 2 + 4 + 2 = 8; the spec-correct row is Semantics(2) + Method(2) +
    Association(HasSemantics, 2) = 6.
    """
    meta = _ctx({0x0A: 40000})  # MemberRef count lifts MethodDefOrRef to 4 bytes.
    assert _table_row_size(meta, 0x18) == 6


def test_assemblyref_row_is_not_a_copy_of_the_assembly_row() -> None:
    """AssemblyRef has no HashAlgId prefix but does carry a trailing HashValue.

    The row had been sized as a copy of the Assembly row -- a phantom 4-byte
    HashAlgId in front and no trailing HashValue blob. Unlike the other four
    fixes this is wrong for the *ordinary* small-heap assembly, not just large
    ones: with 2-byte heaps the copy measures 22 bytes where the spec row is
    2+2+2+2+4 + blob + str + str + blob = 20. Because nearly every assembly has
    an AssemblyRef table, the two-byte drift shifted every later table -- and so
    corrupted ManifestResource enumeration -- on essentially all real inputs.
    """
    assert _table_row_size(_ctx({}), 0x23) == 20
    # With a 4-byte blob heap the mistaken copy happened to measure correctly;
    # pin the true column layout there too so a regression cannot hide again.
    assert _table_row_size(_ctx({}, heap_sizes=0x04), 0x23) == 24


def test_file_hashvalue_column_is_a_blob_not_an_implementation_index() -> None:
    """File.HashValue is a Blob index, not an Implementation coded index.

    A wide blob heap (4-byte) with few File/AssemblyRef/ExportedType rows makes
    the blob index 4 while the Implementation coded index stays 2, so sizing the
    column as Implementation gives 4 + 2 + 2 = 8; the spec-correct row is
    Flags(4) + Name(str, 2) + HashValue(blob, 4) = 10.
    """
    meta = _ctx({}, heap_sizes=0x04)  # 4-byte blob heap, 2-byte strings.
    assert _table_row_size(meta, 0x26) == 10
