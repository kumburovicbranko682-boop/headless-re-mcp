"""M6.4 metadata enumeration unit tests."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.metadata_enum import (
    CAPABILITY,
    _disassemble_il,
    _MetaCtx,
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
