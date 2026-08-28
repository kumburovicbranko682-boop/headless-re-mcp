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


def _row_size_ctx(
    row_counts: dict[int, int],
    *,
    string_index_size: int = 2,
    blob_index_size: int = 2,
    guid_index_size: int = 2,
) -> _MetaCtx:
    """A ``_MetaCtx`` carrying only the fields ``_table_row_size`` reads.

    Row widths depend solely on the per-table row counts and the three heap
    index sizes; the rest of the context (mapped bytes, layout, offsets) is
    irrelevant to the sizing arithmetic under test.
    """
    return _MetaCtx(
        path=Path("in-memory.dll"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=b"",
        heap_sizes=0,
        string_index_size=string_index_size,
        blob_index_size=blob_index_size,
        guid_index_size=guid_index_size,
        row_counts=dict(row_counts),
        table_data_offset=0,
    )


def test_table_row_sizes_follow_ecma335_column_layouts() -> None:
    """Six metadata tables were sized with the wrong ECMA-335 columns.

    A single wrong row width desynchronises ``_table_start`` for every table
    that sorts after it, so enumeration of the higher-id tables (resources,
    nested classes, generic constraints) walked into the middle of rows. Each
    scenario below is tuned so the previously shipped (wrong) formula produces a
    *different* byte count than the spec-correct one, i.e. these assertions fail
    against the old code and pass against the fix.
    """
    # InterfaceImpl (0x09): Class(TypeDef index) + Interface(TypeDefOrRef coded).
    # 16384 TypeDef rows push the TypeDefOrRef coded index to 4 bytes while the
    # simple TypeDef index stays 2. The old code sized the second column as a
    # MethodDef index (2 bytes here), giving 4 instead of 6.
    assert _table_row_size(_row_size_ctx({0x02: 16384}), 0x09) == 2 + 4

    # MethodSemantics (0x18): Semantics(2) + Method(MethodDef index) +
    # Association(HasSemantics coded). 32768 MemberRef rows widen a
    # MethodDefOrRef coded index to 4 bytes; the spec's plain MethodDef index is
    # unaffected and stays 2. The old code used MethodDefOrRef, giving 8 not 6.
    assert _table_row_size(_row_size_ctx({0x0A: 32768}), 0x18) == 2 + 2 + 2

    # AssemblyRef (0x23): Major/Minor/Build/Rev(2 each) + Flags(4) +
    # PublicKeyOrToken(blob) + Name(str) + Culture(str) + HashValue(blob). The
    # old code borrowed Assembly's layout: a leading 4-byte HashAlgId and no
    # trailing HashValue blob, giving 22 bytes instead of 20 with small heaps.
    assert _table_row_size(_row_size_ctx({}), 0x23) == 2 + 2 + 2 + 2 + 4 + 2 + 2 + 2 + 2

    # File (0x26): Flags(4) + Name(str) + HashValue(blob). 16384 AssemblyRef
    # rows widen the Implementation coded index to 4 bytes; File carries a blob
    # index there, not Implementation. The old code produced 10, not 8.
    assert _table_row_size(_row_size_ctx({0x23: 16384}), 0x26) == 4 + 2 + 2

    # NestedClass (0x29): NestedClass(TypeDef index) + EnclosingClass(TypeDef
    # index). Same 4-byte Implementation coded index as above reveals the bug:
    # the old code sized the second column as Implementation, giving 6 not 4.
    assert _table_row_size(_row_size_ctx({0x23: 16384}), 0x29) == 2 + 2

    # MethodSpec (0x2B) and GenericParamConstraint (0x2C) had their column
    # layouts transposed. With 32768 MemberRef rows the MethodDefOrRef coded
    # index is 4 bytes, so the two tables must differ: MethodSpec is
    # MethodDefOrRef(4) + Instantiation blob(2) = 6, while
    # GenericParamConstraint is Owner GenericParam index(2) + Constraint
    # TypeDefOrRef(2) = 4. The old code reported these swapped.
    swapped_ctx = _row_size_ctx({0x0A: 32768})
    assert _table_row_size(swapped_ctx, 0x2B) == 4 + 2
    assert _table_row_size(swapped_ctx, 0x2C) == 2 + 2
