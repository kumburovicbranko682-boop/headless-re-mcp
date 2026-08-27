"""M6.4 metadata enumeration unit tests."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

import headless_re_mcp.dotnet.metadata_enum as metadata_enum
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.metadata_enum import CAPABILITY, _disassemble_il, enumerate_metadata

# TypeDef (table 0x02) row size with two-byte heap/index sizes and only TypeDef
# declared: RID(4) + Name(2) + Namespace(2) + Extends coded index(2) +
# FieldList(2) + MethodList(2).
_TYPEDEF_ROW_SIZE = 14


def _typedef_ctx(*, declared_rows: int, present_rows: int) -> metadata_enum._MetaCtx:
    """A metadata context whose #~ TypeDef header over- or exactly declares rows.

    tables is sized to physically hold present_rows while row_counts declares
    declared_rows, which is the truncated/hand-crafted #~ stream the row cap
    guards against.
    """
    return metadata_enum._MetaCtx(
        path=Path("crafted.dll"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=bytes(_TYPEDEF_ROW_SIZE * present_rows),
        strings=b"",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={0x02: declared_rows},
        table_data_offset=0,
    )


def _patch_ctx(monkeypatch: pytest.MonkeyPatch, ctx: metadata_enum._MetaCtx) -> None:
    monkeypatch.setattr(metadata_enum, "inspect_dotnet", lambda *a, **k: None)
    monkeypatch.setattr(metadata_enum, "_load_metadata_context", lambda _p: ctx)


def test_enumerate_flags_a_table_short_of_its_declared_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A #~ header can declare more rows than the stream physically holds.

    The row cap silently trims the walk to what fits, so total came back as the
    trimmed count with nothing to say the table declared more -- a caller reading
    total as the whole type list was reading a slice of a corrupt/crafted table.
    """
    _patch_ctx(monkeypatch, _typedef_ctx(declared_rows=5, present_rows=2))

    page = enumerate_metadata(Path("crafted.dll"), "types", offset=0, limit=10)

    assert page.total == 2
    assert page.rows_truncated is True
    assert page.declared_total == 5
    body = page.to_dict()
    assert body["rows_truncated"] is True
    assert body["declared_total"] == 5


def test_enumerate_leaves_an_honest_table_unflagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A table whose stream holds exactly what it declares carries no verdict."""
    _patch_ctx(monkeypatch, _typedef_ctx(declared_rows=3, present_rows=3))

    page = enumerate_metadata(Path("crafted.dll"), "types", offset=0, limit=10)

    assert page.total == 3
    assert page.rows_truncated is False
    assert page.declared_total is None
    assert "declared_total" not in page.to_dict()


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
