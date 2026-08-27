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
    _simple_index_size,
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


def _call_tokens(instructions: list[dict[str, object]]) -> list[int]:
    return [
        insn["operand"]
        for insn in instructions
        if insn.get("mnemonic") in {"call", "callvirt", "newobj"}
        and isinstance(insn.get("operand"), int)
    ]


def test_il_unnamed_operand_opcode_does_not_fabricate_a_call() -> None:
    """A single-byte opcode absent from the named subset must still skip its
    operand.

    ``ldc.i8`` (0x21) is not named, but it carries an eight-byte constant. The
    old decoder stepped a single byte, so the constant was read as instructions,
    and a 0x28 (``call``) byte inside it was reported as a real metadata call
    token -- with ``partial`` still False, claiming the disassembly was complete.
    The method here only pushes a constant and returns; it calls nothing.
    """
    il = (
        bytes([0x21])
        + bytes([0x00, 0x28, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00])  # ldc.i8 constant
        + bytes([0x2A])  # ret
    )

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert [insn["mnemonic"] for insn in instructions] == ["op_21", "ret"]
    assert _call_tokens(instructions) == []
    assert partial is False


def test_il_switch_table_is_stepped_over_not_decoded() -> None:
    """``switch`` carries a uint32 count then count*int32 targets.

    Those target bytes are not instructions; letting them decode turned a 0x6f
    byte in the table into a phantom ``callvirt``. The real ``callvirt`` after
    the table must be the only harvested call, and the count is reported.
    """
    il = (
        bytes([0x45])
        + (2).to_bytes(4, "little")  # switch, 2 targets
        + bytes([0x28, 0, 0, 0, 0x6F, 0, 0, 0])  # jump table: bytes look like call/callvirt
        + bytes([0x6F])
        + (0x0A000009).to_bytes(4, "little")  # callvirt <token>
        + bytes([0x2A])  # ret
    )

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert [insn["mnemonic"] for insn in instructions] == ["switch", "callvirt", "ret"]
    assert instructions[0]["operand"] == 2
    assert _call_tokens(instructions) == [0x0A000009]
    assert partial is False


def test_il_two_byte_fe_opcode_skips_its_operand() -> None:
    """``0xFE`` opcodes are two bytes plus an operand; skip the whole thing.

    ``ldftn`` (0xFE 0x06) takes a four-byte method token. The old decoder
    stepped one byte past the 0xFE and read the second byte and token as further
    instructions, so a 0x28 inside the token became a phantom ``call``.
    """
    il = (
        bytes([0xFE, 0x06])
        + bytes([0x28, 0x11, 0x22, 0x33])  # ldftn token containing a call byte
        + bytes([0x2A])  # ret
    )

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert [insn["mnemonic"] for insn in instructions] == ["ldftn", "ret"]
    assert _call_tokens(instructions) == []
    assert partial is False


def test_il_truncated_operand_reports_partial() -> None:
    """A real opcode whose operand runs off the end is genuine truncation."""
    il = bytes([0x28, 0x01, 0x02])  # call with only two of four token bytes

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert instructions == []
    assert partial is True


def test_il_switch_count_past_end_is_partial_not_fabricated() -> None:
    """A switch count that overruns the body truncates honestly, invents nothing."""
    il = bytes([0x45]) + (0xFFFFFFFF).to_bytes(4, "little") + bytes([0x28, 0, 0, 0])

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert instructions == []
    assert partial is True
    assert _call_tokens(instructions) == []


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
