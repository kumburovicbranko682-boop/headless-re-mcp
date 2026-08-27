"""M6.4 metadata enumeration unit tests."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.metadata_enum import CAPABILITY, _disassemble_il, enumerate_metadata


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


def test_il_operand_running_past_end_is_partial_not_an_overread() -> None:
    """An opcode whose operand is cut off by the stream end stops honestly.

    The IL comes from an attacker-controlled method body: a call (4-byte token)
    parked at the tail with fewer than four bytes left must not read past the
    buffer. The decoder bounds-checks the operand, drops the incomplete opcode,
    and flags partial -- the valid prefix still decodes so the caller keeps what
    was real without a truncated body reading as a complete one.
    """
    il = bytes([0x00, 0x28, 0x01, 0x02])  # nop, then call with only 2 of 4 bytes

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert [insn["mnemonic"] for insn in instructions] == ["nop"]
    assert partial is True


def test_il_unknown_opcode_is_named_not_dropped() -> None:
    """An opcode outside the decoded subset is surfaced as op_XX, not skipped.

    Silently dropping unknown bytes would desynchronise every following
    instruction; emitting a named placeholder and advancing one byte keeps the
    stream aligned and tells the reader exactly where the subset ran out.
    """
    il = bytes([0x00, 0xFF, 0x2A])  # nop, unknown 0xff, ret

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert [insn["mnemonic"] for insn in instructions] == ["nop", "op_ff", "ret"]
    assert partial is False


def test_il_two_byte_prefix_is_flagged_partial() -> None:
    """0xFE begins a two-byte opcode the subset does not decode; say so.

    The decoder emits a prefix.fe marker, advances a single byte, and sets
    partial so a body using ceq/clt/etc. is never mistaken for a fully decoded
    one -- the honest signal that this is an opcode subset, not a full CIL
    disassembler.
    """
    il = bytes([0xFE, 0x01])  # 0xFE 0x01 == ceq in full CIL

    instructions, partial = _disassemble_il(il, max_insns=16)

    assert instructions[0]["mnemonic"] == "prefix.fe"
    assert partial is True


def test_il_instruction_cap_reports_partial_only_when_bytes_remain() -> None:
    """The max_insns cap flags partial iff undisassembled bytes are left.

    Hitting the cap with more IL to go must read as partial so a caller does not
    treat a capped listing as the whole method; hitting it exactly at end-of-
    stream is a complete decode and must stay partial=False (no false alarm).
    """
    capped, capped_partial = _disassemble_il(bytes([0x00] * 5), max_insns=3)
    assert len(capped) == 3
    assert capped_partial is True

    exact, exact_partial = _disassemble_il(bytes([0x00] * 3), max_insns=3)
    assert len(exact) == 3
    assert exact_partial is False


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
