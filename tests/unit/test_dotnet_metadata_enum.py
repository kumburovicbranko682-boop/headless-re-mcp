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


def test_il_switch_jump_table_is_skipped_not_read_as_code() -> None:
    """switch has a variable-length operand; its table is not instructions.

    switch (0x45) carries a u32 case count followed by that many i32 target
    deltas. Decoded as a bare one-byte opcode the table was walked as code, so
    everything after a switch disassembled to nonsense and a delta whose first
    byte was 0x28/0x6f/0x73 surfaced in call_tokens as a method the function
    never calls. The fix skips the whole table and reports the case count.
    """
    il = (
        bytes([0x45])
        + (2).to_bytes(4, "little")  # two cases
        + (0).to_bytes(4, "little", signed=True)  # target[0] delta
        + (0x28).to_bytes(4, "little")  # target[1] delta: a call opcode byte if misread
        + bytes([0x2A])  # ret, at the real continuation offset 13
    )

    instructions, partial = _disassemble_il(il, max_insns=32)

    assert [(insn["mnemonic"], insn["operand"], insn["ip"]) for insn in instructions] == [
        ("switch", 2, 0),
        ("ret", None, 13),
    ]
    assert partial is False
    harvested = [
        insn["operand"]
        for insn in instructions
        if insn["mnemonic"] in {"call", "callvirt", "newobj"}
    ]
    assert harvested == []


def test_il_switch_truncated_table_is_reported_partial() -> None:
    """A switch whose declared table runs off the captured IL is not complete."""
    il = bytes([0x45]) + (4).to_bytes(4, "little") + (0).to_bytes(4, "little", signed=True)

    instructions, partial = _disassemble_il(il, max_insns=32)

    assert [(insn["mnemonic"], insn["operand"]) for insn in instructions] == [("switch", 4)]
    assert partial is True


def test_il_switch_with_hostile_count_does_not_hang_or_allocate() -> None:
    """A u32 count of 0xFFFFFFFF must fail closed as partial, not materialize."""
    il = bytes([0x45]) + (0xFFFFFFFF).to_bytes(4, "little") + bytes(4)

    instructions, partial = _disassemble_il(il, max_insns=32)

    assert instructions == [{"ip": 0, "mnemonic": "switch", "operand": 0xFFFFFFFF}]
    assert partial is True


def test_il_switch_opcode_at_eof_is_partial() -> None:
    """A switch opcode with no room for its count is truncated, not a 1-byte op."""
    il = bytes([0x16, 0x45])  # ldc.i4.0 then a bare switch at the end

    instructions, partial = _disassemble_il(il, max_insns=32)

    assert [(insn["mnemonic"], insn["operand"]) for insn in instructions] == [
        ("ldc.i4.0", None),
        ("switch", None),
    ]
    assert partial is True


def test_il_unnamed_operand_opcode_is_skipped_not_walked_as_code() -> None:
    """A known opcode outside the named subset must still skip its operand.

    The decoder names only a subset of opcodes but has to advance by the full
    instruction length for every one it meets. ldc.i8 (0x21) is unnamed and
    carries an eight-byte immediate; stepping a single byte past it walked those
    eight bytes as instructions, so a ``0x28`` inside the constant surfaced in
    call_tokens as a call the method never makes -- and partial stayed false.
    """
    il = (
        bytes([0x21])
        + (0).to_bytes(3, "little")
        + bytes([0x28])  # a call opcode byte inside the ldc.i8 immediate
        + (0xDEADBEEF).to_bytes(4, "little")
        + bytes([0x2A])  # ret, at the real continuation offset 9
    )

    instructions, partial = _disassemble_il(il, max_insns=32)

    assert [(insn["mnemonic"], insn["ip"]) for insn in instructions] == [
        ("op_21", 0),
        ("ret", 9),
    ]
    assert partial is False
    harvested = [
        insn["operand"]
        for insn in instructions
        if insn["mnemonic"] in {"call", "callvirt", "newobj"}
    ]
    assert harvested == []


def test_il_fe_prefixed_opcode_skips_its_operand() -> None:
    """0xFE names a two-byte opcode; its own operand is not instructions.

    Consuming only the 0xFE byte left the real opcode byte and, for ldftn
    (0xFE 0x06) and friends, its four-byte metadata token to be decoded as code.
    A comparison such as ceq (0xFE 0x01) also produced a bogus extra instruction
    from the opcode byte. Both must decode as a single aligned instruction.
    """
    il = (
        bytes([0xFE, 0x01])  # ceq, no operand
        + bytes([0xFE, 0x06])
        + (0x0A000009).to_bytes(4, "little")  # ldftn <token>
        + bytes([0x2A])  # ret at offset 8
    )

    instructions, partial = _disassemble_il(il, max_insns=32)

    assert [(insn["mnemonic"], insn["ip"]) for insn in instructions] == [
        ("fe_01", 0),
        ("fe_06", 2),
        ("ret", 8),
    ]
    assert partial is False
    harvested = [
        insn["operand"]
        for insn in instructions
        if insn["mnemonic"] in {"call", "callvirt", "newobj"}
    ]
    assert harvested == []


def test_il_stays_aligned_across_every_operand_size_class() -> None:
    """Mixed operand widths must all advance correctly for the stream to align.

    A sentinel ``ret`` is placed at a known offset after one opcode from each
    size class (1/4/8-byte single-byte, 0xFE two-byte, and switch). If any
    advance is wrong the sentinel is decoded at the wrong place or as garbage,
    and only the three genuine calls may appear in call_tokens.
    """
    body = bytearray()
    ips: list[int] = []

    def emit(chunk: bytes) -> None:
        ips.append(len(body))
        body.extend(chunk)

    emit(bytes([0x0E, 0x02]))  # ldarg.s (unnamed, 1)
    emit(bytes([0x21]) + (7).to_bytes(8, "little"))  # ldc.i8 (unnamed, 8)
    emit(bytes([0x23]) + (0).to_bytes(8, "little"))  # ldc.r8 (unnamed, 8)
    emit(bytes([0x3B]) + (4).to_bytes(4, "little", signed=True))  # beq (unnamed, 4)
    emit(bytes([0x28]) + (0x0A000001).to_bytes(4, "little"))  # call (named, 4)
    emit(bytes([0x73]) + (0x06000002).to_bytes(4, "little"))  # newobj (named, 4)
    emit(bytes([0xD0]) + (0x04000003).to_bytes(4, "little"))  # ldtoken (unnamed, 4)
    emit(bytes([0xFE, 0x06]) + (0x0A000004).to_bytes(4, "little"))  # ldftn (fe, 4)
    emit(bytes([0xFE, 0x09]) + (1).to_bytes(2, "little"))  # ldarg (fe, 2)
    emit(bytes([0x45]) + (1).to_bytes(4, "little") + (0).to_bytes(4, "little", signed=True))
    ret_ip = len(body)
    body.extend(bytes([0x2A]))  # ret sentinel

    instructions, partial = _disassemble_il(bytes(body), max_insns=200)

    assert partial is False
    assert [insn["ip"] for insn in instructions] == [*ips, ret_ip]
    assert instructions[-1]["mnemonic"] == "ret"
    calls = [
        insn["operand"]
        for insn in instructions
        if insn["mnemonic"] in {"call", "callvirt", "newobj"}
    ]
    assert calls == [0x0A000001, 0x06000002]


def test_il_truncated_unnamed_operand_is_reported_partial() -> None:
    """An unnamed opcode whose operand runs off the buffer is not complete."""
    il = bytes([0x21]) + (0).to_bytes(4, "little")  # ldc.i8 with only 4 of 8 bytes

    instructions, partial = _disassemble_il(il, max_insns=32)

    assert [(insn["mnemonic"], insn["operand"]) for insn in instructions] == [("op_21", None)]
    assert partial is True


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
