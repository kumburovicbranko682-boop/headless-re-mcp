"""A switch table must not desync every instruction that follows it.

``switch`` (0x45) is the one CIL opcode whose operand is variable length:
a uint32 count followed by that many int32 branch targets. It cannot be
expressed in the fixed-width opcode table the linear sweep uses, so before this
it fell through to the unknown-opcode branch, which advances a single byte and
then reads the 4 + 4*count operand bytes as if they were opcodes. The jump
table was disassembled as garbage and, worse, the sweep stayed misaligned for
the rest of the method -- the ``ret`` after it, the calls an agent reads to
follow control flow, all shifted by the operand width, with ``partial`` still
false. These pin that the operand is skipped as a unit and the sweep realigns.
"""

from __future__ import annotations

import struct

from headless_re_mcp.dotnet.metadata_enum import MAX_IL_INSNS, _disassemble_il


def _switch(targets: list[int]) -> bytes:
    body = struct.pack("<I", len(targets))
    for target in targets:
        body += struct.pack("<i", target)
    return b"\x45" + body


def test_switch_operand_is_skipped_as_a_unit_and_the_sweep_realigns() -> None:
    """After a two-arm switch the very next byte must decode as its real opcode.

    The switch spans 1 + 4 + 2*4 = 13 bytes. If those are miscounted the ``ret``
    that follows is read from the middle of the jump table -- here the second
    target is 0x2A, so a one-byte advance would surface a bogus ``ret`` inside
    the operand and never reach the real one.
    """
    il = _switch([0x11, 0x2A]) + b"\x2a"  # switch(2){+0x11,+0x2A}; ret
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert [insn["mnemonic"] for insn in instructions] == ["switch", "ret"]
    switch_insn = instructions[0]
    assert switch_insn["ip"] == 0
    assert switch_insn["operand"] == 2
    assert switch_insn["targets"] == [0x11, 0x2A]
    # The ret is the real one at the end of the body, not a byte pulled from the
    # jump table: its ip is exactly the length of the switch instruction.
    assert instructions[1]["ip"] == len(il) - 1
    assert partial is False


def test_an_empty_switch_still_advances_past_its_count() -> None:
    """switch(0) has a count word but no targets; the next opcode follows it."""
    il = _switch([]) + b"\x00"  # switch(0); nop
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert [insn["mnemonic"] for insn in instructions] == ["switch", "nop"]
    assert instructions[0]["targets"] == []
    assert instructions[1]["ip"] == 5
    assert partial is False


def test_a_switch_whose_table_runs_past_the_body_is_partial() -> None:
    """A count larger than the remaining bytes is truncation, reported honestly.

    Declaring five targets with only two present must not read the following
    bytes as a short table and march on; there is no honest realignment point,
    so the sweep stops and says partial rather than emitting garbage.
    """
    il = b"\x45" + struct.pack("<I", 5) + struct.pack("<ii", 1, 2)
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert partial is True
    assert all(insn["mnemonic"] != "switch" for insn in instructions)


def test_a_truncated_switch_count_word_is_partial() -> None:
    """Even the count word can be cut off; that is truncation, not an opcode."""
    il = b"\x45\x01\x00"  # 0x45 then only two of the four count bytes
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert partial is True
    assert all(insn["mnemonic"] != "switch" for insn in instructions)


def test_short_form_locals_carry_a_one_byte_operand_and_do_not_desync() -> None:
    """ldloc.s / stloc.s consume their slot index; the ret after them survives.

    These short forms sit between the .0-.3 forms and ldnull in the opcode map
    and appear in any method with more than four locals. Missing from the table,
    each advanced a single byte and its index byte was decoded as the next
    opcode -- here stloc.s's index 0x2A would surface a phantom ``ret`` mid
    stream and the real ret would never be reached in step.
    """
    # ldloc.s 4; stloc.s 0x2A; ret  -- the 0x2A index must not read as ret.
    il = b"\x11\x04\x13\x2a\x2a"
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert [insn["mnemonic"] for insn in instructions] == ["ldloc.s", "stloc.s", "ret"]
    assert instructions[0]["operand"] == 4
    assert instructions[1]["operand"] == 0x2A
    assert instructions[2]["ip"] == 4
    assert partial is False


def test_ldc_i4_s_decodes_its_byte_as_signed() -> None:
    """ldc.i4.s carries a signed int8: 0xFF is -1, not 255, and 0x7F stays 127."""
    negative, _ = _disassemble_il(b"\x1f\xff", max_insns=MAX_IL_INSNS)
    assert negative[0]["mnemonic"] == "ldc.i4.s"
    assert negative[0]["operand"] == -1

    positive, _ = _disassemble_il(b"\x1f\x7f", max_insns=MAX_IL_INSNS)
    assert positive[0]["operand"] == 127


def test_short_form_var_index_stays_unsigned() -> None:
    """The ldarg.s/ldloc.s slot index is an unsigned byte, so 0xFF is 255."""
    instructions, _ = _disassemble_il(b"\x0e\xff", max_insns=MAX_IL_INSNS)
    assert instructions[0]["mnemonic"] == "ldarg.s"
    assert instructions[0]["operand"] == 255


def test_conditional_branches_consume_their_target_and_do_not_desync() -> None:
    """beq.s (1-byte) and bne.un (4-byte) skip their whole displacement.

    The comparison branches back every loop and `if`, yet only br/brfalse/brtrue
    were in the table. A `beq.s` fell to the unknown-opcode branch, which
    advanced one byte and read the displacement as the next opcode; the four-byte
    forms desynced by four. Here the short branch's displacement byte is 0x2A, so
    a one-byte advance would surface a phantom ``ret`` inside the operand.
    """
    # beq.s +0x2A; bne.un +5; ret  -- neither displacement may read as an opcode.
    il = b"\x2e\x2a" + b"\x40" + struct.pack("<i", 5) + b"\x2a"
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert [insn["mnemonic"] for insn in instructions] == ["beq.s", "bne.un", "ret"]
    assert instructions[0]["operand"] == 0x2A
    assert instructions[1]["operand"] == 5
    # The ret is the real trailing one, reached in step after both branches.
    assert instructions[2]["ip"] == len(il) - 1
    assert partial is False


def test_conditional_branch_displacements_are_signed() -> None:
    """A backward comparison branch is a negative displacement, not a huge uint.

    ``bge.s 0xFB`` is a jump back five bytes; read unsigned it would be 251, and
    the long ``beq`` form would surface its two's-complement bit pattern instead
    of -10 -- exactly the control-flow misread the signed-operand set prevents.
    """
    short, _ = _disassemble_il(b"\x2f\xfb", max_insns=MAX_IL_INSNS)
    assert short[0]["mnemonic"] == "bge.s"
    assert short[0]["operand"] == -5

    long_form, _ = _disassemble_il(b"\x3b" + struct.pack("<i", -10), max_insns=MAX_IL_INSNS)
    assert long_form[0]["mnemonic"] == "beq"
    assert long_form[0]["operand"] == -10


def test_leave_and_leave_s_consume_their_signed_displacement() -> None:
    """leave/leave.s exit a try region; their signed target must be skipped whole.

    Every method with exception handling ends a guarded block with a leave. Both
    forms were missing, so the byte(s) of the handler displacement were decoded
    as instructions and the tail of the try body came back shifted.
    """
    # leave.s +0x2A; ret -- the displacement byte 0x2A must not read as ret.
    short, partial = _disassemble_il(b"\xde\x2a\x2a", max_insns=MAX_IL_INSNS)
    assert [insn["mnemonic"] for insn in short] == ["leave.s", "ret"]
    assert short[0]["operand"] == 0x2A
    assert short[1]["ip"] == 2
    assert partial is False

    # leave -3 (long form) decodes its four-byte displacement as signed.
    long_form, _ = _disassemble_il(b"\xdd" + struct.pack("<i", -3), max_insns=MAX_IL_INSNS)
    assert long_form[0]["mnemonic"] == "leave"
    assert long_form[0]["operand"] == -3
