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
