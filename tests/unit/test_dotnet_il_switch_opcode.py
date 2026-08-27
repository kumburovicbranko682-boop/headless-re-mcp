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


def test_token_object_model_opcodes_consume_four_bytes_and_stay_aligned() -> None:
    """castclass/ldsfld/newarr/ldtoken/unbox.any skip their whole token.

    These object-model opcodes each carry a 4-byte metadata token and appear in
    nearly every non-trivial method. Missing from the table, each advanced one
    byte and its four token bytes were decoded as instructions -- the common
    four-byte desync. The trailing ret must be reached in step after all of them.
    """
    il = (
        b"\x74" + struct.pack("<I", 0x0100_0002)  # castclass
        + b"\x7e" + struct.pack("<I", 0x0400_0003)  # ldsfld
        + b"\x8d" + struct.pack("<I", 0x0200_0001)  # newarr
        + b"\xd0" + struct.pack("<I", 0x0A00_0004)  # ldtoken
        + b"\xa5" + struct.pack("<I", 0x0100_0005)  # unbox.any
        + b"\x2a"  # ret
    )
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert [insn["mnemonic"] for insn in instructions] == [
        "castclass", "ldsfld", "newarr", "ldtoken", "unbox.any", "ret",
    ]
    assert instructions[-1]["ip"] == len(il) - 1
    assert partial is False


def test_metadata_tokens_decode_unsigned() -> None:
    """A token with the high bit set is a large positive value, not a negative.

    ldsfld carries an unsigned metadata token; a table id in the top byte must
    not flip it negative the way a signed read would.
    """
    instructions, _ = _disassemble_il(
        b"\x7e" + struct.pack("<I", 0xFF00_0000), max_insns=MAX_IL_INSNS
    )
    assert instructions[0]["mnemonic"] == "ldsfld"
    assert instructions[0]["operand"] == 0xFF00_0000


def test_ldc_i8_is_a_signed_eight_byte_constant() -> None:
    """ldc.i8 loads a signed int64: eight 0xFF bytes are -1, not a huge uint."""
    negative, partial = _disassemble_il(
        b"\x21" + struct.pack("<q", -1) + b"\x2a", max_insns=MAX_IL_INSNS
    )
    assert [insn["mnemonic"] for insn in negative] == ["ldc.i8", "ret"]
    assert negative[0]["operand"] == -1
    assert negative[1]["ip"] == 9  # the eight operand bytes were skipped whole
    assert partial is False


def test_ldc_r8_reserves_its_eight_operand_bytes() -> None:
    """ldc.r8 is 8 bytes wide; a double literal must not desync the ret after it.

    The float bits themselves are surfaced raw -- this decoder shows control
    flow and tokens, not rendered floats -- but the width must be right so the
    following instruction is read in step.
    """
    il = b"\x23" + struct.pack("<d", 3.14159) + b"\x2a"  # ldc.r8; ret
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)
    assert [insn["mnemonic"] for insn in instructions] == ["ldc.r8", "ret"]
    assert instructions[1]["ip"] == len(il) - 1
    assert partial is False


def test_two_byte_opcodes_decode_as_a_unit_and_stay_aligned() -> None:
    """The 0xFE family decodes the prefix + sub-opcode + operand together.

    Reading only the 0xFE and letting the sub-opcode fall through decoded it as
    a top-level opcode; for initobj and the wide ldloc the operand bytes were
    then read as instructions and the method desynced -- and the old code also
    flagged the whole rest partial. Here ceq (no operand), initobj (4-byte
    token) and ldloc (2-byte slot) must each decode whole, the ret must land in
    step, and partial must stay false.
    """
    il = (
        b"\xfe\x01"  # ceq
        + b"\xfe\x15" + struct.pack("<I", 0x0200_0001)  # initobj <token>
        + b"\xfe\x0c" + struct.pack("<H", 3)  # ldloc 3
        + b"\x2a"  # ret
    )
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert [insn["mnemonic"] for insn in instructions] == ["ceq", "initobj", "ldloc", "ret"]
    assert instructions[1]["operand"] == 0x0200_0001
    assert instructions[2]["operand"] == 3
    assert instructions[-1]["ip"] == len(il) - 1
    assert partial is False


def test_constrained_prefix_then_callvirt_both_decode() -> None:
    """constrained. is a prefix carrying a token; the call after it still decodes.

    A generic call on a type parameter emits `constrained. <T>` then `callvirt
    <method>`. The prefix's 4-byte token must be consumed so the callvirt is
    read as an instruction, not from inside the token bytes.
    """
    il = (
        b"\xfe\x16" + struct.pack("<I", 0x1B00_0002)  # constrained. <token>
        + b"\x6f" + struct.pack("<I", 0x0A00_0003)  # callvirt <method>
        + b"\x2a"  # ret
    )
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)

    assert [insn["mnemonic"] for insn in instructions] == ["constrained.", "callvirt", "ret"]
    assert instructions[0]["operand"] == 0x1B00_0002
    assert instructions[1]["operand"] == 0x0A00_0003
    assert instructions[-1]["ip"] == len(il) - 1
    assert partial is False


def test_two_byte_slot_index_is_unsigned_and_two_bytes_wide() -> None:
    """ldarg's 0xFE form takes an unsigned uint16 slot: 0xFFFF is 65535."""
    il = b"\xfe\x09" + struct.pack("<H", 0xFFFF) + b"\x2a"  # ldarg 65535; ret
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)
    assert [insn["mnemonic"] for insn in instructions] == ["ldarg", "ret"]
    assert instructions[0]["operand"] == 0xFFFF
    assert instructions[1]["ip"] == 4
    assert partial is False


def test_unknown_two_byte_opcode_advances_past_the_prefix() -> None:
    """An unassigned 0xFE sub-opcode still consumes both bytes, not just one."""
    il = b"\xfe\x08\x2a"  # 0xFE 0x08 is unassigned; then ret
    instructions, partial = _disassemble_il(il, max_insns=MAX_IL_INSNS)
    assert [insn["mnemonic"] for insn in instructions] == ["fe_08", "ret"]
    assert instructions[1]["ip"] == 2
    assert partial is False


def test_a_truncated_two_byte_opcode_is_partial() -> None:
    """A 0xFE with no sub-opcode, or a token cut short, is truncation not garbage."""
    dangling, partial = _disassemble_il(b"\xfe", max_insns=MAX_IL_INSNS)
    assert partial is True
    assert dangling == []

    # initobj declares a 4-byte token but only two bytes remain.
    short, short_partial = _disassemble_il(b"\xfe\x15\x01\x02", max_insns=MAX_IL_INSNS)
    assert short_partial is True
    assert all(insn["mnemonic"] != "initobj" for insn in short)
