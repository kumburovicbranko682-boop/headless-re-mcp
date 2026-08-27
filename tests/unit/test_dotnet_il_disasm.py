"""IL opcode decoding: alignment, operand widths, and honest partials.

The subset disassembler used to know only a handful of opcodes and advance one
byte past anything else. An opcode that carries an inline operand -- ``ldc.i4.s``
is in nearly every method -- therefore had its operand byte decoded as the next
instruction, so the whole tail of a method came out as plausible-looking
nonsense while ``partial`` stayed False. These tests pin the aligned decode.
"""

from __future__ import annotations

import struct

from headless_re_mcp.dotnet.metadata_enum import _disassemble_il


def _mnemonics(il: bytes) -> list[str]:
    insns, _ = _disassemble_il(il, max_insns=256)
    return [insn["mnemonic"] for insn in insns]


def test_short_inline_operand_stays_aligned() -> None:
    # ldc.i4.s 10; stloc.0; ldloc.0; ldc.i4.s 5; ret
    il = bytes([0x1F, 0x0A, 0x0A, 0x06, 0x1F, 0x05, 0x2A])
    insns, partial = _disassemble_il(il, max_insns=64)
    assert [i["mnemonic"] for i in insns] == [
        "ldc.i4.s",
        "stloc.0",
        "ldloc.0",
        "ldc.i4.s",
        "ret",
    ]
    assert insns[0]["operand"] == 10
    assert insns[3]["operand"] == 5
    assert partial is False


def test_two_byte_fe_opcodes_decode() -> None:
    # ceq; ldftn <token>; ldarg 1; ret
    il = bytes([0xFE, 0x01, 0xFE, 0x06, 0x01, 0x00, 0x00, 0x0A, 0xFE, 0x09, 0x01, 0x00, 0x2A])
    insns, partial = _disassemble_il(il, max_insns=64)
    assert [i["mnemonic"] for i in insns] == ["ceq", "ldftn", "ldarg", "ret"]
    assert insns[1]["operand"] == 0x0A000001
    assert insns[2]["operand"] == 1
    assert partial is False


def test_signed_branch_targets_are_negative() -> None:
    # ceq; brtrue.s -5; ret
    il = bytes([0xFE, 0x01, 0x2D, 0xFB, 0x2A])
    insns, _ = _disassemble_il(il, max_insns=64)
    assert insns[1]["mnemonic"] == "brtrue.s"
    assert insns[1]["operand"] == -5


def test_switch_reads_target_table_and_realigns() -> None:
    il = bytes([0x45]) + struct.pack("<I", 2) + struct.pack("<i", 3) + struct.pack("<i", -1)
    il += bytes([0x2A])
    insns, partial = _disassemble_il(il, max_insns=64)
    assert insns[0]["mnemonic"] == "switch"
    assert insns[0]["operand"] == [3, -1]
    assert insns[1]["mnemonic"] == "ret"
    assert partial is False


def test_switch_with_impossible_count_is_bounded_partial() -> None:
    # A count that overruns the IL must not run wild; it stops partial.
    il = bytes([0x45]) + struct.pack("<I", 0x7FFFFFFF) + bytes([0x00, 0x00])
    insns, partial = _disassemble_il(il, max_insns=64)
    assert insns[-1]["mnemonic"] == "switch"
    assert insns[-1]["operand"] is None
    assert partial is True


def test_ldc_i8_consumes_eight_bytes() -> None:
    il = bytes([0x21, 1, 0, 0, 0, 0, 0, 0, 0, 0x2A])
    insns, partial = _disassemble_il(il, max_insns=64)
    assert [i["mnemonic"] for i in insns] == ["ldc.i8", "ret"]
    assert insns[0]["operand"] == 1
    assert partial is False


def test_truncated_operand_is_partial_not_a_wild_read() -> None:
    # ldc.i4 needs four operand bytes; only two are present.
    insns, partial = _disassemble_il(bytes([0x20, 0x01, 0x02]), max_insns=64)
    assert partial is True
    assert all(i["mnemonic"] != "ret" for i in insns)


def test_unknown_opcode_marks_partial() -> None:
    # 0xC0 is unallocated; alignment past it is a guess, so say partial.
    insns, partial = _disassemble_il(bytes([0x00, 0xC0, 0x2A]), max_insns=64)
    assert insns[0]["mnemonic"] == "nop"
    assert insns[1]["mnemonic"] == "op_c0"
    assert partial is True


def test_unknown_two_byte_opcode_marks_partial() -> None:
    insns, partial = _disassemble_il(bytes([0xFE, 0x7F, 0x2A]), max_insns=64)
    assert insns[0]["mnemonic"] == "op_fe_7f"
    assert partial is True
