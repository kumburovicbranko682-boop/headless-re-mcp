"""A MethodDef RVA that does not point at a method header must be refused.

ECMA-335 II.25.4 gives a method body exactly two header shapes: tiny (the first
byte's low two bits are 0b10, size in the upper six) and fat (low two bits
0b11). ``_read_method_body`` dispatched on "is it tiny?" and sent everything
else -- including the two low-bit patterns 0b00 and 0b01 that are not headers at
all -- down the fat branch. It then read four little-endian words as flags,
max_stack, code_size and a local-var-sig token out of whatever bytes happened to
follow, and returned them as an ordinary fat header.

That turns a MethodDef RVA aimed at non-header bytes -- an obfuscator decoy, a
corrupt MethodDef table, or simply a wrong RVA -- into a fabricated method: real
sixteen-bit numbers, a real ``code_size`` slice, ``partial`` decided by whether
that fiction happened to run past EOF. The reader of ``dotnet.il`` had no signal
that the header was invented. The honest answer is to refuse it, the same shape
as the existing guard for a fat header truncated by end-of-file.

Reuses the minimal verified-CLR builder from the truncation-honesty test and
corrupts only the single method-header byte, so the metadata still verifies and
the corruption is exactly the header format bits under test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.metadata_enum import disassemble_method_il
from tests.unit.test_dotnet_il_truncation_honesty import (
    _METHOD_FILE_OFF,
    _write_clr_with_one_method,
)


def _image_with_header_byte(path: Path, header_byte: int) -> None:
    """A valid one-method image, then the header byte overwritten in place.

    The builder writes a tiny header; only the low two bits decide the format,
    so replacing the whole byte lets a test pick tiny (0b10), fat (0b11) or the
    two invalid patterns without disturbing the CLR metadata the verifier reads.
    """
    _write_clr_with_one_method(path, code_size=1, il=b"\x2a")  # one ret
    data = bytearray(path.read_bytes())
    data[_METHOD_FILE_OFF] = header_byte
    path.write_bytes(data)


@pytest.mark.parametrize("fmt_bits", [0x00, 0x01])
def test_a_method_header_with_invalid_format_bits_is_refused(tmp_path: Path, fmt_bits: int) -> None:
    """0b00 and 0b01 are not method headers; neither may be read as a fat body."""
    binary = tmp_path / f"bad_header_{fmt_bits}.exe"
    # Upper bits set too, to prove it is the low two bits that decide -- and that
    # the rejected value is not merely "byte is zero".
    _image_with_header_byte(binary, (0x3F << 2) | fmt_bits)

    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(binary, 0x06000001)

    assert caught.value.code == "not_found"
    assert "invalid format bits" in str(caught.value)


def test_a_genuine_tiny_header_still_disassembles(tmp_path: Path) -> None:
    """The guard must not reject the tiny header the builder actually writes."""
    binary = tmp_path / "tiny_ok.exe"
    _image_with_header_byte(binary, (1 << 2) | 0x02)  # code_size 1, tiny

    result = disassemble_method_il(binary, 0x06000001)

    assert result["header"]["format"] == "tiny"
    assert [insn["mnemonic"] for insn in result["instructions"]] == ["ret"]
    assert result["partial"] is False


def test_a_fat_format_header_takes_the_fat_branch(tmp_path: Path) -> None:
    """0b11 must still be read as fat, not swept up by the new guard.

    The twelve fixed bytes of a fat header fit before EOF here, and the bytes
    that follow the format byte read as flags=0x03, max_stack=0, code_size=0 --
    an empty fat body. The assertion is about which branch was taken (fat, so
    ``format`` is ``"fat"`` and ``header_size`` reads back), not the contents: a
    regression that folded 0b11 into the invalid-format guard would raise here.
    """
    binary = tmp_path / "fat_branch.exe"
    _image_with_header_byte(binary, 0x03)  # fat format bits, header size nibble 0

    result = disassemble_method_il(binary, 0x06000001)

    assert result["header"]["format"] == "fat"
