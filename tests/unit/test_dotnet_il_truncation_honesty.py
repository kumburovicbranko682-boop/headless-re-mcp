"""A method body cut off by end-of-file must read as partial, not complete.

The tiny/fat method header carries ``code_size``, a number out of the sample.
``_read_method_body`` slices that many bytes from the file, and a slice that
crosses EOF silently comes back short. dotnet.il then disassembled the bytes
that existed and answered ``partial: False`` -- so declaring a size past the
end of the file was a cheap way to hide the tail of a method from exactly the
tool built to show it. The reader of that reply has no other signal: the
instructions decode cleanly, the header looks ordinary, and the only honest
answer is the flag.
"""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import disassemble_method_il

_IMAGE_SIZE = 0x800
_METHOD_FILE_OFF = 0x7F0
# .text raw data spans file 0x200..0x800 (exactly EOF) at RVA 0x1000, so the
# method header below sits 16 bytes before the end of a well-formed section.
_METHOD_RVA = 0x1000 + (_METHOD_FILE_OFF - 0x200)


def _write_clr_with_one_method(path: Path, *, code_size: int, il: bytes) -> None:
    """Minimal verified CLR image with one MethodDef pointing at ``il``.

    Same skeleton as test_dotnet_metadata_enum's builder, plus a ``#~`` stream
    holding a single MethodDef row and a ``#Strings`` heap for its name. The
    section's raw data ends exactly at EOF so a ``code_size`` larger than
    ``len(il)`` declares bytes the file does not have -- without any other
    structural anomaly a verifier could object to.
    """
    image = bytearray(_IMAGE_SIZE)
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
    # VirtualSize 0x600 at RVA 0x1000; raw 0x600 bytes at 0x200 -- ends at EOF.
    struct.pack_into("<IIII", image, section + 8, 0x600, 0x1000, 0x600, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x100)
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
    struct.pack_into("<HH", image, cursor, 0, 2)
    cursor += 4

    # MethodDef row: RVA(4) ImplFlags(2) Flags(2) Name(2) Signature(2) ParamList(2)
    method_row = struct.pack("<IHHHHH", _METHOD_RVA, 0, 0, 1, 0, 1)
    tables = bytearray(24)
    tables[4] = 2  # MajorVersion
    struct.pack_into("<Q", tables, 8, 1 << 0x06)  # Valid: MethodDef only
    tables += struct.pack("<I", 1)  # one row
    tables += method_row
    strings_heap = b"\0Main\0"

    tables_rel = 0x40  # relative to metadata root; leaves room for the headers
    strings_rel = tables_rel + len(tables)
    for name, rel, size in (
        (b"#~\0\0", tables_rel, len(tables)),
        (b"#Strings\0\0\0\0", strings_rel, len(strings_heap)),
    ):
        struct.pack_into("<II", image, cursor, rel, size)
        cursor += 8
        image[cursor : cursor + len(name)] = name
        cursor += len(name)
    image[meta_off + tables_rel : meta_off + tables_rel + len(tables)] = tables
    image[meta_off + strings_rel : meta_off + strings_rel + len(strings_heap)] = strings_heap

    # Tiny method header: low bits 0b10, code size in the upper six bits.
    image[_METHOD_FILE_OFF] = (code_size << 2) | 0x02
    body_at = _METHOD_FILE_OFF + 1
    image[body_at : body_at + len(il)] = il
    path.write_bytes(image[:_IMAGE_SIZE])


def test_a_body_cut_off_by_eof_is_reported_partial(tmp_path: Path) -> None:
    """15 bytes exist, 48 are declared: the missing 33 must not read as absent code.

    The bytes that are present decode cleanly (nops), so on the old path
    nothing tripped the partial flag: the reply carried il_bytes=48, fifteen
    instructions and partial=False, and the reader had no way to tell the
    method body from one that really was fifteen nops long.
    """
    binary = tmp_path / "eof_body.exe"
    present = _IMAGE_SIZE - (_METHOD_FILE_OFF + 1)
    _write_clr_with_one_method(binary, code_size=48, il=b"\x00" * present)
    result = disassemble_method_il(binary, 0x06000001)
    assert result["il_bytes"] == 48
    assert len(result["instructions"]) == present
    assert result["partial"] is True


def test_a_body_that_fits_before_eof_still_reads_complete(tmp_path: Path) -> None:
    """The EOF check must not mark an ordinary in-bounds body partial."""
    binary = tmp_path / "whole_body.exe"
    il = b"\x00" * 7 + b"\x2a"  # seven nops and a ret
    _write_clr_with_one_method(binary, code_size=len(il), il=il)
    result = disassemble_method_il(binary, 0x06000001)
    assert result["il_bytes"] == len(il)
    assert [insn["mnemonic"] for insn in result["instructions"][-1:]] == ["ret"]
    assert result["partial"] is False
