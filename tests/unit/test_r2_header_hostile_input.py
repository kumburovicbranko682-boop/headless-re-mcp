"""Hostile-input robustness for the non-PE header parsers in r2/mapping.py.

elf_preferred_base / macho_preferred_base / macho_slice_span read ELF, Mach-O
and fat/universal headers straight off a caller-supplied binary to derive the
load base for coordinate enrichment. That input is untrusted, and the parsers
carry deliberate bounds checks against it -- a program-header count cap, a
sizeofcmds cap, a load-command cursor that cannot run past the buffer, and,
most importantly, a fat ``1 <= nfat <= _FAT_MAX_ARCHS`` guard: without it
``read(nfat * entry_size)`` turns a four-byte field into an ~85 GB request that
CPython answers with a ``MemoryError`` -- which, not being ``OSError``, escapes
the parser's guard and crashes the call on an eight-byte file.

The PE side has test_pe_hostile_input.py; these are the ELF/Mach-O twins. The
contract under every malformed input is the same: degrade to ``(None, None)``
or ``(arch, None)`` -- never raise, never loop, and never fabricate a base the
header does not actually support. A regression that drops one of these bounds
would either crash on, or invent a coordinate for, a hostile file; asserting the
graceful degradation makes that fail the suite instead.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.mapping import (
    elf_preferred_base,
    macho_preferred_base,
    macho_slice_span,
    preferred_base,
)
from headless_re_mcp.core.models import Architecture

_MACHO_LE64 = b"\xcf\xfa\xed\xfe"
_FAT_MAGIC = b"\xca\xfe\xba\xbe"
_X64_CPUTYPE = 0x01000007


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _elf64(
    *,
    machine: int = 0x3E,
    phoff: int = 64,
    phentsize: int = 56,
    phnum: int = 1,
    trailing: bytes = b"",
) -> bytes:
    """A 64-bit ELF ident with the program-header fields set as given."""
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little-endian
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<Q", data, 0x20, phoff)
    struct.pack_into("<H", data, 0x36, phentsize)
    struct.pack_into("<H", data, 0x38, phnum)
    return bytes(data) + trailing


def _thin_macho64(
    *,
    cputype: int = _X64_CPUTYPE,
    ncmds: int,
    sizeofcmds: int,
    commands: bytes = b"",
) -> bytes:
    """A 64-bit thin mach_header_64 (32 bytes) followed by a command region."""
    header = _MACHO_LE64 + struct.pack("<IIIII", cputype, 3, 2, ncmds, sizeofcmds)
    header += struct.pack("<II", 0, 0)  # flags + reserved
    return header + commands


def _fat(nfat: int, entries: bytes = b"") -> bytes:
    return _FAT_MAGIC + struct.pack(">I", nfat) + entries


# --- ELF ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "data"),
    [
        # A program-header count past the 4096 sanity cap must not be trusted.
        ("phnum-over-cap", _elf64(phnum=0xFFFF)),
        # A zero count is structurally valid but yields no PT_LOAD, so no base.
        ("phnum-zero", _elf64(phnum=0)),
        # e_phentsize too small to hold a p_vaddr for this class.
        ("phentsize-too-small", _elf64(phentsize=4)),
        # The program-header table starts past EOF: the short read is caught.
        ("phoff-past-eof", _elf64(phoff=0x7FFFFFFF, phnum=2)),
    ],
)
def test_malformed_elf_names_arch_but_never_a_bogus_base(
    tmp_path: Path, label: str, data: bytes
) -> None:
    arch, base = elf_preferred_base(_write(tmp_path, f"elf-{label}", data))
    # The e_machine is still readable, so the arch label survives; the base does
    # not, so addresses stay va-only rather than rebasing off a number the
    # header never actually supported.
    assert arch is Architecture.X64
    assert base is None


# --- thin Mach-O -------------------------------------------------------------


def test_truncated_macho_header_declines(tmp_path: Path) -> None:
    # Magic present, but fewer than the 24 bytes the header fields need.
    data = _MACHO_LE64 + b"\x00" * 6
    assert macho_preferred_base(_write(tmp_path, "macho-short", data)) == (None, None)


def test_macho_oversized_sizeofcmds_declines(tmp_path: Path) -> None:
    data = _thin_macho64(ncmds=1, sizeofcmds=0x7FFFFFFF)
    assert macho_preferred_base(_write(tmp_path, "macho-soc", data)) == (
        Architecture.X64,
        None,
    )


def test_macho_zero_cmdsize_cannot_spin(tmp_path: Path) -> None:
    # A load command with cmdsize 0 would loop forever without the break; the
    # parser must stop and report no base, not hang.
    commands = struct.pack("<II", 0x19, 0) + b"\x00" * 8
    data = _thin_macho64(ncmds=2, sizeofcmds=len(commands), commands=commands)
    assert macho_preferred_base(_write(tmp_path, "macho-cmd0", data)) == (
        Architecture.X64,
        None,
    )


# --- fat / universal Mach-O --------------------------------------------------


@pytest.mark.parametrize("nfat", [0, 0xFFFFFFFF])
def test_fat_out_of_range_count_is_refused_before_reading(
    tmp_path: Path, nfat: int
) -> None:
    """nfat == 0 and a four-byte-max nfat both refuse before the table read.

    The upper bound is the crash guard: without it, read(nfat * entry_size)
    requests ~85 GB for a four-byte-max nfat and CPython raises MemoryError,
    which is not OSError and so would escape the parser rather than degrade.
    """
    fat = _fat(nfat)
    binary = _write(tmp_path, f"fat-{nfat}", fat)
    assert macho_preferred_base(binary, select=Architecture.X64) == (None, None)
    assert macho_slice_span(binary, Architecture.X64) is None


def test_fat_truncated_table_declines(tmp_path: Path) -> None:
    # Claims three slices but carries only a few bytes of table.
    fat = _fat(3, b"\x00" * 10)
    binary = _write(tmp_path, "fat-trunc", fat)
    assert macho_slice_span(binary, Architecture.X64) is None
    assert macho_preferred_base(binary, select=Architecture.X64) == (None, None)


def test_fat_slice_offset_past_eof_declines(tmp_path: Path) -> None:
    # One well-formed table entry, but its slice offset/size point past EOF, so
    # the thin parse at that offset reads nothing and no base is invented.
    entry = struct.pack(">IIIII", _X64_CPUTYPE, 3, 0x7FFFFFFF, 0x1000, 12)
    binary = _write(tmp_path, "fat-off", _fat(1, entry))
    assert macho_preferred_base(binary, select=Architecture.X64) == (None, None)


# --- generic -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "data"),
    [("empty", b""), ("two-bytes", b"\xca\xfe"), ("garbage", b"not a binary at all")],
)
def test_unrecognised_input_is_va_only_across_the_chain(
    tmp_path: Path, label: str, data: bytes
) -> None:
    assert preferred_base(_write(tmp_path, f"junk-{label}", data)) == (None, None)
