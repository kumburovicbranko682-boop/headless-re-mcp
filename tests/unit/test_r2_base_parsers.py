"""Branch coverage for the ELF/Mach-O base parsers in r2/mapping.py.

test_r2_header_hostile_input pins the count-cap and fat-table crash guards;
these fill the remaining branches of the same parsers over crafted bytes:

- the ELF program-header *table_size* cap (a valid phnum with a huge phentsize
  still cannot be trusted to a megabyte-plus read),
- the OSError degrade shared by all three readers (a directory handed in as a
  binary opens-then-fails),
- the well-formed paths that resolve a base: an ELF that skips a non-PT_LOAD
  segment and takes the PT_LOAD vaddr, and a Mach-O that falls back to the
  lowest non-__PAGEZERO segment when no fileoff==0 header segment is present,
- the Mach-O load-command cursor declining a region shorter than sizeofcmds, a
  trailing stub too small to hold another command, and a non-segment command.

The contract is unchanged: never raise, never loop, and only return a base the
header actually supports.
"""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    elf_preferred_base,
    macho_preferred_base,
    macho_slice_span,
)
from headless_re_mcp.core.models import Architecture

_MACHO_LE64 = b"\xcf\xfa\xed\xfe"
_X64_CPUTYPE = 0x01000007
_LC_SEGMENT_64 = 0x19
_LC_LOAD_DYLIB = 0x0C


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _elf64_ident(*, machine: int = 0x3E, phoff: int, phentsize: int, phnum: int) -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little-endian
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<Q", data, 0x20, phoff)
    struct.pack_into("<H", data, 0x36, phentsize)
    struct.pack_into("<H", data, 0x38, phnum)
    return bytes(data)


def _phdr64(*, p_type: int, vaddr: int, entsize: int = 56) -> bytes:
    entry = bytearray(entsize)
    struct.pack_into("<I", entry, 0, p_type)
    struct.pack_into("<Q", entry, 16, vaddr)  # p_vaddr sits at offset 16 (64-bit)
    return bytes(entry)


def _thin_macho64(*, ncmds: int, sizeofcmds: int, commands: bytes = b"") -> bytes:
    header = _MACHO_LE64 + struct.pack("<IIIII", _X64_CPUTYPE, 3, 2, ncmds, sizeofcmds)
    header += struct.pack("<II", 0, 0)  # flags + reserved
    return header + commands


def _segment64(*, name: bytes, vmaddr: int, fileoff: int, filesize: int) -> bytes:
    segname = name[:16].ljust(16, b"\x00")
    # cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot,
    # initprot, nsects, flags -- a full 72-byte segment_command_64.
    return (
        struct.pack("<II", _LC_SEGMENT_64, 72)
        + segname
        + struct.pack("<QQQQ", vmaddr, 0x1000, fileoff, filesize)
        + struct.pack("<IIII", 0, 0, 0, 0)
    )


# --- ELF --------------------------------------------------------------------


def test_elf_declines_a_program_header_table_over_the_size_cap(tmp_path: Path) -> None:
    # phnum is within the 4096 sanity cap, but a 65535-byte phentsize makes the
    # table exceed _MAX_HEADER, so the read is refused and the base stays None.
    data = _elf64_ident(phoff=64, phentsize=0xFFFF, phnum=4096)
    arch, base = elf_preferred_base(_write(tmp_path, "elf-huge-table", data))
    assert arch is Architecture.X64
    assert base is None


def test_elf_open_failure_degrades_to_none(tmp_path: Path) -> None:
    # A directory opened "rb" raises IsADirectoryError (an OSError), which the
    # reader must swallow into (None, None) rather than propagate.
    assert elf_preferred_base(tmp_path) == (None, None)


def test_elf_skips_non_pt_load_segments_and_takes_the_load_vaddr(tmp_path: Path) -> None:
    table = _phdr64(p_type=4, vaddr=0x9999) + _phdr64(p_type=1, vaddr=0x400000)
    data = _elf64_ident(phoff=64, phentsize=56, phnum=2) + table
    arch, base = elf_preferred_base(_write(tmp_path, "elf-note-then-load", data))
    assert arch is Architecture.X64
    # The PT_NOTE at 0x9999 is skipped; the PT_LOAD vaddr is the base.
    assert base == 0x400000


# --- Mach-O -----------------------------------------------------------------


def test_macho_open_failure_degrades_to_none(tmp_path: Path) -> None:
    assert macho_preferred_base(tmp_path) == (None, None)
    assert macho_slice_span(tmp_path, Architecture.X64) is None


def test_macho_declines_a_command_region_shorter_than_sizeofcmds(tmp_path: Path) -> None:
    # sizeofcmds is within the cap but no command bytes follow the header.
    data = _thin_macho64(ncmds=1, sizeofcmds=100, commands=b"")
    arch, base = macho_preferred_base(_write(tmp_path, "macho-short-cmds", data))
    assert arch is Architecture.X64
    assert base is None


def test_macho_stops_when_a_trailing_stub_cannot_hold_a_command(tmp_path: Path) -> None:
    # Four trailing bytes: too few for even the 8-byte cmd/cmdsize prefix, so
    # the cursor breaks out rather than reading past the buffer.
    data = _thin_macho64(ncmds=1, sizeofcmds=4, commands=b"\x00\x00\x00\x00")
    arch, base = macho_preferred_base(_write(tmp_path, "macho-stub", data))
    assert arch is Architecture.X64
    assert base is None


def test_macho_skips_a_non_segment_command(tmp_path: Path) -> None:
    cmd = struct.pack("<II", _LC_LOAD_DYLIB, 16) + b"\x00" * 8
    data = _thin_macho64(ncmds=1, sizeofcmds=len(cmd), commands=cmd)
    arch, base = macho_preferred_base(_write(tmp_path, "macho-dylib", data))
    assert arch is Architecture.X64
    # No segment command at all, so no base is invented.
    assert base is None


def test_macho_falls_back_to_lowest_segment_when_no_header_segment(tmp_path: Path) -> None:
    # A __DATA segment with a non-zero fileoff: it is not the fileoff==0 header
    # segment, so header_base stays None and the parser returns min_base.
    seg = _segment64(name=b"__DATA", vmaddr=0x2000, fileoff=0x1000, filesize=0x1000)
    data = _thin_macho64(ncmds=1, sizeofcmds=len(seg), commands=seg)
    arch, base = macho_preferred_base(_write(tmp_path, "macho-data-only", data))
    assert arch is Architecture.X64
    assert base == 0x2000
