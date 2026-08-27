"""Mach-O address mapping: Mach-O payloads gain rva/module/arch, not just va.

pe_preferred_base and elf_preferred_base both return (None, None) for a Mach-O,
so without a Mach-O parser enrich_r2_payload would emit va-only Address objects
for it. These tests pin the Mach-O path: macho_preferred_base reads the load
base from the segment that maps the mach header (the vmaddr radare2 reports as
$B, verified against a real r2 in development) while skipping __PAGEZERO, names
the cputype, and the shared preferred_base chains PE -> ELF -> Mach-O so both
the r2 and Ghidra enrichers attach identical coordinates. A non-Mach-O file
yields no base, and a fat binary is declined.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.mapping import enrich_ghidra_payload
from headless_re_mcp.backends.r2.mapping import (
    enrich_r2_payload,
    macho_preferred_base,
    preferred_base,
)
from headless_re_mcp.core.models import Architecture

_LE64 = b"\xcf\xfa\xed\xfe"
_LE32 = b"\xce\xfa\xed\xfe"
_BE64 = b"\xfe\xed\xfa\xcf"


def _segment(
    order: str, name: str, vmaddr: int, fileoff: int, filesize: int, *, is64: bool
) -> bytes:
    if is64:
        body = struct.pack(order + "II", 0x19, 72)
        body += name.encode().ljust(16, b"\x00")
        body += struct.pack(order + "QQQQ", vmaddr, 0x1000, fileoff, filesize)
        body += struct.pack(order + "IIII", 0, 5, 0, 0)
    else:
        body = struct.pack(order + "II", 0x01, 56)
        body += name.encode().ljust(16, b"\x00")
        body += struct.pack(order + "IIII", vmaddr, 0x1000, fileoff, filesize)
        body += struct.pack(order + "IIII", 0, 5, 0, 0)
    return body


def _write_macho(
    path: Path,
    *,
    magic: bytes = _LE64,
    cputype: int = 0x01000007,
    endian: str = "little",
    segments: tuple[tuple[str, int, int, int], ...] = (
        ("__PAGEZERO", 0, 0, 0),
        ("__TEXT", 0x100000000, 0, 0x1000),
    ),
) -> Path:
    """A minimal but structurally valid thin Mach-O: header + LC_SEGMENT(_64)s.

    Each segment is (segname, vmaddr, fileoff, filesize); only the fields
    macho_preferred_base reads are meaningful.
    """
    order = "<" if endian == "little" else ">"
    is64 = magic in (_LE64, _BE64)
    cmds = b"".join(
        _segment(order, name, vmaddr, fileoff, filesize, is64=is64)
        for (name, vmaddr, fileoff, filesize) in segments
    )
    header = magic + struct.pack(order + "IIIII", cputype, 3, 2, len(segments), len(cmds))
    header += struct.pack(order + "I", 0)  # flags
    if is64:
        header += struct.pack(order + "I", 0)  # reserved
    path.write_bytes(header + cmds)
    return path


@pytest.mark.parametrize(
    ("magic", "endian", "cputype", "arch", "text_vmaddr"),
    [
        (_LE64, "little", 0x01000007, Architecture.X64, 0x100000000),
        (_LE32, "little", 0x00000007, Architecture.X86, 0x00004000),
        (_BE64, "big", 0x0100000C, Architecture.ARM64, 0x100000000),
    ],
)
def test_macho_preferred_base_names_arch_and_reads_text_vmaddr(
    tmp_path: Path,
    magic: bytes,
    endian: str,
    cputype: int,
    arch: Architecture,
    text_vmaddr: int,
) -> None:
    binary = _write_macho(
        tmp_path / "bin",
        magic=magic,
        cputype=cputype,
        endian=endian,
        segments=(("__PAGEZERO", 0, 0, 0), ("__TEXT", text_vmaddr, 0, 0x1000)),
    )
    got_arch, base = macho_preferred_base(binary)
    assert got_arch is arch
    # The base is __TEXT's vmaddr (fileoff 0, non-empty), not __PAGEZERO's 0.
    assert base == text_vmaddr


def test_macho_preferred_base_skips_pagezero_for_a_low_text(tmp_path: Path) -> None:
    # __PAGEZERO is at 0; the header-mapping segment here sits at 0x4000 (a PIE-
    # style low base). The derived base must be __TEXT's, never __PAGEZERO's 0.
    binary = _write_macho(
        tmp_path / "low",
        segments=(("__PAGEZERO", 0, 0, 0), ("__TEXT", 0x4000, 0, 0x1000)),
    )
    _arch, base = macho_preferred_base(binary)
    assert base == 0x4000


def test_macho_preferred_base_unknown_cputype_still_yields_base(tmp_path: Path) -> None:
    # PowerPC64: no enum member, but the base is still readable so addresses can
    # still carry rva/module even when the arch label is absent.
    binary = _write_macho(tmp_path / "ppc64", cputype=0x01000012)
    arch, base = macho_preferred_base(binary)
    assert arch is None
    assert base == 0x100000000


def test_macho_preferred_base_declines_non_macho_and_fat(tmp_path: Path) -> None:
    elf = tmp_path / "a.elf"
    elf.write_bytes(b"\x7fELF" + bytes(60))
    assert macho_preferred_base(elf) == (None, None)
    fat = tmp_path / "universal"
    fat.write_bytes(b"\xca\xfe\xba\xbe" + bytes(60))
    assert macho_preferred_base(fat) == (None, None)


def test_preferred_base_chains_pe_elf_macho(tmp_path: Path) -> None:
    # A Mach-O is reached only after PE and ELF both decline; the chain returns
    # the Mach-O base/arch rather than (None, None).
    binary = _write_macho(tmp_path / "chain")
    assert preferred_base(binary) == (Architecture.X64, 0x100000000)


def test_enrich_r2_payload_maps_macho_item_addresses(tmp_path: Path) -> None:
    binary = _write_macho(tmp_path / "app")
    raw = json.dumps([{"offset": 0x100001000, "name": "main", "size": 16}])
    payload = enrich_r2_payload({"raw": raw, "commands": ["aa", "aflj"]}, binary=binary)
    assert payload["module"] == "app"
    assert payload["image_base"] == 0x100000000
    assert payload["architecture"] == "x64"
    assert payload["items"][0]["address"] == {
        "module": "app",
        "rva": 0x1000,
        "va": 0x100001000,
        "architecture": "x64",
    }


def test_enrich_ghidra_payload_maps_macho_entry_addresses(tmp_path: Path) -> None:
    # The Ghidra enricher shares preferred_base, so a Mach-O function entry gets
    # the identical coordinate object the r2 path produces for the same address.
    binary = _write_macho(tmp_path / "app")
    payload = enrich_ghidra_payload(
        {"mode": "functions", "items": [{"name": "main", "entry": "100001000"}], "count": 1},
        binary=binary,
    )
    assert payload["image_base"] == 0x100000000
    assert payload["items"][0]["entry_address"] == {
        "module": "app",
        "rva": 0x1000,
        "va": 0x100001000,
        "architecture": "x64",
    }
