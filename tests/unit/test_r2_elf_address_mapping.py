"""ELF r2 address mapping: ELF payloads gain rva/module/arch, not just va.

pe_preferred_base returns (None, None) for an ELF, so enrich_r2_payload used to
emit va-only Address objects for ELF -- no module, no rva, no architecture --
while PE payloads carried the full {module, rva, va, architecture}. These tests
pin the ELF path: elf_preferred_base reads the load base from PT_LOAD (matching
radare2's own baddr for ET_EXEC and PIE ET_DYN) and names the machine, and
enrich_r2_payload uses it so an ELF item address is enriched the same way a PE's
is. A PE must not be reparsed as ELF, and a non-ELF/short file yields no base.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.mapping import (
    elf_preferred_base,
    enrich_r2_payload,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture


def _write_elf(
    path: Path,
    *,
    is64: bool = True,
    little: bool = True,
    machine: int = 0x3E,
    loads: tuple[int, ...] = (0x400000,),
) -> Path:
    """A minimal but structurally valid ELF: header + PT_LOAD program headers.

    Only the fields elf_preferred_base reads are meaningful; the segments carry
    the given p_vaddr values so the derived base is min(loads).
    """
    endian = "<" if little else ">"
    ei_data = 1 if little else 2
    phentsize = 56 if is64 else 32
    phoff = 64 if is64 else 52
    data = bytearray(phoff + phentsize * len(loads))
    data[:4] = b"\x7fELF"
    data[4] = 2 if is64 else 1
    data[5] = ei_data
    struct.pack_into(endian + "H", data, 18, machine)
    if is64:
        struct.pack_into(endian + "Q", data, 0x20, phoff)
        struct.pack_into(endian + "H", data, 0x36, phentsize)
        struct.pack_into(endian + "H", data, 0x38, len(loads))
    else:
        struct.pack_into(endian + "I", data, 0x1C, phoff)
        struct.pack_into(endian + "H", data, 0x2A, phentsize)
        struct.pack_into(endian + "H", data, 0x2C, len(loads))
    for i, vaddr in enumerate(loads):
        off = phoff + i * phentsize
        struct.pack_into(endian + "I", data, off, 1)  # p_type = PT_LOAD
        if is64:
            struct.pack_into(endian + "Q", data, off + 16, vaddr)  # p_vaddr
        else:
            struct.pack_into(endian + "I", data, off + 8, vaddr)  # p_vaddr
    path.write_bytes(bytes(data))
    return path


@pytest.mark.parametrize(
    ("is64", "machine", "arch"),
    [
        (True, 0x3E, Architecture.X64),
        (False, 0x03, Architecture.X86),
        (True, 0xB7, Architecture.ARM64),
        (False, 0x28, Architecture.ARM),
    ],
)
def test_elf_preferred_base_names_arch_and_reads_load_base(
    tmp_path: Path, is64: bool, machine: int, arch: Architecture
) -> None:
    binary = _write_elf(tmp_path / "b", is64=is64, machine=machine, loads=(0x10000, 0x400000))
    got_arch, base = elf_preferred_base(binary)
    assert got_arch is arch
    # The base is the lowest PT_LOAD p_vaddr, not the first listed.
    assert base == 0x10000


def test_elf_preferred_base_pie_zero_base(tmp_path: Path) -> None:
    # A PIE ET_DYN loads at p_vaddr 0; the base is 0 (not None), so rva == va.
    binary = _write_elf(tmp_path / "pie", loads=(0x0, 0x1000))
    arch, base = elf_preferred_base(binary)
    assert arch is Architecture.X64
    assert base == 0


def test_elf_preferred_base_honours_endianness(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "be", little=False, machine=0xB7, loads=(0x400000,))
    arch, base = elf_preferred_base(binary)
    assert arch is Architecture.ARM64
    assert base == 0x400000


def test_elf_preferred_base_declines_non_elf_and_short(tmp_path: Path) -> None:
    not_elf = tmp_path / "pe"
    not_elf.write_bytes(b"MZ" + bytes(62))
    assert elf_preferred_base(not_elf) == (None, None)
    short = tmp_path / "short"
    short.write_bytes(b"\x7fELF\x02\x01")
    assert elf_preferred_base(short) == (None, None)


def test_elf_preferred_base_unknown_machine_still_yields_base(tmp_path: Path) -> None:
    # A machine the enum cannot name (RISC-V) still gives its load base, so
    # addresses gain rva/module even without an arch label.
    binary = _write_elf(tmp_path / "riscv", machine=0xF3, loads=(0x400000,))
    arch, base = elf_preferred_base(binary)
    assert arch is None
    assert base == 0x400000


def test_enrich_elf_items_carry_rva_module_and_arch(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "a.out", machine=0x3E, loads=(0x400000,))
    raw = json.dumps([{"offset": 0x401106, "name": "crackme_check", "size": 32}])
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aa", "aflj"]}, binary=binary)

    assert enriched["parsed"] is True
    assert enriched["image_base"] == 0x400000
    assert enriched["architecture"] == "x64"
    address = enriched["items"][0]["address"]
    assert address == {
        "module": "a.out",
        "rva": 0x1106,
        "va": 0x401106,
        "architecture": "x64",
    }


def test_enrich_elf_request_and_edge_addresses_enriched(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "a.out", machine=0x3E, loads=(0x400000,))
    raw = json.dumps([{"from": 0x401183, "to": 0x401136, "type": "CALL"}])
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["axtj"], "address": 0x401136},
        binary=binary,
    )
    # Request address enriched.
    assert enriched["address"]["rva"] == 0x1136
    assert enriched["address"]["module"] == "a.out"
    assert enriched["address_va"] == 0x401136
    # Edge endpoints enriched with the same base.
    item = enriched["items"][0]
    assert item["from_address"]["rva"] == 0x1183
    assert item["to_address"]["rva"] == 0x1136


def test_enrich_does_not_reparse_a_pe_as_elf(tmp_path: Path) -> None:
    # A PE whose parse names its arch must keep PE ImageBase semantics; the ELF
    # fallback only runs when the PE parse found neither arch nor base.
    pe = tmp_path / "demo64.exe"
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_off = 0x80
    data[0x3C:0x40] = pe_off.to_bytes(4, "little")
    data[pe_off : pe_off + 4] = b"PE\0\0"
    data[pe_off + 20 : pe_off + 22] = (0xF0).to_bytes(2, "little")
    opt = pe_off + 24
    data[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    data[opt + 24 : opt + 32] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(data))

    arch, base = pe_preferred_base(pe)
    assert arch is Architecture.X64 and base == 0x140000000
    raw = json.dumps([{"offset": 0x140001000, "name": "entry0"}])
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=pe)
    assert enriched["image_base"] == 0x140000000
    assert enriched["items"][0]["address"]["rva"] == 0x1000
