"""ELF Address mapping for the r2 backend (no live r2 required).

``pe_preferred_base`` handled PE ImageBase, but the r2 surface is used on
non-PE targets too: Android native ``.so`` libraries and Linux binaries are
ELF. Before these tests those results carried a bare ``va`` with no module and
no architecture, because the enrichment only knew how to read a PE header.
``elf_preferred_base`` reads the ELF's preferred load base -- the lowest
PT_LOAD ``p_vaddr`` -- so a r2 vaddr can be turned into a module-relative rva,
and tags the architecture for the x86/x64 the enum can express.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    elf_preferred_base,
    enrich_r2_payload,
    pe_preferred_base,
    preferred_base,
)
from headless_re_mcp.core.models import Architecture

# e_machine values.
_EM_386 = 3
_EM_X86_64 = 62
_EM_ARM = 40
_EM_AARCH64 = 183
# e_type values.
_ET_EXEC = 2
_ET_DYN = 3
_PT_LOAD = 1


def _minimal_elf(
    path: Path,
    *,
    class64: bool = True,
    little: bool = True,
    machine: int = _EM_X86_64,
    etype: int = _ET_DYN,
    load_vaddrs: tuple[int, ...] = (0,),
) -> Path:
    """A smallest-viable ELF: a valid header plus one PT_LOAD per vaddr given."""
    endian = "little" if little else "big"
    count = len(load_vaddrs)
    if class64:
        phoff, phentsize = 0x40, 56
        data = bytearray(phoff + count * phentsize)
        data[4] = 2  # ELFCLASS64
        data[0x20:0x28] = phoff.to_bytes(8, endian)
        data[0x36:0x38] = phentsize.to_bytes(2, endian)
        data[0x38:0x3A] = count.to_bytes(2, endian)
        vaddr_off = 0x10
        vaddr_size = 8
    else:
        phoff, phentsize = 0x34, 32
        data = bytearray(phoff + count * phentsize)
        data[4] = 1  # ELFCLASS32
        data[0x1C:0x20] = phoff.to_bytes(4, endian)
        data[0x2A:0x2C] = phentsize.to_bytes(2, endian)
        data[0x2C:0x2E] = count.to_bytes(2, endian)
        vaddr_off = 0x08
        vaddr_size = 4
    data[0:4] = b"\x7fELF"
    data[5] = 1 if little else 2  # EI_DATA
    data[6] = 1  # EI_VERSION
    data[0x10:0x12] = etype.to_bytes(2, endian)
    data[0x12:0x14] = machine.to_bytes(2, endian)
    for index, vaddr in enumerate(load_vaddrs):
        entry = phoff + index * phentsize
        data[entry : entry + 4] = _PT_LOAD.to_bytes(4, endian)
        data[entry + vaddr_off : entry + vaddr_off + vaddr_size] = vaddr.to_bytes(
            vaddr_size, endian
        )
    path.write_bytes(bytes(data))
    return path


def test_arm64_shared_object_binds_module_and_rva_at_base_zero(tmp_path: Path) -> None:
    """The dominant Android case: an arm64 .so loaded at base 0.

    Its preferred base is 0, which for a PE would be the "unknown" sentinel but
    for a position-independent ELF is the real answer: rva == va. The enum has
    no arm member, so the architecture is left absent, but every address still
    gains the module binding it never had before -- a bare va cannot be rebased
    or cross-referenced, a {module, rva, va} can.
    """
    binary = _minimal_elf(
        tmp_path / "libnative.so", machine=_EM_AARCH64, etype=_ET_DYN, load_vaddrs=(0,)
    )
    arch, base = elf_preferred_base(binary)
    assert arch is None  # AArch64 has no Architecture enum member.
    assert base == 0  # base 0 is returned, not discarded as a sentinel.

    raw = json.dumps([{"offset": 0x1234, "name": "sub_1234", "size": 16}])
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    address = enriched["items"][0]["address"]
    assert address == {"module": "libnative.so", "rva": 0x1234, "va": 0x1234}


def test_x86_64_executable_maps_va_to_rva(tmp_path: Path) -> None:
    """A non-PIE Linux x64 binary loads at a non-zero base; rva = va - base."""
    binary = _minimal_elf(
        tmp_path / "app", machine=_EM_X86_64, etype=_ET_EXEC, load_vaddrs=(0x400000,)
    )
    assert elf_preferred_base(binary) == (Architecture.X64, 0x400000)

    raw = json.dumps([{"offset": 0x401000, "name": "main", "size": 64}])
    enriched = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    address = enriched["items"][0]["address"]
    assert address == {
        "module": "app",
        "rva": 0x1000,
        "va": 0x401000,
        "architecture": "x64",
    }
    assert enriched["image_base"] == 0x400000
    assert enriched["architecture"] == "x64"


def test_x86_32_executable_reads_class32_base(tmp_path: Path) -> None:
    """The 32-bit header puts e_phoff and p_vaddr at different offsets."""
    binary = _minimal_elf(
        tmp_path / "app32",
        class64=False,
        machine=_EM_386,
        etype=_ET_EXEC,
        load_vaddrs=(0x8048000,),
    )
    assert elf_preferred_base(binary) == (Architecture.X86, 0x8048000)


def test_lowest_pt_load_wins_regardless_of_order(tmp_path: Path) -> None:
    """The load base is the lowest mapped vaddr, even if listed out of order."""
    binary = _minimal_elf(
        tmp_path / "multi",
        machine=_EM_X86_64,
        etype=_ET_EXEC,
        load_vaddrs=(0x402000, 0x400000, 0x404000),
    )
    assert elf_preferred_base(binary) == (Architecture.X64, 0x400000)


def test_big_endian_header_is_read_with_its_declared_endianness(tmp_path: Path) -> None:
    """EI_DATA drives the integer decode; a big-endian ELF must still parse."""
    binary = _minimal_elf(
        tmp_path / "be.elf",
        little=False,
        machine=_EM_X86_64,
        etype=_ET_EXEC,
        load_vaddrs=(0x400000,),
    )
    assert elf_preferred_base(binary) == (Architecture.X64, 0x400000)


def test_arm_machine_keeps_base_but_reports_no_architecture(tmp_path: Path) -> None:
    """A 32-bit ARM ELF has no enum member; the base is still usable."""
    binary = _minimal_elf(
        tmp_path / "libarm.so",
        class64=False,
        machine=_EM_ARM,
        etype=_ET_DYN,
        load_vaddrs=(0,),
    )
    assert elf_preferred_base(binary) == (None, 0)


def test_no_pt_load_leaves_base_unknown_but_keeps_arch(tmp_path: Path) -> None:
    """An ELF with no loadable segment yields no base; the arch is still known."""
    binary = _minimal_elf(
        tmp_path / "empty.elf", machine=_EM_X86_64, etype=_ET_EXEC, load_vaddrs=()
    )
    assert elf_preferred_base(binary) == (Architecture.X64, None)


def test_non_elf_input_is_rejected(tmp_path: Path) -> None:
    """A plain file and a PE are not ELFs; neither a missing path."""
    plain = tmp_path / "notelf.bin"
    plain.write_bytes(b"MZ" + b"\0" * 200)
    assert elf_preferred_base(plain) == (None, None)
    assert elf_preferred_base(tmp_path / "missing.elf") == (None, None)


def test_truncated_elf_header_degrades_to_no_base(tmp_path: Path) -> None:
    """A file that starts with the magic but is too short must not raise."""
    stub = tmp_path / "stub.elf"
    stub.write_bytes(b"\x7fELF\x02\x01\x01")
    arch, base = elf_preferred_base(stub)
    assert base is None


def test_preferred_base_dispatches_pe_before_elf(tmp_path: Path) -> None:
    """A PE resolves through the PE reader; an ELF falls through to the ELF one.

    The dispatcher is what enrich_r2_payload calls, so both formats enrich the
    same way. A PE must never be re-read as an ELF (its bytes are not one).
    """
    elf = _minimal_elf(
        tmp_path / "d.so", machine=_EM_X86_64, etype=_ET_DYN, load_vaddrs=(0,)
    )
    assert preferred_base(elf) == (Architecture.X64, 0)

    pe = tmp_path / "demo64.exe"
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    data[pe_offset + 20 : pe_offset + 22] = (0xF0).to_bytes(2, "little")
    optional_off = pe_offset + 24
    data[optional_off : optional_off + 2] = (0x20B).to_bytes(2, "little")
    data[optional_off + 24 : optional_off + 32] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(data))
    assert preferred_base(pe) == pe_preferred_base(pe) == (Architecture.X64, 0x140000000)
