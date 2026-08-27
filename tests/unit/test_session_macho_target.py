"""Mach-O is a first-class local-binary session target, alongside PE and ELF.

classify_target routed anything non-Android, non-web, non-ELF to PE, so a
macOS/iOS Mach-O failed in the PE machine probe and never reached the r2/Ghidra
tools that read it fine. These tests pin the Mach-O path: each of the four thin
magics selects the Mach-O kind, the header names x86/x64/arm/arm64 (and declines
a cputype the enum cannot name, without raising), a big-endian (PowerPC) header
is decoded with its own byte order, a fat/universal binary is *not* claimed
(its magic collides with Java), and registry.create binds a Mach-O session with
a real binary and no PE probe.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.session import (
    SessionRegistry,
    classify_target,
    detect_macho_architecture,
)

# (raw magic bytes, is64, endianness) for the four thin Mach-O forms.
_LE64 = b"\xcf\xfa\xed\xfe"
_LE32 = b"\xce\xfa\xed\xfe"
_BE64 = b"\xfe\xed\xfa\xcf"
_BE32 = b"\xfe\xed\xfa\xce"


def _write_macho(
    path: Path, *, magic: bytes = _LE64, cputype: int = 0x01000007, endian: str = "little"
) -> Path:
    order = "<" if endian == "little" else ">"
    # magic + cputype + cpusubtype + filetype + ncmds + sizeofcmds + flags.
    header = magic + struct.pack(order + "IIIII", cputype, 3, 2, 0, 0) + struct.pack(order + "I", 0)
    path.write_bytes(header)
    return path


@pytest.mark.parametrize("magic", [_LE64, _LE32, _BE64, _BE32])
def test_classify_target_routes_every_thin_macho_magic(tmp_path: Path, magic: bytes) -> None:
    endian = "little" if magic in (_LE64, _LE32) else "big"
    binary = _write_macho(tmp_path / "a.out", magic=magic, cputype=7, endian=endian)
    assert classify_target(binary) is TargetKind.MACHO


def test_classify_target_leaves_pe_and_elf_alone(tmp_path: Path) -> None:
    # The split is real, not a catch-all: PE and ELF still win their own magic.
    pe = tmp_path / "x.exe"
    pe.write_bytes(b"MZ" + bytes(62))
    assert classify_target(pe) is TargetKind.PE
    elf = tmp_path / "a.elf"
    elf.write_bytes(b"\x7fELF" + bytes(16))
    assert classify_target(elf) is TargetKind.ELF


def test_classify_target_does_not_claim_a_fat_binary(tmp_path: Path) -> None:
    # FAT_MAGIC (0xCAFEBABE) collides with Java .class; a fat file is left to
    # the PE fallback rather than mis-typed as a thin Mach-O we cannot base.
    fat = tmp_path / "universal"
    fat.write_bytes(b"\xca\xfe\xba\xbe" + bytes(60))
    assert classify_target(fat) is not TargetKind.MACHO


@pytest.mark.parametrize(
    ("magic", "endian", "cputype", "expected"),
    [
        (_LE32, "little", 0x00000007, Architecture.X86),   # CPU_TYPE_X86
        (_LE64, "little", 0x01000007, Architecture.X64),   # CPU_TYPE_X86_64
        (_LE32, "little", 0x0000000C, Architecture.ARM),   # CPU_TYPE_ARM
        (_LE64, "little", 0x0100000C, Architecture.ARM64),  # CPU_TYPE_ARM64
        (_LE64, "little", 0x01000012, None),               # CPU_TYPE_POWERPC64
        (_BE32, "big", 0x00000012, None),                  # CPU_TYPE_POWERPC
    ],
)
def test_detect_macho_architecture_names_only_what_the_enum_can(
    tmp_path: Path, magic: bytes, endian: str, cputype: int, expected: Architecture | None
) -> None:
    binary = _write_macho(tmp_path / "bin", magic=magic, cputype=cputype, endian=endian)
    assert detect_macho_architecture(binary) == expected


def test_detect_macho_architecture_honours_declared_endianness(tmp_path: Path) -> None:
    # A big-endian Mach-O stores cputype big-endian; a little-endian read would
    # see a byte-swapped value and name nothing. The probe must use the magic.
    be = _write_macho(tmp_path / "ppc", magic=_BE64, cputype=0x01000007, endian="big")
    assert detect_macho_architecture(be) == Architecture.X64


def test_detect_macho_architecture_declines_a_truncated_header_without_raising(
    tmp_path: Path,
) -> None:
    stub = tmp_path / "short"
    stub.write_bytes(_LE64 + b"\x07")  # magic but no full cputype
    assert detect_macho_architecture(stub) is None


def test_registry_create_binds_a_macho_session_with_no_pe_probe(tmp_path: Path) -> None:
    binary = _write_macho(tmp_path / "prog", magic=_LE64, cputype=0x01000007)
    session = SessionRegistry().create(binary)
    assert session.target is TargetKind.MACHO
    assert session.binary == binary.resolve()
    assert session.architecture is Architecture.X64
    assert session.sha256


def test_registry_create_labels_an_arm64_macho_session(tmp_path: Path) -> None:
    # An Apple-silicon Mach-O opens and carries the arm64 label the static
    # backends can rely on, the key regression the PE probe used to block.
    binary = _write_macho(tmp_path / "arm64", magic=_LE64, cputype=0x0100000C)
    session = SessionRegistry().create(binary)
    assert session.target is TargetKind.MACHO
    assert session.architecture is Architecture.ARM64


def test_registry_create_opens_an_unnamed_arch_macho_without_a_label(tmp_path: Path) -> None:
    # A cputype the enum cannot name (PowerPC64) still opens as a working Mach-O
    # session with architecture=None -- the backends read it themselves.
    binary = _write_macho(tmp_path / "ppc64", magic=_LE64, cputype=0x01000012)
    session = SessionRegistry().create(binary)
    assert session.target is TargetKind.MACHO
    assert session.architecture is None
