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
from headless_re_mcp.core.session import _read_fat_slices as read_fat_slices

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


def test_classify_target_rejects_a_malformed_cafebabe(tmp_path: Path) -> None:
    # A 0xCAFEBABE file whose arch table does not check out (here nfat=0) is not
    # a fat Mach-O; it falls through to the PE default rather than being claimed.
    fat = tmp_path / "universal"
    fat.write_bytes(b"\xca\xfe\xba\xbe" + bytes(60))
    assert classify_target(fat) is not TargetKind.MACHO


def _thin_bytes(magic: bytes = _LE64, cputype: int = 0x01000007) -> bytes:
    # A header-only thin Mach-O -- enough for a slice, whose magic is all the
    # fat validator reads at the slice offset.
    return magic + struct.pack("<IIIII", cputype, 3, 2, 0, 0) + struct.pack("<II", 0, 0)


def _write_fat(
    path: Path,
    slices: tuple[tuple[int, bytes], ...],
    *,
    magic: bytes = b"\xca\xfe\xba\xbe",
    is64: bool = False,
) -> Path:
    """Wrap thin (cputype, bytes) slices in a fat/universal header.

    Fat headers are always big-endian. Each slice is page-aligned after the
    header + arch table so the declared offsets sit wholly inside the file.
    """
    entry_size = 32 if is64 else 20
    header_end = 8 + entry_size * len(slices)
    cursor = (header_end + 0xFFF) & ~0xFFF
    placed: list[tuple[int, int, int, bytes]] = []  # cputype, offset, size, blob
    for cputype, blob in slices:
        placed.append((cputype, cursor, len(blob), blob))
        cursor += (len(blob) + 0xFFF) & ~0xFFF
    header = magic + struct.pack(">I", len(slices))
    for cputype, offset, size, _blob in placed:
        if is64:
            header += struct.pack(">IIQQII", cputype, 3, offset, size, 12, 0)
        else:
            header += struct.pack(">IIIII", cputype, 3, offset, size, 12)
    image = bytearray(header)
    for _cputype, offset, _size, blob in placed:
        image = image.ljust(offset, b"\x00") + blob
    path.write_bytes(bytes(image))
    return path


# A conventional x86_64 + arm64 universal pair, the common macOS distribution.
_X64_ARM64 = (
    (0x01000007, _thin_bytes(cputype=0x01000007)),
    (0x0100000C, _thin_bytes(cputype=0x0100000C)),
)


def test_classify_target_claims_a_valid_fat_macho(tmp_path: Path) -> None:
    binary = _write_fat(tmp_path / "universal", _X64_ARM64)
    assert classify_target(binary) is TargetKind.MACHO


def test_read_fat_slices_enumerates_the_contained_architectures(tmp_path: Path) -> None:
    binary = _write_fat(tmp_path / "universal", _X64_ARM64)
    slices = read_fat_slices(binary)
    assert slices is not None
    assert [s["architecture"] for s in slices] == ["x64", "arm64"]
    assert all(s["size"] > 0 and s["offset"] > 0 for s in slices)


def test_read_fat_slices_handles_fat_magic_64_offsets(tmp_path: Path) -> None:
    binary = _write_fat(
        tmp_path / "u64",
        ((0x0100000C, _thin_bytes(cputype=0x0100000C)),),
        magic=b"\xca\xfe\xba\xbf",
        is64=True,
    )
    assert classify_target(binary) is TargetKind.MACHO
    slices = read_fat_slices(binary)
    assert slices is not None and slices[0]["architecture"] == "arm64"


def test_read_fat_slices_rejects_a_java_class_lookalike(tmp_path: Path) -> None:
    # A Java class is 0xCAFEBABE + minor(2) + major(2); major >= 45 makes the
    # big-endian nfat_arch read >= 45, above the ceiling, so it is never a fat.
    java = tmp_path / "Fake.class"
    java.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(256))
    assert read_fat_slices(java) is None
    assert classify_target(java) is not TargetKind.MACHO


def test_read_fat_slices_rejects_an_out_of_bounds_slice(tmp_path: Path) -> None:
    # A well-formed count but a slice pointing past EOF is not a fat Mach-O.
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1)
    header += struct.pack(">IIIII", 0x01000007, 3, 0x100000, 0x1000, 12)  # offset past EOF
    bogus = tmp_path / "bogus"
    bogus.write_bytes(header + bytes(64))
    assert read_fat_slices(bogus) is None


def test_read_fat_slices_rejects_a_slice_without_a_macho_magic(tmp_path: Path) -> None:
    # Offsets in bounds, but the bytes at the slice offset are not a thin Mach-O.
    not_macho = b"\x7fELF" + bytes(28)
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1)
    header += struct.pack(">IIIII", 0x01000007, 3, 0x1000, len(not_macho), 12)
    image = bytearray(header).ljust(0x1000, b"\x00") + not_macho
    path = tmp_path / "elfslice"
    path.write_bytes(bytes(image))
    assert read_fat_slices(path) is None


def test_registry_create_labels_fat_as_multi_arch_with_slice_metadata(tmp_path: Path) -> None:
    binary = _write_fat(tmp_path / "app", _X64_ARM64)
    session = SessionRegistry().create(binary)
    assert session.target is TargetKind.MACHO
    # No single architecture for a fat file -- the backends pick a slice.
    assert session.architecture is None
    macho = session.metadata["macho"]
    assert macho["fat"] is True
    assert [s["architecture"] for s in macho["slices"]] == ["x64", "arm64"]


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
