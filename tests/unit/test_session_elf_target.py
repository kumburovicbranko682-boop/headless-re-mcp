"""ELF is a first-class local-binary session target, distinct from PE.

The session layer only ever minted PE targets for local files: classify_target
routed anything non-Android, non-web to PE, and create() then ran the PE machine
probe -- so an ELF failed with "not a PE file" and never reached the r2/Ghidra
tools that read it fine. These tests pin the ELF path: the magic bytes select
the ELF kind, the header names x86/x64 (and declines ARM/AArch64 the enum cannot
name, without raising), a big-endian header is decoded with its own endianness,
and registry.create binds an ELF session with a real binary and no PE probe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.session import (
    SessionRegistry,
    classify_target,
    detect_elf_architecture,
)


def _elf_header(*, ei_class: int, ei_data: int, machine: int) -> bytes:
    """A 20-byte ELF prefix: enough for e_ident and e_machine."""
    header = bytearray(20)
    header[:4] = b"\x7fELF"
    header[4] = ei_class
    header[5] = ei_data
    endian = "big" if ei_data == 2 else "little"
    header[18:20] = int(machine).to_bytes(2, endian)
    return bytes(header)


def _write_elf(path: Path, *, ei_class: int = 2, ei_data: int = 1, machine: int = 0x3E) -> Path:
    path.write_bytes(_elf_header(ei_class=ei_class, ei_data=ei_data, machine=machine))
    return path


def test_classify_target_routes_elf_magic_to_the_elf_kind(tmp_path: Path) -> None:
    # No extension, ELF magic only -- the case a PE-first classifier got wrong.
    binary = _write_elf(tmp_path / "a.out")
    assert classify_target(binary) is TargetKind.ELF
    # And the PE magic still wins for PE, so the split is real, not a catch-all.
    pe = tmp_path / "x.exe"
    pe.write_bytes(b"MZ" + bytes(62))
    assert classify_target(pe) is TargetKind.PE


@pytest.mark.parametrize(
    ("ei_class", "machine", "expected"),
    [
        (1, 0x03, Architecture.X86),   # EM_386
        (2, 0x3E, Architecture.X64),   # EM_X86_64
        (1, 0x28, None),               # EM_ARM -- analyzable, but no enum member
        (2, 0xB7, None),               # EM_AARCH64 -- same
        (2, 0x08, None),               # EM_MIPS -- same
    ],
)
def test_detect_elf_architecture_names_only_what_the_enum_can(
    tmp_path: Path, ei_class: int, machine: int, expected: Architecture | None
) -> None:
    binary = _write_elf(tmp_path / "bin", ei_class=ei_class, machine=machine)
    assert detect_elf_architecture(binary) == expected


def test_detect_elf_architecture_honours_declared_endianness(tmp_path: Path) -> None:
    # A big-endian ELF stores e_machine big-endian; a little-endian read would
    # see 0x3E00 and name nothing. The probe must use EI_DATA.
    be = _write_elf(tmp_path / "be", ei_class=2, ei_data=2, machine=0x3E)
    assert detect_elf_architecture(be) == Architecture.X64


def test_detect_elf_architecture_declines_a_truncated_header_without_raising(
    tmp_path: Path,
) -> None:
    # classify_target only sends real \x7fELF files here, but a truncated one
    # must still open as a session (arch unknown), not abort session creation.
    stub = tmp_path / "short"
    stub.write_bytes(b"\x7fELF\x02\x01")
    assert detect_elf_architecture(stub) is None


def test_registry_create_binds_an_elf_session_with_no_pe_probe(tmp_path: Path) -> None:
    binary = _write_elf(tmp_path / "prog", ei_class=2, machine=0x3E)
    registry = SessionRegistry()
    session = registry.create(binary)
    assert session.target is TargetKind.ELF
    assert session.binary == binary.resolve()
    assert session.architecture == Architecture.X64
    assert session.sha256


def test_registry_create_opens_an_arm_elf_with_unknown_architecture(tmp_path: Path) -> None:
    # The key regression: an AArch64 ELF used to die in the PE probe. Now it
    # opens, carrying no architecture label -- the static backends read it.
    binary = _write_elf(tmp_path / "arm", ei_class=2, machine=0xB7)
    session = SessionRegistry().create(binary)
    assert session.target is TargetKind.ELF
    assert session.architecture is None
    assert session.binary == binary.resolve()
