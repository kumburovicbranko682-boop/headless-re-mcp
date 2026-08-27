"""Header-based architecture naming shared by the portable static backends."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.backends.common.arch import (
    binary_architecture,
    elf_architecture,
    macho_architecture,
    pe_architecture,
)
from headless_re_mcp.core.models import Architecture


def _pe(tmp_path: Path, *, x64: bool) -> Path:
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    optional_size = 0xF0 if x64 else 0xE0
    data[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    optional_off = pe_offset + 24
    data[optional_off : optional_off + 2] = (0x20B if x64 else 0x10B).to_bytes(2, "little")
    path = tmp_path / ("pe64.bin" if x64 else "pe32.bin")
    path.write_bytes(bytes(data))
    return path


def _elf(tmp_path: Path, *, machine: int, ei_data: int = 1, ei_class: int = 2) -> Path:
    order = "little" if ei_data == 1 else "big"
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    data[4] = ei_class
    data[5] = ei_data
    data[6] = 1
    data[16:18] = (2).to_bytes(2, order)
    data[18:20] = int(machine).to_bytes(2, order)
    path = tmp_path / f"elf_{machine}_{ei_data}.bin"
    path.write_bytes(bytes(data))
    return path


def _macho(tmp_path: Path, *, cputype: int, magic: bytes = b"\xcf\xfa\xed\xfe") -> Path:
    order = "little" if magic[3:4] == b"\xfe" else "big"
    data = bytearray(32)
    data[0:4] = magic
    data[4:8] = int(cputype).to_bytes(4, order)  # type: ignore[arg-type]
    path = tmp_path / f"macho_{cputype}.bin"
    path.write_bytes(bytes(data))
    return path


def test_pe_architecture(tmp_path: Path) -> None:
    assert pe_architecture(_pe(tmp_path, x64=True)) is Architecture.X64
    assert pe_architecture(_pe(tmp_path, x64=False)) is Architecture.X86
    assert pe_architecture(_elf(tmp_path, machine=62)) is None


def test_elf_architecture_names_x86_x64_arm_arm64(tmp_path: Path) -> None:
    assert elf_architecture(_elf(tmp_path, machine=3, ei_class=1)) is Architecture.X86
    assert elf_architecture(_elf(tmp_path, machine=62)) is Architecture.X64
    assert elf_architecture(_elf(tmp_path, machine=40, ei_class=1)) is Architecture.ARM
    assert elf_architecture(_elf(tmp_path, machine=183)) is Architecture.ARM64
    # big-endian e_machine must be honoured, not read little
    assert elf_architecture(_elf(tmp_path, machine=183, ei_data=2)) is Architecture.ARM64
    assert elf_architecture(_elf(tmp_path, machine=243)) is None  # EM_RISCV


def test_macho_architecture_names_x86_x64_arm_arm64(tmp_path: Path) -> None:
    assert macho_architecture(_macho(tmp_path, cputype=0x00000007, magic=b"\xce\xfa\xed\xfe")) \
        is Architecture.X86
    assert macho_architecture(_macho(tmp_path, cputype=0x01000007)) is Architecture.X64
    assert macho_architecture(_macho(tmp_path, cputype=0x0000000C, magic=b"\xce\xfa\xed\xfe")) \
        is Architecture.ARM
    assert macho_architecture(_macho(tmp_path, cputype=0x0100000C)) is Architecture.ARM64
    # fat/universal has no single architecture
    fat = tmp_path / "fat.bin"
    fat.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 24)
    assert macho_architecture(fat) is None


def test_binary_architecture_dispatches_by_format(tmp_path: Path) -> None:
    assert binary_architecture(_pe(tmp_path, x64=True)) is Architecture.X64
    assert binary_architecture(_elf(tmp_path, machine=183)) is Architecture.ARM64  # Android arm64
    assert binary_architecture(_macho(tmp_path, cputype=0x01000007)) is Architecture.X64


def test_binary_architecture_unknown_and_missing(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a known binary header at all, just text")
    assert binary_architecture(junk) is None
    assert binary_architecture(tmp_path / "does-not-exist") is None
