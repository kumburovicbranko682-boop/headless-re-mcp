"""Native (ELF / Mach-O) targets classify and open as sessions.

Before this, only PE, APK and web were recognised: an ELF fell through to the
PE fallback and ``SessionRegistry.create`` rejected it with "not a PE file", so
the portable backends (radare2, Ghidra) -- which analyse ELF/Mach-O fine --
could not even be reached for a non-Windows native binary. These pin the
classification (including the deliberate refusal of the ambiguous Mach-O fat
magic) and that a native session opens with its binary bound and no PE arch.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.session import SessionRegistry, classify_target, describe_native

_ELF = b"\x7fELF\x02\x01\x01\x00"
_MACHO_THIN = [
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
]


def _write(tmp_path: Path, name: str, magic: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(magic + b"\x00" * 64)
    return path


def test_elf_magic_classifies_as_native(tmp_path: Path) -> None:
    assert classify_target(_write(tmp_path, "prog.elf", _ELF)) is TargetKind.NATIVE
    # No extension either -- magic alone must be enough.
    assert classify_target(_write(tmp_path, "prog", _ELF)) is TargetKind.NATIVE


@pytest.mark.parametrize("magic", _MACHO_THIN)
def test_macho_thin_magics_classify_as_native(tmp_path: Path, magic: bytes) -> None:
    assert classify_target(_write(tmp_path, "prog.macho", magic)) is TargetKind.NATIVE


def test_macho_fat_magic_is_not_treated_as_native(tmp_path: Path) -> None:
    """0xCAFEBABE is also a Java .class file; refuse the collision, stay on PE."""
    fat = _write(tmp_path, "universal", b"\xca\xfe\xba\xbe")
    assert classify_target(fat) is TargetKind.PE


def test_pe_and_unknown_still_classify_as_pe(tmp_path: Path) -> None:
    assert classify_target(_write(tmp_path, "app.exe", b"MZ\x90\x00")) is TargetKind.PE
    # An unrecognised header keeps the historical PE fallback (and its error).
    assert classify_target(_write(tmp_path, "mystery", b"\x01\x02\x03\x04")) is TargetKind.PE


def _elf_header(*, bits: int, order: str, e_type: int, e_machine: int) -> bytes:
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2 if bits == 64 else 1
    head[5] = 1 if order == "little" else 2
    endian = "<" if order == "little" else ">"
    struct.pack_into(f"{endian}H", head, 16, e_type)
    struct.pack_into(f"{endian}H", head, 18, e_machine)
    return bytes(head)


def _macho_header(magic: bytes, *, cputype: int, filetype: int) -> bytes:
    order = "little" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else "big"
    endian = "<" if order == "little" else ">"
    head = bytearray(32)
    head[0:4] = magic
    struct.pack_into(f"{endian}i", head, 4, cputype)
    struct.pack_into(f"{endian}I", head, 12, filetype)
    return bytes(head)


def test_describe_elf_x86_64_names_arch_and_facts(tmp_path: Path) -> None:
    path = tmp_path / "x64.elf"
    path.write_bytes(_elf_header(bits=64, order="little", e_type=2, e_machine=0x3E))
    arch, meta = describe_native(path)
    assert arch is Architecture.X64
    assert meta["native"] == {
        "format": "elf",
        "bits": 64,
        "endianness": "little",
        "type": "executable",
        "machine": "x86-64",
    }


def test_describe_elf_i386_maps_to_x86(tmp_path: Path) -> None:
    path = tmp_path / "x86.elf"
    path.write_bytes(_elf_header(bits=32, order="little", e_type=2, e_machine=0x03))
    arch, meta = describe_native(path)
    assert arch is Architecture.X86
    assert meta["native"]["bits"] == 32
    assert meta["native"]["machine"] == "x86"


def test_describe_elf_aarch64_reports_machine_without_arch(tmp_path: Path) -> None:
    """A non-x86 machine has no Architecture enum value, but must stay legible."""
    path = tmp_path / "arm.elf"
    path.write_bytes(_elf_header(bits=64, order="little", e_type=3, e_machine=0xB7))
    arch, meta = describe_native(path)
    assert arch is None
    assert meta["native"]["machine"] == "aarch64"
    assert meta["native"]["type"] == "shared-object"


def test_describe_elf_big_endian_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "be.elf"
    path.write_bytes(_elf_header(bits=64, order="big", e_type=2, e_machine=0x14))
    _, meta = describe_native(path)
    assert meta["native"]["endianness"] == "big"
    assert meta["native"]["machine"] == "ppc"


def test_describe_macho_x86_64_executable(tmp_path: Path) -> None:
    path = tmp_path / "prog.macho"
    path.write_bytes(_macho_header(b"\xcf\xfa\xed\xfe", cputype=0x01000007, filetype=2))
    arch, meta = describe_native(path)
    assert arch is Architecture.X64
    assert meta["native"] == {
        "format": "macho",
        "bits": 64,
        "endianness": "little",
        "type": "executable",
        "machine": "x86-64",
    }


def test_describe_macho_arm64_reports_machine_without_arch(tmp_path: Path) -> None:
    path = tmp_path / "arm.macho"
    path.write_bytes(_macho_header(b"\xcf\xfa\xed\xfe", cputype=0x0100000C, filetype=6))
    arch, meta = describe_native(path)
    assert arch is None
    assert meta["native"]["machine"] == "arm64"
    assert meta["native"]["type"] == "dylib"


def test_describe_unrecognised_header_is_a_minimal_block(tmp_path: Path) -> None:
    path = tmp_path / "mystery"
    path.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 32)
    arch, meta = describe_native(path)
    assert arch is None
    assert meta == {"native": {"format": "unknown"}}


def test_create_opens_a_native_session_with_its_binary(tmp_path: Path) -> None:
    elf = tmp_path / "native.bin"
    elf.write_bytes(_elf_header(bits=64, order="little", e_type=2, e_machine=0x3E))
    session = SessionRegistry().create(elf)

    assert session.target is TargetKind.NATIVE
    assert session.binary == elf.resolve()
    assert session.sha256
    # The x86-64 machine type is now first-class, and the header facts ride
    # along in metadata exactly like describe_apk populates an APK session.
    assert session.architecture is Architecture.X64
    assert session.metadata["native"]["format"] == "elf"
    assert session.metadata["native"]["machine"] == "x86-64"
