"""Native (ELF / Mach-O) targets classify and open as sessions.

Before this, only PE, APK and web were recognised: an ELF fell through to the
PE fallback and ``SessionRegistry.create`` rejected it with "not a PE file", so
the portable backends (radare2, Ghidra) -- which analyse ELF/Mach-O fine --
could not even be reached for a non-Windows native binary. These pin the
classification (including the deliberate refusal of the ambiguous Mach-O fat
magic) and that a native session opens with its binary bound and no PE arch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import SessionRegistry, classify_target

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


def test_create_opens_a_native_session_with_its_binary(tmp_path: Path) -> None:
    elf = _write(tmp_path, "native.bin", _ELF)
    session = SessionRegistry().create(elf)

    assert session.target is TargetKind.NATIVE
    assert session.binary == elf.resolve()
    assert session.sha256
    # No PE machine type was parsed (and, crucially, no "not a PE file" raised).
    assert session.architecture is None
