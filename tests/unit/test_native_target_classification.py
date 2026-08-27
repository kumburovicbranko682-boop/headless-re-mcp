"""ELF and Mach-O images are portable-static (native) targets, not PE.

r2 reads ELF/Mach-O exactly as it reads a PE, but ``classify_target`` used to
fall those through to PE, and PE session creation then rejected them with "not a
PE file" -- leaving the entire ``r2.*`` tool surface unreachable for the native
binary formats on Linux/macOS. These pin the classification and that a native
session is created file-backed (so ``require_binary`` -- and thus every r2 tool
-- works) without running r2 itself; ``test_m11_r2_live_gate`` proves the tools
end to end.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import SessionRegistry, classify_target

_MACHO_MAGICS = [
    b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
    b"\xce\xfa\xed\xfe",  # 32-bit little-endian
    b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
    b"\xfe\xed\xfa\xce",  # 32-bit big-endian
]


def _write(path: Path, head: bytes) -> Path:
    path.write_bytes(head + b"\x00" * 64)
    return path


def test_elf_magic_classifies_as_native(tmp_path: Path) -> None:
    assert classify_target(_write(tmp_path / "a.out", b"\x7fELF")) is TargetKind.NATIVE


@pytest.mark.parametrize("magic", _MACHO_MAGICS)
def test_each_macho_magic_classifies_as_native(magic: bytes, tmp_path: Path) -> None:
    assert classify_target(_write(tmp_path / "mach", magic)) is TargetKind.NATIVE


def test_unrecognised_bytes_still_fall_through_to_pe(tmp_path: Path) -> None:
    """The 'not a PE file' path is preserved for genuinely unknown files."""
    assert classify_target(_write(tmp_path / "blob", b"\x01\x02\x03\x04")) is TargetKind.PE
    # The Mach-O fat magic is intentionally NOT native (it collides with a Java
    # .class), so it must not be misclassified.
    assert classify_target(_write(tmp_path / "fat", b"\xca\xfe\xba\xbe")) is TargetKind.PE


def test_native_session_is_created_file_backed_without_pe_validation(tmp_path: Path) -> None:
    """An ELF must produce a usable session -- not the old 'not a PE file'."""
    elf = _write(tmp_path / "prog", b"\x7fELF")
    registry = SessionRegistry()
    session = registry.create(str(elf))

    assert session.target is TargetKind.NATIVE
    # File-backed with no fabricated PE machine type.
    assert session.binary == elf.resolve()
    assert session.sha256
    assert session.architecture is None
    assert session.require_binary() == elf.resolve()
