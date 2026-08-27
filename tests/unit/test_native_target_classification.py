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

from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.session import SessionRegistry, classify_target, describe_native

_MACHO_MAGICS = [
    b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
    b"\xce\xfa\xed\xfe",  # 32-bit little-endian
    b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
    b"\xfe\xed\xfa\xce",  # 32-bit big-endian
]


def _write(path: Path, head: bytes) -> Path:
    path.write_bytes(head + b"\x00" * 64)
    return path


def _elf_header(*, bits: int, endian: str, e_type: int, e_machine: int) -> bytes:
    """A first-20-bytes ELF header -- all describe_native reads."""
    ei_class = {32: 1, 64: 2}[bits]
    ei_data = {"little": 1, "big": 2}[endian]
    order = "little" if endian == "little" else "big"
    return (
        b"\x7fELF"
        + bytes([ei_class, ei_data, 1])
        + b"\x00" * 9
        + e_type.to_bytes(2, order)
        + e_machine.to_bytes(2, order)
    )


def _macho_header(*, magic: bytes, big: bool, cputype: int, filetype: int) -> bytes:
    order = "big" if big else "little"
    return magic + cputype.to_bytes(4, order) + b"\x00" * 4 + filetype.to_bytes(4, order)


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
    # File-backed with no fabricated PE machine type (the zero-filled header has
    # machine 0, so no architecture is claimed).
    assert session.binary == elf.resolve()
    assert session.sha256
    assert session.architecture is None
    assert session.require_binary() == elf.resolve()


def test_describe_native_reads_an_elf_executables_identity(tmp_path: Path) -> None:
    path = tmp_path / "prog"
    path.write_bytes(_elf_header(bits=64, endian="little", e_type=2, e_machine=0x3E))
    assert describe_native(path)["native"] == {
        "format": "elf",
        "bits": 64,
        "endian": "little",
        "type": "exec",
        "arch": "x86-64",
    }


def test_describe_native_reads_a_pie_aarch64_elf(tmp_path: Path) -> None:
    """PIE shows as type 'dyn'; aarch64 is reported but is not a modelled Architecture."""
    path = tmp_path / "prog"
    path.write_bytes(_elf_header(bits=64, endian="little", e_type=3, e_machine=0xB7))
    native = describe_native(path)["native"]
    assert native["type"] == "dyn"
    assert native["arch"] == "aarch64"


def test_describe_native_reads_a_macho_executable(tmp_path: Path) -> None:
    path = tmp_path / "mach"
    path.write_bytes(
        _macho_header(magic=b"\xcf\xfa\xed\xfe", big=False, cputype=0x01000007, filetype=2)
    )
    assert describe_native(path)["native"] == {
        "format": "macho",
        "bits": 64,
        "endian": "little",
        "arch": "x86-64",
        "type": "exec",
    }


def test_describe_native_tolerates_a_truncated_header(tmp_path: Path) -> None:
    """The magic was already confirmed; a short header must not raise."""
    path = tmp_path / "stub"
    path.write_bytes(b"\x7fELF")
    assert describe_native(path) == {"native": {"format": "elf"}}


def test_native_session_carries_the_detected_identity(tmp_path: Path) -> None:
    elf = tmp_path / "prog"
    elf.write_bytes(_elf_header(bits=64, endian="little", e_type=2, e_machine=0x3E))
    session = SessionRegistry().create(str(elf))

    assert session.architecture is Architecture.X64
    assert session.metadata["native"]["arch"] == "x86-64"
    assert session.metadata["native"]["format"] == "elf"
