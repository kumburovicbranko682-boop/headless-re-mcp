"""ELF/Mach-O binaries are a target kind of their own, not broken PEs.

Until ``TargetKind.NATIVE`` existed, ``classify_target`` mapped an ELF/Mach-O to
PE and ``SessionRegistry.create`` then rejected it in ``detect_pe_architecture``
as "not a PE file", so radare2/Ghidra could not open a session for the binary
format Linux and macOS ship. These pin the classification, the stdlib-only
identity (``describe_native``), and that a native session is file-backed for the
format-agnostic tools yet still refused by the PE-only ones.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, TargetKind, TargetMismatch
from headless_re_mcp.core.session import (
    SessionRegistry,
    classify_target,
    describe_native,
    native_architecture,
)


def _elf(
    *,
    bits: int = 64,
    little: bool = True,
    e_type: int = 2,
    e_machine: int = 0x3E,
) -> bytes:
    order = "little" if little else "big"
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2 if bits == 64 else 1
    head[5] = 1 if little else 2
    head[16:18] = e_type.to_bytes(2, order)
    head[18:20] = e_machine.to_bytes(2, order)
    return bytes(head)


def _macho(magic: bytes, *, cputype: int, filetype: int = 2) -> bytes:
    order = "little" if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else "big"
    head = bytearray(32)
    head[0:4] = magic
    head[4:8] = cputype.to_bytes(4, order)
    head[12:16] = filetype.to_bytes(4, order)
    return bytes(head)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_an_elf_is_classified_native(tmp_path: Path) -> None:
    path = _write(tmp_path, "prog", _elf())
    assert classify_target(path) is TargetKind.NATIVE


@pytest.mark.parametrize(
    "magic",
    [b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"],
)
def test_every_thin_macho_magic_is_classified_native(tmp_path: Path, magic: bytes) -> None:
    path = _write(tmp_path, "prog", _macho(magic, cputype=0x0100000C))
    assert classify_target(path) is TargetKind.NATIVE


def test_a_fat_or_java_cafebabe_is_not_taken_for_native(tmp_path: Path) -> None:
    """0xCAFEBABE opens a Java .class as well as a fat Mach-O; do not guess."""
    path = _write(tmp_path, "Thing.class", b"\xca\xfe\xba\xbe" + b"\x00" * 60)
    assert classify_target(path) is not TargetKind.NATIVE


def test_describe_native_reads_a_64bit_x86_elf(tmp_path: Path) -> None:
    info = describe_native(_write(tmp_path, "prog", _elf()))
    assert info == {
        "native": {
            "format": "elf",
            "bits": 64,
            "endian": "little",
            "type": "executable",
            "arch": "x86-64",
        }
    }
    assert native_architecture(info) is Architecture.X64


def test_describe_native_reads_a_big_endian_32bit_elf(tmp_path: Path) -> None:
    # 32-bit, big-endian, shared object, PowerPC (e_machine 0x14).
    data = _elf(bits=32, little=False, e_type=3, e_machine=0x14)
    info = describe_native(_write(tmp_path, "lib.so", data))
    assert info["native"]["bits"] == 32
    assert info["native"]["endian"] == "big"
    assert info["native"]["type"] == "shared-object"
    assert info["native"]["arch"] == "ppc"
    # ppc has no Architecture; the session records it for display but stays None.
    assert native_architecture(info) is None


def test_describe_native_reads_a_64bit_arm_macho(tmp_path: Path) -> None:
    data = _macho(b"\xcf\xfa\xed\xfe", cputype=0x0100000C, filetype=6)
    info = describe_native(_write(tmp_path, "dylib", data))
    assert info["native"] == {
        "format": "macho",
        "bits": 64,
        "endian": "little",
        "type": "dylib",
        "arch": "aarch64",
    }
    assert native_architecture(info) is None


def test_describe_native_tolerates_a_truncated_header(tmp_path: Path) -> None:
    """A file that is only its magic still reports the format, not a blank."""
    info = describe_native(_write(tmp_path, "stub", b"\x7fELF"))
    assert info["native"]["format"] == "elf"
    assert info["native"]["bits"] is None
    assert info["native"]["arch"] is None


def test_describe_native_refuses_a_non_native_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ELF or Mach-O"):
        describe_native(_write(tmp_path, "text", b"not a binary"))


def test_create_opens_a_native_session_that_pe_tools_refuse(tmp_path: Path) -> None:
    path = _write(tmp_path, "prog", _elf())
    session = SessionRegistry().create(str(path))

    assert session.target is TargetKind.NATIVE
    assert session.architecture is Architecture.X64
    assert session.metadata["native"]["format"] == "elf"
    # File-backed for the format-agnostic tools (radare2/Ghidra use this).
    assert session.require_binary() == path.resolve()
    # But a PE-only tool must still be turned away with a structured mismatch.
    with pytest.raises(TargetMismatch) as caught:
        session.require_pe()
    assert caught.value.details["actual_target"] == TargetKind.NATIVE.value
