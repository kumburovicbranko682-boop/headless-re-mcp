"""The stdlib ELF reader (summarize_elf) and elf.summary service routing.

Native code -- an Android app's lib/**/*.so, a Linux executable, an ELF malware
sample -- could only be opened here through r2 or Ghidra, external tools that are
not always installed. The ELF header, section table and .dynamic array are exact
structures. These tests pin the reader on a hand-assembled ELF (portable, so they
run on Windows CI too where no real ELF exists): its header, its section list,
the shared-library dependencies/soname/runpath from .dynamic, the stripped flag,
the 32-bit and big-endian header paths, its resilience to a corrupt section
offset, its refusal of a non-ELF, and the service routing that turns a bad file
into a precise envelope rather than a fault.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.elf import ElfParseError, summarize_elf
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _elf_ident(bits: int, endian: str) -> bytes:
    ei_class = 2 if bits == 64 else 1
    ei_data = 1 if endian == "<" else 2
    return b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8


def _build_elf_header_only(
    *, bits: int = 64, endian: str = "<", etype: int = 2, machine: int = 62
) -> bytes:
    """A valid ELF header with no section or program tables (e_shoff = 0)."""
    if bits == 64:
        fmt = endian + "HHIQQQIHHHHHH"
        ehsize = 64
    else:
        fmt = endian + "HHIIIIIHHHHHH"
        ehsize = 52
    header = struct.pack(fmt, etype, machine, 1, 0x1000, 0, 0, 0, ehsize, 0, 0, 0, 0, 0)
    return _elf_ident(bits, endian) + header


def _build_elf64(*, etype: int = 3, machine: int = 62, stripped: bool = False) -> bytes:
    """A little-endian 64-bit ELF with .text/.dynstr/.dynamic (+ .symtab) sections."""
    dynstr = bytearray(b"\x00")

    def add_dynstr(text: str) -> int:
        offset = len(dynstr)
        dynstr.extend(text.encode("ascii") + b"\x00")
        return offset

    off_libc = add_dynstr("libc.so.6")
    off_soname = add_dynstr("libfoo.so")
    off_runpath = add_dynstr("$ORIGIN/../lib")
    dynamic = b"".join(
        struct.pack("<qQ", tag, val)
        for tag, val in [(1, off_libc), (14, off_soname), (29, off_runpath), (0, 0)]
    )
    text = b"\x90" * 8
    symtab = b"\x00" * 24  # one dummy Elf64_Sym, present only when not stripped

    sections: list[tuple[str, int, int, bytes]] = [
        ("", 0, 0, b""),
        (".text", 1, 0x6, text),
        (".dynstr", 3, 0x2, bytes(dynstr)),
        (".dynamic", 6, 0x2, dynamic),
    ]
    if not stripped:
        sections.append((".symtab", 2, 0x0, symtab))
    sections.append((".shstrtab", 3, 0x0, b""))

    shstr = bytearray(b"\x00")
    name_off: dict[str, int] = {}
    for name, _type, _flags, _content in sections:
        if name and name not in name_off:
            name_off[name] = len(shstr)
            shstr.extend(name.encode("ascii") + b"\x00")
    sections[-1] = (".shstrtab", 3, 0x0, bytes(shstr))

    offset = 64
    placed: list[tuple[str, int, int, int, int]] = []
    contents = bytearray()
    for name, stype, flags, content in sections:
        if stype == 0:
            placed.append((name, stype, flags, 0, 0))
            continue
        placed.append((name, stype, flags, offset, len(content)))
        contents.extend(content)
        offset += len(content)
    shoff = offset

    sht = b"".join(
        struct.pack(
            "<IIQQQQIIQQ",
            name_off.get(name, 0) if name else 0,
            stype,
            flags,
            0,
            off,
            size,
            0,
            0,
            1,
            0,
        )
        for name, stype, flags, off, size in placed
    )
    shstrndx = next(i for i, entry in enumerate(placed) if entry[0] == ".shstrtab")
    ehdr = struct.pack(
        "<HHIQQQIHHHHHH",
        etype,
        machine,
        1,
        0x1000,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        len(placed),
        shstrndx,
    )
    return _elf_ident(64, "<") + ehdr + bytes(contents) + sht


def test_full_summary_64() -> None:
    out = summarize_elf(_build_elf64())
    assert out["class"] == "ELF64"
    assert out["bitness"] == 64
    assert out["endianness"] == "little"
    assert out["type"] == "shared object"
    assert out["machine"] == "x86-64"
    assert out["entry"] == "0x1000"
    assert out["has_sections"] is True
    assert out["needed"] == ["libc.so.6"]
    assert out["soname"] == "libfoo.so"
    assert out["runpath"] == "$ORIGIN/../lib"
    assert out["stripped"] is False
    names = {section["name"] for section in out["sections"]}
    assert {".text", ".dynstr", ".dynamic", ".symtab"} <= names
    text = next(s for s in out["sections"] if s["name"] == ".text")
    assert text["flags"] == "AX"
    assert out["warnings"] == []


def test_stripped_binary_has_no_symtab() -> None:
    out = summarize_elf(_build_elf64(stripped=True))
    assert out["stripped"] is True
    assert ".symtab" not in {s["name"] for s in out["sections"]}


def test_executable_type_is_named() -> None:
    out = summarize_elf(_build_elf64(etype=2))
    assert out["type"] == "executable"


def test_header_only_32bit() -> None:
    out = summarize_elf(_build_elf_header_only(bits=32, machine=40))
    assert out["class"] == "ELF32"
    assert out["bitness"] == 32
    assert out["machine"] == "ARM"
    assert out["has_sections"] is False
    assert out["needed"] == []
    assert out["sections"] == []


def test_big_endian_header() -> None:
    out = summarize_elf(_build_elf_header_only(bits=32, endian=">", machine=8))
    assert out["endianness"] == "big"
    assert out["machine"] == "MIPS"


def test_a_section_table_past_eof_is_a_warning() -> None:
    data = bytearray(_build_elf64())
    # e_shoff sits at file offset 40 (16 ident + e_type/e_machine/e_version/e_entry/e_phoff).
    struct.pack_into("<Q", data, 40, 0xFFFFFFF0)  # section table -> past EOF

    out = summarize_elf(bytes(data))
    assert out["sections"] == []
    assert any("past end of file" in w for w in out["warnings"])


@pytest.mark.parametrize(
    "blob",
    [b"", b"MZ\x00\x00" + b"\x00" * 40, b"\x7fELF\x02\x01\x01\x00", b"\x00" * 64],
)
def test_non_elf_raises(blob: bytes) -> None:
    with pytest.raises(ElfParseError):
        summarize_elf(blob)


def test_unknown_class_and_encoding_raise() -> None:
    with pytest.raises(ElfParseError):
        summarize_elf(b"\x7fELF\x09\x01\x01\x00" + b"\x00" * 56)  # bad EI_CLASS
    with pytest.raises(ElfParseError):
        summarize_elf(b"\x7fELF\x02\x09\x01\x00" + b"\x00" * 56)  # bad EI_DATA


# --- service routing ----------------------------------------------------------


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_reads_an_elf(tmp_path: Path) -> None:
    binary = tmp_path / "libfoo.so"
    binary.write_bytes(_build_elf64())
    result = _service(tmp_path).elf_summary(str(binary))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["class"] == "ELF64"
    assert result.data["needed"] == ["libc.so.6"]


def test_service_refuses_a_non_elf(tmp_path: Path) -> None:
    junk = tmp_path / "not.so"
    junk.write_bytes(b"this is not an ELF binary")
    result = _service(tmp_path).elf_summary(str(junk))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).elf_summary(str(tmp_path / "nope.so"))
    assert not result.ok
    assert result.error.code == "not_found"


def test_service_refuses_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.core.service_elf as service_elf

    monkeypatch.setattr(service_elf, "ELF_SUMMARY_MAX_BYTES", 16)
    binary = tmp_path / "libfoo.so"
    binary.write_bytes(_build_elf64())
    result = _service(tmp_path).elf_summary(str(binary))
    assert not result.ok
    assert result.error.code == "too_large"
