"""Cross-validate the entry-owner fact against pefile, readelf and llvm.

A session over a PE, ELF or Mach-O now names the section that owns the entry
point -- the home of the first executed byte. ".text"/"__text" is the boring
answer a linker emits; a packer stub's own section (UPX1) is the classic
anomaly; None -- no section table, or no mapped section claiming the address
-- is itself a triage fact. The span arithmetic is the reader's own in every
format (PE virtual spans against the entry RVA, ELF sh_addr spans of ALLOC
sections against e_entry, Mach-O section file spans against LC_MAIN's
entryoff), so each format gets its own independent referee:

- PE: pefile's ``get_section_by_rva`` resolves the owner through its own
  section objects, over the committed UPX pair -- the same program before and
  after packing, where the owner flips from .text to UPX1.
- ELF: readelf prints the entry address (``-h``) and the section table
  (``-S``); recomputing the owner from its rows must land on the session's
  answer over a real gcc binary, and a header edit that drops the section
  table (what sstrip ships) pins the honest None.
- Mach-O: llvm-objdump prints LC_MAIN's entryoff and llvm-readobj the section
  file spans; recomputing the owner from those must land on the session's
  answer over the committed fixture.

pefile ships in the project's ``pe`` extra; readelf/gcc come from binutils/gcc
and llvm-objdump/llvm-readobj from the workflow's llvm install. skip != pass:
each leg skips, naming the missing piece, only when its own referee is absent.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_UPX_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "upx"
_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"

# readelf -SW rows whose flags include A (SHF_ALLOC) -- the only sections that
# can own an entry: "[14] .text PROGBITS 0000000000001040 001040 0000f8 00 AX ...".
_READELF_ALLOC_ROW_RE = re.compile(
    r"\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+\S*A\S*\s",
    re.IGNORECASE,
)
_READELF_ENTRY_RE = re.compile(r"Entry point address:\s+0x([0-9a-f]+)", re.IGNORECASE)
# llvm-objdump --macho --all-headers prints LC_MAIN as "cmd LC_MAIN" /
# "cmdsize 24" / "entryoff 1088"; llvm-readobj --sections prints per-section
# "Name: __text (...)", "Size: 0x8" and a decimal file "Offset: 1088" (the
# RelocationOffset line that follows is hex-prefixed, so it cannot match).
_MACHO_ENTRYOFF_RE = re.compile(r"^\s*entryoff\s+(\d+)\s*$", re.MULTILINE)
_MACHO_SECTION_RE = re.compile(
    r"Name:\s+(\S+)\s+\(.*?\n.*?Size:\s+0x([0-9a-f]+).*?\n\s+Offset:\s+(\d+)",
    re.DOTALL,
)


def _pefile() -> ModuleType | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _session_entry_facts(path: Path) -> dict[str, Any]:
    """The reader's entry facts off a session's pe/native metadata block."""
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        metadata = created.data["session"]["metadata"]
        facts = metadata.get("pe") or metadata.get("native") or {}
        return {key: facts.get(key) for key in ("entry", "entry_section")}
    finally:
        service.close_all()


@pytest.mark.integration
def test_pe_entry_owner_agrees_with_pefile_on_the_upx_pair() -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE entry-owner gate not run (skip != pass)")
    pairs = [
        (
            _UPX_ROOT / f"console_fixture-{arch}.pre-upx.exe",
            _UPX_ROOT / f"console_fixture-{arch}.upx.exe",
        )
        for arch in ("x64", "x86")
    ]
    if not all(pre.is_file() and packed.is_file() for pre, packed in pairs):
        pytest.skip(f"upx fixtures missing under {_UPX_ROOT} (skip != pass)")

    for pre, packed in pairs:
        for binary in (pre, packed):
            # Independent ground truth: pefile resolves the owner through its
            # own section objects and its own contains_rva arithmetic.
            pe = pefile_mod.PE(str(binary))
            rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            section = pe.get_section_by_rva(rva)
            assert section is not None, f"{binary.name}: pefile finds no owner"
            expected = section.Name.rstrip(b"\x00").decode("latin-1")
            assert _session_entry_facts(binary)["entry_section"] == expected
        # The semantic anchor: packing the same program moved the entry from
        # the compiler's code section into the packer stub's.
        assert _session_entry_facts(pre)["entry_section"] == ".text"
        assert _session_entry_facts(packed)["entry_section"] == "UPX1"


@pytest.mark.integration
def test_elf_entry_owner_agrees_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc")
    readelf = shutil.which("readelf")
    if gcc is None or readelf is None:
        pytest.skip("gcc/readelf not installed — ELF entry-owner gate not run (skip != pass)")

    source = tmp_path / "hello.c"
    source.write_text('#include <stdio.h>\nint main(void){puts("hi");return 0;}\n')
    binary = tmp_path / "hello"
    subprocess.run(
        [gcc, "-o", str(binary), str(source)], check=True, capture_output=True, timeout=120
    )

    # Independent ground truth: readelf prints the entry address and the
    # section rows; recomputing the owner from ALLOC rows is its own span
    # arithmetic over its own parse.
    header_dump = subprocess.run(
        [readelf, "-hW", str(binary)], capture_output=True, text=True, timeout=60, check=True
    ).stdout
    entry_match = _READELF_ENTRY_RE.search(header_dump)
    assert entry_match, header_dump
    entry = int(entry_match.group(1), 16)
    section_dump = subprocess.run(
        [readelf, "-SW", str(binary)], capture_output=True, text=True, timeout=60, check=True
    ).stdout
    owners = [
        name
        for name, addr_hex, size_hex in _READELF_ALLOC_ROW_RE.findall(section_dump)
        if int(addr_hex, 16) <= entry < int(addr_hex, 16) + int(size_hex, 16)
    ]
    assert owners == [".text"], section_dump

    facts = _session_entry_facts(binary)
    assert facts["entry"] == entry
    assert facts["entry_section"] == owners[0]

    # The sstrip shape: zero e_shoff/e_shnum/e_shstrndx so the file carries no
    # section table at all. readelf agrees there are no sections left, the
    # entry survives, and the honest owner is None.
    raw = bytearray(binary.read_bytes())
    struct.pack_into("<Q", raw, 0x28, 0)  # e_shoff
    struct.pack_into("<H", raw, 0x3C, 0)  # e_shnum
    struct.pack_into("<H", raw, 0x3E, 0)  # e_shstrndx
    stripped = tmp_path / "hello.sstripped"
    stripped.write_bytes(bytes(raw))
    stripped_dump = subprocess.run(
        [readelf, "-SW", str(stripped)], capture_output=True, text=True, timeout=60, check=True
    ).stdout
    assert not _READELF_ALLOC_ROW_RE.search(stripped_dump), stripped_dump

    stripped_facts = _session_entry_facts(stripped)
    assert stripped_facts["entry"] == entry
    assert stripped_facts["entry_section"] is None


@pytest.mark.integration
def test_macho_entry_owner_agrees_with_llvm() -> None:
    objdump = shutil.which("llvm-objdump")
    readobj = shutil.which("llvm-readobj")
    if objdump is None or readobj is None:
        pytest.skip(
            "llvm-objdump/llvm-readobj not installed — Mach-O entry-owner gate not run"
            " (skip != pass)"
        )
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE} (skip != pass)")

    # Independent ground truth: llvm-objdump decodes LC_MAIN's entryoff and
    # llvm-readobj each section's file offset and size; the owner is the
    # section whose file span covers the offset, recomputed here from llvm's
    # numbers alone.
    headers = subprocess.run(
        [objdump, "--macho", "--all-headers", str(_MACHO_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    entry_match = _MACHO_ENTRYOFF_RE.search(headers)
    assert entry_match, headers
    entryoff = int(entry_match.group(1))
    sections_dump = subprocess.run(
        [readobj, "--sections", str(_MACHO_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    owners = [
        name
        for name, size_hex, offset in _MACHO_SECTION_RE.findall(sections_dump)
        if int(offset) > 0 and int(offset) <= entryoff < int(offset) + int(size_hex, 16)
    ]
    assert owners == ["__text"], sections_dump

    facts = _session_entry_facts(_MACHO_FIXTURE)
    assert facts["entry_section"] == owners[0]
    assert facts["entry"] is not None
