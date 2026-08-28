"""Cross-validate the DWARF debug-info census against readelf, llvm-dwarfdump and llvm-objdump.

A native session now reports the DWARF debug sections an image carries --
``.debug_info``/``.debug_line``/... for ELF, ``__debug_*`` in the ``__DWARF``
segment for Mach-O -- as ``{present, sections, size}``. This is what a ``-g``
build ships and a release build does not: source lines, types and variable
names that hand the analyst the program in near-source form, the native pair
to the PE and .NET PDB facts. The detection (which section names are DWARF,
their normalized base names, their total size) is ours, so independent tools
referee it:

* ELF, over a real ``gcc -g`` probe -- ``readelf -S`` reads the section table
  and ``llvm-dwarfdump --show-section-sizes`` parses the DWARF itself, so a
  three-way agreement proves the sections both exist and are genuine DWARF,
  not merely named that way; a stripped release build must read empty on all
  three;
* Mach-O, over an independently built ``__DWARF`` image -- ``llvm-objdump
  --macho --section-headers`` lists the section names and sizes through its
  own Mach-O parser (its strict load-command decode doubles as the
  well-formedness check); the committed fixture is the real-world negative.

gcc, readelf and strip ship with the CI runner; llvm-dwarfdump and llvm-objdump
come from the workflow's ``llvm`` install. skip != pass: each test skips only
when its own referee is unavailable.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"

_PROBE_C = "int helper(int x){return x*2;}\nint main(void){return helper(21);}\n"

# readelf -S -W row: "[NN] .debug_info PROGBITS <addr> <off> <size> ...". The
# size is the third hex field after the type; capture the DWARF name and it.
_READELF_ROW_RE = re.compile(
    r"\]\s+(\.z?debug_\S+)\s+\w+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)"
)
# llvm-dwarfdump --show-section-sizes row: ".debug_info   128 (0.76%)".
_DWARFDUMP_ROW_RE = re.compile(r"^(\.z?debug_\S+)\s+(\d+)", re.MULTILINE)
# llvm-objdump --macho --section-headers row: "0 __debug_info 00000060 <vma> DATA, DEBUG".
_OBJDUMP_ROW_RE = re.compile(r"^\s*\d+\s+(__\S+)\s+([0-9a-fA-F]+)\s", re.MULTILINE)


def _norm(name: str) -> str:
    """The census's normalization, restated: container prefix off, zdebug folded."""
    base = name.lstrip(".")
    if base.startswith("__"):
        base = base[2:]
    if base.startswith("zdebug_"):
        base = "debug_" + base[len("zdebug_") :]
    return base


def _session_debug_info(binary: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["native"]["debug_info"]
        assert isinstance(facts, dict)
        return facts
    finally:
        service.close_all()


def _readelf_dwarf(readelf: str, binary: Path) -> tuple[list[str], int]:
    result = subprocess.run(
        [readelf, "-S", "-W", str(binary)], capture_output=True, text=True, timeout=120, check=True
    )
    names: set[str] = set()
    total = 0
    for match in _READELF_ROW_RE.finditer(result.stdout):
        names.add(_norm(match.group(1)))
        total += int(match.group(2), 16)
    return sorted(names), total


def _dwarfdump_dwarf(dwarfdump: str, binary: Path) -> tuple[list[str], int]:
    result = subprocess.run(
        [dwarfdump, "--show-section-sizes", str(binary)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    names: set[str] = set()
    total = 0
    for match in _DWARFDUMP_ROW_RE.finditer(result.stdout):
        names.add(_norm(match.group(1)))
        total += int(match.group(2))
    return sorted(names), total


def _objdump_dwarf(objdump: str, binary: Path) -> tuple[list[str], int]:
    result = subprocess.run(
        [objdump, "--macho", "--section-headers", str(binary)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    names: set[str] = set()
    total = 0
    for match in _OBJDUMP_ROW_RE.finditer(result.stdout):
        base = _norm(match.group(1))
        if base.startswith("debug_"):
            names.add(base)
            total += int(match.group(2), 16)
    return sorted(names), total


# ---------------------------------------------------------------------------
# ELF: readelf and llvm-dwarfdump referee a real gcc -g probe.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_gcc_g_probe_agrees_with_readelf_and_dwarfdump(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("gcc not installed — ELF debug-info gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf not installed — ELF debug-info gate not run (skip != pass)")
    dwarfdump = shutil.which("llvm-dwarfdump")
    if dwarfdump is None:
        pytest.skip("llvm-dwarfdump not installed — DWARF referee missing (skip != pass)")

    source = tmp_path / "probe.c"
    source.write_text(_PROBE_C)
    binary = tmp_path / "probe.debug"
    subprocess.run(
        [gcc, "-g", str(source), "-o", str(binary)], check=True, capture_output=True, timeout=120
    )

    facts = _session_debug_info(binary)
    assert facts["present"] is True
    session_names = facts["sections"]
    assert "debug_info" in session_names and "debug_line" in session_names

    readelf_names, readelf_size = _readelf_dwarf(readelf, binary)
    dwarfdump_names, dwarfdump_size = _dwarfdump_dwarf(dwarfdump, binary)
    # Three-way agreement: the section table (readelf) and the DWARF parser
    # (dwarfdump) both see exactly the sections the census reports, at exactly
    # the census's total size -- so the sections exist and are genuine DWARF.
    assert session_names == readelf_names == dwarfdump_names
    assert facts["size"] == readelf_size == dwarfdump_size


@pytest.mark.integration
def test_a_stripped_release_probe_is_clean_for_all(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("gcc not installed — ELF debug-info gate not run (skip != pass)")
    strip = shutil.which("strip")
    if strip is None:
        pytest.skip("strip not installed — ELF debug-info gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf not installed — ELF debug-info gate not run (skip != pass)")

    source = tmp_path / "probe.c"
    source.write_text(_PROBE_C)
    binary = tmp_path / "probe.release"
    subprocess.run(
        [gcc, str(source), "-o", str(binary)], check=True, capture_output=True, timeout=120
    )
    subprocess.run([strip, str(binary)], check=True, capture_output=True, timeout=120)

    # A release build carries no DWARF: the empty census must be the shared
    # answer, and readelf must see no .debug_* section either.
    assert _session_debug_info(binary) == {"present": False, "sections": [], "size": 0}
    assert _readelf_dwarf(readelf, binary) == ([], 0)


# ---------------------------------------------------------------------------
# Mach-O: llvm-objdump referees an independently built __DWARF image.
# ---------------------------------------------------------------------------


def _macho_with_dwarf(sections: list[tuple[str, int]]) -> bytes:
    """A minimal MH_EXECUTE Mach-O with a ``__DWARF`` segment of given sections.

    ``sections`` are (sectname, byte size). Built here independently of the
    reader; llvm-objdump's strict Mach-O decode doubles as the
    well-formedness check.
    """
    nsects = len(sections)
    header_end = 32 + 72 + 80 * nsects
    layout: list[tuple[str, int, int]] = []
    offset = header_end
    for name, size in sections:
        layout.append((name, offset, size))
        offset += size
    total_file = offset
    seg = bytearray(72)
    struct.pack_into("<II", seg, 0, 0x19, 72 + 80 * nsects)  # LC_SEGMENT_64
    seg[8:24] = b"__DWARF".ljust(16, b"\0")
    struct.pack_into("<Q", seg, 24, 0x1000)  # vmaddr
    struct.pack_into("<Q", seg, 32, 0x1000 + total_file)  # vmsize
    struct.pack_into("<Q", seg, 40, 0)  # fileoff
    struct.pack_into("<Q", seg, 48, total_file)  # filesize
    struct.pack_into("<II", seg, 56, 7, 1)  # maxprot, initprot
    struct.pack_into("<I", seg, 64, nsects)
    body = bytearray()
    blobs = bytearray()
    for name, off, size in layout:
        sect = bytearray(80)
        sect[0:16] = name.encode().ljust(16, b"\0")
        sect[16:32] = b"__DWARF".ljust(16, b"\0")
        struct.pack_into("<Q", sect, 32, 0x1000 + off)  # addr
        struct.pack_into("<Q", sect, 40, size)  # size
        struct.pack_into("<I", sect, 48, off)  # offset
        body += sect
        blobs += b"\x00" * size
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(seg) + len(body), 0, 0)
    return header + bytes(seg) + bytes(body) + bytes(blobs)


@pytest.mark.integration
def test_a_macho_dwarf_segment_agrees_with_llvm_objdump(tmp_path: Path) -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O debug-info gate not run (skip != pass)")

    binary = tmp_path / "g.macho"
    binary.write_bytes(_macho_with_dwarf([("__debug_info", 96), ("__debug_line", 40)]))

    facts = _session_debug_info(binary)
    assert facts["present"] is True
    objdump_names, objdump_size = _objdump_dwarf(objdump, binary)
    # llvm-objdump's own Mach-O parser lists the same DWARF sections, at the
    # same total size, the census reports.
    assert facts["sections"] == objdump_names == ["debug_info", "debug_line"]
    assert facts["size"] == objdump_size == 136


@pytest.mark.integration
def test_the_committed_macho_fixture_is_clean_for_both() -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O debug-info gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"Mach-O fixture missing: {_MACHO_FIXTURE} (skip != pass)")

    assert _session_debug_info(_MACHO_FIXTURE) == {"present": False, "sections": [], "size": 0}
    assert _objdump_dwarf(objdump, _MACHO_FIXTURE) == ([], 0)
