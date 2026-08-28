"""Cross-validate the W^X posture census against readelf, llvm-objdump and pefile.

A session now counts (or names) the mappings a process could both write and
run -- the W^X violation a packer or self-modifying loader needs and no stock
toolchain emits: ELF PT_LOAD segments whose flags carry PF_W and PF_X
(``wx_segments``), Mach-O segments whose initprot carries write and execute
(``wx_segments``), and PE sections whose characteristics carry
IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE (``wx_sections``). The flag
decodes are all ours, so each format gets its own referee -- readelf's Flg
column, llvm-objdump's initprot rows, pefile's Characteristics -- against both
a planted violation (the referee must see it too, so it is a genuine second
opinion) and a clean real-world image where zero must be the shared answer:
the census must not hallucinate on the gcc probe, the committed Mach-O
fixture or an mcs-built PE.

readelf/gcc ship with the CI runner; llvm and pefile come from the workflow's
llvm and ``pe`` extra installs; mcs from mono-mcs. skip != pass: each test
skips only when its own referee is unavailable.
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

# llvm-objdump --macho --all-headers prints one "initprot rwx" / "initprot
# r-x" row per segment load command.
_LLVM_INITPROT_RE = re.compile(r"^\s*initprot (\S+)$", re.MULTILINE)


def _pefile() -> Any | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _session_facts(binary: Path, namespace: str) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"][namespace]
        assert isinstance(facts, dict)
        return facts
    finally:
        service.close_all()


def _elf_with_loads(flags_per_load: list[int]) -> bytes:
    """A minimal 64-bit ELF whose PT_LOADs carry the given p_flags.

    Built here independently of the reader's unit builder; readelf's strict
    program-header decode doubles as the well-formedness check.
    """
    phnum = len(flags_per_load)
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1  # 64-bit, little-endian, version 1
    struct.pack_into("<H", ehdr, 16, 2)  # ET_EXEC
    struct.pack_into("<H", ehdr, 18, 62)  # x86-64
    struct.pack_into("<Q", ehdr, 32, 64)  # e_phoff
    struct.pack_into("<H", ehdr, 54, 56)  # e_phentsize
    struct.pack_into("<H", ehdr, 56, phnum)
    body = bytearray()
    for index, p_flags in enumerate(flags_per_load):
        phdr = bytearray(56)
        struct.pack_into("<I", phdr, 0, 1)  # PT_LOAD
        struct.pack_into("<I", phdr, 4, p_flags)
        struct.pack_into("<Q", phdr, 8, 0)  # p_offset
        struct.pack_into("<Q", phdr, 16, 0x1000 * (index + 1))  # p_vaddr
        struct.pack_into("<Q", phdr, 24, 0x1000 * (index + 1))  # p_paddr
        struct.pack_into("<Q", phdr, 32, 0x100)  # p_filesz
        struct.pack_into("<Q", phdr, 40, 0x100)  # p_memsz
        struct.pack_into("<Q", phdr, 48, 0x1000)  # p_align
        body += phdr
    return bytes(ehdr) + bytes(body)


def _readelf_wx_loads(readelf: str, binary: Path) -> int:
    """How many LOAD rows readelf -l -W prints with both W and E in Flg."""
    result = subprocess.run(
        [readelf, "-l", "-W", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    count = 0
    for line in result.stdout.splitlines():
        tokens = line.split()
        if len(tokens) < 8 or tokens[0] != "LOAD":
            continue
        # Columns: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg... Align;
        # the flags render as up to three letters that may split on spaces
        # ("R E" vs "RWE"), so everything between MemSiz and Align is Flg.
        flags = "".join(tokens[6:-1])
        if "W" in flags and "E" in flags:
            count += 1
    return count


@pytest.mark.integration
def test_elf_wx_segments_agree_with_readelf(tmp_path: Path) -> None:
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf not installed — ELF W^X gate not run (skip != pass)")

    # R+X text, R+W data, and the planted violation: one RWE mapping.
    binary = tmp_path / "wx.elf"
    binary.write_bytes(_elf_with_loads([0x5, 0x6, 0x7]))
    referee = _readelf_wx_loads(readelf, binary)
    # readelf must see the planted RWE row, so it is a genuine second opinion.
    assert referee == 1
    assert _session_facts(binary, "native")["wx_segments"] == referee


@pytest.mark.integration
def test_a_gcc_probe_counts_zero_wx_segments_like_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    readelf = shutil.which("readelf")
    if gcc is None:
        pytest.skip("gcc not installed — ELF W^X gate not run (skip != pass)")
    if readelf is None:
        pytest.skip("readelf not installed — ELF W^X gate not run (skip != pass)")

    # A stock toolchain never maps anything writable and executable at once;
    # a census that hallucinates on a real binary would fail exactly here.
    source = tmp_path / "probe.c"
    source.write_text("int main(void) { return 0; }\n")
    binary = tmp_path / "probe.bin"
    subprocess.run(
        [gcc, str(source), "-o", str(binary)], check=True, capture_output=True, timeout=120
    )
    referee = _readelf_wx_loads(readelf, binary)
    assert referee == 0
    assert _session_facts(binary, "native")["wx_segments"] == 0


def _macho_with_initprots(initprots: list[int]) -> bytes:
    """A minimal 64-bit Mach-O with one LC_SEGMENT_64 per given initprot."""
    body = bytearray()
    for index, initprot in enumerate(initprots):
        cmd = bytearray(72)
        struct.pack_into("<II", cmd, 0, 0x19, 72)  # LC_SEGMENT_64
        cmd[8:24] = f"__SEG{index}".encode().ljust(16, b"\x00")
        struct.pack_into("<Q", cmd, 24, 0x1000 * (index + 1))  # vmaddr
        struct.pack_into("<Q", cmd, 32, 0x1000)  # vmsize
        struct.pack_into("<II", cmd, 56, 0x7, initprot)  # maxprot, initprot
        body += cmd
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, len(initprots), len(body), 0, 0
    )
    return header + bytes(body)


def _llvm_wx_segments(objdump: str, binary: Path) -> int:
    """How many initprot rows llvm-objdump prints carrying both w and x."""
    result = subprocess.run(
        [objdump, "--macho", "--all-headers", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    prots = _LLVM_INITPROT_RE.findall(result.stdout)
    assert prots, result.stdout  # the decode must have reached the segments
    return sum(1 for prot in prots if "w" in prot and "x" in prot)


@pytest.mark.integration
def test_macho_wx_segments_agree_with_llvm_objdump(tmp_path: Path) -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O W^X gate not run (skip != pass)")

    # r-x text, rw- data, and the planted violation: one rwx segment.
    binary = tmp_path / "wx.macho"
    binary.write_bytes(_macho_with_initprots([0x5, 0x3, 0x7]))
    referee = _llvm_wx_segments(objdump, binary)
    assert referee == 1
    assert _session_facts(binary, "native")["wx_segments"] == referee


@pytest.mark.integration
def test_the_committed_macho_fixture_counts_zero_like_llvm_objdump() -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O W^X gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    referee = _llvm_wx_segments(objdump, _MACHO_FIXTURE)
    assert referee == 0
    assert _session_facts(_MACHO_FIXTURE, "native")["wx_segments"] == 0


def _pe_with_wx_section() -> bytes:
    """A minimal PE32+ whose section table plants one W+X section among clean ones."""
    sections = [
        (b".text", 0x6000_0020),  # code | execute | read
        (b"UPX0", 0xE000_0080),  # uninitialized | execute | read | write
        (b".data", 0xC000_0040),  # initialized | read | write
    ]
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack(
        "<HHIIIHH", 0x8664, len(sections), 0, 0, 0, opt_size, 0x0102
    )
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    table = bytearray()
    for index, (name, characteristics) in enumerate(sections):
        sect = bytearray(40)
        sect[0 : len(name)] = name
        struct.pack_into("<I", sect, 8, 0x1000)  # VirtualSize
        struct.pack_into("<I", sect, 12, 0x1000 * (index + 1))  # VirtualAddress
        struct.pack_into("<I", sect, 36, characteristics)
        table += sect
    return bytes(dos) + coff + bytes(opt) + bytes(table)


def _pefile_wx_sections(pefile_mod: Any, binary: Path) -> list[str]:
    """The section names pefile reads with both MEM_WRITE and MEM_EXECUTE."""
    pe = pefile_mod.PE(str(binary))
    write = pefile_mod.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
    execute = pefile_mod.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
    return [
        section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        for section in pe.sections
        if section.Characteristics & write and section.Characteristics & execute
    ]


@pytest.mark.integration
def test_pe_wx_sections_agree_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE W^X gate not run (skip != pass)")

    binary = tmp_path / "packed.exe"
    binary.write_bytes(_pe_with_wx_section())
    referee = _pefile_wx_sections(pefile_mod, binary)
    # pefile must see the planted W+X section, so it is a genuine second opinion.
    assert referee == ["UPX0"]
    assert _session_facts(binary, "pe")["wx_sections"] == referee


@pytest.mark.integration
def test_an_mcs_built_pe_counts_zero_like_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE W^X gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE gate not run (skip != pass)")

    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    referee = _pefile_wx_sections(pefile_mod, binary)
    assert referee == []
    assert _session_facts(binary, "pe")["wx_sections"] == []
