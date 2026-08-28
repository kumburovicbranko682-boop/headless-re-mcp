"""Cross-validate the PE Rich header census against pefile.

A session over a PE now reports MSVC's toolchain census tool-free -- the
XOR-masked block between the DOS stub and the PE header where the Microsoft
linker records one (product id, build, count) row per tool whose objects it
consumed. The PE toolchain provenance, the pair to an ELF .comment, a Mach-O
build-tool entry and the WASM producers section -- and a classic attribution
artifact, since the census survives a fully stripped build. The marker scan,
the mask recovery and the backwards walk to the DanS sentinel are all ours, so
pefile referees them: its parse_rich_header() decodes the same block with its
own logic, and this compares the two row for row. The negative side matters as
much: Mono's mcs writes the PE itself and leaves no Rich header, so both
readers must call the census absent rather than hallucinate one.

pefile ships in the project's ``pe`` extra; mcs comes from mono-mcs in CI. skip
!= pass: each test skips only when its own referee is unavailable.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService


def _pefile() -> Any | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _pe_with_rich_header(entries: list[tuple[int, int, int]], key: int) -> bytes:
    """A minimal PE64 whose bytes at 0x80 are an MSVC-shaped Rich header.

    Masked exactly the way the Microsoft linker masks it -- DanS ^ key, three
    masked zeros, the (comp.id ^ key, count ^ key) pairs, the plain ``Rich``
    marker and the plain key -- and laid out independently of the reader's own
    unit builder, so the decode is gated on bytes it did not generate. pefile
    anchors its own decode at 0x80, which is where MSVC puts the block.
    """

    def mask(value: int) -> bytes:
        return (value ^ key).to_bytes(4, "little")

    region = mask(0x536E6144) + mask(0) * 3  # DanS + the three masked pads
    for product_id, build, count in entries:
        region += mask((product_id << 16) | build) + mask(count)
    region += b"Rich" + key.to_bytes(4, "little")

    e_lfanew = 0x80 + ((len(region) + 15) & ~15)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    stub = bytes(dos) + region + bytes(e_lfanew - 0x80 - len(region))

    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    return stub + coff + bytes(opt)


def _pefile_rich(pefile_mod: Any, binary: Path) -> dict[str, Any] | None:
    """pefile's view of the census, reshaped into the reader's fact form."""
    pe = pefile_mod.PE(str(binary))
    rich = pe.parse_rich_header()
    if rich is None:
        return None
    values = rich["values"]
    entries = [
        {
            "product_id": values[index] >> 16,
            "build": values[index] & 0xFFFF,
            "count": values[index + 1],
        }
        for index in range(0, len(values) - 1, 2)
    ]
    return {"checksum": rich["checksum"], "entries": entries}


def _session_rich(binary: Path) -> dict[str, Any] | None:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        rich = created.data["session"]["metadata"]["pe"].get("rich_header")
        assert rich is None or isinstance(rich, dict)
        return rich
    finally:
        service.close_all()


@pytest.mark.integration
def test_a_planted_rich_header_agrees_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE Rich header gate not run (skip != pass)")

    # Rows shaped like a real MSVC link: the C compiler, the C++ compiler and
    # masm of one toolset build, plus the linker's own row.
    entries = [(0x0104, 31933, 9), (0x0105, 31933, 3), (0x0103, 31933, 1), (0x0102, 31933, 1)]
    binary = tmp_path / "msvc.exe"
    binary.write_bytes(_pe_with_rich_header(entries, key=0x8A0BCA31))

    # Independent ground truth: pefile recovers the mask and unrolls the pairs
    # with its own decoder. It must see the planted rows, so it is a genuine
    # second opinion.
    referee = _pefile_rich(pefile_mod, binary)
    assert referee is not None
    assert referee["checksum"] == 0x8A0BCA31
    assert referee["entries"] == [
        {"product_id": product_id, "build": build, "count": count}
        for product_id, build, count in entries
    ]

    assert _session_rich(binary) == referee


@pytest.mark.integration
def test_an_mcs_built_pe_reads_no_census_like_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE Rich header gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE gate not run (skip != pass)")

    # Mono writes the PE image itself; only MSVC-family linkers leave a Rich
    # header, so the census must read absent -- on both sides. A reader that
    # invents rows out of the DOS stub would fail exactly here.
    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    assert _pefile_rich(pefile_mod, binary) is None
    assert _session_rich(binary) is None
