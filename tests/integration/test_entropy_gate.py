"""Cross-validate the high-entropy section census against radare2 and pefile.

A session now flags sections whose bytes measure near-random -- the packed or
encrypted payload the magic-byte censuses cannot see, because an encrypted
stage two opens with no magic at all. The Shannon measure is ours, so each
format gets an independent referee that computes the same number from the
same bytes: radare2's ``iS entropy`` for ELF and Mach-O, pefile's
``get_entropy`` for PE. Each referee's numbers are pushed through the census's
own published threshold and size floor, so the whole flag list -- names,
rounded entropies and sizes -- must match record for record.

Positives are planted where the referee can also see them (a real deflate
stream stashed by objcopy into a gcc probe, a uniform-spread section in
independently built Mach-O and PE images); negatives are real, unpacked
binaries -- the gcc probe, the committed Mach-O fixture, an mcs-built PE --
where an empty flag list must be the shared answer: the census must not
hallucinate packing where a stock toolchain produced none.

gcc, objcopy and zlib ship with the CI runner; radare2, pefile and mcs come
from the workflow's r2 deb, ``pe`` extra and mono-mcs installs. skip != pass:
each test skips only when its own referee is unavailable.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"

# The census's published contract: flag at or past 7.2 bits per byte, skip
# sections smaller than 256 bytes, round to two decimals. The referees'
# numbers go through the same gauntlet so flag lists compare exactly.
_THRESHOLD = 7.2
_MIN_SIZE = 256

_PROBE_C = "int main(void) { return 0; }\n"


def _pefile() -> Any | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _session_flags(binary: Path, namespace: str) -> list[dict[str, Any]]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        flags = created.data["session"]["metadata"][namespace]["high_entropy_sections"]
        assert isinstance(flags, list)
        return flags
    finally:
        service.close_all()


def _r2_rows(r2: str, binary: Path) -> list[tuple[str, int, float]]:
    """radare2's per-section (name, size, entropy) rows -- the referee's read."""
    result = subprocess.run(
        [r2, "-q", "-c", "iSj entropy", str(binary)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    rows: list[tuple[str, int, float]] = []
    for row in json.loads(result.stdout):
        if "entropy" in row:
            rows.append((str(row["name"]), int(row["size"]), float(row["entropy"])))
    return rows


def _referee_flags(rows: list[tuple[str, int, float]]) -> list[dict[str, Any]]:
    """The referee's numbers pushed through the census's own contract."""
    return [
        {"section": name, "entropy": round(entropy, 2), "size": size}
        for name, size, entropy in rows
        if size >= _MIN_SIZE and entropy >= _THRESHOLD
    ]


def _gcc_probe(tmp_path: Path, gcc: str) -> Path:
    source = tmp_path / "probe.c"
    source.write_text(_PROBE_C)
    binary = tmp_path / "probe"
    subprocess.run(
        [gcc, str(source), "-o", str(binary)], check=True, capture_output=True, timeout=120
    )
    return binary


# ---------------------------------------------------------------------------
# ELF: radare2 referees a real deflate stream stashed into a real gcc binary.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_stashed_deflate_stream_flags_like_radare2(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("gcc not installed — ELF entropy gate not run (skip != pass)")
    objcopy = shutil.which("objcopy")
    if objcopy is None:
        pytest.skip("objcopy not installed — ELF entropy gate not run (skip != pass)")
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — ELF entropy gate not run (skip != pass)")

    # A real compressed payload: what a packer actually parks on disk. Big
    # enough for the measure to settle well past the threshold.
    corpus = " ".join(f"record {i} value {i * i}" for i in range(20000)).encode()
    stash = tmp_path / "stash.bin"
    stash.write_bytes(zlib.compress(corpus, level=9))
    probe = _gcc_probe(tmp_path, gcc)
    packed = tmp_path / "packed"
    subprocess.run(
        [objcopy, "--add-section", f".stash={stash}", str(probe), str(packed)],
        check=True,
        capture_output=True,
        timeout=120,
    )

    flags = _session_flags(packed, "native")
    assert [flag["section"] for flag in flags] == [".stash"]
    assert flags[0]["entropy"] >= _THRESHOLD
    # The referee reads the same file: identical flag list, record for record.
    assert flags == _referee_flags(_r2_rows(r2, packed))


@pytest.mark.integration
def test_a_plain_gcc_probe_is_clean_for_both(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("gcc not installed — ELF entropy gate not run (skip != pass)")
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — ELF entropy gate not run (skip != pass)")

    probe = _gcc_probe(tmp_path, gcc)
    # A stock toolchain packs nothing: the empty census must be the shared
    # answer, not a hallucination on either side.
    assert _session_flags(probe, "native") == []
    assert _referee_flags(_r2_rows(r2, probe)) == []


# ---------------------------------------------------------------------------
# Mach-O: radare2 referees an independently built image and the fixture.
# ---------------------------------------------------------------------------


def _macho_with_sections(sections: list[tuple[str, bytes]]) -> bytes:
    """A minimal MH_EXECUTE arm64 Mach-O whose __DATA sections carry bytes.

    Built here independently of the reader's unit builder; radare2's strict
    load-command decode doubles as the well-formedness check.
    """
    nsects = len(sections)
    seg = bytearray(72)
    struct.pack_into("<II", seg, 0, 0x19, 72 + 80 * nsects)  # LC_SEGMENT_64
    seg[8:24] = b"__DATA".ljust(16, b"\0")
    struct.pack_into("<Q", seg, 24, 0x1000)  # vmaddr
    struct.pack_into("<Q", seg, 32, 0x1000)  # vmsize
    struct.pack_into("<II", seg, 56, 7, 3)  # maxprot rwx, initprot rw-
    struct.pack_into("<I", seg, 64, nsects)
    header_end = 32 + len(seg) + 80 * nsects
    body = bytearray()
    blobs = bytearray()
    offset = header_end
    for name, data in sections:
        sect = bytearray(80)
        sect[0:16] = name.encode().ljust(16, b"\0")
        sect[16:32] = b"__DATA".ljust(16, b"\0")
        struct.pack_into("<Q", sect, 32, 0x1000 + offset)  # addr
        struct.pack_into("<Q", sect, 40, len(data))  # size
        struct.pack_into("<I", sect, 48, offset)  # offset
        body += sect
        blobs += data
        offset += len(data)
    ncmds_size = len(seg) + len(body)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, ncmds_size, 0, 0)
    return header + bytes(seg) + bytes(body) + bytes(blobs)


@pytest.mark.integration
def test_a_macho_uniform_section_flags_like_radare2(tmp_path: Path) -> None:
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — Mach-O entropy gate not run (skip != pass)")

    # Every byte value equally often: exactly 8.0 bits per byte on both
    # sides, the deterministic stand-in for an encrypted payload.
    binary = tmp_path / "packed.macho"
    binary.write_bytes(
        _macho_with_sections([("__text", b"\x90" * 512), ("__blob", bytes(range(256)) * 4)])
    )

    flags = _session_flags(binary, "native")
    assert flags == [{"section": "__blob", "entropy": 8.0, "size": 1024}]
    # radare2 spells a Mach-O section "nth.__SEG.__sect"; map to the section
    # name the reader reports before comparing record for record.
    rows = [
        (name.rsplit(".", 1)[-1], size, entropy)
        for name, size, entropy in _r2_rows(r2, binary)
    ]
    assert flags == _referee_flags(rows)


@pytest.mark.integration
def test_the_committed_macho_fixture_is_clean_for_both() -> None:
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — Mach-O entropy gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip("Mach-O fixture missing — Mach-O entropy gate not run (skip != pass)")

    assert _session_flags(_MACHO_FIXTURE, "native") == []
    assert _referee_flags(_r2_rows(r2, _MACHO_FIXTURE)) == []


# ---------------------------------------------------------------------------
# PE: pefile referees an independently built image and an mcs-built one.
# ---------------------------------------------------------------------------


def _pe_with_section_data(sections: list[tuple[bytes, bytes]]) -> bytes:
    """A minimal PE32 whose sections carry (name, raw bytes).

    Built here independently of the reader's unit builder; pefile's strict
    section-table decode doubles as the well-formedness check.
    """
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x014C, len(sections), 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    optional[0:2] = (0x10B).to_bytes(2, "little")
    # Real alignments: pefile aligns PointerToRawData down to FileAlignment
    # before reading, so raw pointers must sit on 0x200 boundaries.
    optional[32:36] = (0x1000).to_bytes(4, "little")  # SectionAlignment
    optional[36:40] = (0x200).to_bytes(4, "little")  # FileAlignment
    optional[92:96] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes
    table = bytearray()
    payloads = bytearray()
    headers_size = 0x40 + len(coff) + len(optional) + 40 * len(sections)
    data_off = (headers_size + 0x1FF) & ~0x1FF
    for index, (name, payload) in enumerate(sections):
        raw_size = (len(payload) + 0x1FF) & ~0x1FF
        sect = bytearray(40)
        sect[0 : len(name)] = name
        struct.pack_into("<I", sect, 8, len(payload))  # VirtualSize
        struct.pack_into("<I", sect, 12, 0x1000 * (index + 1))  # VirtualAddress
        struct.pack_into("<I", sect, 16, raw_size)  # SizeOfRawData
        struct.pack_into("<I", sect, 20, data_off + len(payloads))  # PointerToRawData
        table += sect
        payloads += payload.ljust(raw_size, b"\x00")
    padding = bytes(data_off - headers_size)
    return bytes(dos) + coff + bytes(optional) + bytes(table) + padding + bytes(payloads)


def _pefile_flags(pefile_mod: Any, binary: Path) -> list[dict[str, Any]]:
    """pefile's get_entropy pushed through the census's own contract."""
    pe = pefile_mod.PE(str(binary))
    try:
        rows = [
            (
                section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                int(section.SizeOfRawData),
                float(section.get_entropy()),
            )
            for section in pe.sections
        ]
    finally:
        pe.close()
    return _referee_flags(rows)


@pytest.mark.integration
def test_a_pe_uniform_section_flags_like_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE entropy gate not run (skip != pass)")

    binary = tmp_path / "packed.exe"
    binary.write_bytes(
        _pe_with_section_data([(b".text", b"\x90" * 512), (b"UPX1", bytes(range(256)) * 4)])
    )

    flags = _session_flags(binary, "pe")
    assert flags == [{"section": "UPX1", "entropy": 8.0, "size": 1024}]
    assert flags == _pefile_flags(pefile_mod, binary)


@pytest.mark.integration
def test_an_mcs_built_pe_agrees_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE entropy gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE gate not run (skip != pass)")

    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.Write("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    # IL and metadata are structured, not packed: whatever pefile measures,
    # the census must land on the identical flag list.
    assert _session_flags(binary, "pe") == _pefile_flags(pefile_mod, binary)
