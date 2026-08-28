"""Cross-validate the session-level PE PDB fingerprint against objdump and pefile.

A session over any PE now reports its CodeView RSDS record tool-free -- the
build fingerprint, the pair to an ELF build-id and a Mach-O UUID: the per-build
PDB GUID and age (whose concatenation is the symbol-server key) and the PDB
path the linker baked in. The debug-directory walk, the file-pointer/RVA
resolution and the mixed-endian GUID decode are all ours, so two independent
decoders referee them: GNU ``objdump -p`` walks the same directory straight
from the file and prints the RSDS signature, age and path on its own ``(format
RSDS ...)`` line, and pefile parses the CV_INFO_PDB70 record into its own GUID
fields, which this gate reassembles and compares hex for hex. One case gates a
synthetic native PE with a planted record; the other gates the committed .NET
fixture, tying the session-level fact to the same bytes the dotnet.inspect
deep reader and its own objdump gate already agree on.

The same debug directory also carries the deterministic-build declaration, so
the build-time gate lives here too: ``link_time`` is the COFF TimeDateStamp,
``reproducible`` is whether a type-16 (REPRO) entry declares the stamp a
content hash rather than a time, and ``link_time_utc`` is rendered only while
the stamp still claims to be one. pefile referees the raw stamp and the
debug-entry types through its own parse, and the UTC rendering is re-derived
through time.gmtime -- an implementation the reader does not share. A real
compiler case (Mono's mcs) ties the fact to a producer neither builder
controls: whatever mcs emitted, the reader and pefile must agree on it.

objdump ships with binutils; pefile ships in the project's ``pe`` extra. skip
!= pass: each check skips, naming why, only when its referee is unavailable.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"

# objdump -p prints the CodeView record as one parenthesised line, e.g.
# "(format RSDS signature a1b2c3d4... age 3 pdb C:\build\app.pdb)".
_RSDS_RE = re.compile(
    r"\(format RSDS signature ([0-9a-fA-F]+) age (\d+) pdb (.*?)\)\s*$",
    re.MULTILINE,
)

_GUID = "0f1e2d3c-4b5a-4796-8877-665544332211"
_AGE = 7
_PDB_PATH = r"D:\work\secret-project\engine.pdb"


def _pefile() -> Any | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _pe_with_rsds(guid: str, age: int, pdb_path: str) -> bytes:
    """A minimal native PE whose debug directory (index 6) holds one RSDS record.

    Built here independently of the reader's own test builder so the two
    implementations cannot share a blind spot: the blob sits at the section
    start and the IMAGE_DEBUG_DIRECTORY entry behind it at +0x100, the reverse
    of the unit builder's layout.
    """
    sect_rva = 0x1000
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0x0102)
    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)

    blob = b"RSDS" + uuid.UUID(guid).bytes_le + age.to_bytes(4, "little")
    blob += pdb_path.encode() + b"\x00"
    sec = bytearray(0x200)
    sec[0 : len(blob)] = blob
    table_off = 0x100
    struct.pack_into(
        "<IIHHIIII", sec, table_off, 0, 0, 0, 0, 2, len(blob), sect_rva, raw_off
    )

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x1_4000_0000)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, sect_rva + 0x1000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 112 + 6 * 8, sect_rva + table_off, 28)

    sect = bytearray(40)
    sect[0:6] = b".rdata"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, len(sec))
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x40000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    return bytes(out + sec)


def _objdump_rsds(binary: Path) -> tuple[str, int, str] | None:
    """objdump's view of the RSDS record, or None when objdump cannot help."""
    objdump = shutil.which("objdump")
    if objdump is None:
        return None
    result = subprocess.run(
        [objdump, "-p", str(binary)], capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0 or "File format not recognized" in result.stderr:
        return None
    match = _RSDS_RE.search(result.stdout)
    assert match, f"objdump printed no RSDS line:\n{result.stdout}"
    guid_hex, age, path = match.groups()
    return guid_hex.lower(), int(age), path


def _pefile_rsds(pefile_mod: Any, binary: Path) -> tuple[str, int, str]:
    """pefile's view of the RSDS record, its GUID fields reassembled here."""
    pe = pefile_mod.PE(str(binary))
    entry = next(e for e in pe.DIRECTORY_ENTRY_DEBUG if e.struct.Type == 2)
    cv = entry.entry
    assert cv.CvSignature == b"RSDS"
    guid = (
        f"{cv.Signature_Data1:08x}-{cv.Signature_Data2:04x}-{cv.Signature_Data3:04x}-"
        f"{cv.Signature_Data4:02x}{cv.Signature_Data5:02x}-{cv.Signature_Data6.hex()}"
    )
    path = cv.PdbFileName.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return guid, int(cv.Age), path


def _session_pdb(binary: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        pdb = created.data["session"]["metadata"]["pe"]["pdb"]
        assert isinstance(pdb, dict)
        return pdb
    finally:
        service.close_all()


@pytest.mark.integration
def test_a_planted_rsds_record_agrees_with_objdump_and_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE PDB fingerprint gate not run (skip != pass)")

    binary = tmp_path / "fingerprinted.exe"
    binary.write_bytes(_pe_with_rsds(_GUID, _AGE, _PDB_PATH))

    # Referee one: pefile parses the CV_INFO_PDB70 record into its own GUID
    # fields; reassembled, they must be the record we planted.
    pefile_guid, pefile_age, pefile_path = _pefile_rsds(pefile_mod, binary)
    assert pefile_guid == _GUID
    assert pefile_age == _AGE
    assert pefile_path == _PDB_PATH

    pdb = _session_pdb(binary)
    assert pdb["guid"] == pefile_guid
    assert pdb["age"] == pefile_age
    assert pdb["path"] == pefile_path
    assert pdb["signature"] == f"{pefile_guid.replace('-', '').upper()}{pefile_age:X}"

    # Referee two: objdump walks the same directory straight from the file; a
    # binutils without PE/COFF support skips this arm, not the gate.
    objdump_view = _objdump_rsds(binary)
    if objdump_view is not None:
        guid_hex, age, path = objdump_view
        assert pdb["guid"].replace("-", "") == guid_hex
        assert pdb["age"] == age
        assert pdb["path"] == path


@pytest.mark.integration
def test_the_committed_fixture_fingerprint_agrees_with_objdump() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    objdump_view = _objdump_rsds(_FIXTURE)
    if objdump_view is None:
        pytest.skip("objdump lacks PE/COFF support — fingerprint gate not run (skip != pass)")
    guid_hex, age, path = objdump_view

    # The session-level fact must read the same bytes the deep dotnet.inspect
    # reader and its objdump gate already agree on -- one fingerprint, three
    # independent decoders.
    pdb = _session_pdb(_FIXTURE)
    assert pdb["guid"].replace("-", "") == guid_hex
    assert pdb["age"] == age
    assert pdb["path"] == path
    assert pdb["signature"] == f"{guid_hex.upper()}{age:X}"


def _pe_with_stamp(stamp: int, debug_types: list[int]) -> bytes:
    """A minimal native PE with a planted COFF stamp and typed debug entries.

    Built independently of the reader's unit builder: the debug table sits at
    +0x100 into the section (the RSDS builder's layout, reversed from the unit
    builder's) and every entry's blob is empty -- the REPRO declaration is the
    entry type itself, not its payload.
    """
    sect_rva = 0x1000
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, stamp, 0, 0, opt_size, 0x0102)
    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)

    sec = bytearray(0x200)
    table_off = 0x100
    for i, dbg_type in enumerate(debug_types):
        struct.pack_into(
            "<IIHHIIII", sec, table_off + i * 28, 0, 0, 0, 0, dbg_type, 0, 0, 0
        )

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x1_4000_0000)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, sect_rva + 0x1000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    if debug_types:
        struct.pack_into("<II", opt, 112 + 6 * 8, sect_rva + table_off, 28 * len(debug_types))

    sect = bytearray(40)
    sect[0:6] = b".rdata"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, len(sec))
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x40000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    return bytes(out + sec)


def _pefile_build_time(pefile_mod: Any, binary: Path) -> tuple[int, bool]:
    """``(stamp, reproducible)`` as pefile reads them off its own parse."""
    pe = pefile_mod.PE(str(binary))
    stamp = int(pe.FILE_HEADER.TimeDateStamp)
    entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])
    return stamp, any(int(entry.struct.Type) == 16 for entry in entries)


def _session_build_time(binary: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        pe = created.data["session"]["metadata"]["pe"]
        keys = ("link_time", "link_time_utc", "reproducible")
        return {key: pe[key] for key in keys if key in pe}
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize(
    ("stamp", "debug_types"),
    [
        # A classically dated build: a real stamp, a CodeView-free debug dir.
        (0x60000000, []),
        # A deterministic build: the stamp is a hash, REPRO says so.
        (0xE3B0C442, [16]),
        # REPRO rides behind another entry type, as in real Roslyn output.
        (0xE3B0C442, [2, 16]),
        # An unfilled stamp: no time to render, nothing declared.
        (0, []),
    ],
    ids=["dated", "repro", "repro-behind-codeview", "zero-stamp"],
)
def test_build_time_agrees_with_pefile(
    tmp_path: Path, stamp: int, debug_types: list[int]
) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE build-time gate not run (skip != pass)")

    binary = tmp_path / f"stamped_{stamp:x}.exe"
    binary.write_bytes(_pe_with_stamp(stamp, debug_types))

    # Referee sanity: pefile reads back exactly the stamp and declaration we
    # planted, so the comparison below cannot pass vacuously.
    pefile_stamp, pefile_repro = _pefile_build_time(pefile_mod, binary)
    assert pefile_stamp == stamp
    assert pefile_repro is (16 in debug_types)

    facts = _session_build_time(binary)
    assert facts["link_time"] == pefile_stamp
    assert facts["reproducible"] is pefile_repro
    if stamp and not pefile_repro:
        # The UTC rendering, re-derived through time.gmtime rather than the
        # reader's datetime path.
        rendered = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))
        assert facts["link_time_utc"] == rendered
    else:
        # A hash or an unfilled stamp must never be dressed up as a date.
        assert "link_time_utc" not in facts


@pytest.mark.integration
def test_build_time_of_an_mcs_compiled_pe_agrees_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE build-time gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — build-time gate not run (skip != pass)")

    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    before = int(time.time())
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )
    after = int(time.time())

    pefile_stamp, pefile_repro = _pefile_build_time(pefile_mod, binary)
    facts = _session_build_time(binary)
    assert facts["link_time"] == pefile_stamp
    assert facts["reproducible"] is pefile_repro
    if pefile_repro or pefile_stamp == 0:
        assert "link_time_utc" not in facts
    else:
        # Mono stamps the wall clock; a rendering that strays from the compile
        # window would mean the reader misread or misconverted the field.
        assert before <= pefile_stamp <= after + 60
        assert facts["link_time_utc"] == time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(pefile_stamp)
        )
