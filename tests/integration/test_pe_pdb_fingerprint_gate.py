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

objdump ships with binutils; pefile ships in the project's ``pe`` extra. skip
!= pass: each check skips, naming why, only when its referee is unavailable.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
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
