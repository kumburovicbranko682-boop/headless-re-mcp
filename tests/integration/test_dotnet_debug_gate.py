"""Cross-validate the tool-free .NET PDB reference against GNU objdump.

``inspect_dotnet`` reads the PE debug directory itself to report the CodeView
RSDS record -- the per-build PDB GUID and age (the symbol-server key, the
managed analogue of an ELF build-id / Mach-O UUID) and the PDB path the linker
baked in. That reader and the fixture it reads are both ours, so nothing proved
its view of the debug directory matches an independent decoder. GNU ``objdump
-p`` walks the same directory straight from the file and prints the RSDS
signature, age and PDB path on its own ``(format RSDS signature ... age ... pdb
...)`` line; this requires they agree, the build-fingerprint analogue of the
metadata gate cross-checking the reader against monodis.

objdump ships with binutils (the same package the ELF gates' readelf comes
from). skip != pass -- the gate skips, naming why, only when objdump is absent
or was built without PE/COFF target support and so cannot read the assembly.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"

# objdump -p prints the CodeView record as one parenthesised line, e.g.
# "(format RSDS signature a1b2c3d4... age 1 pdb C:\build\...\MyAssembly.pdb)".
_RSDS_RE = re.compile(
    r"\(format RSDS signature ([0-9a-fA-F]+) age (\d+) pdb (.*?)\)\s*$",
    re.MULTILINE,
)


@pytest.mark.integration
def test_pure_python_pdb_reference_agrees_with_objdump() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    objdump = shutil.which("objdump")
    if objdump is None:
        pytest.skip("objdump (binutils) not installed — PDB cross-check not run (skip != pass)")

    result = subprocess.run(
        [objdump, "-p", str(_FIXTURE)], capture_output=True, text=True, timeout=60
    )
    # A binutils built without PE/COFF targets refuses the image outright; that
    # is a missing capability, not a reader failure, so it skips (not passes).
    if result.returncode != 0 or "File format not recognized" in result.stderr:
        pytest.skip("objdump lacks PE/COFF support — PDB cross-check not run (skip != pass)")
    match = _RSDS_RE.search(result.stdout)
    assert match, result.stdout
    objdump_hex, objdump_age, objdump_path = match.groups()

    # The tool-free reader, reached exactly as a client would: inspect_dotnet
    # reads the debug directory off the same file with no code of objdump's.
    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        report = service.dotnet_inspect(session_id)
        assert report.ok, report.error
        pdb = report.data["pdb"]
    finally:
        service.close_all()

    assert pdb is not None, "reader found no PDB reference where objdump did"
    # The GUID: objdump prints the RSDS 16 bytes as 32 hex digits in record
    # order; the reader's dashed GUID is the same bytes, so stripping dashes
    # and lower-casing must match hex for hex.
    assert pdb["guid"].replace("-", "").lower() == objdump_hex.lower()
    assert pdb["age"] == int(objdump_age)
    assert pdb["path"] == objdump_path
    # The symbol-server key the reader derives is objdump's GUID hex (upper)
    # with the age appended -- the exact string a symbol server indexes by.
    assert pdb["signature"] == f"{objdump_hex.upper()}{int(objdump_age):X}"
    # And it is the real thing the fixture baked in, GUID and path and all.
    assert pdb["guid"] == "a1b2c3d4-e5f6-4788-99aa-bbccddeeff00"
    assert pdb["path"] == r"C:\build\headless\MyAssembly.pdb"
