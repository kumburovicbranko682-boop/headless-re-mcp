"""Cross-validate the PE CheckSum fact against pefile's own algorithm.

A session over a PE now reads the optional header's declared CheckSum and
whether it matches the file's recomputed sum -- the PE self-integrity fact,
the pair to the DEX header's adler32 ``checksum_ok``. The 16-bit
end-around-carry sum (imagehlp's CheckSumMappedFile) is reimplemented in the
reader, so pefile referees it end to end: ``generate_checksum()`` is pefile's
own independent implementation of the same reference algorithm, and
``OPTIONAL_HEADER.CheckSum`` its own decode of the declared field.

The strongest leg lets the referee do the writing: pefile stamps its own
computed checksum into a real mcs-compiled binary, and the session must
independently validate it True -- then one flipped byte must flip the verdict
to False on both sides at once. Nothing is echoed: the writer and the reader
never share code.

pefile ships in the project's ``pe`` extra; mcs comes from mono-mcs in CI.
skip != pass: each test skips, naming the missing piece, only when its own
referee is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_UPX_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "upx"
_DOTNET_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
)


def _pefile() -> ModuleType | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _session_checksum(path: Path) -> dict[str, Any] | None:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["pe"].get("checksum")
    finally:
        service.close_all()


@pytest.mark.integration
def test_checksum_agrees_with_pefile_over_the_fixtures() -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE checksum gate not run (skip != pass)")
    fixtures = [
        *(
            _UPX_ROOT / f"console_fixture-{arch}.{stage}.exe"
            for arch in ("x64", "x86")
            for stage in ("pre-upx", "upx")
        ),
        _DOTNET_FIXTURE,
    ]
    present = [fixture for fixture in fixtures if fixture.is_file()]
    if not present:
        pytest.skip("no PE fixtures present (skip != pass)")

    for fixture in present:
        pe = pefile_mod.PE(str(fixture))
        declared = pe.OPTIONAL_HEADER.CheckSum
        fact = _session_checksum(fixture)
        assert fact is not None, fixture.name
        # The declared field, decoded independently on both sides.
        assert fact["declared"] == declared, fixture.name
        if declared == 0:
            assert fact["valid"] is None, fixture.name
        else:
            # The verdict must equal pefile's own recompute-and-compare.
            assert fact["valid"] == (pe.generate_checksum() == declared), fixture.name


@pytest.mark.integration
def test_a_pefile_stamped_checksum_validates_and_one_byte_breaks_it(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE checksum gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE checksum gate not run"
                    " (skip != pass)")

    # A real compiler's PE, checksummed by the referee itself: pefile computes
    # the sum with its own algorithm and writes it into the header. The
    # session's independent recompute must agree it is valid.
    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    compiled = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{compiled}", str(source)], check=True, capture_output=True, timeout=120
    )
    pe = pefile_mod.PE(str(compiled))
    stamped_value = pe.generate_checksum()
    assert stamped_value != 0
    pe.OPTIONAL_HEADER.CheckSum = stamped_value
    stamped = tmp_path / "stamped.exe"
    pe.write(str(stamped))

    fact = _session_checksum(stamped)
    assert fact == {"declared": stamped_value, "valid": True}

    # One flipped byte in the image: both the session and pefile must now
    # call the same declared value a lie.
    raw = bytearray(stamped.read_bytes())
    raw[-1] ^= 0xFF
    patched = tmp_path / "patched.exe"
    patched.write_bytes(bytes(raw))

    patched_fact = _session_checksum(patched)
    assert patched_fact == {"declared": stamped_value, "valid": False}
    reparsed = pefile_mod.PE(str(patched))
    assert reparsed.generate_checksum() != reparsed.OPTIONAL_HEADER.CheckSum
