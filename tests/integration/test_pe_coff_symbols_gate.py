"""Cross-validate the PE COFF symbol count against llvm-readobj over MinGW.

A session over a PE now reads the COFF header's NumberOfSymbols -- the PE
member of the stripped-status family, the pair to the ELF and Mach-O
``stripped`` facts, inverted into a count because the defaults differ: MSVC
images never carry COFF symbols (they live in the PDB), while MinGW/Cygwin
builds ship full tables until someone runs strip, so a non-zero count is both
the GNU-toolchain tell and an analysis windfall.

The gate builds a real Windows PE with x86_64-w64-mingw32-gcc, has
llvm-readobj (a fully independent COFF decoder) read SymbolCount off the same
header, and requires the session to match it -- non-zero on the fresh build,
then zero on both sides after the MinGW strip removes the table. The
committed MSVC/mcs fixtures anchor the other default: llvm-readobj and the
session must both read 0 over every one of them.

mingw-w64 and llvm come from CI's toolchain step. skip != pass: each test
skips, naming the missing piece, only when its own referee is unavailable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
_SYMBOL_COUNT_RE = re.compile(r"^\s*SymbolCount:\s*(\d+)\s*$", re.MULTILINE)


def _readobj_symbol_count(readobj: str, path: Path) -> int:
    proc = subprocess.run(
        [readobj, "--file-header", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    match = _SYMBOL_COUNT_RE.search(proc.stdout)
    assert match is not None, f"llvm-readobj printed no SymbolCount for {path.name}"
    return int(match.group(1))


def _session_coff_symbols(path: Path) -> int | None:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["pe"].get("coff_symbol_count")
    finally:
        service.close_all()


@pytest.mark.integration
def test_a_mingw_build_matches_llvm_readobj_before_and_after_strip(tmp_path: Path) -> None:
    gcc = shutil.which("x86_64-w64-mingw32-gcc")
    if gcc is None:
        pytest.skip("x86_64-w64-mingw32-gcc not installed — MinGW COFF-symbol gate not run"
                    " (skip != pass)")
    readobj = shutil.which("llvm-readobj")
    if readobj is None:
        pytest.skip("llvm-readobj not installed — MinGW COFF-symbol gate not run"
                    " (skip != pass)")
    strip = shutil.which("x86_64-w64-mingw32-strip") or shutil.which("llvm-strip")
    if strip is None:
        pytest.skip("no PE-capable strip installed — MinGW COFF-symbol gate not run"
                    " (skip != pass)")

    source = tmp_path / "hello.c"
    source.write_text(
        "#include <stdio.h>\n"
        "static int answer(void) { return 42; }\n"
        "int main(void) { printf(\"%d\\n\", answer()); return 0; }\n"
    )
    built = tmp_path / "hello.exe"
    subprocess.run(
        [gcc, "-o", str(built), str(source)], check=True, capture_output=True, timeout=300
    )

    # The fresh MinGW image must carry a real symbol table, and the session's
    # count must equal llvm-readobj's independent decode of the same header.
    referee_count = _readobj_symbol_count(readobj, built)
    assert referee_count > 0, "a fresh MinGW build should carry COFF symbols"
    assert _session_coff_symbols(built) == referee_count

    # strip removes the table: both sides must now read zero.
    stripped = tmp_path / "stripped.exe"
    shutil.copyfile(built, stripped)
    subprocess.run([strip, str(stripped)], check=True, capture_output=True, timeout=120)
    assert _readobj_symbol_count(readobj, stripped) == 0
    assert _session_coff_symbols(stripped) == 0


@pytest.mark.integration
def test_the_msvc_and_mcs_fixtures_read_zero_on_both_sides() -> None:
    readobj = shutil.which("llvm-readobj")
    if readobj is None:
        pytest.skip("llvm-readobj not installed — fixture COFF-symbol gate not run"
                    " (skip != pass)")
    fixtures = sorted(_FIXTURES.rglob("*.exe"))
    if not fixtures:
        pytest.skip(f"no PE fixtures under {_FIXTURES} (skip != pass)")

    # The other default: MSVC (upx pair) and mcs (.NET) images carry no COFF
    # table, and the session must agree with llvm-readobj on every one.
    for fixture in fixtures:
        assert _readobj_symbol_count(readobj, fixture) == 0, fixture.name
        assert _session_coff_symbols(fixture) == 0, fixture.name
