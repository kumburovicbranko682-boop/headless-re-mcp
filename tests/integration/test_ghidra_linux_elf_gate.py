"""Ghidra headless live gate: a real analyzeHeadless import on Linux.

The only Ghidra coverage anywhere is the degradation path in
``test_m11_optional_backends_gate`` -- it asserts the *errors* are well-shaped
when analyzeHeadless is missing, and unit tests drive fakes. Nothing on any
platform proved a real analyzeHeadless can be launched and import a binary.

This gate compiles a tiny ELF and drives ``GhidraClient.analyze_binary``, which
imports and auto-analyzes without the Jython postScript, so it exercises the
launcher and the analyzer end to end on Linux. It surfaced the bug fixed
alongside it: discovery preferred ``analyzeHeadless.bat`` over the POSIX
``analyzeHeadless``, so a correct Linux install launched the Windows batch file
and failed with Errno 13.

Scope note: ``functions``/``symbols``/``xrefs``/``decompile`` route through
``ExportJson.py`` (``@runtime Jython``). Ghidra 11.3+ dropped the bundled
Jython, so that postScript aborts until it is ported to PyGhidra/Java -- a
version-compat gap independent of this Linux launcher fix, so this gate does
not assert those paths. skip != pass: it skips honestly when
HEADLESS_RE_GHIDRA_HOME is unset or no C compiler exists.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

_SOURCE = """\
#include <stdio.h>
static int helper_add(int a, int b) { return a + b; }
int helper_compute(int x) { return helper_add(x, 7) * 2; }
int main(void) { printf("%d\\n", helper_compute(3)); return 0; }
"""


def _compiler() -> str | None:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _build_elf(tmp_path: Path) -> Path:
    compiler = _compiler()
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — Ghidra ELF Gate not run (skip != pass)")
    source = tmp_path / "ghidra_fixture.c"
    source.write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / "ghidra_fixture"
    # Compiler path comes from shutil.which and the args are fixed literals.
    result = subprocess.run(
        [compiler, "-O0", "-o", str(out), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0 or not out.is_file():
        pytest.skip(
            f"C compiler could not link the fixture ({result.returncode}) — "
            "Ghidra ELF Gate not run (skip != pass)"
        )
    return out


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="POSIX ELF gate; Windows lanes use PE fixtures")
def test_ghidra_headless_imports_and_analyzes_a_linux_elf(tmp_path: Path) -> None:
    client = GhidraClient(home=Settings.load().ghidra_home)
    if not client.available:
        pytest.skip(
            "Ghidra analyzeHeadless not configured (HEADLESS_RE_GHIDRA_HOME) — "
            "Ghidra ELF Gate not run (skip != pass)"
        )
    # The launcher discovery must not have handed back a Windows .bat on POSIX.
    assert client.analyze is not None
    assert not str(client.analyze).endswith(".bat"), client.analyze

    elf = _build_elf(tmp_path)
    project_dir = tmp_path / "ghidra_project"
    result = client.analyze_binary(elf, project_dir, timeout=300.0)

    # A launcher that merely exited 0 is not enough: the analyzer must report it
    # actually imported and analysed the binary. analyzeHeadless prints this
    # only after the auto-analysis pipeline runs to completion.
    assert "Analysis succeeded" in result["stdout_excerpt"], result["stdout_excerpt"][-800:]
    assert "deleted" in result["note"]
