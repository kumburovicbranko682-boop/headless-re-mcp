"""Ghidra headless live gate: import, function recovery and decompilation.

The only other Ghidra coverage is the degradation path in
``test_m11_optional_backends_gate`` (it asserts the *errors* are well-shaped
when analyzeHeadless is missing) and unit tests driving fakes. Nothing proved a
real analyzeHeadless can launch, import a binary, run ``ExportJson`` under the
script runtime it ships for, and decompile.

This gate compiles a tiny ELF with named functions and drives GhidraClient end
to end. It guards two fixes made alongside it: launcher discovery picking the
Windows ``.bat`` over the POSIX ``analyzeHeadless`` on Linux (Errno 13), and
``ExportJson`` being a Jython script that Ghidra 11.3+ can no longer run, which
had silently broken ``functions``/``decompile`` on every current release.

skip != pass: it skips honestly when HEADLESS_RE_GHIDRA_HOME is unset or no C
compiler exists.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

# -O0 keeps the functions distinct and inlining-free; the names are asserted
# below to prove real analysis rather than just a zero exit code.
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
def test_ghidra_headless_recovers_and_decompiles_a_linux_elf(tmp_path: Path) -> None:
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

    # Function recovery: analyzeHeadless imports and analyses, then the Java
    # ExportJson postScript writes the listing. Seeing the source's own symbols
    # proves both the analyzer and the (previously Jython-broken) export ran.
    listed = client.functions(elf, project_dir, limit=512, timeout=600.0)
    items = listed.get("items")
    assert isinstance(items, list) and listed.get("count", 0) >= 1, listed
    by_name = {str(item.get("name") or ""): item for item in items}
    assert "main" in by_name, sorted(by_name)
    assert "helper_compute" in by_name, sorted(by_name)

    # Decompiling main must yield real C that names the helper it calls; an
    # empty or header-only result cannot contain the callee's symbol.
    entry = "0x" + str(by_name["main"]["entry"])
    decompiled = client.decompile(elf, project_dir, entry, timeout=600.0)
    assert decompiled.get("found") is True, decompiled
    assert str(decompiled.get("function") or "") == "main"
    assert "helper_compute" in str(decompiled.get("decompiled") or ""), decompiled
