"""Ghidra headless gate: real analyzeHeadless, real functions, real decompile.

Ghidra is advertised as a portable backend, yet nothing exercised it end to
end -- the unit tests mock ``run_bounded`` away, so two breakages survived
untested: the adapter preferred the Windows ``analyzeHeadless.bat`` launcher on
every platform, and the Jython export script read a global ``ARGS`` that Ghidra
never injects. This gate runs the actual launcher against a compiled ELF and
checks that the export script returns parsed functions and a decompilation, so
those paths can never silently rot again. skip != pass: it skips only when
Ghidra/Java is not configured or no C compiler can produce a binary.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

_FIXTURE_SOURCE = """
#include <stdio.h>
static int helper(int x) { return x * 3 + 1; }
int compute(int a, int b) { return helper(a) + helper(b); }
int main(void) { printf("%d\\n", compute(2, 5)); return 0; }
"""
# analyzeHeadless starts a JVM and re-imports the binary on every call, so each
# leg is a full headless run; give it room without hanging the suite.
_HEADLESS_TIMEOUT_S = 300.0


def _build_elf_fixture(tmp_path: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "ghidra_fixture.c"
    source.write_text(_FIXTURE_SOURCE, encoding="utf-8")
    binary = tmp_path / "ghidra_fixture"
    try:
        subprocess.run(
            [compiler, "-O0", "-o", str(binary), str(source)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return binary if binary.is_file() else None


@pytest.mark.integration
def test_ghidra_headless_functions_and_decompile(tmp_path: Path) -> None:
    home = getattr(Settings.load(), "ghidra_home", None)
    client = GhidraClient(home=home)
    if not client.available:
        pytest.skip(
            "Ghidra analyzeHeadless / Java not configured — Gate not run (skip != pass)"
        )
    fixture = _build_elf_fixture(tmp_path)
    if fixture is None:
        pytest.skip("no C compiler to build an ELF fixture — Gate not run (skip != pass)")

    project = tmp_path / "project"

    functions = client.functions(fixture, project, limit=128, timeout=_HEADLESS_TIMEOUT_S)
    assert functions.get("mode") == "functions"
    names = {item["name"] for item in functions.get("items", [])}
    # A compiled-with-symbols ELF must yield at least these two named functions;
    # if analyzeHeadless or the export script were broken, there would be none.
    assert "main" in names
    assert "compute" in names

    entry = next(
        item["entry"] for item in functions["items"] if item["name"] == "compute"
    )
    decompiled = client.decompile(fixture, project, entry, timeout=_HEADLESS_TIMEOUT_S)
    assert decompiled.get("function") == "compute"
    body = decompiled.get("decompiled", "")
    # The decompiler is the headline Ghidra capability; assert it produced C, not
    # merely that the call returned an envelope.
    assert isinstance(body, str) and len(body) > 0
    assert "return" in body
