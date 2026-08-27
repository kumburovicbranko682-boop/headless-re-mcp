"""Ghidra headless live gate: real analyzeHeadless over a real binary.

Ghidra is cross-platform (a JVM tool), so unlike the x64dbg/WinDbg gates this
one is meant to run on Linux CI too. It is the first thing that ever executes
``analyzeHeadless`` in this project's tests -- everything else only asserted
that a *missing* Ghidra degrades cleanly, which is exactly how two real bugs
(the launcher picked the Windows ``.bat`` on POSIX, and the export script read
an undefined ``ARGS``) survived: analysis succeeded and only the export failed,
invisible until something ran it end to end.

Skip != pass: the gate skips with a reason when Ghidra or a C compiler is
absent, and runs for real when both are present. CI installs Ghidra so the skip
there means a genuine regression, not a bare machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Named helpers so the assertions can prove Ghidra recovered real functions
# rather than just "some" functions; -O0 keeps them from being inlined away.
_FIXTURE_SRC = """
#include <stdio.h>

int add_numbers(int a, int b) { return a + b; }

int multiply(int a, int b) {
    int result = 0;
    for (int i = 0; i < b; i++) result += a;
    return result;
}

int main(int argc, char **argv) {
    int summed = add_numbers(argc, 7);
    int scaled = multiply(summed, 3);
    printf("%d\\n", scaled);
    return 0;
}
"""


def _resolve_ghidra_home() -> Path | None:
    """Project config first, then Ghidra's own GHIDRA_INSTALL_DIR convention."""
    configured = getattr(Settings.load(), "ghidra_home", None)
    if configured is not None:
        return Path(configured)
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    return Path(env) if env else None


def _compile_portable_elf(tmp_path: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = tmp_path / "ghidra_fixture.c"
    src.write_text(_FIXTURE_SRC, encoding="utf-8")
    out = tmp_path / "ghidra_fixture.elf"
    # -no-pie keeps entry points at fixed addresses, so a follow-up xrefs/decompile
    # by address lands where "functions" reported it.
    result = subprocess.run(
        [compiler, "-O0", "-no-pie", "-o", str(out), str(src)],
        capture_output=True,
        timeout=120,
    )
    return out if result.returncode == 0 and out.is_file() else None


def _resolve_fixture(tmp_path: Path) -> Path | None:
    """The Windows PE fixture when present, else a freshly compiled ELF.

    Ghidra analyses both formats; the point is to hand it a real binary on
    whatever platform CI runs, not to depend on the Windows-only build.
    """
    pe_fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if pe_fixture.is_file():
        return pe_fixture
    if os.name == "nt":
        return None
    return _compile_portable_elf(tmp_path)


@pytest.mark.integration
def test_ghidra_headless_recovers_functions_symbols_and_decompiles(tmp_path: Path) -> None:
    client = GhidraClient(home=_resolve_ghidra_home())
    if not client.available:
        pytest.skip(
            "Ghidra analyzeHeadless not configured "
            "(set HEADLESS_RE_GHIDRA_HOME) — live Gate not run (skip != pass)"
        )
    binary = _resolve_fixture(tmp_path)
    if binary is None:
        pytest.skip("no binary fixture and no C compiler — Gate not run (skip != pass)")

    project = tmp_path / "ghidra-project"

    functions = client.functions(binary, project, limit=256, timeout=600.0)
    assert functions.get("count", 0) >= 1
    names = {item["name"] for item in functions["items"]}
    entries = {item["name"]: item["entry"] for item in functions["items"]}

    symbols = client.symbols(binary, project, limit=256, timeout=600.0)
    assert symbols.get("count", 0) >= 1

    # A compiled ELF still carries its symbol names; assert against them so the
    # gate proves real recovery, not merely a non-empty list. The PE fixture may
    # be stripped differently, so only insist on the named functions for the ELF
    # we built ourselves.
    if binary.suffix == ".elf":
        assert {"add_numbers", "multiply", "main"} <= names
        main_entry = entries["main"]
        decompiled = client.decompile(binary, project, main_entry, timeout=600.0)
        assert decompiled.get("function") == "main"
        body = decompiled.get("decompiled", "")
        assert isinstance(body, str) and body.strip()
        # main calls both helpers, so a real decompile of it must mention one.
        assert "add_numbers" in body or "multiply" in body

        xrefs = client.xrefs(binary, project, entries["add_numbers"], limit=64, timeout=600.0)
        # main calls add_numbers exactly once; a real xref index finds the call.
        assert xrefs.get("count", 0) >= 1
