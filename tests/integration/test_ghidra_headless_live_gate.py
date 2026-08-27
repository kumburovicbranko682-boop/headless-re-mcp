"""Ghidra headless live gate: real analyzeHeadless across the whole export surface.

The Ghidra line had no live coverage at all -- the only integration test asserts
the *degrade* path (``capability_unavailable`` when unconfigured) and the planned
tool list. So ``ghidra.functions`` / ``symbols`` / ``xrefs`` / ``decompile``, the
``ExportJson.py`` postScript they drive, the JSON it writes, and the "analyzeHeadless
exited non-zero but still wrote content" success rule were only ever run against
mocks. Standing this gate up immediately surfaced two bugs that made the line dead
on arrival, both now fixed and pinned here:

  * launcher selection probed ``analyzeHeadless.bat`` first, so on Linux (where
    Ghidra ships both launchers) the client picked the Windows ``.bat`` and every
    call died with a PermissionError from Popen; and
  * ``ExportJson.py`` read its arguments from a bare ``ARGS`` global that Ghidra
    never injects, so the script raised ``NameError: name 'ARGS' is not defined``
    the instant it actually executed -- it must use ``getScriptArgs()``.

The gate compiles a small ELF with named helpers and a distinctive string, then
drives the real client across the full surface: it recovers those functions and
symbols by name, finds the call from ``main`` into ``add_numbers`` via xrefs, and
decompiles both the arithmetic of ``add_numbers`` and the marker string in
``main``. ``-O0 -no-pie`` keeps the helpers un-inlined and their addresses stable
so xrefs/decompile land where the function listing reported.

This gate is deliberately Ghidra-generation agnostic: it drives whatever
``HEADLESS_RE_GHIDRA_HOME`` points at. The client picks the launch model from the
install's feature layout -- analyzeHeadless directly for Jython Ghidra (<= 11.2),
or ``python -m pyghidra.ghidra_launch`` for PyGhidra Ghidra (>= 11.3, which has no
Jython) -- so the same assertions exercise whichever runtime CI installs. Both
launch paths are covered in CI by two jobs pointing this gate at an 11.2 and a 12
install respectively.

Skip != pass: the gate skips with a reason when Ghidra (HEADLESS_RE_GHIDRA_HOME),
java or a C compiler is absent, and runs for real when all are present. CI
installs them, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_MARKER = "GHIDRA_GATE_MARKER"
_FIXTURE_SRC = f"""
#include <stdio.h>

int add_numbers(int a, int b) {{ return a + b; }}

int multiply(int a, int b) {{
    int result = 0;
    for (int i = 0; i < b; i++) result += a;
    return result;
}}

int main(int argc, char **argv) {{
    int summed = add_numbers(argc, 7);
    int scaled = multiply(summed, 3);
    printf("{_MARKER} %d\\n", scaled);
    return 0;
}}
"""


def _ghidra_home() -> Path | None:
    configured = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not configured:
        return None
    home = Path(configured)
    return home if home.is_dir() else None


def _compile_elf(tmp_path: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = tmp_path / "ghidra_fixture.c"
    src.write_text(_FIXTURE_SRC, encoding="utf-8")
    out = tmp_path / "ghidra_fixture.elf"
    result = subprocess.run(
        [compiler, "-O0", "-no-pie", "-o", str(out), str(src)],
        capture_output=True,
        timeout=120,
    )
    return out if result.returncode == 0 and out.is_file() else None


@pytest.mark.integration
def test_ghidra_recovers_functions_symbols_xrefs_and_decompiles(tmp_path: Path) -> None:
    home = _ghidra_home()
    if home is None:
        pytest.skip("HEADLESS_RE_GHIDRA_HOME not set — Ghidra Gate not run (skip != pass)")
    client = GhidraClient(home=home)
    if not client.available:
        pytest.skip("analyzeHeadless/java not available — Ghidra Gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)
    if binary is None:
        pytest.skip("no C compiler to build the fixture — Ghidra Gate not run (skip != pass)")

    # functions: the named helpers must be recovered, not merely "some" functions.
    functions = client.functions(binary, tmp_path / "p_functions", limit=256, timeout=300.0)
    by_name = {str(item["name"]): item for item in functions["items"]}
    assert "add_numbers" in by_name, sorted(by_name)
    assert "multiply" in by_name, sorted(by_name)
    assert "main" in by_name, sorted(by_name)
    add_entry = str(by_name["add_numbers"]["entry"])
    main_entry = str(by_name["main"]["entry"])

    # symbols: the same helpers appear in the symbol table.
    symbols = client.symbols(binary, tmp_path / "p_symbols", limit=512, timeout=300.0)
    symbol_names = {str(item["name"]) for item in symbols["items"]}
    assert {"add_numbers", "main"} <= symbol_names

    # xrefs: main calls add_numbers, so a real reference index has that call.
    xrefs = client.xrefs(binary, tmp_path / "p_xrefs", add_entry, limit=64, timeout=300.0)
    assert xrefs["count"] >= 1, "no xrefs to add_numbers"
    assert any("CALL" in str(item.get("type")) for item in xrefs["items"]), xrefs["items"]

    # decompile: add_numbers decompiles to real C -- its addition and its return.
    decompiled_add = client.decompile(binary, tmp_path / "p_add", add_entry, timeout=300.0)
    assert decompiled_add["found"] is True
    assert decompiled_add["function"] == "add_numbers"
    add_src = str(decompiled_add["decompiled"])
    assert "+" in add_src
    assert "return" in add_src

    # decompile: main recovers the distinctive string literal from its printf.
    decompiled_main = client.decompile(binary, tmp_path / "p_main", main_entry, timeout=300.0)
    assert decompiled_main["found"] is True
    assert _MARKER in str(decompiled_main["decompiled"])
