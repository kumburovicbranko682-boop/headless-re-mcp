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


@pytest.mark.integration
def test_ghidra_symbols_lists_named_symbols(tmp_path: Path) -> None:
    """The symbols export mode is a separate ExportJson.py branch from functions.

    functions/decompile proved the launcher and argument plumbing, but the symbol
    table walk (``st.getAllSymbols``) is its own path that nothing exercised. A
    compiled-with-symbols ELF must surface its named routines here.
    """
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
    symbols = client.symbols(fixture, project, limit=512, timeout=_HEADLESS_TIMEOUT_S)
    assert symbols.get("mode") == "symbols"
    assert symbols.get("count", 0) >= 1
    names = {item["name"] for item in symbols.get("items", [])}
    # The three routines the fixture defines must all appear in the symbol table.
    assert {"main", "compute", "helper"} <= names
    for item in symbols["items"]:
        assert item.get("name")
        assert "address" in item
        assert "type" in item


@pytest.mark.integration
def test_ghidra_xrefs_recovers_a_call_edge(tmp_path: Path) -> None:
    """The xrefs export mode resolves an address and walks references to it.

    This is the last untested ExportJson.py branch, and the only one that takes a
    caller-supplied address argument -- exactly the shape that hid the ARGS bug.
    ``compute`` calls ``helper`` twice, so references to helper's entry must
    include recovered call edges, proving the reference walk actually ran.
    """
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
    helper_entry = next(
        item["entry"] for item in functions["items"] if item["name"] == "helper"
    )
    xrefs = client.xrefs(fixture, project, helper_entry, limit=64, timeout=_HEADLESS_TIMEOUT_S)
    assert xrefs.get("mode") == "xrefs"
    assert xrefs.get("count", 0) >= 1
    for item in xrefs["items"]:
        assert "from" in item and "to" in item and "type" in item
    # compute -> helper is a direct call, so at least one reference to helper's
    # entry must be a recovered call edge, not merely a data/indirection artefact.
    call_edges = [
        item for item in xrefs["items"]
        if "CALL" in str(item.get("type", "")) and item.get("to") == helper_entry
    ]
    assert call_edges, f"no call edge to helper among {xrefs['items']}"
