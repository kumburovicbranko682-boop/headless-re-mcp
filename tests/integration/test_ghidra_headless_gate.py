"""Ghidra headless live gate: analyzeHeadless + ExportJson.py actually work.

Every other test of the Ghidra backend only exercises the degradation path
(``capability_unavailable`` when it is not configured). Nothing ran the real
thing, so two host-portability bugs hid here until this gate: the launcher
picker preferred the Windows ``.bat`` on Linux, and ExportJson.py read a global
``ARGS`` that Ghidra never defines (the API is ``getScriptArgs()``), which left
every export empty.

Ghidra is a user-provided install discovered via ``HEADLESS_RE_GHIDRA_HOME``
(same as the config), and the fixture is a tiny ELF compiled on the fly, so this
skips honestly when Ghidra, a JRE, or a C compiler is absent -- skip != pass.
The ExportJson.py script is a Jython GhidraScript; a Ghidra without a Python
(Jython) provider cannot run it, and the export path will surface that.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

_C_SOURCE = textwrap.dedent(
    """
    #include <stdio.h>
    int add(int a, int b) { return a + b; }
    int compute(int x) { return add(x, 42); }
    int main(void) {
        printf("HEADLESS_RE_GHIDRA_MARKER %d\\n", compute(1));
        return 0;
    }
    """
)


def _ghidra_home() -> Path | None:
    home = Settings.load().ghidra_home
    return home if home is not None else None


def _compile_elf(dest_dir: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = dest_dir / "ghfix.c"
    src.write_text(_C_SOURCE, encoding="utf-8")
    out = dest_dir / "ghfix.elf"
    # -no-pie keeps the classic non-relocated layout so addresses are stable to
    # eyeball; fall back to a plain build if the toolchain rejects those flags.
    for args in (
        [compiler, "-O0", "-fno-pie", "-no-pie", "-o", str(out), str(src)],
        [compiler, "-O0", "-o", str(out), str(src)],
    ):
        result = subprocess.run(args, capture_output=True)
        if result.returncode == 0 and out.is_file():
            return out
    return None


@dataclass
class _Harness:
    client: GhidraClient
    elf: Path
    projects: Path
    entries: dict[str, str]

    def project(self, name: str) -> Path:
        path = self.projects / name
        path.mkdir(parents=True, exist_ok=True)
        return path


@pytest.fixture(scope="module")
def _harness(tmp_path_factory: pytest.TempPathFactory) -> _Harness:
    home = _ghidra_home()
    if home is None:
        pytest.skip("HEADLESS_RE_GHIDRA_HOME not set — Ghidra Gate not run (skip != pass)")
    client = GhidraClient(home=home)
    if not client.available:
        pytest.skip("Ghidra analyzeHeadless / JRE not available — Gate not run (skip != pass)")
    root = tmp_path_factory.mktemp("ghidra")
    elf = _compile_elf(root)
    if elf is None:
        pytest.skip("no C compiler to build the ELF fixture — Gate not run (skip != pass)")
    # One analysis up front both proves the functions export and gives the
    # entry addresses the xref/decompile checks reuse, so the gate does not
    # re-import for every lookup.
    functions = client.functions(elf, root / "proj-fn", limit=256, timeout=300.0)
    entries = {item["name"]: item["entry"] for item in functions["items"]}
    harness = _Harness(client=client, elf=elf, projects=root, entries=entries)
    harness._functions = functions  # type: ignore[attr-defined]
    return harness


@pytest.mark.integration
def test_functions_export_lists_the_compiled_functions(_harness: _Harness) -> None:
    functions = _harness._functions  # type: ignore[attr-defined]
    assert functions["count"] >= 1
    names = set(_harness.entries)
    assert {"add", "compute", "main"} <= names, names


@pytest.mark.integration
def test_symbols_export_includes_the_functions(_harness: _Harness) -> None:
    symbols = _harness.client.symbols(_harness.elf, _harness.project("proj-sym"), timeout=300.0)
    names = {item["name"] for item in symbols["items"]}
    assert {"add", "compute", "main"} <= names, names


@pytest.mark.integration
def test_xrefs_export_finds_the_call_into_add(_harness: _Harness) -> None:
    add_entry = _harness.entries.get("add")
    assert add_entry, "the functions export did not surface add()"
    xrefs = _harness.client.xrefs(
        _harness.elf, _harness.project("proj-xref"), add_entry, timeout=300.0
    )
    # compute() calls add(), so add must have at least one incoming reference.
    assert xrefs["count"] >= 1
    assert all("from" in item and "to" in item for item in xrefs["items"])


@pytest.mark.integration
def test_decompile_export_returns_c_for_a_function(_harness: _Harness) -> None:
    compute_entry = _harness.entries.get("compute")
    assert compute_entry, "the functions export did not surface compute()"
    result = _harness.client.decompile(
        _harness.elf, _harness.project("proj-dec"), compute_entry, timeout=300.0
    )
    assert result.get("function") == "compute"
    # The decompiled C must show the call compute() makes into add().
    assert "add" in result.get("decompiled", "")
    assert result.get("truncated") is False
