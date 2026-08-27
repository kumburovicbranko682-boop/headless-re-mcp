"""Ghidra live gate on a native ELF. skip != pass when Ghidra or cc is missing.

The Ghidra backend was only ever exercised with a mocked ``analyzeHeadless``
(``test_ghidra_client``), so two things that only fail against a real install
went unnoticed: the launcher probe preferred the Windows ``analyzeHeadless.bat``
on Linux (EACCES on a correct install), and the export post-script was Jython,
which Ghidra refuses to run since 11.0 unless started with PyGhidra. This gate
points the real backend at a freshly compiled ELF and drives every export mode
end to end, so a regression in the launcher choice or the script runtime shows
up as a failure rather than silence.

It runs only when ``HEADLESS_RE_GHIDRA_HOME`` (or ``GHIDRA_INSTALL_DIR`` /
``GHIDRA_HOME``) points at an install with ``support/analyzeHeadless`` and a JDK
is on PATH; otherwise it skips loudly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_C_SOURCE = """
#include <stdio.h>

int add(int a, int b) { return a + b; }
int mul(int a, int b) { return a * b; }

int main(void) {
    printf("hello %d %d\\n", add(2, 3), mul(4, 5));
    return 0;
}
"""

_FLAG_SETS: tuple[list[str], ...] = (
    ["-O0", "-fno-pic", "-no-pie"],
    ["-O0"],
    [],
)


def _compiler() -> str | None:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _compile_elf(compiler: str, source: Path, out: Path) -> bool:
    for flags in _FLAG_SETS:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [compiler, *flags, "-o", str(out), str(source)],
            capture_output=True,
        )
        if result.returncode == 0 and out.is_file():
            return True
    return False


def _ghidra_home() -> Path | None:
    for var in ("HEADLESS_RE_GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        value = os.environ.get(var)
        if value:
            return Path(value)
    return None


def _client_or_skip() -> GhidraClient:
    client = GhidraClient(home=_ghidra_home())
    if not client.available:
        pytest.skip(
            "Ghidra not configured (set HEADLESS_RE_GHIDRA_HOME to an install with "
            "support/analyzeHeadless, JDK on PATH) — Ghidra Gate not run (skip != pass)"
        )
    return client


@pytest.fixture
def elf_binary(tmp_path: Path) -> Path:
    compiler = _compiler()
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the ELF sample (skip != pass)")
    source = tmp_path / "sample.c"
    source.write_text(_C_SOURCE, encoding="utf-8")
    binary = tmp_path / "sample.elf"
    if not _compile_elf(compiler, source, binary):
        pytest.skip("compiler could not produce an ELF here (skip != pass)")
    return binary


def _entry_of(items: list[dict], name: str) -> str | None:
    for item in items:
        if item.get("name") == name and isinstance(item.get("entry"), str):
            return item["entry"]
    return None


@pytest.mark.integration
def test_ghidra_analyzes_then_lists_functions_and_symbols(
    elf_binary: Path, tmp_path: Path
) -> None:
    client = _client_or_skip()

    analyzed = client.analyze_binary(elf_binary, tmp_path / "p_analyze", timeout=300.0)
    assert "import" in analyzed["note"]

    functions = client.functions(elf_binary, tmp_path / "p_functions", limit=100, timeout=300.0)
    items = functions.get("items") or []
    assert functions["count"] == len(items)
    assert isinstance(functions["has_more"], bool)
    assert items, "Ghidra listed no functions (post-script did not run?)"
    for item in items:
        assert isinstance(item["name"], str)
        assert isinstance(item["entry"], str) and item["entry"]
        assert isinstance(item["body_size"], int)
    # The sample is not stripped, so our own functions must be recovered by name.
    names = {item["name"] for item in items}
    assert {"add", "mul", "main"} & names, f"expected our functions, got {sorted(names)[:10]}"

    symbols = client.symbols(elf_binary, tmp_path / "p_symbols", limit=200, timeout=300.0)
    symbol_items = symbols.get("items") or []
    assert symbols["count"] == len(symbol_items)
    assert symbol_items, "Ghidra listed no symbols"
    for item in symbol_items:
        assert isinstance(item["name"], str)
        assert isinstance(item["address"], str)
        assert isinstance(item["type"], str)


@pytest.mark.integration
def test_ghidra_decompiles_and_lists_xrefs_for_a_function(
    elf_binary: Path, tmp_path: Path
) -> None:
    client = _client_or_skip()

    functions = client.functions(elf_binary, tmp_path / "p_functions", limit=100, timeout=300.0)
    items = functions.get("items") or []
    assert items, "no functions to decompile"
    entry = _entry_of(items, "add") or items[0]["entry"]

    decompiled = client.decompile(elf_binary, tmp_path / "p_decompile", entry, timeout=300.0)
    body = decompiled.get("decompiled") or ""
    assert isinstance(body, str) and body.strip(), "decompiler returned nothing"
    assert "{" in body and "}" in body, "decompilation is not C-like"
    assert decompiled["truncated"] is False
    assert isinstance(decompiled.get("entry"), str)

    xrefs = client.xrefs(elf_binary, tmp_path / "p_xrefs", entry, limit=100, timeout=300.0)
    xref_items = xrefs.get("items") or []
    assert xrefs["count"] == len(xref_items)
    assert isinstance(xrefs["has_more"], bool)
    for item in xref_items:
        assert isinstance(item["from"], str)
        assert isinstance(item["to"], str)
        assert isinstance(item["type"], str)
