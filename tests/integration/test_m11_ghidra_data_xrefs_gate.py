"""M11 Ghidra data xrefs gate: who reads this string, via the ReferenceManager.

The Ghidra live and ARM xref gates seek to *function* entries and assert inbound
CALL edges, so the data side of Ghidra's ReferenceManager is unproven -- the
counterpart to the r2 data-xref gate. The most common triage move, "find every
place this string is used", locates the string Ghidra auto-labelled in .rodata
and asks for references *to* it, expecting DATA edges rather than calls.

This gate compiles an ELF where one string literal is loaded from two functions,
finds the string through Ghidra's own symbol export (the ``s_..._<addr>`` label
Ghidra mints for a recognised string, proving it read the bytes), and asserts
xrefs on that address returns exactly the two DATA references, each inside its
loading function's body. It then seeks xrefs at a *function* and gets a CALL
instead, proving the reference type follows the target kind, not the tool.

Runs where a Jython-capable Ghidra (HEADLESS_RE_GHIDRA_HOME) and a C compiler
are present; skips honestly otherwise. skip != pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_MARKER = "ghidra-dataxref-secret-8b2c"
# One literal referenced from two functions: the compiler merges them into a
# single .rodata string, so each function's load is a DATA xref to one address.
_ELF_SOURCE = """
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int alpha(void) { return puts("ghidra-dataxref-secret-8b2c"); }

__attribute__((noinline))
int beta(const char *s) { return strcmp(s, "ghidra-dataxref-secret-8b2c") == 0; }

int main(int argc, char **argv) {
    if (argc > 1) return beta(argv[1]);
    return alpha();
}
"""
_ANALYZE_TIMEOUT_S = 300.0


def _build_native_fixture(tmp_path: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "ghidra_data_fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    binary = tmp_path / "ghidra_data_fixture.bin"
    for extra in (["-O0", "-fno-inline", "-fno-pic", "-no-pie"], ["-O0"], []):
        try:
            subprocess.run(
                [compiler, *extra, str(source), "-o", str(binary)],
                check=True,
                capture_output=True,
                timeout=60.0,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue
        if binary.is_file():
            return binary
    return None


def _within_body(from_addr: str, entry_hex: str, body_size: int) -> bool:
    try:
        source = int(from_addr, 16)
    except ValueError:
        return False
    start = int(entry_hex, 16)
    return start <= source < start + body_size


def _client() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
def test_m11_ghidra_recovers_string_data_references(tmp_path: Path) -> None:
    client = _client()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    fixture = _build_native_fixture(tmp_path)
    if fixture is None:
        pytest.skip("no C compiler (cc/gcc/clang) — Ghidra data xref Gate not run (skip != pass)")
    project = tmp_path / "ghidra_project"

    # Functions: entry + body so DATA edges can be attributed to a loading site.
    funcs = client.functions(fixture, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    entry_for = {str(i.get("name") or ""): str(i.get("entry")) for i in funcs["items"]}
    body_for = {str(i.get("name") or ""): int(i.get("body_size") or 0) for i in funcs["items"]}
    for name in ("main", "alpha", "beta"):
        assert name in entry_for, list(entry_for)

    # Symbols: Ghidra recognised the string and minted an s_..._<addr> label, so
    # the address comes from Ghidra's own analysis, not a hand-computed offset.
    symbols = client.symbols(fixture, project, limit=1024, timeout=_ANALYZE_TIMEOUT_S)
    string_syms = [
        s
        for s in symbols["items"]
        if str(s.get("name")).startswith("s_") and _MARKER in str(s.get("name"))
    ]
    assert string_syms, [s.get("name") for s in symbols["items"] if "s_" in str(s.get("name"))]
    string_addr = str(string_syms[0]["address"])

    # The decisive query: references TO the string are data-kind edges, one per
    # loading function, never calls. Ghidra reports DATA for a plain address
    # load and refines to PARAM when the address feeds a call argument (both
    # are data references in RefType terms); which one appears depends on the
    # codegen, so the gate accepts either while still rejecting control flow.
    xrefs = client.xrefs(fixture, project, string_addr, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert xrefs.get("mode") == "xrefs"
    assert xrefs.get("count", 0) == 2, xrefs["items"]
    assert all(str(x.get("to")) == string_addr for x in xrefs["items"]), xrefs["items"]
    assert all(str(x.get("type")) in {"DATA", "PARAM"} for x in xrefs["items"]), xrefs["items"]
    assert not any(
        "CALL" in str(x.get("type")) or "JUMP" in str(x.get("type")) for x in xrefs["items"]
    ), xrefs["items"]

    # Each DATA edge originates inside exactly one of the two loading functions.
    in_alpha = [
        x
        for x in xrefs["items"]
        if _within_body(str(x.get("from")), entry_for["alpha"], body_for["alpha"])
    ]
    in_beta = [
        x
        for x in xrefs["items"]
        if _within_body(str(x.get("from")), entry_for["beta"], body_for["beta"])
    ]
    assert len(in_alpha) == 1, xrefs["items"]
    assert len(in_beta) == 1, xrefs["items"]

    # Same ReferenceManager, different target kind: xrefs at the function alpha
    # returns a CALL from main -- proving the edge type follows the target.
    xrefs_alpha = client.xrefs(
        fixture, project, entry_for["alpha"], limit=256, timeout=_ANALYZE_TIMEOUT_S
    )
    call_from_main = [
        x
        for x in xrefs_alpha["items"]
        if "CALL" in str(x.get("type"))
        and _within_body(str(x.get("from")), entry_for["main"], body_for["main"])
    ]
    assert call_from_main, xrefs_alpha["items"]
