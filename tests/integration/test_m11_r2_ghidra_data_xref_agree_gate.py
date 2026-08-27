"""M11 static<->static gate: r2 and Ghidra agree on who reads a string.

The existing r2<->Ghidra agreement gate corroborates the *call* graph across two
independent static engines; the per-engine data-xref gates prove each tool finds
a string's readers on its own. This gate closes the loop on the data side: it
asks r2 (analysis + capstone) and Ghidra (its own loader + analyzer) to locate
the same .rodata string and enumerate the code sites that reference it, then
asserts the two engines converge on the identical string address and the
identical set of load-site addresses. Two disassemblers agreeing to the byte on
where a string lives and who loads it is strong evidence the data-flow recovery
is real, not a single tool's artefact.

The fixture is -no-pie so addresses are absolute and directly comparable across
engines with no rebasing. skip != pass when radare2/rizin, Ghidra or a C
compiler is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "xengine-dataxref-secret-5d7a"
# One literal, two readers: the compiler merges the string into a single
# .rodata entry, so each function's load is a data reference to one address.
_SRC = """
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int alpha(void) { return puts("xengine-dataxref-secret-5d7a"); }

__attribute__((noinline))
int beta(const char *s) { return strcmp(s, "xengine-dataxref-secret-5d7a") == 0; }

int main(int argc, char **argv) {
    if (argc > 1) return beta(argv[1]);
    return alpha();
}
"""
_ANALYZE_TIMEOUT_S = 300.0
# Ghidra reports DATA for a plain address load and PARAM when the address feeds
# a call argument; both are data references (never control flow).
_DATA_KINDS = {"DATA", "PARAM"}


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


def _build_no_pie_elf(dest: Path) -> Path | None:
    compiler = _compiler()
    if compiler is None:
        return None
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "f.bin"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local compiler
            [compiler, "-O0", "-fno-pic", "-no-pie", "-o", str(binary), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return binary if binary.is_file() else None


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


def _r2_string_va(client: R2Client, binary: Path) -> int | None:
    for s in client.run(binary, ["izj"], timeout=60.0)["items"]:
        if _MARKER in str(s.get("string", "")):
            return int(s["vaddr"])
    return None


def _r2_data_sites(client: R2Client, binary: Path, string_va: int) -> set[int]:
    """Code addresses that load ``string_va`` as data (r2)."""
    sites: set[int] = set()
    for edge in client.xrefs_to(binary, string_va, timeout=60.0)["items"]:
        if "CALL" in str(edge.get("type")) or "JUMP" in str(edge.get("type")):
            continue
        frm = edge.get("from_address")
        value = frm.get("va") if isinstance(frm, dict) else edge.get("from")
        if isinstance(value, int):
            sites.add(value)
    return sites


def _gh_string_addr(client: GhidraClient, binary: Path, project: Path) -> int | None:
    syms = client.symbols(binary, project, limit=1024, timeout=_ANALYZE_TIMEOUT_S)
    for sym in syms["items"]:
        name = str(sym.get("name"))
        if name.startswith("s_") and _MARKER in name:
            return int(str(sym.get("address")), 16)
    return None


def _gh_data_sites(client: GhidraClient, binary: Path, project: Path, string_addr: int) -> set[int]:
    """Code addresses that reference ``string_addr`` as data (Ghidra)."""
    sites: set[int] = set()
    xrefs = client.xrefs(
        binary, project, f"{string_addr:08x}", limit=256, timeout=_ANALYZE_TIMEOUT_S
    )
    for x in xrefs["items"]:
        if str(x.get("type")) not in _DATA_KINDS:
            continue
        try:
            sites.add(int(str(x.get("from")), 16))
        except ValueError:
            continue
    return sites


@pytest.mark.integration
def test_m11_r2_and_ghidra_agree_on_string_readers(tmp_path: Path) -> None:
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — agreement Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = _build_no_pie_elf(tmp_path)
    if binary is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the ELF fixture (skip != pass)")
    project = tmp_path / "ghidra_project"

    # Ghidra's function map anchors the load sites to alpha/beta bodies.
    gh_funcs = ghidra.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    entry: dict[str, int] = {}
    size: dict[str, int] = {}
    for it in gh_funcs["items"]:
        name = str(it.get("name"))
        if name in ("alpha", "beta"):
            entry[name] = int(str(it.get("entry")), 16)
            size[name] = int(it.get("body_size") or 0)
    assert {"alpha", "beta"} <= set(entry), entry

    # Agreement 1: both engines locate the same string at the same address.
    r2_string = _r2_string_va(r2, binary)
    gh_string = _gh_string_addr(ghidra, binary, project)
    assert r2_string is not None, "r2 did not find the marker string"
    assert gh_string is not None, "Ghidra did not label the marker string"
    assert r2_string == gh_string, (hex(r2_string), hex(gh_string))

    # Agreement 2: both engines find the identical set of load sites -- exactly
    # the two functions that read the literal, to the byte.
    r2_sites = _r2_data_sites(r2, binary, r2_string)
    gh_sites = _gh_data_sites(ghidra, binary, project, gh_string)
    assert len(r2_sites) == 2, sorted(map(hex, r2_sites))
    assert r2_sites == gh_sites, (sorted(map(hex, r2_sites)), sorted(map(hex, gh_sites)))

    # Agreement 3: one agreed site lands in alpha's body, the other in beta's.
    def _in(addr: int, name: str) -> bool:
        return entry[name] <= addr < entry[name] + size[name]

    assert sum(1 for a in r2_sites if _in(a, "alpha")) == 1, (sorted(map(hex, r2_sites)), entry)
    assert sum(1 for a in r2_sites if _in(a, "beta")) == 1, (sorted(map(hex, r2_sites)), entry)
