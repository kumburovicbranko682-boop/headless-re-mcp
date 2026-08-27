"""M11 static<->static gate: r2 and Ghidra agree on the recovered program.

The cross-checks so far pit the dynamic line against a static one; this pits the
two independent static engines against each other. r2 (analysis + capstone) and
Ghidra (its own loader + analyzer) reconstruct the same -no-pie ELF from
scratch, and this gate asserts they agree on both the function entry addresses
and the exact call-site addresses of the two-edge call graph
(main -> crackme_check -> mangle). Two engines built on different disassemblers
converging on the same addresses is strong evidence the recovery is real rather
than an artifact of one tool.

Because the fixture is non-PIE the addresses are absolute and directly
comparable, no rebasing. skip != pass when radare2/rizin, Ghidra or a C compiler
is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client

_SRC = """
#include <stdio.h>
static int mangle(int x) { return (x ^ 0x41) + 7; }
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    return acc;
}
int main(int argc, char **argv) {
    if (argc > 1) return crackme_check(argv[1]);
    printf("gate\\n");
    return 0;
}
"""
_ANALYZE_TIMEOUT_S = 300.0


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


def _r2_call_sites(client: R2Client, binary: Path, target: int, caller: str) -> set[int]:
    """Call-site addresses that reach ``target`` from function ``caller`` (r2)."""
    sites: set[int] = set()
    for x in client.xrefs_to(binary, target, timeout=60.0)["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        if caller not in str(x.get("fcn_name") or ""):
            continue
        frm = x.get("from_address")
        value = frm.get("va") if isinstance(frm, dict) else x.get("from")
        if isinstance(value, int):
            sites.add(value)
    return sites


def _gh_call_sites_within(
    client: GhidraClient, binary: Path, project: Path, target: int, lo: int, hi: int
) -> set[int]:
    """CALL sites reaching ``target`` whose source lies in ``[lo, hi)`` (Ghidra)."""
    sites: set[int] = set()
    xrefs = client.xrefs(binary, project, target, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    for x in xrefs["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        try:
            src = int(str(x.get("from")), 16)
        except ValueError:
            continue  # synthetic sources like "Entry Point"
        if lo <= src < hi:
            sites.add(src)
    return sites


@pytest.mark.integration
def test_m11_r2_and_ghidra_agree_on_functions_and_calls(tmp_path: Path) -> None:
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

    names = ("main", "crackme_check", "mangle")

    # r2's recovered entries (absolute, -no-pie).
    r2_funcs = r2.run(binary, ["aa", "aflj"], timeout=60.0)
    assert r2_funcs.get("parsed") is True
    r2_entry: dict[str, int] = {}
    for f in r2_funcs["items"]:
        for key in names:
            if key in str(f.get("name")):
                r2_entry.setdefault(key, int(f["offset"]))
    assert set(r2_entry) == set(names), r2_entry

    # Ghidra's recovered entries and body sizes.
    gh_funcs = ghidra.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert gh_funcs.get("mode") == "functions"
    gh_entry: dict[str, int] = {}
    gh_size: dict[str, int] = {}
    for it in gh_funcs["items"]:
        name = str(it.get("name"))
        if name in names:
            gh_entry[name] = int(str(it.get("entry")), 16)
            gh_size[name] = int(it.get("body_size") or 0)
    assert set(gh_entry) == set(names), gh_entry

    # Agreement 1: both engines put every function at the identical address.
    for key in names:
        assert r2_entry[key] == gh_entry[key], (key, hex(r2_entry[key]), hex(gh_entry[key]))

    # Agreement 2: both engines find the main -> crackme_check call at the same
    # site, and that site is inside main's body.
    r2_main_to_check = _r2_call_sites(r2, binary, r2_entry["crackme_check"], "main")
    gh_main_to_check = _gh_call_sites_within(
        ghidra, binary, project, gh_entry["crackme_check"],
        gh_entry["main"], gh_entry["main"] + gh_size["main"],
    )
    shared_outer = r2_main_to_check & gh_main_to_check
    assert shared_outer, (sorted(map(hex, r2_main_to_check)), sorted(map(hex, gh_main_to_check)))

    # Agreement 3: the inner edge crackme_check -> mangle, same way.
    r2_check_to_mangle = _r2_call_sites(r2, binary, r2_entry["mangle"], "crackme_check")
    gh_check_to_mangle = _gh_call_sites_within(
        ghidra, binary, project, gh_entry["mangle"],
        gh_entry["crackme_check"], gh_entry["crackme_check"] + gh_size["crackme_check"],
    )
    shared_inner = r2_check_to_mangle & gh_check_to_mangle
    assert shared_inner, (
        sorted(map(hex, r2_check_to_mangle)),
        sorted(map(hex, gh_check_to_mangle)),
    )
