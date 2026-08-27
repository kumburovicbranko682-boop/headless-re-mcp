"""M11 static<->static gate: r2 and Ghidra recover a stripped binary alike.

The Ghidra-only stripped gate proves one engine can find functions with no
symbol table; this asks whether the two independent engines *agree* when both
are working blind. With r2's deeper ``aaa`` pass now available, radare2 follows
calls to recover functions that are not in ``.symtab`` and not directly named,
so it and Ghidra can be cross-checked on the same stripped image.

Ground truth comes from ``nm`` on an unstripped twin (identical -no-pie flags,
so the addresses match). After ``strip -s`` the gate confirms the binary carries
no symbols, then asserts both engines recover a function at ``crackme_check``'s
and ``mangle``'s addresses and name each purely from the address (r2's
``fcn.<addr>``, Ghidra's ``FUN_<addr>``) -- no symbol to borrow -- and that both
find the ``crackme_check -> mangle`` call at the identical site inside
crackme_check's body. ``main`` is deliberately not required of r2: nothing calls
it directly (the CRT passes it by pointer), so r2's call-following does not reach
it while Ghidra's broader analysis does -- a real, documented capability edge,
which the gate records by asserting Ghidra recovers main and the two engines
agree on the call-reachable pair. skip != pass when radare2/rizin, Ghidra, a C
compiler, or binutils (nm/strip) is missing.
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

__attribute__((noinline))
static int mangle(int x) { return (x ^ 0x5a) + 0x1337; }

__attribute__((noinline))
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    if (acc == 0x2b67) puts("m");
    return acc;
}

int main(int argc, char **argv) { return argc > 1 ? crackme_check(argv[1]) : 0; }
"""
_ANALYZE_TIMEOUT_S = 300.0
_R2_ANALYSIS = "aaa"


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


def _build_unstripped(dest: Path) -> Path | None:
    compiler = _compiler()
    if compiler is None:
        return None
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "u.bin"
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


def _strip_copy(binary: Path, dest: Path) -> Path | None:
    strip = shutil.which("strip")
    if strip is None:
        return None
    stripped = dest / "s.bin"
    shutil.copy(binary, stripped)
    try:
        subprocess.run(  # noqa: S603 - fixed args, local binutils
            [strip, "-s", str(stripped)], check=True, capture_output=True, timeout=60.0
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return stripped


def _nm(binary: Path) -> str | None:
    nm = shutil.which("nm")
    if nm is None:
        return None
    out = subprocess.run(  # noqa: S603 - fixed args, local binutils
        [nm, str(binary)], capture_output=True, text=True, timeout=60.0
    )
    return out.stdout


def _nm_addr(nm_output: str, name: str) -> int | None:
    for line in nm_output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == name:
            return int(parts[0], 16)
    return None


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


def _r2_call_sites(client: R2Client, binary: Path, target: int) -> set[int]:
    sites: set[int] = set()
    for x in client.xrefs_to(binary, target, analysis=_R2_ANALYSIS, timeout=120.0)["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        frm = x.get("from_address")
        value = frm.get("va") if isinstance(frm, dict) else x.get("from")
        if isinstance(value, int):
            sites.add(value)
    return sites


def _gh_call_sites(client: GhidraClient, binary: Path, project: Path, target: int) -> set[int]:
    sites: set[int] = set()
    xrefs = client.xrefs(binary, project, f"{target:08x}", limit=64, timeout=_ANALYZE_TIMEOUT_S)
    for x in xrefs["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        try:
            sites.add(int(str(x.get("from")), 16))
        except ValueError:
            continue
    return sites


@pytest.mark.integration
def test_m11_r2_and_ghidra_agree_on_a_stripped_binary(tmp_path: Path) -> None:
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — stripped agreement Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    unstripped = _build_unstripped(tmp_path)
    if unstripped is None:
        pytest.skip("no C compiler (cc/gcc/clang) — stripped Gate not run (skip != pass)")
    nm_output = _nm(unstripped)
    if nm_output is None:
        pytest.skip("nm (binutils) missing — cannot pin ground-truth addresses (skip != pass)")

    resolved = {name: _nm_addr(nm_output, name) for name in ("main", "crackme_check", "mangle")}
    assert all(v is not None for v in resolved.values()), resolved
    planted: dict[str, int] = {k: v for k, v in resolved.items() if v is not None}
    check_addr = planted["crackme_check"]
    mangle_addr = planted["mangle"]
    main_addr = planted["main"]

    stripped = _strip_copy(unstripped, tmp_path)
    if stripped is None:
        pytest.skip("strip (binutils) missing — stripped Gate not run (skip != pass)")
    assert "crackme_check" not in (_nm(stripped) or ""), "binary is not actually stripped"

    project = tmp_path / "ghidra_project"

    # r2, blind, with the deeper call-following pass.
    r2_funcs = r2.run(stripped, [_R2_ANALYSIS, "aflj"], timeout=120.0)
    r2_names: dict[int, str] = {int(f["offset"]): str(f.get("name")) for f in r2_funcs["items"]}

    # Ghidra, blind.
    gh_funcs = ghidra.functions(stripped, project, limit=512, timeout=_ANALYZE_TIMEOUT_S)
    gh_names: dict[int, str] = {}
    gh_size: dict[int, int] = {}
    for it in gh_funcs["items"]:
        try:
            addr = int(str(it.get("entry")), 16)
        except ValueError:
            continue
        gh_names[addr] = str(it.get("name"))
        gh_size[addr] = int(it.get("body_size") or 0)

    # Both engines recover the two call-reachable functions at the same
    # addresses, each named purely from the address -- no symbol to borrow.
    for addr in (check_addr, mangle_addr):
        assert addr in r2_names, (hex(addr), sorted(map(hex, r2_names)))
        assert addr in gh_names, (hex(addr), sorted(map(hex, gh_names)))
        assert f"{addr:08x}" in r2_names[addr], (hex(addr), r2_names[addr])
        assert gh_names[addr] == f"FUN_{addr:08x}", (hex(addr), gh_names[addr])

    # Both engines find the crackme_check -> mangle call at the identical site,
    # inside crackme_check's recovered body.
    r2_sites = _r2_call_sites(r2, stripped, mangle_addr)
    gh_sites = _gh_call_sites(ghidra, stripped, project, mangle_addr)
    shared = r2_sites & gh_sites
    assert shared, (sorted(map(hex, r2_sites)), sorted(map(hex, gh_sites)))
    check_size = gh_size.get(check_addr, 0)
    assert check_size > 0, gh_size
    assert any(check_addr <= s < check_addr + check_size for s in shared), (
        sorted(map(hex, shared)),
        hex(check_addr),
        check_size,
    )

    # The documented capability edge: main is reached only by pointer, so
    # Ghidra's broader analysis recovers it while r2's call-following does not.
    assert main_addr in gh_names, (hex(main_addr), "Ghidra should still find main")
    assert main_addr not in r2_names, (hex(main_addr), r2_names.get(main_addr))
