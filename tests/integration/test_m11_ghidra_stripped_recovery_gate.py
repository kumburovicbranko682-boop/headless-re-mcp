"""M11 Ghidra gate: function + decompile recovery from a stripped binary.

Every other static gate leans on the symbol table -- it matches ``main`` or
``crackme_check`` by name -- so none of them prove the engine can recover a
function the analyzer had to *find* rather than read from ``.symtab``. This
strips the binary (``strip -s``, no symbols at all) and asks Ghidra to do it
blind: locate the functions, decompile one, and resolve its internal call, with
no names to lean on.

Ground truth comes from ``nm`` on an unstripped twin built with identical
-no-pie flags (so the code layout, and therefore the addresses, are the same).
The gate confirms the shipped binary is genuinely stripped, that Ghidra recovers
a function at each planted address and labels them ``FUN_<addr>`` (proving the
name came from analysis, not a symbol), and that decompiling ``crackme_check``'s
address still yields its real behaviour -- the loop bound, the compare constant,
the marker string inline, and a call rendered as ``FUN_<mangle_addr>``, i.e. the
internal edge resolved to the right address without a symbol. r2's whitelisted
``aa`` is too shallow to recover these blind, so this is a Ghidra-only capability
gate. skip != pass when Ghidra, a C compiler, or binutils (nm/strip) is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_MARKER = "decomp-marker-7c1e"
_SRC = """
#include <stdio.h>

__attribute__((noinline))
static int mangle(int x) { return (x ^ 0x5a) + 0x1337; }

__attribute__((noinline))
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    if (acc == 0x2b67) puts("decomp-marker-7c1e");
    return acc;
}

int main(int argc, char **argv) { return argc > 1 ? crackme_check(argv[1]) : 0; }
"""
_ANALYZE_TIMEOUT_S = 300.0


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


@pytest.mark.integration
def test_m11_ghidra_recovers_functions_from_a_stripped_binary(tmp_path: Path) -> None:
    client = _ghidra()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
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

    stripped = _strip_copy(unstripped, tmp_path)
    if stripped is None:
        pytest.skip("strip (binutils) missing — stripped Gate not run (skip != pass)")

    # Independent proof the shipped binary carries no symbols to lean on.
    stripped_nm = _nm(stripped) or ""
    assert "crackme_check" not in stripped_nm, stripped_nm[:200]

    project = tmp_path / "ghidra_project"
    funcs = client.functions(stripped, project, limit=512, timeout=_ANALYZE_TIMEOUT_S)
    addr_to_name: dict[int, str] = {}
    addr_to_size: dict[int, int] = {}
    for it in funcs["items"]:
        try:
            addr = int(str(it.get("entry")), 16)
        except ValueError:
            continue
        addr_to_name[addr] = str(it.get("name"))
        addr_to_size[addr] = int(it.get("body_size") or 0)

    # Boundary detection without symbols: Ghidra found a function at each planted
    # address, and named it from the address (FUN_<addr>), not a symbol table.
    for name, addr in planted.items():
        assert addr in addr_to_name, (name, hex(addr), sorted(map(hex, addr_to_name)))
        assert addr_to_name[addr] == f"FUN_{addr:08x}", (name, addr_to_name[addr])

    # Decompiling the stripped crackme_check still reconstructs its behaviour.
    dec = client.decompile(stripped, project, f"{check_addr:x}", timeout=_ANALYZE_TIMEOUT_S)
    assert dec.get("mode") == "decompile"
    assert dec.get("function") == f"FUN_{check_addr:08x}", dec
    c = str(dec.get("decompiled"))
    assert c.strip(), "empty decompilation"
    assert "< 8" in c, c
    assert "0x2b67" in c, c
    assert _MARKER in c, c
    # The internal call edge resolved to mangle's address despite no symbol.
    assert f"FUN_{mangle_addr:08x}(" in c, c

    # And the call graph corroborates it: a CALL to mangle originates inside
    # crackme_check's recovered body.
    check_size = addr_to_size.get(check_addr, 0)
    assert check_size > 0, addr_to_size
    xrefs = client.xrefs(
        stripped, project, f"{mangle_addr:08x}", limit=64, timeout=_ANALYZE_TIMEOUT_S
    )
    call_sites: set[int] = set()
    for x in xrefs["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        try:
            call_sites.add(int(str(x.get("from")), 16))
        except ValueError:
            continue
    assert any(check_addr <= s < check_addr + check_size for s in call_sites), (
        sorted(map(hex, call_sites)),
        hex(check_addr),
        check_size,
    )
