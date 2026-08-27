"""M11 Ghidra decompile gate: recovered pseudo-C carries real semantics.

The Ghidra live/xref gates exercise the function, symbol and reference exports,
but the DecompInterface path -- the highest-level and slowest capability -- is
only touched by contract tests that call it with a throwaway address and check
it does not crash. This gate proves the decompiler actually reconstructs a
function's behaviour: it compiles a -no-pie ELF whose ``crackme_check`` loops
over its argument, calls a helper ``mangle``, compares against a constant and
prints a marker string, then asserts the recovered C names the function, invokes
``mangle``, embeds the ``puts("...")`` call with the literal inline, and shows
the loop bound and compare constant. A second function (``mangle``) is
decompiled to prove per-address scoping -- its arithmetic constants appear while
the other function's marker does not -- and an out-of-function address yields an
empty decompilation rather than an error.

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

_MARKER = "decomp-marker-7c1e"
# Distinct, decompiler-visible semantics: a helper call, a loop bound, a compare
# constant and a string print, so the recovered C can be checked for real
# behaviour rather than mere non-emptiness.
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


@pytest.mark.integration
def test_m11_ghidra_decompiles_a_function_with_real_semantics(tmp_path: Path) -> None:
    client = _ghidra()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    binary = _build_no_pie_elf(tmp_path)
    if binary is None:
        pytest.skip("no C compiler (cc/gcc/clang) — decompile Gate not run (skip != pass)")
    project = tmp_path / "ghidra_project"

    funcs = client.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    entry = {str(i.get("name")): str(i.get("entry")) for i in funcs["items"]}
    for name in ("crackme_check", "mangle"):
        assert name in entry, list(entry)

    # Decompile the outer function: the payload must name it, echo its entry and
    # not be truncated.
    outer = client.decompile(binary, project, entry["crackme_check"], timeout=_ANALYZE_TIMEOUT_S)
    assert outer.get("mode") == "decompile"
    assert outer.get("function") == "crackme_check", outer
    assert str(outer.get("entry")) == entry["crackme_check"], outer
    assert outer.get("truncated") is False
    c = str(outer.get("decompiled"))
    assert c.strip(), "empty decompilation"

    # The recovered C carries the function's real behaviour: it names itself,
    # calls the helper, prints the literal inline, and keeps the loop bound and
    # compare constant.
    assert "crackme_check" in c, c
    assert "mangle(" in c, c
    assert "puts(" in c, c
    assert _MARKER in c, c
    assert "< 8" in c, c
    assert "0x2b67" in c, c

    # A different address decompiles a different function: mangle's arithmetic
    # constants surface, and crucially the outer function's marker does not,
    # proving decompilation is scoped to the requested address.
    inner = client.decompile(binary, project, entry["mangle"], timeout=_ANALYZE_TIMEOUT_S)
    assert inner.get("function") == "mangle", inner
    inner_c = str(inner.get("decompiled"))
    assert "0x5a" in inner_c, inner_c
    assert "0x1337" in inner_c, inner_c
    assert _MARKER not in inner_c, inner_c

    # Contract: an address outside any function yields an empty decompilation
    # (no function/entry keys), not an error.
    empty = client.decompile(binary, project, "0x0", timeout=_ANALYZE_TIMEOUT_S)
    assert empty.get("mode") == "decompile"
    assert empty.get("function") is None, empty
    assert str(empty.get("decompiled")) == "", empty
