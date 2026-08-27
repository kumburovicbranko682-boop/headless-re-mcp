"""M11 Ghidra decompile gate: real pseudo-C recovered from a PE.

The other Ghidra decompile gates all feed the DecompInterface an ELF; this feeds
it a Windows PE cross-built with mingw-w64, so the whole pipeline -- PE loader,
analyzer, decompiler -- runs on the Portable Executable container instead of
ELF. The interesting difference is the print: in a PE ``puts`` is an imported
symbol reached through the import thunk table, not an ELF PLT stub, and this gate
asserts the decompiler still renders that call with its string literal inline. It
compiles the same ``crackme_check``/``mangle`` fixture as the ELF decompile gate,
then asserts the recovered C names the function, calls ``mangle``, embeds
``puts("<marker>")``, and keeps the loop bound and compare constant; a second
function proves per-address scoping (its arithmetic constants appear, the outer
marker does not) and an unmapped address yields an empty decompilation.

Complements the r2 PE imports gate and the r2<->Ghidra PE agreement gate, which
stop at function and reference recovery: this carries PE support up to the
decompiler. skip != pass when Ghidra or the mingw cross compiler is missing.
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
_MINGW = "x86_64-w64-mingw32-gcc"
_ANALYZE_TIMEOUT_S = 300.0


def _build_pe(dest: Path) -> Path | None:
    compiler = shutil.which(_MINGW)
    if compiler is None:
        return None
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    exe = dest / "f.exe"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local cross compiler
            [compiler, "-O0", "-o", str(exe), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return exe if exe.is_file() else None


def _is_pe(binary: Path) -> bool:
    blob = binary.read_bytes()
    if blob[:2] != b"MZ" or len(blob) < 0x40:
        return False
    pe_off = int.from_bytes(blob[0x3C:0x40], "little")
    return blob[pe_off : pe_off + 4] == b"PE\x00\x00"


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
def test_m11_ghidra_decompiles_a_pe_function(tmp_path: Path) -> None:
    client = _ghidra()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    binary = _build_pe(tmp_path)
    if binary is None:
        pytest.skip(f"{_MINGW} missing — cannot build the PE fixture (skip != pass)")
    assert _is_pe(binary), binary.read_bytes()[:2]
    project = tmp_path / "ghidra_project"

    funcs = client.functions(binary, project, limit=512, timeout=_ANALYZE_TIMEOUT_S)
    entry = {str(i.get("name")): str(i.get("entry")) for i in funcs["items"]}
    for name in ("crackme_check", "mangle"):
        assert name in entry, list(entry)

    # Outer function: decompiled through the PE loader, named and complete.
    outer = client.decompile(binary, project, entry["crackme_check"], timeout=_ANALYZE_TIMEOUT_S)
    assert outer.get("mode") == "decompile"
    assert outer.get("function") == "crackme_check", outer
    assert str(outer.get("entry")) == entry["crackme_check"], outer
    assert outer.get("truncated") is False
    c = str(outer.get("decompiled"))
    assert c.strip(), "empty decompilation"

    # Real behaviour survives: the helper call, the imported puts with its literal
    # inline, the loop bound and the compare constant.
    assert "crackme_check" in c, c
    assert "mangle(" in c, c
    assert "puts(" in c, c
    assert _MARKER in c, c
    assert "< 8" in c, c
    assert "0x2b67" in c, c

    # A second address decompiles a different function: mangle's constants appear
    # while the outer marker does not, so decompilation is address-scoped.
    inner = client.decompile(binary, project, entry["mangle"], timeout=_ANALYZE_TIMEOUT_S)
    assert inner.get("function") == "mangle", inner
    inner_c = str(inner.get("decompiled"))
    assert "0x5a" in inner_c, inner_c
    assert "0x1337" in inner_c, inner_c
    assert _MARKER not in inner_c, inner_c

    # Contract: an address outside the mapped image yields an empty
    # decompilation (no function/entry), not an error.
    empty = client.decompile(binary, project, "0x0", timeout=_ANALYZE_TIMEOUT_S)
    assert empty.get("mode") == "decompile"
    assert empty.get("function") is None, empty
    assert str(empty.get("decompiled")) == "", empty
