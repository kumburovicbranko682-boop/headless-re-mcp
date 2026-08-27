"""M11 Ghidra decompile gate: real pseudo-C recovered from a 32-bit x86 ELF.

The Ghidra decompile gates cover x86-64 (ELF and PE), aarch64 and arm32, leaving
32-bit x86 -- a distinct lifter (``x86:LE:32``) with a different calling
convention and register set -- untested at the decompiler level even though the
i386 agreement gate now covers its function and call recovery. This compiles the
same ``crackme_check``/``mangle`` fixture with ``gcc -m32`` and asserts the
recovered C names the function, calls ``mangle``, embeds ``puts("<marker>")``
with the literal inline, and keeps the loop bound and compare constant; a second
function proves per-address scoping (its arithmetic constants appear, the outer
marker does not) and an unmapped address yields an empty decompilation.

Runs where Ghidra (HEADLESS_RE_GHIDRA_HOME) and a 32-bit-capable gcc
(gcc-multilib) are present; skips honestly otherwise. skip != pass.
"""

from __future__ import annotations

import os
import shutil
import struct
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
_EM_386 = 3


def _build_i386_elf(dest: Path) -> Path | None:
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        return None
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "f.bin"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local compiler
            [compiler, "-m32", "-O0", "-fno-pic", "-no-pie", "-o", str(binary), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None  # no gcc-multilib / 32-bit libc
    return binary if binary.is_file() else None


def _is_i386_elf(binary: Path) -> bool:
    blob = binary.read_bytes()
    if blob[:4] != b"\x7fELF" or len(blob) < 20:
        return False
    is_32bit = blob[4] == 1  # EI_CLASS == ELFCLASS32
    machine = struct.unpack("<H", blob[18:20])[0]
    return is_32bit and machine == _EM_386


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
def test_m11_ghidra_decompiles_an_i386_function(tmp_path: Path) -> None:
    client = _ghidra()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    binary = _build_i386_elf(tmp_path)
    if binary is None:
        pytest.skip(
            "no 32-bit-capable gcc (gcc-multilib) — i386 decompile Gate not run (skip != pass)"
        )
    assert _is_i386_elf(binary), binary.read_bytes()[:20]
    project = tmp_path / "ghidra_project"

    funcs = client.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    entry = {str(i.get("name")): str(i.get("entry")) for i in funcs["items"]}
    for name in ("crackme_check", "mangle"):
        assert name in entry, list(entry)

    # Outer function: named, complete, and behaviourally faithful for i386.
    outer = client.decompile(binary, project, entry["crackme_check"], timeout=_ANALYZE_TIMEOUT_S)
    assert outer.get("mode") == "decompile"
    assert outer.get("function") == "crackme_check", outer
    assert outer.get("truncated") is False
    c = str(outer.get("decompiled"))
    assert c.strip(), "empty decompilation"
    assert "crackme_check" in c, c
    assert "mangle(" in c, c
    assert "puts(" in c, c
    assert _MARKER in c, c
    assert "< 8" in c, c
    assert "0x2b67" in c, c

    # A second address decompiles a different function: mangle's constants
    # surface while the outer marker does not, proving per-address scoping.
    inner = client.decompile(binary, project, entry["mangle"], timeout=_ANALYZE_TIMEOUT_S)
    assert inner.get("function") == "mangle", inner
    inner_c = str(inner.get("decompiled"))
    assert "0x5a" in inner_c, inner_c
    assert "0x1337" in inner_c, inner_c
    assert _MARKER not in inner_c, inner_c

    # Contract: an address outside any function yields an empty decompilation.
    empty = client.decompile(binary, project, "0x0", timeout=_ANALYZE_TIMEOUT_S)
    assert empty.get("mode") == "decompile"
    assert empty.get("function") is None, empty
    assert str(empty.get("decompiled")) == "", empty
