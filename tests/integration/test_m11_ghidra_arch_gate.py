"""M11 Ghidra arch gate: the headless decompiler on a non-x86 target.

The live Ghidra gate proves analyzeHeadless + ExportJson.py end to end, but only
on an x86-64 ELF. Ghidra's defining feature is its architecture-independent
decompiler, so this gate cross-compiles the same crackme to AArch64 and asserts
Ghidra recovers the call graph and decompiles ARM64 back to the *same* C logic
-- mangle's exact ``(x ^ 0x41) + 7`` and crackme_check's surviving call and loop
bound. Ghidra auto-selects the language from the ELF, so recovering that
arithmetic is itself proof it decoded ARM64 rather than misreading it as x86.

Before trusting Ghidra it confirms the fixture really is AArch64 by reading the
ELF e_machine. Runs where a Jython-capable Ghidra (HEADLESS_RE_GHIDRA_HOME) and
the aarch64 cross compiler are present; skips honestly otherwise. skip != pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

# Identical logic to the x86-64 Ghidra gate so the two are directly comparable;
# only the target architecture differs.
_ELF_SOURCE = """
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
_EM_AARCH64 = 183  # ELF e_machine value for AArch64.


def _arm_compiler() -> str | None:
    return shutil.which("aarch64-linux-gnu-gcc")


def _build_aarch64_fixture(tmp_path: Path) -> Path | None:
    compiler = _arm_compiler()
    if compiler is None:
        return None
    source = tmp_path / "ghidra_arm_fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    binary = tmp_path / "ghidra_arm_fixture.bin"
    # Keep symbols and stable addresses like the x86-64 gate; fall back if the
    # cross toolchain rejects the flags.
    for extra in (["-O0", "-fno-pic", "-no-pie"], ["-O0"], []):
        try:
            subprocess.run(
                [compiler, *extra, str(source), "-o", str(binary)],
                check=True,
                capture_output=True,
                timeout=120.0,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue
        if binary.is_file():
            return binary
    return None


def _elf_machine(binary: Path) -> tuple[int, int]:
    header = binary.read_bytes()[:20]
    assert header[:4] == b"\x7fELF", header[:4]
    return header[4], int.from_bytes(header[18:20], "little")


def _client() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


_ANALYZE_TIMEOUT_S = 300.0


@pytest.mark.integration
def test_m11_ghidra_decompiles_an_aarch64_target(tmp_path: Path) -> None:
    client = _client()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    fixture = _build_aarch64_fixture(tmp_path)
    if fixture is None:
        pytest.skip("aarch64-linux-gnu-gcc missing — Ghidra ARM64 Gate not run (skip != pass)")

    # Independent of Ghidra: the fixture really is a 64-bit AArch64 ELF.
    ei_class, e_machine = _elf_machine(fixture)
    assert ei_class == 2, ei_class  # ELFCLASS64
    assert e_machine == _EM_AARCH64, e_machine

    project = tmp_path / "ghidra_project"

    # Functions: Ghidra selects the ARM64 language from the ELF and recovers the
    # whole call graph as named functions.
    funcs = client.functions(fixture, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert funcs.get("mode") == "functions"
    entry_for = {str(item.get("name") or ""): str(item.get("entry")) for item in funcs["items"]}
    assert "crackme_check" in entry_for, list(entry_for)
    assert "main" in entry_for, list(entry_for)
    assert "mangle" in entry_for, list(entry_for)

    # Decompiling crackme_check on ARM64 recovers the same structure as x86-64:
    # the surviving call into the helper and the loop bound.
    decomp = client.decompile(
        fixture, project, entry_for["crackme_check"], timeout=_ANALYZE_TIMEOUT_S
    )
    assert decomp.get("mode") == "decompile"
    assert "crackme_check" in str(decomp.get("function") or "")
    body = str(decomp.get("decompiled") or "")
    assert "crackme_check" in body, body
    assert "mangle(" in body, body
    assert "< 8" in body, body

    # mangle decompiles to its exact arithmetic ((x ^ 0x41) + 7). Recovering
    # these operators/constants from ARM64 machine code is the strongest proof
    # the decompiler decoded the right architecture.
    decomp_mangle = client.decompile(
        fixture, project, entry_for["mangle"], timeout=_ANALYZE_TIMEOUT_S
    )
    assert "mangle" in str(decomp_mangle.get("function") or "")
    mangle_body = str(decomp_mangle.get("decompiled") or "")
    assert "0x41" in mangle_body, mangle_body
    assert "^" in mangle_body, mangle_body
    assert "+ 7" in mangle_body, mangle_body
