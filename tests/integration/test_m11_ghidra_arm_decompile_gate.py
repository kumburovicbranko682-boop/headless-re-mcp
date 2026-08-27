"""M11 Ghidra decompile gate across ARM architectures (AArch64 + ARM32).

The x86-64 decompile gate proves Ghidra's DecompInterface reconstructs a
function's behaviour, but a decompiler is a per-architecture translator: it lifts
each processor's instructions into p-code and reduces that to C. ARM's very
different encodings -- ``bl`` calls, ``adrp``/``add`` and literal-pool address
materialisation, condition-flag arithmetic -- exercise a separate lifter, so
passing on x86 says nothing about ARM. If the ARM p-code lift were wrong the
recovered C would be garbage (or empty) on every ARM binary while the x86 gate
stayed green.

For AArch64 and ARM32 this compiles the same crackme as the x86 decompile gate
(a helper call, a loop bound, a compare constant and a marker print), confirms
the ELF machine independently, and asserts the recovered C for ``crackme_check``
names itself, calls ``mangle``, prints the literal inline and keeps the loop
bound and compare constant -- while a second function (``mangle``) yields its
arithmetic constants and not the other function's marker, proving per-address
scoping on the ARM lifter too.

Runs where a Jython-capable Ghidra (HEADLESS_RE_GHIDRA_HOME) and the ARM cross
compiler are present; skips honestly otherwise. skip != pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_MARKER = "decomp-marker-7c1e"
# Same distinct, decompiler-visible semantics as the x86-64 decompile gate.
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
# arch -> (cross compiler, base flags, expected ei_class, expected e_machine)
_TARGETS = {
    "aarch64": ("aarch64-linux-gnu-gcc", ["-O0"], 2, 183),  # ELFCLASS64, EM_AARCH64
    "arm32": ("arm-linux-gnueabihf-gcc", ["-O0", "-marm"], 1, 40),  # ELFCLASS32, EM_ARM
}
_ANALYZE_TIMEOUT_S = 300.0


def _build(compiler: str, base_flags: list[str], dest: Path) -> Path | None:
    source = dest / "fixture.c"
    source.write_text(_SRC, encoding="utf-8")
    binary = dest / "fixture.bin"
    for extra in ([*base_flags, "-fno-pic", "-no-pie"], base_flags, []):
        try:
            subprocess.run(  # noqa: S603 - fixed args, local cross compiler
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


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
@pytest.mark.parametrize("arch", sorted(_TARGETS))
def test_m11_ghidra_decompiles_arm_function_with_real_semantics(arch: str, tmp_path: Path) -> None:
    compiler_name, base_flags, want_class, want_machine = _TARGETS[arch]
    client = _ghidra()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} missing — Ghidra ARM decompile Gate not run (skip != pass)")
    binary = _build(compiler, base_flags, tmp_path)
    if binary is None:
        pytest.skip(f"{compiler_name} could not build {arch} fixture (skip != pass)")

    # Independent of Ghidra: the fixture really is this ARM variant.
    assert _elf_machine(binary) == (want_class, want_machine), _elf_machine(binary)

    project = tmp_path / "ghidra_project"

    funcs = client.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    entry = {str(i.get("name")): str(i.get("entry")) for i in funcs["items"]}
    for name in ("crackme_check", "mangle"):
        assert name in entry, list(entry)

    # The ARM lifter reconstructs the outer function's real behaviour.
    outer = client.decompile(binary, project, entry["crackme_check"], timeout=_ANALYZE_TIMEOUT_S)
    assert outer.get("function") == "crackme_check", outer
    assert str(outer.get("entry")) == entry["crackme_check"], outer
    assert outer.get("truncated") is False
    c = str(outer.get("decompiled"))
    assert c.strip(), "empty decompilation"
    assert "crackme_check" in c, c
    assert "mangle(" in c, c
    assert "puts(" in c, c
    assert _MARKER in c, c
    assert "< 8" in c, c
    assert "0x2b67" in c, c

    # A different address decompiles a different function on the ARM lifter:
    # mangle's arithmetic constants surface and the outer marker does not.
    inner = client.decompile(binary, project, entry["mangle"], timeout=_ANALYZE_TIMEOUT_S)
    assert inner.get("function") == "mangle", inner
    inner_c = str(inner.get("decompiled"))
    assert "0x5a" in inner_c, inner_c
    assert "0x1337" in inner_c, inner_c
    assert _MARKER not in inner_c, inner_c
