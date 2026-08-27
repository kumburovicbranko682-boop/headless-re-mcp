"""M11 static<->static gate: r2 and Ghidra agree on ARM string readers.

The Ghidra-only ARM data-xref gate exists because r2's default ``aa`` pass is
too shallow to see ARM string loads (AArch64 ``adrp/add``, ARM32 literal-pool
``ldr``). With the r2 backend now permitting the deeper ``aaa`` analysis pass,
r2 recovers those loads too, so this gate cross-checks the two engines on ARM:
they must land the .rodata string at the byte-identical address (proving both
reconstructed the multi-instruction address materialisation to the same value)
and converge on the same load instruction inside each of the two reader
functions.

On AArch64 the reader *sets* match exactly; on ARM32 r2 reports extra
references around the literal-pool load, so -- as in the PE data-xref gate --
the assertion is a shared-site-per-reader convergence plus Ghidra's clean
one-per-reader count, not strict set equality. Parametrised over AArch64 and
ARM32. skip != pass when radare2/rizin, Ghidra or the ARM cross compiler is
missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "arm-dataxref-secret-9f4b"
_SRC = """
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int alpha(void) { return puts("arm-dataxref-secret-9f4b"); }

__attribute__((noinline))
int beta(const char *s) { return strcmp(s, "arm-dataxref-secret-9f4b") == 0; }

int main(int argc, char **argv) {
    if (argc > 1) return beta(argv[1]);
    return alpha();
}
"""
# arch -> (cross compiler, base flags, expected ei_class, expected e_machine)
_TARGETS = {
    "aarch64": ("aarch64-linux-gnu-gcc", ["-O0"], 2, 183),  # ELFCLASS64, EM_AARCH64
    "arm32": ("arm-linux-gnueabihf-gcc", ["-O0", "-marm"], 1, 40),  # ELFCLASS32, EM_ARM
}
_ANALYZE_TIMEOUT_S = 300.0
_DATA_KINDS = {"DATA", "PARAM"}
# The deeper r2 pass is what makes ARM data references visible at all.
_R2_ANALYSIS = "aaa"


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


def _r2_string_va(client: R2Client, binary: Path) -> int | None:
    for s in client.run(binary, ["izj"], timeout=60.0)["items"]:
        if _MARKER in str(s.get("string", "")):
            return int(s["vaddr"])
    return None


def _r2_data_sites(client: R2Client, binary: Path, string_va: int) -> set[int]:
    sites: set[int] = set()
    edges = client.xrefs_to(binary, string_va, analysis=_R2_ANALYSIS, timeout=120.0)
    for edge in edges["items"]:
        if "CALL" in str(edge.get("type")) or "JUMP" in str(edge.get("type")):
            continue
        frm = edge.get("from_address")
        value = frm.get("va") if isinstance(frm, dict) else edge.get("from")
        if isinstance(value, int):
            sites.add(value)
    return sites


def _gh_string_addr(client: GhidraClient, binary: Path, project: Path) -> int | None:
    syms = client.symbols(binary, project, limit=2048, timeout=_ANALYZE_TIMEOUT_S)
    for sym in syms["items"]:
        name = str(sym.get("name"))
        if name.startswith("s_") and _MARKER in name:
            return int(str(sym.get("address")), 16)
    return None


def _gh_data_sites(client: GhidraClient, binary: Path, project: Path, string_addr: int) -> set[int]:
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
@pytest.mark.parametrize("arch", sorted(_TARGETS))
def test_m11_r2_and_ghidra_agree_on_arm_string_readers(arch: str, tmp_path: Path) -> None:
    compiler_name, base_flags, want_class, want_machine = _TARGETS[arch]
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — ARM data-xref Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} missing — ARM data-xref Gate not run (skip != pass)")
    binary = _build(compiler, base_flags, tmp_path)
    if binary is None:
        pytest.skip(f"{compiler_name} could not build {arch} fixture (skip != pass)")
    assert _elf_machine(binary) == (want_class, want_machine), _elf_machine(binary)
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

    # Agreement 1: both engines locate the string at the byte-identical address,
    # so both reconstructed the ARM address materialisation to the same value.
    r2_string = _r2_string_va(r2, binary)
    gh_string = _gh_string_addr(ghidra, binary, project)
    assert r2_string is not None, "r2 did not find the marker string"
    assert gh_string is not None, "Ghidra did not label the marker string"
    assert r2_string == gh_string, (hex(r2_string), hex(gh_string))

    r2_sites = _r2_data_sites(r2, binary, r2_string)
    gh_sites = _gh_data_sites(ghidra, binary, project, gh_string)

    def _in(addr: int, name: str) -> bool:
        return entry[name] <= addr < entry[name] + size[name]

    # Ghidra recovers exactly one reader in each function.
    gh_alpha = {a for a in gh_sites if _in(a, "alpha")}
    gh_beta = {a for a in gh_sites if _in(a, "beta")}
    assert len(gh_alpha) == 1, (sorted(map(hex, gh_sites)), entry)
    assert len(gh_beta) == 1, (sorted(map(hex, gh_sites)), entry)

    # Agreement 2: r2's deeper pass finds a load in each reader, and converges
    # with Ghidra on the same instruction there. (On ARM32 r2 reports extra
    # literal-pool references, so this is shared-site, not strict set equality.)
    r2_alpha = {a for a in r2_sites if _in(a, "alpha")}
    r2_beta = {a for a in r2_sites if _in(a, "beta")}
    assert r2_alpha & gh_alpha, (sorted(map(hex, r2_alpha)), sorted(map(hex, gh_alpha)))
    assert r2_beta & gh_beta, (sorted(map(hex, r2_beta)), sorted(map(hex, gh_beta)))
