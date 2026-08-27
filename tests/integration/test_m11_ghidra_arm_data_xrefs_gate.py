"""M11 Ghidra data xrefs gate across ARM architectures (AArch64 + ARM32).

The x86-64 Ghidra data-xref gate proves string references are recovered when the
address is loaded directly (a single ``lea``). ARM never materialises an address
that way: AArch64 splits it across ``adrp`` + ``add`` (page base plus 12-bit
offset) and ARM32 loads it from a PC-relative literal pool. Recovering "who reads
this string" therefore requires Ghidra to propagate the constant across those two
instructions / through the pool -- if its analysis or the ExportJson xrefs branch
mishandled ARM address materialisation, string cross-referencing would silently
return nothing on every ARM binary while the x86 gate still passed.

This is deliberately Ghidra-only: radare2's shallow ``aa`` pass (the sole
analysis command the r2 backend whitelists) records no data references to the
string on ARM, so a cross-engine agreement is not achievable here -- a real limit
of that engine's default analysis, not something to paper over. For each
architecture the gate compiles an ELF where one literal is read from two
functions, finds the string via Ghidra's own ``s_..._<addr>`` label, and asserts
the ReferenceManager returns exactly the two data-kind references, one inside
each reader, with a call edge appearing only when the target is a function.

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

_MARKER = "arm-dataxref-secret-9f4b"
# One literal, two readers: the compiler merges it into a single .rodata entry,
# so each function's load is a data reference to one address -- materialised via
# adrp/add on AArch64 and a literal-pool ldr on ARM32.
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
# Ghidra reports DATA for a plain address load and PARAM when the address feeds a
# call argument; both are data references, never control flow.
_DATA_KINDS = {"DATA", "PARAM"}


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


def _within(from_addr: str, entry: int, size: int) -> bool:
    try:
        src = int(from_addr, 16)
    except ValueError:
        return False
    return entry <= src < entry + size


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
@pytest.mark.parametrize("arch", sorted(_TARGETS))
def test_m11_ghidra_recovers_arm_string_data_references(arch: str, tmp_path: Path) -> None:
    compiler_name, base_flags, want_class, want_machine = _TARGETS[arch]
    client = _ghidra()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} missing — Ghidra ARM data xref Gate not run (skip != pass)")
    binary = _build(compiler, base_flags, tmp_path)
    if binary is None:
        pytest.skip(f"{compiler_name} could not build {arch} fixture (skip != pass)")

    # Independent of Ghidra: the fixture really is this ARM variant.
    assert _elf_machine(binary) == (want_class, want_machine), _elf_machine(binary)

    project = tmp_path / "ghidra_project"

    funcs = client.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    entry: dict[str, int] = {}
    size: dict[str, int] = {}
    for it in funcs["items"]:
        name = str(it.get("name"))
        if name in ("alpha", "beta"):
            entry[name] = int(str(it.get("entry")), 16)
            size[name] = int(it.get("body_size") or 0)
    assert {"alpha", "beta"} <= set(entry), entry

    # Ghidra recognised the string and minted an s_..._<addr> label, so the
    # address comes from Ghidra's own analysis of the ARM materialisation.
    symbols = client.symbols(binary, project, limit=2048, timeout=_ANALYZE_TIMEOUT_S)
    string_syms = [
        s
        for s in symbols["items"]
        if str(s.get("name")).startswith("s_") and _MARKER in str(s.get("name"))
    ]
    assert string_syms, [s.get("name") for s in symbols["items"] if "s_" in str(s.get("name"))]
    string_addr = str(string_syms[0]["address"])

    # The decisive query: references TO the string are data-kind edges, one per
    # reader, recovered despite the adrp/add or literal-pool indirection.
    xrefs = client.xrefs(binary, project, string_addr, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert xrefs.get("count", 0) == 2, xrefs["items"]
    assert all(str(x.get("to")) == string_addr for x in xrefs["items"]), xrefs["items"]
    assert all(str(x.get("type")) in _DATA_KINDS for x in xrefs["items"]), xrefs["items"]
    assert not any(
        "CALL" in str(x.get("type")) or "JUMP" in str(x.get("type")) for x in xrefs["items"]
    ), xrefs["items"]

    # One data edge lands in alpha's body, the other in beta's.
    in_alpha = [
        x for x in xrefs["items"] if _within(str(x.get("from")), entry["alpha"], size["alpha"])
    ]
    in_beta = [
        x for x in xrefs["items"] if _within(str(x.get("from")), entry["beta"], size["beta"])
    ]
    assert len(in_alpha) == 1, xrefs["items"]
    assert len(in_beta) == 1, xrefs["items"]

    # Same ReferenceManager, different target kind: xrefs at the function alpha
    # returns a CALL (bl) -- proving the edge type follows the target, not the
    # tool, on ARM as on x86.
    xrefs_alpha = client.xrefs(
        binary, project, f"{entry['alpha']:08x}", limit=256, timeout=_ANALYZE_TIMEOUT_S
    )
    assert any("CALL" in str(x.get("type")) for x in xrefs_alpha["items"]), xrefs_alpha["items"]
