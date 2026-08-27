"""M11 Ghidra xrefs gate across ARM architectures (AArch64 + ARM32).

The Ghidra live gate proves the ExportJson.py xrefs branch (Ghidra's
ReferenceManager) recovers the call graph on x86-64, and the ARM decompile gates
prove the decompiler on ARM -- but nothing proves the *xref recovery* survives a
different call encoding. On ARM a call is branch-with-link (``bl``/``blx``),
which Ghidra classifies as UNCONDITIONAL_CALL rather than the x86 CALL flavor;
if the ReferenceManager export mis-decoded those, the recovered call graph would
be wrong on every ARM binary and only the decompile gates would still pass. This
is the Ghidra counterpart to the r2 ARM targeted-xrefs gate.

For each architecture the gate cross-compiles the two-edge crackme
(main -> crackme_check -> mangle), independently confirms the ELF machine, and
asserts Ghidra recovers both inbound CALL edges: crackme_check carries a CALL
whose source lies inside main's body, and mangle a CALL whose source lies inside
crackme_check's body, with every reference pointing at the requested address.

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

# Identical logic to the x86-64 / AArch64 / ARM32 Ghidra gates so the call graph
# is directly comparable; only the target architecture differs.
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

# arch -> (cross compiler, base cc flags, expected ei_class, expected e_machine)
_TARGETS = {
    "aarch64": ("aarch64-linux-gnu-gcc", ["-O0"], 2, 183),  # ELFCLASS64, EM_AARCH64
    "arm32": ("arm-linux-gnueabihf-gcc", ["-O0", "-marm"], 1, 40),  # ELFCLASS32, EM_ARM (A32)
}
_ANALYZE_TIMEOUT_S = 300.0


def _build(compiler: str, base_flags: list[str], dest: Path) -> Path | None:
    source = dest / "fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    binary = dest / "fixture.bin"
    # -no-pie keeps entry addresses stable; fall back if a toolchain rejects it.
    for extra in ([*base_flags, "-fno-pic", "-no-pie"], base_flags, []):
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


def _within_body(from_addr: str, entry_hex: str, body_size: int) -> bool:
    """True when a Ghidra ``from`` address falls inside ``[entry, entry+body)``."""
    try:
        source = int(from_addr, 16)
    except ValueError:
        return False  # synthetic sources like "Entry Point" are not addresses
    start = int(entry_hex, 16)
    return start <= source < start + body_size


def _client() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
@pytest.mark.parametrize("arch", sorted(_TARGETS))
def test_m11_ghidra_recovers_arm_call_edges(arch: str, tmp_path: Path) -> None:
    compiler_name, base_flags, want_class, want_machine = _TARGETS[arch]
    client = _client()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} missing — Ghidra ARM xrefs Gate not run (skip != pass)")

    fixture = _build(compiler, base_flags, tmp_path)
    if fixture is None:
        pytest.skip(f"{compiler_name} could not build {arch} fixture (skip != pass)")

    # Independent of Ghidra: the fixture really is the ARM variant we expect.
    ei_class, e_machine = _elf_machine(fixture)
    assert (ei_class, e_machine) == (want_class, want_machine), (ei_class, e_machine)

    project = tmp_path / "ghidra_project"

    # Functions: Ghidra selects the ARM language from the ELF and recovers the
    # whole call graph as named functions with entry + body_size.
    funcs = client.functions(fixture, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert funcs.get("mode") == "functions"
    entry_for: dict[str, str] = {}
    body_for: dict[str, int] = {}
    for item in funcs["items"]:
        name = str(item.get("name") or "")
        if isinstance(item.get("entry"), str) and isinstance(item.get("body_size"), int):
            entry_for[name] = str(item["entry"])
            body_for[name] = int(item["body_size"])
    for name in ("main", "crackme_check", "mangle"):
        assert name in entry_for, list(entry_for)

    # Outer edge: main is the sole caller of crackme_check, so the xrefs branch
    # surfaces an inbound CALL whose source is inside main's body. On ARM the
    # reference type is UNCONDITIONAL_CALL (bl), which "CALL" still matches.
    xrefs_check = client.xrefs(
        fixture, project, entry_for["crackme_check"], limit=256, timeout=_ANALYZE_TIMEOUT_S
    )
    assert xrefs_check.get("mode") == "xrefs"
    assert all(
        str(x.get("to")) == entry_for["crackme_check"] for x in xrefs_check["items"]
    ), xrefs_check["items"]
    call_from_main = [
        x
        for x in xrefs_check["items"]
        if "CALL" in str(x.get("type"))
        and _within_body(str(x.get("from")), entry_for["main"], body_for["main"])
    ]
    assert call_from_main, xrefs_check["items"]

    # Inner edge: crackme_check calls mangle, so mangle carries an inbound CALL
    # originating inside crackme_check's body -- the second bl edge recovered.
    xrefs_mangle = client.xrefs(
        fixture, project, entry_for["mangle"], limit=256, timeout=_ANALYZE_TIMEOUT_S
    )
    assert all(
        str(x.get("to")) == entry_for["mangle"] for x in xrefs_mangle["items"]
    ), xrefs_mangle["items"]
    call_from_check = [
        x
        for x in xrefs_mangle["items"]
        if "CALL" in str(x.get("type"))
        and _within_body(
            str(x.get("from")), entry_for["crackme_check"], body_for["crackme_check"]
        )
    ]
    assert call_from_check, xrefs_mangle["items"]
