"""M11 static<->static gate: r2 and Ghidra agree on the ARM call graph.

The x86-64 agreement gate corroborates function entries and call-site addresses
across the two independent static engines, and separate per-engine ARM xref
gates prove each tool decodes ``bl``/``blx`` on its own. This gate combines the
two: for AArch64 and ARM32 it cross-compiles the two-edge crackme
(main -> crackme_check -> mangle) and asserts r2 (analysis + capstone) and Ghidra
(its own loader + analyzer) converge -- to the byte -- on the same function
entries and the same branch-with-link call sites. On ARM a call is a single
``bl`` instruction, so unlike a string load (which may split across adrp/add)
both engines attribute the edge to one comparable address.

Because the fixtures are -no-pie the addresses are absolute and directly
comparable with no rebasing. r2 decorates names (``sym.mangle``) and lists the
PLT stub ``sym.imp.__libc_start_main`` whose name contains "main", so entries
are matched on the precise trailing component with imports excluded. skip != pass
when radare2/rizin, Ghidra or the ARM cross compiler is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client

# Same two-edge call graph as the x86-64 agreement and ARM xref gates.
_SRC = """
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
# arch -> (cross compiler, base flags, expected ei_class, expected e_machine)
_TARGETS = {
    "aarch64": ("aarch64-linux-gnu-gcc", ["-O0"], 2, 183),  # ELFCLASS64, EM_AARCH64
    "arm32": ("arm-linux-gnueabihf-gcc", ["-O0", "-marm"], 1, 40),  # ELFCLASS32, EM_ARM
}
_NAMES = ("main", "crackme_check", "mangle")
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


def _r2_entries(client: R2Client, binary: Path) -> dict[str, int]:
    """Map our three function names to r2's recovered entry addresses.

    r2 prefixes real symbols (``sym.mangle``) and also lists the PLT thunk
    ``sym.imp.__libc_start_main`` -- whose name contains "main" -- so match on
    the precise trailing dotted component and drop imports.
    """
    result = client.run(binary, ["aa", "aflj"], timeout=60.0)
    entries: dict[str, int] = {}
    for fn in result["items"]:
        name = str(fn.get("name"))
        if ".imp." in name:
            continue
        core = name.rsplit(".", 1)[-1]
        if core in _NAMES:
            entries.setdefault(core, int(fn["offset"]))
    return entries


def _r2_call_sites(client: R2Client, binary: Path, target: int) -> set[int]:
    """Every ``bl`` call-site address that reaches ``target`` (r2)."""
    sites: set[int] = set()
    for edge in client.xrefs_to(binary, target, timeout=60.0)["items"]:
        if "CALL" not in str(edge.get("type")):
            continue
        frm = edge.get("from_address")
        value = frm.get("va") if isinstance(frm, dict) else edge.get("from")
        if isinstance(value, int):
            sites.add(value)
    return sites


def _gh_call_sites(client: GhidraClient, binary: Path, project: Path, target: int) -> set[int]:
    """Every CALL-edge source address that reaches ``target`` (Ghidra)."""
    sites: set[int] = set()
    xrefs = client.xrefs(binary, project, target, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    for x in xrefs["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        try:
            sites.add(int(str(x.get("from")), 16))
        except ValueError:
            continue  # synthetic sources such as "Entry Point"
    return sites


@pytest.mark.integration
@pytest.mark.parametrize("arch", sorted(_TARGETS))
def test_m11_r2_and_ghidra_agree_on_arm_call_graph(arch: str, tmp_path: Path) -> None:
    compiler_name, base_flags, want_class, want_machine = _TARGETS[arch]
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — ARM agreement Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} missing — ARM agreement Gate not run (skip != pass)")
    binary = _build(compiler, base_flags, tmp_path)
    if binary is None:
        pytest.skip(f"{compiler_name} could not build {arch} fixture (skip != pass)")

    # Independent of either engine: the fixture really is this ARM variant.
    assert _elf_machine(binary) == (want_class, want_machine), _elf_machine(binary)

    project = tmp_path / "ghidra_project"

    # Ghidra's recovered entries + body sizes (authoritative bounds for calls).
    gh_funcs = ghidra.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    gh_entry: dict[str, int] = {}
    gh_size: dict[str, int] = {}
    for it in gh_funcs["items"]:
        name = str(it.get("name"))
        if name in _NAMES:
            gh_entry[name] = int(str(it.get("entry")), 16)
            gh_size[name] = int(it.get("body_size") or 0)
    assert set(gh_entry) == set(_NAMES), gh_entry

    # r2's recovered entries.
    r2_entry = _r2_entries(r2, binary)
    assert set(r2_entry) == set(_NAMES), r2_entry

    # Agreement 1: both engines place every function at the identical address.
    for name in _NAMES:
        assert r2_entry[name] == gh_entry[name], (name, hex(r2_entry[name]), hex(gh_entry[name]))

    # Agreement 2: the main -> crackme_check bl is found at one shared site, and
    # that site lies inside main's body.
    outer = _r2_call_sites(r2, binary, r2_entry["crackme_check"]) & _gh_call_sites(
        ghidra, binary, project, gh_entry["crackme_check"]
    )
    assert outer, "no shared main->crackme_check call site"
    lo, hi = gh_entry["main"], gh_entry["main"] + gh_size["main"]
    assert any(lo <= s < hi for s in outer), (sorted(map(hex, outer)), hex(lo), hex(hi))

    # Agreement 3: the inner crackme_check -> mangle bl, same way.
    inner = _r2_call_sites(r2, binary, r2_entry["mangle"]) & _gh_call_sites(
        ghidra, binary, project, gh_entry["mangle"]
    )
    assert inner, "no shared crackme_check->mangle call site"
    lo, hi = gh_entry["crackme_check"], gh_entry["crackme_check"] + gh_size["crackme_check"]
    assert any(lo <= s < hi for s in inner), (sorted(map(hex, inner)), hex(lo), hex(hi))
