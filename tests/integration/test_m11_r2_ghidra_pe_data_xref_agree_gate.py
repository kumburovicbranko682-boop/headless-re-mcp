"""M11 static<->static gate: r2 and Ghidra agree on who reads a PE string.

The ELF data-xref agreement gate asserts the two engines converge to the byte on
a .rodata string and its exact set of readers; this asks the same question of a
Windows PE cross-built with mingw. A PE puts the literal in .rdata behind a
non-zero ImageBase, so agreeing on the string address means both engines folded
ImageBase + RVA identically -- and they do, to the byte.

The reader *sets* are not identical here, and that is the honest finding: r2
recovers exactly the two planted loads (one in ``alpha``, one in ``beta``),
while Ghidra's deeper analysis also turns up extra references on a PE (a
non-code pointer/relocation entry, and a second in-function reference), so the
strict set equality the -no-pie ELF gate can assert does not hold. The gate
encodes the relationship that is actually true: both engines land on the
identical string address, and inside each planted reader they converge on the
same load instruction -- so r2's readers are corroborated by Ghidra at the byte,
even though Ghidra sees more. skip != pass when radare2/rizin, Ghidra or the
mingw cross compiler is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "xengine-dataxref-secret-5d7a"
_SRC = """
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int alpha(void) { return puts("xengine-dataxref-secret-5d7a"); }

__attribute__((noinline))
int beta(const char *s) { return strcmp(s, "xengine-dataxref-secret-5d7a") == 0; }

int main(int argc, char **argv) {
    if (argc > 1) return beta(argv[1]);
    return alpha();
}
"""
_MINGW = "x86_64-w64-mingw32-gcc"
_ANALYZE_TIMEOUT_S = 300.0
_DATA_KINDS = {"DATA", "PARAM"}


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


def _r2_string_va(client: R2Client, binary: Path) -> int | None:
    for s in client.run(binary, ["izj"], timeout=60.0)["items"]:
        if _MARKER in str(s.get("string", "")):
            return int(s["vaddr"])
    return None


def _r2_data_sites(client: R2Client, binary: Path, string_va: int) -> set[int]:
    sites: set[int] = set()
    for edge in client.xrefs_to(binary, string_va, timeout=60.0)["items"]:
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
def test_m11_r2_and_ghidra_agree_on_pe_string_readers(tmp_path: Path) -> None:
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — PE data-xref Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = _build_pe(tmp_path)
    if binary is None:
        pytest.skip(f"{_MINGW} missing — cannot build the PE fixture (skip != pass)")
    assert _is_pe(binary), binary.read_bytes()[:2]
    project = tmp_path / "ghidra_project"

    # Ghidra's function map anchors the load sites to alpha/beta bodies.
    gh_funcs = ghidra.functions(binary, project, limit=512, timeout=_ANALYZE_TIMEOUT_S)
    entry: dict[str, int] = {}
    size: dict[str, int] = {}
    for it in gh_funcs["items"]:
        name = str(it.get("name"))
        if name in ("alpha", "beta"):
            entry[name] = int(str(it.get("entry")), 16)
            size[name] = int(it.get("body_size") or 0)
    assert {"alpha", "beta"} <= set(entry), entry

    # Agreement 1: both engines locate the same string at the same absolute
    # address -- so both resolved the PE ImageBase + RVA identically.
    r2_string = _r2_string_va(r2, binary)
    gh_string = _gh_string_addr(ghidra, binary, project)
    assert r2_string is not None, "r2 did not find the marker string"
    assert gh_string is not None, "Ghidra did not label the marker string"
    assert r2_string == gh_string, (hex(r2_string), hex(gh_string))

    r2_sites = _r2_data_sites(r2, binary, r2_string)
    gh_sites = _gh_data_sites(ghidra, binary, project, gh_string)

    def _in(addr: int, name: str) -> bool:
        return entry[name] <= addr < entry[name] + size[name]

    # r2 recovers exactly the two planted loads: one in alpha, one in beta.
    r2_alpha = {a for a in r2_sites if _in(a, "alpha")}
    r2_beta = {a for a in r2_sites if _in(a, "beta")}
    assert len(r2_alpha) == 1, (sorted(map(hex, r2_sites)), entry)
    assert len(r2_beta) == 1, (sorted(map(hex, r2_sites)), entry)

    # Agreement 2: inside each planted reader, Ghidra corroborates r2's load at
    # the identical instruction address. (Ghidra also reports extra references
    # elsewhere on a PE, so this is a shared-site claim, not set equality.)
    gh_alpha = {a for a in gh_sites if _in(a, "alpha")}
    gh_beta = {a for a in gh_sites if _in(a, "beta")}
    assert r2_alpha & gh_alpha, (sorted(map(hex, r2_alpha)), sorted(map(hex, gh_alpha)))
    assert r2_beta & gh_beta, (sorted(map(hex, r2_beta)), sorted(map(hex, gh_beta)))
