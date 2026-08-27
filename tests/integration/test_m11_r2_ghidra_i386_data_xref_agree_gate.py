"""M11 static<->static gate: r2 and Ghidra agree on who reads an i386 string.

The x86-64 ELF data-xref agreement gate asserts both engines converge to the
byte on a .rodata string and its exact set of readers; this makes the same
claim for 32-bit x86, where the string is loaded by absolute address (i386
-no-pie) rather than the rip-relative form x86-64 uses, and decoded by each
engine's distinct 32-bit path. Unlike the PE case -- where Ghidra's deeper
analysis surfaces extra references -- an i386 -no-pie ELF yields identical
reader sets, so this gate asserts strict set equality: r2 and Ghidra land on the
same string address and the identical two load sites, one in ``alpha`` and one
in ``beta``.

skip != pass when radare2/rizin, Ghidra or a 32-bit-capable gcc (gcc-multilib)
is missing.
"""

from __future__ import annotations

import os
import shutil
import struct
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
_ANALYZE_TIMEOUT_S = 300.0
_DATA_KINDS = {"DATA", "PARAM"}
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
    syms = client.symbols(binary, project, limit=1024, timeout=_ANALYZE_TIMEOUT_S)
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
def test_m11_r2_and_ghidra_agree_on_i386_string_readers(tmp_path: Path) -> None:
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — i386 data-xref Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = _build_i386_elf(tmp_path)
    if binary is None:
        pytest.skip("no 32-bit-capable gcc (gcc-multilib) — i386 Gate not run (skip != pass)")
    assert _is_i386_elf(binary), binary.read_bytes()[:20]
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

    # Agreement 1: both engines locate the same string at the same address.
    r2_string = _r2_string_va(r2, binary)
    gh_string = _gh_string_addr(ghidra, binary, project)
    assert r2_string is not None, "r2 did not find the marker string"
    assert gh_string is not None, "Ghidra did not label the marker string"
    assert r2_string == gh_string, (hex(r2_string), hex(gh_string))

    # Agreement 2: identical set of load sites -- exactly the two readers, to
    # the byte (i386 -no-pie yields matching sets, unlike the PE case).
    r2_sites = _r2_data_sites(r2, binary, r2_string)
    gh_sites = _gh_data_sites(ghidra, binary, project, gh_string)
    assert len(r2_sites) == 2, sorted(map(hex, r2_sites))
    assert r2_sites == gh_sites, (sorted(map(hex, r2_sites)), sorted(map(hex, gh_sites)))

    # Agreement 3: one agreed site lands in alpha's body, the other in beta's.
    def _in(addr: int, name: str) -> bool:
        return entry[name] <= addr < entry[name] + size[name]

    assert sum(1 for a in r2_sites if _in(a, "alpha")) == 1, (sorted(map(hex, r2_sites)), entry)
    assert sum(1 for a in r2_sites if _in(a, "beta")) == 1, (sorted(map(hex, r2_sites)), entry)
