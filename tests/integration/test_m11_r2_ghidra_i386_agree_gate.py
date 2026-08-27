"""M11 static<->static gate: r2 and Ghidra agree on a 32-bit x86 (i386) ELF.

The agreement matrix so far is x86-64 (the ELF agreement gate), aarch64 and
arm32 (the ARM agreement gate) plus x86-64 PE -- but nothing exercises 32-bit
x86, a distinct instruction set decoded by a different path in both engines
(capstone's x86-32 mode and Ghidra's ``x86:LE:32`` lifter). This builds a
-no-pie i386 ELF with ``gcc -m32`` and asserts r2 and Ghidra independently land
``main``, ``crackme_check`` and ``mangle`` at the identical absolute addresses
and find the two-edge call graph (main -> crackme_check -> mangle) at the
identical call sites. Two disassemblers converging on the same i386 addresses is
strong evidence the recovery is real rather than an artifact of one tool.

The fixture is non-PIE so addresses are absolute and directly comparable. skip
!= pass when radare2/rizin, Ghidra or a 32-bit-capable gcc (gcc-multilib) is
missing.
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
_NAMES = ("main", "crackme_check", "mangle")
_ANALYZE_TIMEOUT_S = 300.0
_EM_386 = 3


def _build_i386_elf(dest: Path) -> Path | None:
    """Build a -no-pie 32-bit x86 ELF, or None when the toolchain can't."""
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
    """True for a 32-bit little-endian ELF whose machine is EM_386."""
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


def _seg(name: object) -> str:
    return str(name or "").split(".")[-1]


def _r2_call_sites(client: R2Client, binary: Path, target: int, caller: str) -> set[int]:
    sites: set[int] = set()
    for x in client.xrefs_to(binary, target, timeout=60.0)["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        if _seg(x.get("fcn_name")) != caller:
            continue
        frm = x.get("from_address")
        value = frm.get("va") if isinstance(frm, dict) else x.get("from")
        if isinstance(value, int):
            sites.add(value)
    return sites


def _gh_call_sites_within(
    client: GhidraClient, binary: Path, project: Path, target: int, lo: int, hi: int
) -> set[int]:
    sites: set[int] = set()
    xrefs = client.xrefs(binary, project, target, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    for x in xrefs["items"]:
        if "CALL" not in str(x.get("type")):
            continue
        try:
            src = int(str(x.get("from")), 16)
        except ValueError:
            continue  # synthetic sources like "Entry Point"
        if lo <= src < hi:
            sites.add(src)
    return sites


@pytest.mark.integration
def test_m11_r2_and_ghidra_agree_on_an_i386_elf(tmp_path: Path) -> None:
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — i386 agreement Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = _build_i386_elf(tmp_path)
    if binary is None:
        pytest.skip("no 32-bit-capable gcc (gcc-multilib) — i386 Gate not run (skip != pass)")
    assert _is_i386_elf(binary), binary.read_bytes()[:20]
    project = tmp_path / "ghidra_project"

    # r2's recovered entries (absolute, -no-pie), matched by exact symbol name.
    r2_funcs = r2.run(binary, ["aa", "aflj"], timeout=60.0)
    assert r2_funcs.get("parsed") is True
    r2_entry: dict[str, int] = {}
    for f in r2_funcs["items"]:
        seg = _seg(f.get("name"))
        if seg in _NAMES:
            r2_entry.setdefault(seg, int(f["offset"]))
    assert set(r2_entry) == set(_NAMES), r2_entry

    # Ghidra's recovered entries and body sizes.
    gh_funcs = ghidra.functions(binary, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert gh_funcs.get("mode") == "functions"
    gh_entry: dict[str, int] = {}
    gh_size: dict[str, int] = {}
    for it in gh_funcs["items"]:
        name = str(it.get("name"))
        if name in _NAMES:
            gh_entry[name] = int(str(it.get("entry")), 16)
            gh_size[name] = int(it.get("body_size") or 0)
    assert set(gh_entry) == set(_NAMES), gh_entry

    # Agreement 1: both engines put every function at the identical address.
    for key in _NAMES:
        assert r2_entry[key] == gh_entry[key], (key, hex(r2_entry[key]), hex(gh_entry[key]))

    # Agreement 2: main -> crackme_check at the same site, inside main's body.
    r2_outer = _r2_call_sites(r2, binary, r2_entry["crackme_check"], "main")
    gh_outer = _gh_call_sites_within(
        ghidra,
        binary,
        project,
        gh_entry["crackme_check"],
        gh_entry["main"],
        gh_entry["main"] + gh_size["main"],
    )
    assert r2_outer & gh_outer, (sorted(map(hex, r2_outer)), sorted(map(hex, gh_outer)))

    # Agreement 3: crackme_check -> mangle, same way.
    r2_inner = _r2_call_sites(r2, binary, r2_entry["mangle"], "crackme_check")
    gh_inner = _gh_call_sites_within(
        ghidra,
        binary,
        project,
        gh_entry["mangle"],
        gh_entry["crackme_check"],
        gh_entry["crackme_check"] + gh_size["crackme_check"],
    )
    assert r2_inner & gh_inner, (sorted(map(hex, r2_inner)), sorted(map(hex, gh_inner)))
