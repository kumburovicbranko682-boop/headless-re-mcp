"""M11 static<->static gate: r2 and Ghidra agree on a PE program.

The ELF agreement gate pits the two static engines against each other on a
System V ELF; this does the same on a Windows PE cross-built with mingw-w64. A PE
is a genuinely different reconstruction problem: the loader maps everything at a
non-zero ImageBase, so both engines must fold ImageBase + RVA into the same
absolute VAs before their function entries and call sites can line up at all. If
r2 (analysis + capstone) and Ghidra (its own PE loader + analyzer) independently
land ``main``, ``crackme_check`` and ``mangle`` at the identical addresses and
find the two-edge call graph (main -> crackme_check -> mangle) at the identical
call-site addresses, the PE recovery is real on both sides rather than an
artifact of one tool.

Name matching is exact here, not substring: a mingw PE is full of ``*main*``
runtime symbols (``mainCRTStartup``, ``__tmainCRTStartup``, ``__main``), so the
substring shortcut the ELF gate can afford would mis-bind ``main``. skip != pass
when radare2/rizin, Ghidra or the mingw cross compiler is missing.
"""

from __future__ import annotations

import os
import shutil
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
_MINGW = "x86_64-w64-mingw32-gcc"
_NAMES = ("main", "crackme_check", "mangle")
_ANALYZE_TIMEOUT_S = 300.0


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


def _seg(name: object) -> str:
    """Last dotted segment of an r2 symbol name (``sym.main`` -> ``main``)."""
    return str(name or "").split(".")[-1]


def _r2_call_sites(client: R2Client, binary: Path, target: int, caller: str) -> set[int]:
    """CALL-site VAs reaching ``target`` from the function named exactly ``caller``."""
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
    """CALL sites reaching ``target`` whose source lies in ``[lo, hi)`` (Ghidra)."""
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
def test_m11_r2_and_ghidra_agree_on_a_pe(tmp_path: Path) -> None:
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — PE agreement Gate not run (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = _build_pe(tmp_path)
    if binary is None:
        pytest.skip(f"{_MINGW} missing — cannot build the PE fixture (skip != pass)")
    assert _is_pe(binary), binary.read_bytes()[:2]
    project = tmp_path / "ghidra_project"

    # r2's recovered entries, matched by exact symbol name (PE has many *main*).
    r2_funcs = r2.run(binary, ["aa", "aflj"], timeout=60.0)
    assert r2_funcs.get("parsed") is True
    r2_entry: dict[str, int] = {}
    for f in r2_funcs["items"]:
        seg = _seg(f.get("name"))
        if seg in _NAMES:
            r2_entry.setdefault(seg, int(f["offset"]))
    assert set(r2_entry) == set(_NAMES), r2_entry

    # Ghidra's recovered entries and body sizes, matched exactly.
    gh_funcs = ghidra.functions(binary, project, limit=512, timeout=_ANALYZE_TIMEOUT_S)
    assert gh_funcs.get("mode") == "functions"
    gh_entry: dict[str, int] = {}
    gh_size: dict[str, int] = {}
    for it in gh_funcs["items"]:
        name = str(it.get("name"))
        if name in _NAMES:
            gh_entry[name] = int(str(it.get("entry")), 16)
            gh_size[name] = int(it.get("body_size") or 0)
    assert set(gh_entry) == set(_NAMES), gh_entry

    # Agreement 1: every function at the identical absolute VA. For a PE this
    # means both engines resolved ImageBase + RVA the same way -- the addresses
    # sit above a common non-zero ImageBase, unlike the -no-pie ELF gate.
    for key in _NAMES:
        assert r2_entry[key] == gh_entry[key], (key, hex(r2_entry[key]), hex(gh_entry[key]))
    image_base = min(gh_entry.values()) & ~0xFFFF
    assert image_base > 0, {k: hex(v) for k, v in gh_entry.items()}

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
