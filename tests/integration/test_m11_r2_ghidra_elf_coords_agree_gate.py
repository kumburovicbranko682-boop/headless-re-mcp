"""M11 cross-engine gate: r2 and Ghidra emit identical ELF coordinate objects.

The existing agree gates compare raw virtual addresses at the client layer.
Both backends now also attach a structured ``{module, rva, va, architecture}``
object beside every address they report -- r2 via ``enrich_r2_payload`` and
Ghidra via ``enrich_ghidra_payload`` -- so an agent can join the two engines'
output on rva/module instead of re-deriving bases itself. This gate makes that
shared coordinate frame part of the contract: one ELF session, driven through
the AnalysisService exactly as an MCP caller would, must yield

* the same top-level frame (module, image_base, architecture) from both
  engines,
* byte-for-byte identical coordinate objects for the same recovered function
  entries (r2's ``address`` vs Ghidra's ``entry_address``), and
* an identical ``from_address`` object for the same crackme_check -> mangle
  call site, with Ghidra's ``to_address`` landing on that same mangle
  coordinate.

skip != pass when radare2/rizin, Ghidra or a C compiler is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

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
_TIMEOUT_S = 300.0
_COORD_KEYS = {"module", "rva", "va", "architecture"}


def _build_no_pie_elf(dest: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "f.bin"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local compiler
            [compiler, "-O0", "-fno-pic", "-no-pie", "-o", str(binary), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return binary if binary.is_file() else None


def _coord(value: object) -> dict[str, Any]:
    """A complete coordinate object, or the assertion says what was missing."""
    assert isinstance(value, dict), value
    assert set(value) == _COORD_KEYS, value
    return value


def _frame(payload: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (payload.get("module"), payload.get("image_base"), payload.get("architecture"))


@pytest.mark.integration
def test_m11_r2_and_ghidra_emit_identical_elf_coordinates(tmp_path: Path) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — coords Gate not run (skip != pass)")
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home or not GhidraClient(home=Path(home)).available:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = _build_no_pie_elf(tmp_path)
    if binary is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the ELF fixture (skip != pass)")

    service = AnalysisService(Settings.load())
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    assert created.data["session"]["target"] == "elf", created.data
    sid = str(created.data["session"]["id"])
    assert service.r2_open(sid).ok

    # r2's recovered entries with their coordinate objects.
    r2_funcs = service.r2_functions(sid, timeout=60.0)
    assert r2_funcs.ok and r2_funcs.data is not None, r2_funcs.error
    r2_coord: dict[str, dict[str, Any]] = {}
    for item in r2_funcs.data.get("items", []):
        for key in ("crackme_check", "mangle"):
            if key in str(item.get("name")):
                r2_coord.setdefault(key, _coord(item.get("address")))
    assert set(r2_coord) == {"crackme_check", "mangle"}, sorted(r2_coord)

    # Ghidra's recovered entries with theirs, through the same session.
    gh_funcs = service.ghidra_functions(sid, limit=256, timeout=_TIMEOUT_S)
    assert gh_funcs.ok and gh_funcs.data is not None, gh_funcs.error
    gh_items = {str(i.get("name")): i for i in gh_funcs.data.get("items", [])}
    for key in ("crackme_check", "mangle"):
        assert key in gh_items, sorted(gh_items)
    gh_coord = {key: _coord(gh_items[key].get("entry_address")) for key in r2_coord}

    # Agreement 1: one coordinate frame. Both engines derive it from the same
    # ELF header, and both name the same module, base and architecture.
    assert _frame(r2_funcs.data) == _frame(gh_funcs.data), (r2_funcs.data, gh_funcs.data)
    assert isinstance(r2_funcs.data.get("image_base"), int), r2_funcs.data

    # Agreement 2: the coordinate objects for the same functions are identical
    # field by field -- module, rva, va and architecture all match.
    for key, expected in r2_coord.items():
        assert gh_coord[key] == expected, (key, expected, gh_coord[key])

    # Agreement 3: the crackme_check -> mangle call site. r2's axtj edge and
    # Ghidra's reference list both carry from_address objects; the same site
    # must appear in both with the identical object.
    mangle = r2_coord["mangle"]
    r2_xrefs = service.r2_xrefs_to(sid, int(mangle["va"]), timeout=60.0)
    assert r2_xrefs.ok and r2_xrefs.data is not None, r2_xrefs.error
    r2_sites: list[dict[str, Any]] = []
    for edge in r2_xrefs.data.get("items", []):
        if "CALL" in str(edge.get("type")) and "crackme_check" in str(edge.get("fcn_name") or ""):
            r2_sites.append(_coord(edge.get("from_address")))
    assert r2_sites, r2_xrefs.data

    gh_xrefs = service.ghidra_xrefs(sid, str(gh_items["mangle"]["entry"]), limit=256,
                                    timeout=_TIMEOUT_S)
    assert gh_xrefs.ok and gh_xrefs.data is not None, gh_xrefs.error
    check_lo = int(gh_coord["crackme_check"]["va"])
    check_hi = check_lo + int(gh_items["crackme_check"].get("body_size") or 0)
    gh_sites: list[dict[str, Any]] = []
    for edge in gh_xrefs.data.get("items", []):
        if "CALL" not in str(edge.get("type")):
            continue
        source = _coord(edge.get("from_address"))
        if check_lo <= int(source["va"]) < check_hi:
            gh_sites.append(source)
            # The edge's target object is the same mangle coordinate both
            # engines already agreed on above.
            assert _coord(edge.get("to_address")) == mangle, edge
    assert gh_sites, gh_xrefs.data

    shared = [site for site in r2_sites if site in gh_sites]
    assert shared, (r2_sites, gh_sites)
