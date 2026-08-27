"""M11 cross-engine gate: r2 exports and Ghidra symbols agree on coordinates.

The r2<->Ghidra agreement gates converge on functions, call and data edges, but
the *named-symbol* surface -- what an agent joins on when it correlates "the
export table" (r2 ``iEj``) with "the symbol table" (Ghidra) -- was only ever
pinned per engine (the r2 exports gate, the Ghidra symbols enrichment unit
test), never across the two. This closes that: one ELF session driven through
the AnalysisService must have

* r2's export table and Ghidra's symbol table carry the same top-level frame
  (module, image_base, architecture), and
* for each exported function, r2's ``address`` coordinate object and Ghidra's
  ``address_detail`` coordinate object be identical field for field -- same
  module, rva, va and architecture -- even though the engines type the symbol
  differently (r2 ``FUNC``/``GLOBAL``, Ghidra ``Function``), which is exactly
  why the join is on the coordinate, not the name's type, and
* the static helper stay out of r2's export surface (it is not GLOBAL), so the
  agreement is about the real public API, not every label.

The fixture is a ``-no-pie`` executable built with ``-rdynamic`` so its global
functions land in the dynamic symbol table (r2 lists them as exports) while the
image keeps absolute addresses both engines load at the same base -- no
rebasing, unlike a shared object, whose ET_DYN base the two engines pick
differently. skip != pass when radare2/rizin, Ghidra or a C compiler is missing.
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

_COORD_KEYS = {"module", "rva", "va", "architecture"}
_EXPORTS = ("re_sym_alpha", "re_sym_beta")
_HIDDEN = "re_sym_hidden"
_ET_EXEC = 2  # ELF e_type for a non-PIE executable: absolute addresses.
_SRC = r"""
#include <stdio.h>

static int re_sym_hidden(int x) { return x * 3 + 1; }

__attribute__((noinline)) int re_sym_alpha(int x) { return re_sym_hidden(x) * 7 + 3; }

__attribute__((noinline)) int re_sym_beta(const char *s) {
    return (int)(s ? s[0] : 0) + re_sym_hidden(2);
}

int main(int argc, char **argv) { return re_sym_alpha(argc) + re_sym_beta(argv[0]); }
"""


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc")


def _build_rdynamic_exec(dest: Path) -> Path | None:
    compiler = _compiler()
    if compiler is None:
        return None
    src = dest / "s.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "s.bin"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local compiler
            [compiler, "-O0", "-fno-inline", "-no-pie", "-fno-pic", "-rdynamic",
             "-o", str(binary), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return binary if binary.is_file() else None


def _elf_type(binary: Path) -> int:
    header = binary.read_bytes()[:18]
    assert header[:4] == b"\x7fELF", header[:4]
    return int.from_bytes(header[16:18], "little")


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


def _coord(value: object) -> tuple[Any, ...]:
    assert isinstance(value, dict), value
    assert set(value) == _COORD_KEYS, value
    return (value["module"], value["rva"], value["va"], value["architecture"])


def _frame(payload: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (payload.get("module"), payload.get("image_base"), payload.get("architecture"))


@pytest.mark.integration
def test_m11_r2_exports_and_ghidra_symbols_agree(tmp_path: Path) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — symbol agreement Gate not run (skip != pass)")
    if _ghidra() is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = _build_rdynamic_exec(tmp_path)
    if binary is None:
        pytest.skip("no C compiler (cc/gcc) — cannot build the ELF fixture (skip != pass)")
    # Independent of the engines: a non-PIE executable, so both load it at the
    # same absolute base and no rebasing can hide a disagreement.
    assert _elf_type(binary) == _ET_EXEC, _elf_type(binary)

    service = AnalysisService(Settings.load())
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session["target"] == "elf", session
    sid = str(session["id"])

    r2_exports = service.r2_exports(sid, timeout=60.0)
    assert r2_exports.ok and r2_exports.data is not None, r2_exports.error
    assert r2_exports.data.get("parsed") is True, r2_exports.data

    gh_symbols = service.ghidra_symbols(sid, limit=2048, timeout=300.0)
    assert gh_symbols.ok and gh_symbols.data is not None, gh_symbols.error
    assert gh_symbols.data.get("mode") == "symbols", gh_symbols.data

    # Agreement 1: one frame from both the export table and the symbol table.
    assert _frame(r2_exports.data) == _frame(gh_symbols.data), (
        r2_exports.data.get("module"),
        gh_symbols.data.get("module"),
    )
    _module, image_base, architecture = _frame(r2_exports.data)
    assert image_base and image_base > 0, r2_exports.data  # non-PIE: real base
    assert architecture == "x64", r2_exports.data

    r2_by = {str(e.get("name")): e for e in r2_exports.data.get("items", [])}
    gh_by = {str(s.get("name")): s for s in gh_symbols.data.get("items", [])}

    # Agreement 2: each exported function has the identical coordinate object in
    # both tables, and its rva really is va - image_base.
    seen: set[tuple[Any, ...]] = set()
    for name in _EXPORTS:
        r2_entry = r2_by.get(name)
        gh_entry = gh_by.get(name)
        assert r2_entry is not None, sorted(r2_by)
        assert gh_entry is not None, [n for n in gh_by if "re_sym" in n]
        # r2 classifies it as a real global export, not an import thunk.
        assert r2_entry.get("type") == "FUNC", r2_entry
        assert r2_entry.get("bind") == "GLOBAL", r2_entry
        assert r2_entry.get("is_imported") is False, r2_entry

        r2_coord = _coord(r2_entry.get("address"))
        gh_coord = _coord(gh_entry.get("address_detail"))
        assert r2_coord == gh_coord, (name, r2_coord, gh_coord)
        module, rva, va, arch = r2_coord
        assert module == binary.name
        assert arch == "x64"
        assert rva == va - image_base, (name, r2_coord, image_base)
        seen.add(r2_coord)

    # The two exports are distinct symbols at distinct addresses.
    assert len(seen) == 2, seen

    # Agreement 3: the static helper is internal -- absent from the export
    # surface (r2 lists no GLOBAL FUNC for it), so the agreement above is about
    # the real public API rather than every label the symbol table happens to
    # carry.
    hidden = r2_by.get(_HIDDEN)
    assert hidden is None or hidden.get("bind") != "GLOBAL" or hidden.get("is_imported"), hidden
