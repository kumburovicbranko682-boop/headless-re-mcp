"""radare2 robustness gate: the realistic and hostile binary-session cases.

``test_r2_service_gate`` proves the happy path on an *unstripped* ELF, where r2
reads names straight from the symbol table. Two things that gate does not cover:

* a **stripped** binary -- the realistic reverse-engineering target, where there
  is no symbol table and r2 must recover functions by *analysis* (``aa``). This
  is the whole reason to reach for r2, so it deserves a live assertion.
* **hostile input** -- a file that classifies as ``binary`` (ELF magic) but is
  otherwise garbage must still come back as a structured envelope, never an
  uncaught crash or an ``internal_error`` incident.

Both run through the product surface (``session.create`` -> ``r2.*``) over the
``binary`` target kind. skip != pass: skips when radare2/rizin or a C compiler
is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

_SOURCE = """
#include <stdio.h>
int headless_compute(int a, int b) { return a * b + 7; }
int main(void) {
    puts("HEADLESS-R2-STRIPPED");
    return headless_compute(3, 4);
}
"""
_MARKER = "HEADLESS-R2-STRIPPED"


def _compile_elf(tmp_path: Path, *, stripped: bool) -> Path | None:
    """Compile the source to an ELF (optionally stripped), or None if unbuildable."""
    if os.name == "nt":
        return None
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "r2rob.c"
    source.write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / ("r2rob_stripped" if stripped else "r2rob")
    strip_flag = ["-s"] if stripped else []
    for extra in (["-no-pie"], []):
        try:
            subprocess.run(
                [compiler, "-O0", *strip_flag, *extra, "-o", str(out), str(source)],
                check=True,
                capture_output=True,
                timeout=90,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if out.is_file():
            return out
    return None


def _names(data: dict) -> list[str]:
    return [str(item.get("name") or "") for item in data.get("items", [])]


@pytest.mark.integration
def test_r2_service_analyses_a_stripped_elf(tmp_path: Path) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — r2 robustness gate not run (skip != pass)")
    target = _compile_elf(tmp_path, stripped=True)
    if target is None:
        pytest.skip("no C compiler to build a stripped ELF (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(target))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "binary"
        session_id = created.data["session"]["id"]

        functions = service.r2_functions(session_id, timeout=60.0)
        assert functions.ok, functions.error
        assert functions.data["parsed"] is True
        # The payoff: r2 recovered functions with no symbol table to read from,
        # so this is analysis (`aa`), not symbol lookup.
        assert functions.data["count"] >= 1, functions.data
        names = _names(functions.data)
        # Our source names are gone (stripped), and what remains are analysis- or
        # linker-derived labels (entry*/fcn.*), proving the binary really is
        # stripped and r2 still found code.
        assert "sym.headless_compute" not in names, names
        assert any(n.startswith(("fcn.", "entry")) for n in names), names

        # Strings live in .rodata, not the symbol table, so they survive stripping.
        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok, strings.error
        assert any(_MARKER in str(i.get("string") or "") for i in strings.data["items"]), (
            strings.data.get("items")
        )

        # The dynamic symbol table (.dynsym) is required for linking and is not
        # stripped, so imports remain recoverable.
        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok, imports.error
        assert "puts" in _names(imports.data), _names(imports.data)

        # And a recovered function still disassembles to real instructions.
        entry_va = functions.data["items"][0]["address"]["va"]
        disasm = service.r2_disasm(session_id, int(entry_va), count=8, timeout=60.0)
        assert disasm.ok, disasm.error
        assert disasm.data["count"] >= 1, disasm.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_r2_binary_session_tolerates_a_corrupt_elf(tmp_path: Path) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — r2 robustness gate not run (skip != pass)")
    # ELF magic so it classifies as binary, then garbage: a plausible truncated
    # or malformed sample the tool must not choke on.
    corrupt = tmp_path / "corrupt.elf"
    corrupt.write_bytes(b"\x7fELF" + b"\xde\xad\xbe\xef" * 64)

    service = AnalysisService()
    try:
        created = service.create_session(str(corrupt))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "binary"
        session_id = created.data["session"]["id"]

        # Every op must return a structured envelope. Whether r2 tolerantly opens
        # the junk (ok, empty results) or rejects it (structured backend_error)
        # is a version detail; what the contract guarantees is no crash and no
        # internal_error incident on hostile input.
        for name, call in (
            ("open", service.r2_open),
            ("info", service.r2_info),
            ("functions", service.r2_functions),
            ("strings", service.r2_strings),
            ("imports", service.r2_imports),
        ):
            result = call(session_id, timeout=60.0)
            if result.ok:
                # A parsed listing over garbage must be empty, not fabricated.
                if name in {"functions", "strings", "imports"}:
                    assert result.data.get("count", 0) == 0, (name, result.data)
            else:
                assert result.error is not None
                assert result.error.code != "internal_error", (name, result.error)
    finally:
        service.close_all()
