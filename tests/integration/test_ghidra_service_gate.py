"""Ghidra service gate: drive ghidra.* through a BINARY session on a real ELF.

The existing Ghidra live gate calls ``GhidraClient`` directly. This one goes
through the product surface a caller actually uses -- ``session.create`` ->
``ghidra.analyze`` / ``ghidra.functions`` / ``ghidra.symbols`` /
``ghidra.decompile`` / ``ghidra.xrefs`` -- which only became reachable for an ELF
once sessions learned the ``binary`` target kind (an ELF was rejected at create
with "not a PE file" before). It also covers ``ghidra.xrefs`` end to end, which
the client-level gate never exercises.

It asserts on recovered *content*, not just envelope shapes: our own function by
name, the decompiled arithmetic body, and the call edge into it. A regression in
the Ghidra backend, the ExportJson postScript, or the service wiring is caught
rather than skipped past.

skip != pass: skips honestly when Ghidra/Java are not configured
(HEADLESS_RE_GHIDRA_HOME), when no C compiler can produce a target, or when the
Ghidra in use cannot run the Jython ExportJson postScript (bundled up to 12.0.x,
an installable extension from 12.1) -- that is an install choice, not a defect.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

# Unstripped, non-PIE C so Ghidra recovers our named function at an absolute
# entry and the decompiler yields a body we can recognise on any target arch.
_SOURCE = """
#include <stdio.h>
int headless_compute(int a, int b) { return a * b + 7; }
int main(void) {
    puts("GHIDRA-SVC-GATE");
    return headless_compute(3, 4);
}
"""
_FUNC = "headless_compute"


def _compile_elf(tmp_path: Path) -> Path | None:
    """Compile the source to a small ELF, or None when no compiler exists."""
    if os.name == "nt":
        return None
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "ghsvc.c"
    source.write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / "ghsvc"
    for extra in (["-no-pie"], []):
        try:
            subprocess.run(
                [compiler, "-O0", *extra, "-o", str(out), str(source)],
                check=True,
                capture_output=True,
                timeout=90,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if out.is_file():
            return out
    return None


def _skip_if_no_jython(result: Result) -> None:
    """A Ghidra without a runnable Jython cannot produce the export.

    That is an install choice (12.1 dropped the bundled Jython), not a regression
    in this code, so treat "export JSON missing" as a skip -- but only that exact
    signature; any other failure is a real one the gate must surface.
    """
    if result.ok:
        return
    error = result.error
    if error is not None and error.code == "backend_error" and "missing" in error.message:
        pytest.skip(
            "Ghidra ran but its postScript produced no export "
            "(Jython not available?) — export gate not run (skip != pass)"
        )


def _entry_of(items: list[dict], name: str) -> str | None:
    for item in items:
        if item.get("name") == name and item.get("entry"):
            return str(item["entry"])
    return None


@pytest.mark.integration
def test_ghidra_service_recovers_elf_content(tmp_path: Path) -> None:
    if not GhidraClient(home=getattr(Settings.load(), "ghidra_home", None)).available:
        pytest.skip("Ghidra/Java not configured (HEADLESS_RE_GHIDRA_HOME) — not run (skip != pass)")
    target = _compile_elf(tmp_path)
    if target is None:
        pytest.skip("no C compiler to build an ELF target (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(target))
        assert created.ok, created.error
        # The whole point: an ELF is now a first-class binary session, so the
        # portable backend is reachable through the product, not just its client.
        assert created.data["session"]["target"] == "binary"
        session_id = created.data["session"]["id"]

        # analyze uses no postScript, so it works on any Ghidra and proves the
        # launcher and JVM this platform runs are actually usable.
        analyzed = service.ghidra_analyze(session_id, timeout=300.0)
        assert analyzed.ok, analyzed.error
        assert analyzed.data.get("project_dir")

        functions = service.ghidra_functions(session_id, limit=256, timeout=300.0)
        _skip_if_no_jython(functions)
        assert functions.ok, functions.error
        assert functions.data.get("count", 0) >= 1
        items = functions.data.get("items") or []
        assert all(item.get("name") and item.get("entry") for item in items)
        entry = _entry_of(items, _FUNC)
        assert entry is not None, [item.get("name") for item in items]

        symbols = service.ghidra_symbols(session_id, limit=256, timeout=300.0)
        _skip_if_no_jython(symbols)
        assert symbols.ok, symbols.error
        assert symbols.data.get("count", 0) >= 1
        assert all(
            item.get("name") and item.get("address")
            for item in symbols.data.get("items") or []
        )

        decompiled = service.ghidra_decompile(session_id, entry, timeout=300.0)
        _skip_if_no_jython(decompiled)
        assert decompiled.ok, decompiled.error
        assert decompiled.data.get("found") is True
        body = decompiled.data.get("decompiled") or ""
        assert isinstance(body, str) and body.strip(), "decompilation produced no C text"
        # Our function is trivial arithmetic; the recovered body must carry it.
        assert "return" in body, body
        assert "*" in body and "7" in body, body

        xrefs = service.ghidra_xrefs(session_id, entry, limit=256, timeout=300.0)
        _skip_if_no_jython(xrefs)
        assert xrefs.ok, xrefs.error
        edges = xrefs.data.get("items") or []
        # main calls headless_compute, so a CALL edge must point at its entry.
        call_edges = [
            edge
            for edge in edges
            if str(edge.get("to")) == entry and "CALL" in str(edge.get("type") or "")
        ]
        assert call_edges, edges
        assert call_edges[0].get("from"), call_edges[0]
    finally:
        service.close_all()
