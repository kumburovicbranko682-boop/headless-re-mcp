"""M11 Ghidra live gate: real headless analysis, decompilation and xrefs.

Ghidra is a cross-platform Java backend. This gate runs analyzeHeadless against
a committed PE and asserts each wired tool returns the binary's real analysis --
functions, symbols, a decompiled function, and typed cross-references. It skips
with an explicit "skip != pass" message when Ghidra is not configured.

It also guards two fixes without which Ghidra never ran off Windows at all: the
adapter used to pick the Windows .bat launcher on POSIX, and a project placed
under the default artifact root (~/.local/share, a dot element) was rejected by
Ghidra before analysis. Both paths are exercised here end to end.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_CANDIDATES = (
    _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe",
    _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe",
)


def _fixture() -> Path:
    for candidate in _FIXTURE_CANDIDATES:
        if candidate.is_file():
            return candidate
    pytest.fail(f"no ghidra fixture is committed at any of {[str(c) for c in _FIXTURE_CANDIDATES]}")


@pytest.mark.integration
def test_m11_ghidra_headless_analysis_maps_the_binary() -> None:
    settings = Settings.load()
    if not GhidraClient(home=getattr(settings, "ghidra_home", None)).available:
        pytest.skip(
            "Ghidra analyzeHeadless not configured (HEADLESS_RE_GHIDRA_HOME) — "
            "Gate not run (skip != pass)"
        )
    fixture = _fixture()
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(fixture))
        assert created.ok, created.error
        session_id = str(created.data["session"]["id"])

        # Functions: headless import + auto-analysis must find real functions
        # with an entry point and a measured body size.
        functions = service.ghidra_functions(session_id, limit=64, timeout=280.0)
        assert functions.ok, functions.error
        assert functions.data["count"] >= 1
        rows = cast(list[dict[str, Any]], functions.data["items"])
        assert all(r.get("name") and r.get("entry") for r in rows), rows[:3]
        assert any(int(r.get("body_size") or 0) > 0 for r in rows)
        target = rows[0]
        entry = str(target["entry"])

        # Symbols: the PE's imports resolve to named symbols.
        symbols = service.ghidra_symbols(session_id, limit=64, timeout=280.0)
        assert symbols.ok, symbols.error
        assert symbols.data["count"] >= 1
        sym_rows = cast(list[dict[str, Any]], symbols.data["items"])
        assert all(s.get("name") and s.get("address") and s.get("type") for s in sym_rows), (
            sym_rows[:3]
        )

        # Decompile: the function at the listed entry must decompile to real C.
        decompiled = service.ghidra_decompile(session_id, entry, timeout=280.0)
        assert decompiled.ok, decompiled.error
        assert decompiled.data["found"] is True
        assert decompiled.data["function"] == target["name"]
        body = str(decompiled.data["decompiled"])
        assert body.strip(), "decompiler returned an empty body for a found function"
        # Real decompiled C, not a status string.
        assert "{" in body and "}" in body

        # Xrefs: the query must round-trip; when the entry has callers they come
        # back as typed from/to edges.
        xrefs = service.ghidra_xrefs(session_id, entry, limit=64, timeout=280.0)
        assert xrefs.ok, xrefs.error
        for ref in cast(list[dict[str, Any]], xrefs.data["items"]):
            assert ref.get("from") and ref.get("to") and ref.get("type"), ref
    finally:
        service.close_all()
