"""Ghidra headless live gate: the whole functions/symbols/xrefs/decompile line.

The Ghidra unit tests all stub ``run_bounded``, so two production-only breakages
sailed through them: Ghidra 11.4 dropping bundled Jython (the Jython postScript
aborted every export) and ``ProjectLocator`` refusing a project location with a
dot-prefixed path element (the default ``~/.local`` artifact root). This gate
drives a real analyzeHeadless against a committed PE fixture, through the
service, with the artifact root deliberately placed under a dot directory so a
regression of either fix turns the gate red. skip != pass when Ghidra is absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


@pytest.mark.integration
def test_ghidra_headless_drives_the_whole_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"PE fixture missing: {_FIXTURE}")
    # Force a dot-prefixed artifact root so the run exercises the project
    # location that Ghidra's ProjectLocator used to reject outright.
    dotted_root = tmp_path / ".local" / "artifacts"
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(dotted_root))
    settings = Settings.load()
    if not GhidraClient(home=getattr(settings, "ghidra_home", None)).available:
        pytest.skip("Ghidra analyzeHeadless not configured — live Gate not run (skip != pass)")

    service = AnalysisService(settings)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        functions = service.ghidra_functions(session_id, limit=64, timeout=400.0)
        assert functions.ok, functions.error
        assert functions.data["count"] >= 1
        first = functions.data["items"][0]
        assert set(first) >= {"name", "entry", "body_size"}
        entry = next(
            (item["entry"] for item in functions.data["items"] if item["body_size"] > 8),
            first["entry"],
        )

        symbols = service.ghidra_symbols(session_id, limit=64, timeout=400.0)
        assert symbols.ok, symbols.error
        assert symbols.data["count"] >= 1
        assert set(symbols.data["items"][0]) >= {"name", "address", "type"}

        decompiled = service.ghidra_decompile(session_id, entry, timeout=400.0)
        assert decompiled.ok, decompiled.error
        assert isinstance(decompiled.data["truncated"], bool)
        assert len(decompiled.data["decompiled"].strip()) > 0

        xrefs = service.ghidra_xrefs(session_id, entry, limit=64, timeout=400.0)
        assert xrefs.ok, xrefs.error
        assert isinstance(xrefs.data["count"], int)

        analyzed = service.ghidra_analyze(session_id, timeout=400.0)
        assert analyzed.ok, analyzed.error
        assert set(analyzed.data) >= {"project_dir", "stdout_excerpt", "note"}
    finally:
        service.close_all()
