"""Ghidra headless gate: analyzeHeadless + ExportJson end to end on Linux.

The Ghidra line had no integration coverage that executes anywhere: every unit
test fakes run_bounded, so no test had ever launched a real analyzeHeadless.
Running one immediately surfaced two bugs that prove it. The launcher discovery
tried analyzeHeadless.bat before the shell script, and a stock Ghidra install
ships both side by side, so on Linux every ghidra.* call handed Popen a Windows
batch file and died with EACCES. Past that, the packaged ExportJson.py read an
ARGS global that Ghidra's Jython never injects (arguments arrive via
getScriptArgs()), so every functions/symbols/xrefs/decompile export raised
NameError inside the JVM and the client reported "export JSON missing after
postScript". Both are fixed; this gate is what found them and what keeps them
fixed.

It drives the surface two ways. GhidraClient reads a committed, non-stripped
Linux ELF (fixtures/native/ghidra_elf_fixture) whose three named functions give
the exports something checkable: functions and symbols must name them, xrefs
must see main's call into compute_checksum, and the decompiler must hand back
readable C containing the checksum's `* 0x1f` multiply. AnalysisService then
runs ghidra.analyze and ghidra.functions against the committed PE fixture to
prove the service wiring: artifact registration, timeline stamps, pagination,
and the closed-session and missing-home refusals.

Real-tool tests skip with an explicit "skip != pass" when analyzeHeadless is
not configured (HEADLESS_RE_GHIDRA_HOME); the two guard tests always run.
Verified against Ghidra 11.3.2 headless on OpenJDK 21, Linux.
"""

from __future__ import annotations

import json
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ELF_FIXTURE = _PROJECT_ROOT / "fixtures" / "native" / "ghidra_elf_fixture"
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_ELF_FUNCTIONS = ("compute_checksum", "greet", "main")
# Every analyzeHeadless invocation imports and analyses from scratch (the
# project is deleted each run), so give slow machines room without letting a
# hung JVM stall the suite forever.
_TIMEOUT_S = 300.0


def _client() -> GhidraClient:
    return GhidraClient(home=Settings.load().ghidra_home)


def _skip_without_ghidra() -> None:
    if not _client().available:
        pytest.skip(
            "Ghidra analyzeHeadless not configured (HEADLESS_RE_GHIDRA_HOME) — "
            "Ghidra Gate not run (skip != pass)"
        )


@lru_cache(maxsize=1)
def _elf_functions() -> dict[str, dict[str, Any]]:
    """One shared functions export for the ELF: each headless run costs ~7s."""
    project = Path(tempfile.mkdtemp(prefix="ghidra-gate-")) / "elf"
    data = _client().functions(_ELF_FIXTURE, project, limit=64, timeout=_TIMEOUT_S)
    assert data.get("count", 0) >= 1, data
    return {str(item["name"]): item for item in data["items"]}


@pytest.mark.integration
def test_ghidra_functions_and_symbols_name_the_elf_functions() -> None:
    """The functions and symbols exports carry the fixture's real names.

    A faked run can return any items; only a real analyzeHeadless proves the
    import, the auto-analysis and the Jython export agree on what the binary
    contains.
    """
    _skip_without_ghidra()
    assert _ELF_FIXTURE.is_file(), f"fixture missing: {_ELF_FIXTURE}"

    functions = _elf_functions()
    for name in _ELF_FUNCTIONS:
        assert name in functions, f"function missing from export: {name}"
        entry = functions[name]["entry"]
        assert isinstance(entry, str) and int(entry, 16) > 0
        assert int(functions[name]["body_size"]) > 0

    project = Path(tempfile.mkdtemp(prefix="ghidra-gate-")) / "symbols"
    symbols = _client().symbols(_ELF_FIXTURE, project, limit=256, timeout=_TIMEOUT_S)
    assert symbols["count"] >= len(_ELF_FUNCTIONS)
    by_name = {str(item["name"]): item for item in symbols["items"]}
    for name in _ELF_FUNCTIONS:
        assert name in by_name, f"symbol missing from export: {name}"
        assert by_name[name]["type"] == "Function"
        # The symbol table and the function manager agree on the entry point.
        assert by_name[name]["address"] == functions[name]["entry"]


@pytest.mark.integration
def test_ghidra_decompile_recovers_readable_c() -> None:
    """The decompiler returns real C for a known function, and found=False for
    an address inside no function — the two cases the derived flag must split.
    """
    _skip_without_ghidra()
    assert _ELF_FIXTURE.is_file(), f"fixture missing: {_ELF_FIXTURE}"

    entry = _elf_functions()["compute_checksum"]["entry"]
    project = Path(tempfile.mkdtemp(prefix="ghidra-gate-")) / "decompile"
    client = _client()

    result = client.decompile(_ELF_FIXTURE, project, f"0x{entry}", timeout=_TIMEOUT_S)
    assert result["found"] is True
    assert result["function"] == "compute_checksum"
    assert result["entry"] == entry
    code = result["decompiled"]
    assert isinstance(code, str) and code.strip()
    assert "compute_checksum" in code
    # The loop body multiplies by 31: proof this is the fixture's algorithm
    # decompiled, not boilerplate.
    assert "0x1f" in code
    assert "return" in code
    assert result["truncated"] is False

    # Address 0 is mapped to no function: found says so instead of the empty
    # string masquerading as a function whose body decompiled to nothing.
    missed = client.decompile(_ELF_FIXTURE, project, "0x0", timeout=_TIMEOUT_S)
    assert missed["found"] is False
    assert missed.get("function") is None
    assert missed["decompiled"] == ""


@pytest.mark.integration
def test_ghidra_xrefs_see_the_call_from_main() -> None:
    """References to compute_checksum include main's direct call.

    The fixture's main() calls compute_checksum(marker), so a correct xrefs
    export must contain an UNCONDITIONAL_CALL whose source lies inside main's
    body and whose target is compute_checksum's entry.
    """
    _skip_without_ghidra()
    assert _ELF_FIXTURE.is_file(), f"fixture missing: {_ELF_FIXTURE}"

    functions = _elf_functions()
    target = functions["compute_checksum"]["entry"]
    main_entry = int(functions["main"]["entry"], 16)
    main_end = main_entry + int(functions["main"]["body_size"])

    project = Path(tempfile.mkdtemp(prefix="ghidra-gate-")) / "xrefs"
    xrefs = _client().xrefs(_ELF_FIXTURE, project, f"0x{target}", timeout=_TIMEOUT_S)
    assert xrefs["count"] >= 1
    calls = [
        item
        for item in xrefs["items"]
        if item["type"] == "UNCONDITIONAL_CALL" and item["to"] == target
    ]
    assert calls, f"no call reference to compute_checksum in {xrefs['items']}"
    sources = [int(str(item["from"]), 16) for item in calls]
    assert any(main_entry <= source < main_end for source in sources), (
        f"no call source inside main [{main_entry:#x}, {main_end:#x}): {sources}"
    )


@pytest.mark.integration
def test_ghidra_service_surface_analyzes_a_pe() -> None:
    """ghidra.analyze and ghidra.functions work through AnalysisService.

    Beyond the client, the service must record the backend, stamp the timeline,
    register the export JSON as an artifact and honour the pagination bound.
    """
    _skip_without_ghidra()
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    service = AnalysisService()
    try:
        created = service.create_session(str(_PE_FIXTURE))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "pe"
        session_id = created.data["session"]["id"]

        analyzed = service.ghidra_analyze(session_id, timeout=_TIMEOUT_S)
        assert analyzed.ok, analyzed.error
        # The note must warn that the project is gone: the sibling tools each
        # import again, and a caller who believes they read this project would
        # wait on nothing.
        assert "deleted" in analyzed.data["note"]

        functions = service.ghidra_functions(session_id, limit=8, timeout=_TIMEOUT_S)
        assert functions.ok, functions.error
        assert functions.data["count"] == 8
        assert functions.data["has_more"] is True
        first = functions.data["items"][0]
        assert isinstance(first["name"], str) and first["name"]
        assert isinstance(first["entry"], str) and int(first["entry"], 16) > 0

        # The export JSON landed on disk and was registered as an artifact.
        export_path = Path(functions.data["export_path"])
        assert export_path.is_file()
        exported = json.loads(export_path.read_text(encoding="utf-8"))
        assert exported["mode"] == "functions"
        assert len(exported["items"]) == 8
        assert "artifact_id" in functions.data

        artifacts = service.artifacts_list(session_id)
        assert artifacts.ok, artifacts.error
        kinds = {item.get("kind") for item in artifacts.data["artifacts"]}
        assert "ghidra_functions" in kinds

        timeline = service.timeline_list(session_id)
        assert timeline.ok, timeline.error
        events = {entry.get("event") for entry in timeline.data["events"]}
        assert "ghidra.analyze" in events
        assert "ghidra.functions" in events
    finally:
        service.close_all()


@pytest.mark.integration
def test_ghidra_tools_refuse_a_closed_session() -> None:
    """The session-state guard fires before any JVM launches.

    This needs no Ghidra install: the refusal must come from the service, so it
    always runs and pins the invalid_request mapping.
    """
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = service.create_session(str(_PE_FIXTURE)).data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        refused = service.ghidra_functions(session_id)
        assert not refused.ok
        assert refused.error is not None
        assert refused.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_ghidra_degrades_when_home_unset(tmp_path: Path) -> None:
    """No ghidra_home degrades to capability_unavailable, never a crash.

    Always runs: it pins settings.ghidra_home to None, so a machine with Ghidra
    installed still exercises the absent-tool branch.
    """
    assert _PE_FIXTURE.is_file(), f"fixture missing: {_PE_FIXTURE}"

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        ghidra_home=None,
        health_check_interval_s=0.0,
    )
    service = AnalysisService(settings)
    try:
        session_id = service.create_session(str(_PE_FIXTURE)).data["session"]["id"]

        analyzed = service.ghidra_analyze(session_id)
        assert not analyzed.ok
        assert analyzed.error is not None
        assert analyzed.error.code == "capability_unavailable"

        functions = service.ghidra_functions(session_id)
        assert not functions.ok
        assert functions.error is not None
        assert functions.error.code == "capability_unavailable"
    finally:
        service.close_all()
