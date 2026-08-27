"""Built-in PE detection gate: real UPX-packed input vs its unpacked original.

The detection surface (``detect.scan`` / ``packer.classify`` /
``unpack.recommend`` / ``detect.explain``) has a pure-Python PE-heuristics engine
that needs no external tool -- Detect It Easy and Exeinfo PE are strictly
optional second opinions. Yet it had only unit coverage: no integration gate ran
it end-to-end through ``AnalysisService`` against a real packed binary, and the
one external-tool gate (``test_exeinfope_gate.py``) skips without Exeinfo PE.

This gate runs the built-in engine (``use_die=False, use_exeinfope=False``)
against a matched pair of committed fixtures: ``console_fixture-x64.upx.exe`` (a
genuinely UPX-packed PE) and ``console_fixture-x64.pre-upx.exe`` (the same
program before packing). The pair is what makes the assertions honest -- the
engine must call the packed one UPX (with the UPX0/UPX1 sections and a
high-entropy UPX1) and the unpacked one clean, so a heuristic that simply always
says "packed" (or never does) fails one side or the other. Both fixtures and the
engine are always present, so this gate always runs; the closed-session
(``invalid_request``) and unknown-finding (``finding_not_found``) guards run
inline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PACKED = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.upx.exe"
_UNPACKED = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"

_UPX_FINDING_ID = "builtin:packer:upx-sections"


def _source_status(report: dict) -> dict[str, str]:
    return {src["name"]: src["status"] for src in report.get("sources", [])}


def _packer_finding(report: dict) -> dict | None:
    for finding in report.get("findings", []):
        if finding.get("category") == "packer" and "UPX" in str(finding.get("name", "")).upper():
            return finding
    return None


@pytest.mark.integration
def test_detection_classifies_a_real_upx_packed_pe() -> None:
    assert _PACKED.is_file(), f"fixture missing: {_PACKED}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_PACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        scan = service.detect_scan(session_id, use_die=False, use_exeinfope=False)
        assert scan.ok, scan.error
        report = scan.data["report"]

        # The built-in engine ran; the external tools were honestly reported off.
        statuses = _source_status(report)
        assert statuses.get("builtin.pe") == "completed", statuses
        assert statuses.get("diec") == "disabled"
        assert statuses.get("exeinfope") == "disabled"

        # A UPX packer finding, from the built-in engine alone.
        packer = _packer_finding(report)
        assert packer is not None, [f.get("id") for f in report["findings"]]
        assert packer["id"] == _UPX_FINDING_ID
        assert 0.0 < packer["confidence"] <= 1.0

        # The tell-tale UPX section layout, with a high-entropy packed UPX1.
        sections = {s["name"]: s for s in report["pe"]["sections"]}
        assert {"UPX0", "UPX1"} <= set(sections), list(sections)
        assert sections["UPX1"]["entropy"] > 7.0, sections["UPX1"]

        classified = service.packer_classify(session_id, use_die=False)
        assert classified.ok, classified.error
        assert classified.data["conclusion"] == "candidates"
        candidate_ids = {c.get("id") for c in classified.data["candidates"]}
        assert _UPX_FINDING_ID in candidate_ids, candidate_ids

        recommended = service.unpack_recommend(session_id, use_die=False)
        assert recommended.ok, recommended.error
        recommendation = recommended.data["recommendation"]
        assert recommendation["route"] == "upx"
        assert recommendation["confidence"] > 0.5
        assert any("upx" in tool.lower() for tool in recommendation["suggested_tools"])

        explained = service.detect_explain(session_id, _UPX_FINDING_ID, use_die=False)
        assert explained.ok, explained.error
        assert explained.data["finding"]["id"] == _UPX_FINDING_ID
        assert explained.data["sha256"] == report["sha256"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_detection_finds_no_packer_in_the_unpacked_original() -> None:
    """The same program before UPX must classify clean -- the contrast is the point."""
    assert _UNPACKED.is_file(), f"fixture missing: {_UNPACKED}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_UNPACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        scan = service.detect_scan(session_id, use_die=False, use_exeinfope=False)
        assert scan.ok, scan.error
        assert _packer_finding(scan.data["report"]) is None, scan.data["report"]["findings"]

        classified = service.packer_classify(session_id, use_die=False)
        assert classified.ok, classified.error
        assert classified.data["conclusion"] == "none_detected"
        assert classified.data["candidates"] == []

        recommended = service.unpack_recommend(session_id, use_die=False)
        assert recommended.ok, recommended.error
        assert recommended.data["recommendation"]["route"] == "none"
    finally:
        service.close_all()


@pytest.mark.integration
def test_detect_scan_refuses_a_closed_session() -> None:
    service = AnalysisService()
    try:
        created = service.create_session(str(_UNPACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        service.close_session(session_id)

        result = service.detect_scan(session_id, use_die=False, use_exeinfope=False)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_detect_explain_reports_an_unknown_finding() -> None:
    service = AnalysisService()
    try:
        created = service.create_session(str(_PACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        result = service.detect_explain(
            session_id, "builtin:nope:not-a-real-finding", use_die=False
        )
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "finding_not_found"
    finally:
        service.close_all()
