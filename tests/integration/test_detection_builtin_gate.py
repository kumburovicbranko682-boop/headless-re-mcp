"""Live Gate for the built-in, pure-Python PE detection engine.

Every other detection gate leans on an external second opinion: the DIE gate
drives ``diec``, the Exeinfo gate needs a Windows GUI binary. But the engine
that always runs -- ``detect.scan(use_die=False)`` and everything layered on it
(``packer.classify``, ``unpack.recommend``, ``detect.explain``) -- had no
end-to-end coverage, so a regression in the UPX heuristics, the section-entropy
math, or the route recommendation would surface only once a real sample came in.

This gate pins that engine against a committed pair: a UPX-packed PE and its
unpacked original. It is deliberately tool-free, so it runs on any machine and
never skips -- skip is never a pass, and here there is nothing to skip. It
checks the packed sample is flagged as UPX with the expected section-name and
high-entropy evidence, that classify concludes "candidates" and recommend routes
to the official UPX unpacker, and that the clean original stays quiet
("none_detected", route "none"). The explain and closed-session guards are
pinned too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_REPO = Path(__file__).resolve().parents[2]
_PACKED = _REPO / "fixtures" / "upx" / "console_fixture-x64.upx.exe"
_CLEAN = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            diec=None,
        )
    )


def _require_fixture(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _open(service: AnalysisService, path: Path) -> str:
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _findings_by_id(report: dict) -> dict[str, dict]:
    return {item["id"]: item for item in report["findings"]}


@pytest.mark.integration
def test_builtin_engine_flags_upx_on_the_packed_pe(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    service = _service(tmp_path)
    session_id = _open(service, _PACKED)

    scanned = service.detect_scan(session_id, use_die=False, use_exeinfope=False)
    assert scanned.ok and scanned.data is not None, scanned.error
    assert scanned.data["die_enabled"] is False
    assert scanned.data["claims_universal_unpack"] is False
    report = scanned.data["report"]

    # The built-in engine ran; the external opinions were explicitly disabled.
    sources = {item["name"]: item["status"] for item in report["sources"]}
    assert sources["builtin.pe"] == "completed"
    assert sources["diec"] == "disabled"

    # Every finding comes from the built-in engine (no diec entries leak in).
    assert report["findings"]
    assert all(item["source"] == "builtin.pe" for item in report["findings"])

    findings = _findings_by_id(report)
    assert findings["builtin:format:pe"]["category"] == "file_format"

    packer = findings["builtin:packer:upx-sections"]
    assert packer["category"] == "packer"
    assert packer["name"] == "UPX"
    assert packer["confidence"] >= 0.8
    section_evidence = packer["evidence"][0]["details"]["sections"]
    assert "UPX0" in section_evidence and "UPX1" in section_evidence

    # UPX's compressed section reads as high entropy; the heuristic must see it.
    entropy_finding = findings["builtin:anomaly:high-entropy:UPX1"]
    assert entropy_finding["category"] == "anomaly"
    entropy = entropy_finding["evidence"][0]["details"]["entropy"]
    assert entropy > 7.0, entropy

    # The writable+executable UPX loader sections are flagged as anomalies.
    rwx = [
        item for fid, item in findings.items() if fid.startswith("builtin:anomaly:rwx-section:UPX")
    ]
    assert rwx, "no rwx UPX section anomaly reported"

    assert report.get("sha256")
    assert report.get("path")


@pytest.mark.integration
def test_builtin_engine_is_quiet_on_the_unpacked_original(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    _require_fixture(_CLEAN)
    service = _service(tmp_path)

    packed_report = service.detect_scan(_open(service, _PACKED), use_die=False).data["report"]
    clean = service.detect_scan(_open(service, _CLEAN), use_die=False)
    assert clean.ok and clean.data is not None, clean.error
    clean_report = clean.data["report"]

    clean_findings = _findings_by_id(clean_report)
    # It is still recognisably a PE, just not a packed one.
    assert "builtin:format:pe" in clean_findings
    assert not [item for item in clean_report["findings"] if item["category"] == "packer"]
    assert not [
        fid
        for fid in clean_findings
        if fid.startswith("builtin:anomaly:rwx-section:UPX")
        or fid.startswith("builtin:anomaly:high-entropy:")
    ]
    # The packed sample must produce strictly more evidence than its origin.
    assert len(packed_report["findings"]) > len(clean_report["findings"])


@pytest.mark.integration
def test_packer_classify_contrasts_packed_and_clean(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    _require_fixture(_CLEAN)
    service = _service(tmp_path)

    packed = service.packer_classify(_open(service, _PACKED), use_die=False)
    assert packed.ok and packed.data is not None, packed.error
    assert packed.data["conclusion"] == "candidates"
    assert packed.data["claims_universal_unpack"] is False
    assert any(c["name"] == "UPX" for c in packed.data["candidates"])

    clean = service.packer_classify(_open(service, _CLEAN), use_die=False)
    assert clean.ok and clean.data is not None, clean.error
    assert clean.data["conclusion"] == "none_detected"
    assert clean.data["candidates"] == []


@pytest.mark.integration
def test_unpack_recommend_routes_upx_for_packed_and_none_for_clean(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    _require_fixture(_CLEAN)
    service = _service(tmp_path)

    packed = service.unpack_recommend(_open(service, _PACKED), use_die=False)
    assert packed.ok and packed.data is not None, packed.error
    assert packed.data["authoritative"] is False
    packed_route = packed.data["recommendation"]
    assert packed_route["route"] == "upx"
    assert packed_route["confidence"] >= 0.8
    assert "unpack.upx.test" in packed_route["suggested_tools"]
    assert "unpack.auto" in packed_route["suggested_tools"]

    clean = service.unpack_recommend(_open(service, _CLEAN), use_die=False)
    assert clean.ok and clean.data is not None, clean.error
    clean_route = clean.data["recommendation"]
    assert clean_route["route"] == "none"
    assert "static.open" in clean_route["suggested_tools"]


@pytest.mark.integration
def test_detect_explain_returns_one_finding_and_rejects_unknown(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    service = _service(tmp_path)
    session_id = _open(service, _PACKED)

    scanned = service.detect_scan(session_id, use_die=False)
    packer_id = "builtin:packer:upx-sections"
    assert packer_id in _findings_by_id(scanned.data["report"])

    explained = service.detect_explain(session_id, packer_id, use_die=False)
    assert explained.ok and explained.data is not None, explained.error
    assert explained.data["finding"]["id"] == packer_id
    assert explained.data["finding"]["evidence"]
    assert explained.data["sha256"] and explained.data["path"]

    missing = service.detect_explain(session_id, "builtin:not:a:finding", use_die=False)
    assert missing.ok is False and missing.error is not None
    assert missing.error.code == "finding_not_found"

    blank = service.detect_explain(session_id, "   ", use_die=False)
    assert blank.ok is False and blank.error is not None
    assert blank.error.code == "invalid_request"


@pytest.mark.integration
def test_builtin_detection_refuses_a_closed_session(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    service = _service(tmp_path)
    session_id = _open(service, _PACKED)
    service.close_session(session_id)

    for result in (
        service.detect_scan(session_id, use_die=False),
        service.packer_classify(session_id, use_die=False),
        service.unpack_recommend(session_id, use_die=False),
    ):
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
