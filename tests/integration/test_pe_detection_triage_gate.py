"""PE detection triage Gate: the built-in scanner tells a packed PE from its twin.

The built-in PE detector (``detection/pe.py``) is the pure-Python, no-external-tool
front of the whole reverse-engineering flow: ``detect.scan`` feeds ``packer.classify``
which feeds ``unpack.recommend``. Every existing check of that path either exercises
hand-built synthetic PEs (``tests/unit/test_detection_pe.py``) or requires the UPX /
DIE / IDA CLIs (``tests/unit/test_upx_fixtures.py``, ``test_unpack_live_gate.py``), so
none of them prove the triage chain works on a *real* UPX-packed binary through the
service layer -- nor that it stays silent on the same program before it was packed.

This gate drives the three service methods against the committed fixture pair
(``console_fixture-<arch>.upx.exe`` and its ``.pre-upx.exe`` twin: the exact same
program, packed and unpacked) and asserts the contrast:

  * the packed image surfaces the UPX packer candidate plus a measured high-entropy
    section, and ``unpack.recommend`` routes to ``upx``;
  * the unpacked twin surfaces neither, ``packer.classify`` concludes
    ``none_detected``, and ``unpack.recommend`` routes to ``none``.

DIE and Exeinfo PE are disabled, so the run needs no external tool and the report's
only completed source is ``builtin.pe``: this is the built-in detector proving itself,
not a second opinion leaning on someone else's verdict. A missing fixture skips loudly
(skip != pass); nothing else should skip on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.detection import FindingCategory

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _PROJECT_ROOT / "fixtures" / "upx"

# The high-entropy anomaly threshold in detection/pe.py; the assertions below tie
# the finding to a section measurement that actually crosses it.
_HIGH_ENTROPY = 7.2

_ARCHES = [pytest.param("x86", id="x86"), pytest.param("x64", id="x64")]


def _fixture_pair(arch: str) -> tuple[Path, Path]:
    packed = _FIXTURES / f"console_fixture-{arch}.upx.exe"
    unpacked = _FIXTURES / f"console_fixture-{arch}.pre-upx.exe"
    for path in (packed, unpacked):
        if not path.is_file():
            pytest.skip(f"missing committed UPX fixture: {path} (skip != pass)")
    return packed, unpacked


def _builtin_only_service(tmp_path: Path) -> AnalysisService:
    """A service with every external scanner unset: only the built-in PE path runs."""
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=None,
        diec=None,
    )
    return AnalysisService(settings)


def _data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), getattr(result, "error", None)
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _session_id(service: AnalysisService, binary: Path) -> str:
    created = _data(service.create_session(str(binary)))
    session = created["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _max_section_entropy(report: JsonObject) -> float:
    sections = report["pe"]["sections"]
    assert isinstance(sections, list) and sections, report["pe"]
    return max(float(section["entropy"]) for section in sections)


@pytest.mark.integration
@pytest.mark.parametrize("arch", _ARCHES)
def test_detection_triage_flags_upx_and_stays_silent_on_the_unpacked_twin(
    tmp_path: Path, arch: str
) -> None:
    packed, unpacked = _fixture_pair(arch)
    service = _builtin_only_service(tmp_path)
    try:
        # --- the packed image: every triage stage should point at UPX ---
        packed_id = _session_id(service, packed)

        scan = _data(service.detect_scan(packed_id, use_die=False, use_exeinfope=False))
        report = scan["report"]
        assert report["format"] == "PE"
        assert report["architecture"] == arch
        # No external tool ran, so there is nothing to warn about: the built-in
        # detector stood on its own with DIE/Exeinfo explicitly disabled.
        assert report["warnings"] == [], report["warnings"]
        assert scan["die_enabled"] is False
        assert scan["claims_universal_unpack"] is False
        sources = {source["name"]: source["status"] for source in report["sources"]}
        assert sources.get("builtin.pe") == "completed", sources
        assert sources.get("diec") == "disabled", sources

        finding_ids = {finding["id"] for finding in report["findings"]}
        categories = {finding["category"] for finding in report["findings"]}
        assert FindingCategory.PACKER.value in categories, report["findings"]
        packer = next(
            finding
            for finding in report["findings"]
            if finding["category"] == FindingCategory.PACKER.value
        )
        assert packer["name"] == "UPX", packer
        # The packer verdict is anchored to a measured high-entropy section, not a
        # bare name match: prove both the finding and the measurement behind it.
        assert any("high-entropy" in fid for fid in finding_ids), finding_ids
        assert _max_section_entropy(report) >= _HIGH_ENTROPY, report["pe"]["sections"]

        classified = _data(service.packer_classify(packed_id, use_die=False))
        assert classified["conclusion"] == "candidates", classified
        names = {candidate["name"] for candidate in classified["candidates"]}
        assert "UPX" in names, classified["candidates"]
        upx_candidate = next(c for c in classified["candidates"] if c["name"] == "UPX")
        assert float(upx_candidate["confidence"]) >= 0.8, upx_candidate

        recommended = _data(service.unpack_recommend(packed_id, use_die=False))
        recommendation = recommended["recommendation"]
        assert recommendation["route"] == "upx", recommendation
        assert recommendation["authoritative"] is False
        tools = set(recommendation["suggested_tools"])
        assert {"unpack.upx.unpack", "unpack.auto"} <= tools, tools

        # --- the same program, unpacked: none of the above should fire ---
        clean_id = _session_id(service, unpacked)

        clean_scan = _data(service.detect_scan(clean_id, use_die=False, use_exeinfope=False))
        clean_report = clean_scan["report"]
        assert clean_report["architecture"] == arch
        clean_categories = {finding["category"] for finding in clean_report["findings"]}
        assert FindingCategory.PACKER.value not in clean_categories, clean_report["findings"]
        clean_ids = {finding["id"] for finding in clean_report["findings"]}
        assert not any("high-entropy" in fid for fid in clean_ids), clean_ids
        # The unpacked twin carries no section that crosses the packing threshold --
        # the contrast that keeps the packed verdict from being a coincidence.
        assert _max_section_entropy(clean_report) < _HIGH_ENTROPY, clean_report["pe"]["sections"]

        clean_classified = _data(service.packer_classify(clean_id, use_die=False))
        assert clean_classified["conclusion"] == "none_detected", clean_classified
        assert clean_classified["candidates"] == [], clean_classified

        clean_recommended = _data(service.unpack_recommend(clean_id, use_die=False))
        assert clean_recommended["recommendation"]["route"] == "none", clean_recommended
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize("arch", _ARCHES)
def test_detect_explain_resolves_the_upx_finding_and_rejects_unknown_ids(
    tmp_path: Path, arch: str
) -> None:
    packed, _ = _fixture_pair(arch)
    service = _builtin_only_service(tmp_path)
    try:
        session_id = _session_id(service, packed)

        explained = _data(
            service.detect_explain(session_id, "builtin:packer:upx-sections", use_die=False)
        )
        finding = explained["finding"]
        assert finding["name"] == "UPX", finding
        assert finding["category"] == FindingCategory.PACKER.value
        assert finding["evidence"], finding
        assert finding["evidence"][0]["kind"] == "section_name", finding["evidence"]

        missing = service.detect_explain(
            session_id, "builtin:packer:not-a-real-finding", use_die=False
        )
        assert missing.ok is False
        assert missing.error is not None
        assert missing.error.code == "finding_not_found", missing.error
    finally:
        service.close_all()
