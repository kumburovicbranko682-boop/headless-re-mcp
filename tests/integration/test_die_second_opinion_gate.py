"""Live Gate for the official Detect It Easy (``diec``) second-opinion route.

The built-in PE engine and the UPX unpack routes have their own gates. What was
never exercised end-to-end is the *external* DIE path that ``detect.scan`` takes
when ``use_die=True``: spawning ``diec -j``, parsing its JSON into findings,
persisting a bounded raw artifact, and registering that artifact for collection.
Unit tests only reached this path with a stubbed scanner, so a real regression in
argv assembly, JSON parsing, or artifact bookkeeping would have gone unseen.

This gate drives the whole route against a committed UPX-packed PE and its
unpacked original. It proves DIE flags UPX on the packed file (independently
agreeing with the built-in engine), stays silent about packers on the clean
original, and that both the DIE source status and the persisted+registered
artifact come back intact. It skips only when no ``diec`` is available -- skip is
never a pass -- and pins the honest degradation paths (unavailable / disabled /
closed session) so a silent downgrade cannot masquerade as a clean scan.

``diec`` is discovered from ``HEADLESS_RE_DIEC`` or from ``PATH``; on the Linux
reference machine the official 3.x ``.deb`` puts it on ``PATH``.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.doctor import ProbeStatus, probe_die

_REPO = Path(__file__).resolve().parents[2]
_PACKED = _REPO / "fixtures" / "upx" / "console_fixture-x64.upx.exe"
_CLEAN = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _resolve_diec() -> Path:
    configured = os.environ.get("HEADLESS_RE_DIEC")
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()
    discovered = shutil.which("diec")
    if discovered:
        return Path(discovered).resolve()
    pytest.skip("no diec CLI on PATH or HEADLESS_RE_DIEC; skip is not a pass")


def _settings(tmp_path: Path, *, diec: Path | None) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
    )


def _require_fixture(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _scan(service: AnalysisService, path: Path, **kwargs: object):
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    scanned = service.detect_scan(session_id, use_exeinfope=False, timeout=30.0, **kwargs)
    return session_id, scanned


@pytest.mark.integration
def test_die_flags_upx_on_a_real_packed_pe(tmp_path: Path) -> None:
    diec = _resolve_diec()
    _require_fixture(_PACKED)
    service = AnalysisService(_settings(tmp_path, diec=diec))

    session_id, scanned = _scan(service, _PACKED, use_die=True)
    assert scanned.ok and scanned.data is not None, scanned.error
    assert scanned.data["die_enabled"] is True
    assert scanned.data["claims_universal_unpack"] is False
    report = scanned.data["report"]

    sources = {item["name"]: item for item in report["sources"]}
    # The external scan runs alongside -- not instead of -- the built-in engine.
    assert sources["builtin.pe"]["status"] == "completed"
    die_source = sources["diec"]
    assert die_source["status"] == "completed", die_source

    die_findings = [item for item in report["findings"] if item["source"] == "diec"]
    assert die_findings, "diec produced no findings on a packed sample"

    packers = [item for item in die_findings if item["category"] == "packer"]
    assert packers, f"diec did not report a packer: {die_findings}"
    upx = next((item for item in packers if item["name"].casefold() == "upx"), None)
    assert upx is not None, f"diec packer finding was not UPX: {packers}"
    assert "upx" in upx["summary"].casefold()
    # DIE carries the packer version through evidence; a real scan resolves it.
    version = upx["evidence"][0]["details"].get("version", "")
    assert version and version[0].isdigit(), upx["evidence"]

    # DIE independently agrees with the built-in engine that this is UPX.
    builtin_packers = [
        item
        for item in report["findings"]
        if item["source"] == "builtin.pe" and item["category"] == "packer"
    ]
    assert any("upx" in item["name"].casefold() for item in builtin_packers), builtin_packers

    # The bounded raw JSON is persisted and registered for collection, and the
    # stored payload is the real DIE document (an object with detects).
    artifact_path = die_source.get("artifact")
    assert isinstance(artifact_path, str) and Path(artifact_path).is_file(), die_source
    listing = service.artifacts_list(session_id)
    assert listing.ok and listing.data is not None, listing.error
    die_artifacts = [item for item in listing.data["artifacts"] if item["kind"] == "detection_die"]
    assert len(die_artifacts) == 1, listing.data["artifacts"]
    assert die_artifacts[0]["source"] == "detect.scan"
    assert die_artifacts[0]["path"] == artifact_path

    stored = json.loads(Path(artifact_path).read_text())
    assert stored["tool"] == "diec"
    raw = json.loads(stored["raw_json"])
    assert isinstance(raw.get("detects"), list) and raw["detects"], raw

    service.close_session(session_id)


@pytest.mark.integration
def test_die_stays_silent_about_packers_on_the_unpacked_original(tmp_path: Path) -> None:
    diec = _resolve_diec()
    _require_fixture(_CLEAN)
    service = AnalysisService(_settings(tmp_path, diec=diec))

    session_id, scanned = _scan(service, _CLEAN, use_die=True)
    assert scanned.ok and scanned.data is not None, scanned.error
    report = scanned.data["report"]
    sources = {item["name"]: item for item in report["sources"]}
    assert sources["diec"]["status"] == "completed", sources["diec"]

    die_findings = [item for item in report["findings"] if item["source"] == "diec"]
    # DIE still recognises the file, it just must not invent a packer here.
    assert any(item["category"] == "file_format" for item in die_findings), die_findings
    die_packers = [item for item in die_findings if item["category"] == "packer"]
    assert not die_packers, f"diec flagged a packer on the clean original: {die_packers}"

    # A DIE artifact is still written for the clean scan (auditability).
    assert isinstance(sources["diec"].get("artifact"), str)

    service.close_session(session_id)


@pytest.mark.integration
def test_die_unavailable_is_reported_not_silently_dropped(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    # No diec configured, but the caller still asked for it: the scan must say so
    # rather than return built-in-only findings as if DIE had cleared the file.
    service = AnalysisService(_settings(tmp_path, diec=None))

    session_id, scanned = _scan(service, _PACKED, use_die=True)
    assert scanned.ok and scanned.data is not None, scanned.error
    report = scanned.data["report"]
    sources = {item["name"]: item for item in report["sources"]}
    assert sources["diec"]["status"] == "unavailable", sources["diec"]
    assert any("Detect It Easy is unavailable" in w for w in report["warnings"]), report["warnings"]
    # Built-in findings are still valid and returned.
    assert sources["builtin.pe"]["status"] == "completed"
    assert not [item for item in report["findings"] if item["source"] == "diec"]

    service.close_session(session_id)


@pytest.mark.integration
def test_die_disabled_by_caller_is_distinct_from_unavailable(tmp_path: Path) -> None:
    diec = _resolve_diec()
    _require_fixture(_PACKED)
    service = AnalysisService(_settings(tmp_path, diec=diec))

    session_id, scanned = _scan(service, _PACKED, use_die=False)
    assert scanned.ok and scanned.data is not None, scanned.error
    assert scanned.data["die_enabled"] is False
    sources = {item["name"]: item for item in scanned.data["report"]["sources"]}
    # A configured tool the caller turned off reads as "disabled", never as a
    # completed scan and never as "unavailable".
    assert sources["diec"]["status"] == "disabled", sources["diec"]
    assert not [item for item in scanned.data["report"]["findings"] if item["source"] == "diec"]

    service.close_session(session_id)


@pytest.mark.integration
def test_die_scan_refuses_a_closed_session(tmp_path: Path) -> None:
    diec = _resolve_diec()
    _require_fixture(_PACKED)
    service = AnalysisService(_settings(tmp_path, diec=diec))

    created = service.create_session(str(_PACKED))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    service.close_session(session_id)

    scanned = service.detect_scan(session_id, use_die=True, timeout=30.0)
    assert scanned.ok is False
    assert scanned.error is not None
    assert scanned.error.code == "invalid_request"


@pytest.mark.integration
def test_die_doctor_probe_reports_ready(tmp_path: Path) -> None:
    diec = _resolve_diec()
    probe = probe_die(_settings(tmp_path, diec=diec))
    assert probe.status == ProbeStatus.READY, (probe.status, probe.details)
    assert probe.details.get("json_capable") is True
    version = probe.details.get("version")
    assert isinstance(version, str) and version[0].isdigit(), probe.details
