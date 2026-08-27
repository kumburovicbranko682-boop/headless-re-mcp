from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection import (
    DetectionEvidence,
    DetectionFinding,
    DetectionSource,
    FindingCategory,
    ScanMode,
)
from headless_re_mcp.detection.die import DieProcessError, DieScanResult


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xC3\x90"
    path.write_bytes(image)


def _settings(tmp_path: Path, diec: Path | None = None) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
    )


def _session_id(result: object) -> str:
    data = result.data
    assert isinstance(data, dict)
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _die_result(path: Path) -> DieScanResult:
    finding = DetectionFinding(
        id="die:0:0",
        category=FindingCategory.PACKER,
        name="UPX",
        summary="Packer: UPX",
        confidence=1.0,
        source="diec",
        evidence=(
            DetectionEvidence(
                kind="die_signature",
                description="Packer: UPX",
                details={"type": "Packer"},
            ),
        ),
    )
    return DieScanResult(
        path=path,
        size=path.stat().st_size,
        mode=ScanMode.NORMAL,
        findings=(finding,),
        source=DetectionSource(
            name="diec", status="completed", version="3.21", summary="fake DIE"
        ),
        raw={"detects": []},
        raw_json='{"detects": []}',
        stdout='{"detects": []}',
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def _die_result_clean(path: Path) -> DieScanResult:
    """A DIE scan that completed and found no packer/protector/obfuscator."""
    return DieScanResult(
        path=path,
        size=path.stat().st_size,
        mode=ScanMode.NORMAL,
        findings=(),
        source=DetectionSource(
            name="diec", status="completed", version="3.21", summary="fake DIE"
        ),
        raw={"detects": []},
        raw_json='{"detects": []}',
        stdout='{"detects": []}',
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def test_packer_classify_inconclusive_when_die_unavailable(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    # No diec configured: the primary packer detector never runs, so an empty
    # candidate list must not read as a clean "none_detected".
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    classified = service.packer_classify(session_id)

    assert classified.ok and classified.data is not None
    assert classified.data["candidates"] == []
    assert classified.data["conclusion"] == "inconclusive"
    assert classified.data["signature_scan_completed"] is False
    diec = next(s for s in classified.data["scanners"] if s["name"] == "diec")
    assert diec["status"] == "unavailable"


def test_packer_classify_none_detected_only_when_signature_scan_completes(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(
        _settings(tmp_path, diec),
        die_scanner=lambda executable, path, *, mode, timeout: _die_result_clean(path),
    )
    session_id = _session_id(service.create_session(str(binary)))

    classified = service.packer_classify(session_id)

    assert classified.ok and classified.data is not None
    assert classified.data["candidates"] == []
    assert classified.data["conclusion"] == "none_detected"
    assert classified.data["signature_scan_completed"] is True
    diec_scanner = next(s for s in classified.data["scanners"] if s["name"] == "diec")
    assert diec_scanner["status"] == "completed"


def test_packer_classify_failed_die_is_inconclusive_not_clean(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")

    def _boom(executable: Path, path: Path, *, mode: ScanMode, timeout: float) -> DieScanResult:
        raise DieProcessError("process_failed", "diec exited with status 1")

    service = AnalysisService(_settings(tmp_path, diec), die_scanner=_boom)
    session_id = _session_id(service.create_session(str(binary)))

    classified = service.packer_classify(session_id)

    assert classified.ok and classified.data is not None
    assert classified.data["candidates"] == []
    # A crashed scanner is not evidence of a clean sample.
    assert classified.data["conclusion"] == "inconclusive"
    assert classified.data["signature_scan_completed"] is False
    diec_scanner = next(s for s in classified.data["scanners"] if s["name"] == "diec")
    assert diec_scanner["status"] == "failed"


def test_packer_classify_reports_candidates_with_scanner_disclosure(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(
        _settings(tmp_path, diec),
        die_scanner=lambda executable, path, *, mode, timeout: _die_result(path),
    )
    session_id = _session_id(service.create_session(str(binary)))

    classified = service.packer_classify(session_id)

    assert classified.ok and classified.data is not None
    assert classified.data["conclusion"] == "candidates"
    assert classified.data["signature_scan_completed"] is True
    assert any(s["name"] == "diec" for s in classified.data["scanners"])


def test_unpack_recommend_flags_inconclusive_detection(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    # diec not configured: classify is inconclusive, so a route of "none" must
    # not read as a confirmed clean sample.
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.unpack_recommend(session_id)

    assert result.ok and result.data is not None
    assert result.data["detection_conclusion"] == "inconclusive"
    assert result.data["detection_inconclusive"] is True
    assert result.data["signature_scan_completed"] is False
    assert result.data["recommendation"]["route"] == "none"
    assert "note" in result.data
    assert "inconclusive" in result.data["note"]
    assert any(s["name"] == "diec" for s in result.data["scanners"])


def test_unpack_recommend_clean_scan_is_not_flagged(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(
        _settings(tmp_path, diec),
        die_scanner=lambda executable, path, *, mode, timeout: _die_result_clean(path),
    )
    session_id = _session_id(service.create_session(str(binary)))

    result = service.unpack_recommend(session_id)

    assert result.ok and result.data is not None
    assert result.data["detection_conclusion"] == "none_detected"
    assert result.data["detection_inconclusive"] is False
    assert result.data["signature_scan_completed"] is True
    assert result.data["recommendation"]["route"] == "none"
    assert "note" not in result.data


def test_unpack_plan_flags_inconclusive_detection(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.unpack_plan(session_id)

    assert result.ok and result.data is not None
    assert result.data["plan"]["route"] == "none"
    assert result.data["detection_conclusion"] == "inconclusive"
    assert result.data["detection_inconclusive"] is True
    assert result.data["signature_scan_completed"] is False
    assert "note" in result.data
    assert "inconclusive" in result.data["note"]
    assert any(s["name"] == "diec" for s in result.data["scanners"])


def test_unpack_plan_clean_scan_is_not_flagged(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(
        _settings(tmp_path, diec),
        die_scanner=lambda executable, path, *, mode, timeout: _die_result_clean(path),
    )
    session_id = _session_id(service.create_session(str(binary)))

    result = service.unpack_plan(session_id)

    assert result.ok and result.data is not None
    assert result.data["plan"]["route"] == "none"
    assert result.data["detection_conclusion"] == "none_detected"
    assert result.data["detection_inconclusive"] is False
    assert result.data["signature_scan_completed"] is True
    assert "note" not in result.data


def test_detection_service_uses_builtin_fallback_when_die_is_missing(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id, use_die=True)

    assert result.ok and result.data is not None
    report = result.data["report"]
    assert report["architecture"] == "x64"
    assert any(source["status"] == "unavailable" for source in report["sources"])
    assert report["warnings"]


def test_detection_service_merges_die_and_persists_raw_artifact(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(
        _settings(tmp_path, diec),
        die_scanner=lambda executable, path, *, mode, timeout: _die_result(path),
    )
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id)

    assert result.ok and result.data is not None
    report = result.data["report"]
    assert any(finding["id"] == "die:0:0" for finding in report["findings"])
    die_source = next(source for source in report["sources"] if source["name"] == "diec")
    artifact = Path(die_source["artifact"])
    assert artifact.is_file()
    assert '"raw_json":"{\\"detects\\": []}"' in artifact.read_text(encoding="utf-8")


def test_detection_explain_and_packer_classify_are_non_authoritative(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(
        _settings(tmp_path, diec),
        die_scanner=lambda executable, path, *, mode, timeout: _die_result(path),
    )
    session_id = _session_id(service.create_session(str(binary)))

    explained = service.detect_explain(session_id, "die:0:0")
    classified = service.packer_classify(session_id)

    assert explained.ok and explained.data is not None
    assert explained.data["finding"]["name"] == "UPX"
    assert classified.ok and classified.data is not None
    assert classified.data["conclusion"] == "candidates"
    assert classified.data["candidates"][0]["category"] == "packer"
    assert classified.data["stealth_profile"] is None


def test_detection_rejects_changed_input_and_invalid_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))
    binary.write_bytes(binary.read_bytes() + b"changed")

    changed = service.detect_scan(session_id)
    invalid = service.detect_scan(session_id, timeout=0)

    assert not changed.ok and changed.error is not None
    assert changed.error.code == "input_changed"
    assert not invalid.ok and invalid.error is not None
    assert invalid.error.code == "invalid_request"


@pytest.mark.parametrize("mode", list(ScanMode))
def test_detection_modes_are_accepted(tmp_path: Path, mode: ScanMode) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id, mode=mode, use_die=False)

    assert result.ok and result.data is not None
    assert result.data["report"]["mode"] == mode.value
