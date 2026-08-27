"""Coverage for unpack_recommend plus detect/classify guard paths.

``test_detection_service.py`` and ``test_detection_service_exeinfope.py``
cover the DIE/Exeinfo happy paths. This file pins the previously-untested
``unpack_recommend`` method end to end, the fail-closed flag validation and
scanner/artifact error handling in ``detect_scan``, and the malformed-report
defenses in ``detect_explain`` / ``packer_classify``.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_detect as service_detect_module
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection import (
    DetectionEvidence,
    DetectionFinding,
    DetectionSource,
    FindingCategory,
    PeFormatError,
    ScanMode,
)
from headless_re_mcp.detection.die import DieScanError, DieScanResult

JsonObject = dict[str, object]


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
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _settings(
    tmp_path: Path, *, diec: Path | None = None, exeinfope: Path | None = None
) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
        exeinfope=exeinfope,
    )


def _session_id(result: Result[JsonObject]) -> str:
    data = result.data
    assert isinstance(data, dict)
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _upx_die_result(path: Path) -> DieScanResult:
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
        source=DetectionSource(name="diec", status="completed", version="3.21", summary="fake DIE"),
        raw={"detects": []},
        raw_json='{"detects": []}',
        stdout='{"detects": []}',
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def _service_with_upx_die(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(
        _settings(tmp_path, diec=diec),
        die_scanner=lambda executable, path, *, mode, timeout: _upx_die_result(path),
    )
    session_id = _session_id(service.create_session(str(binary)))
    return service, session_id


def _plain_service(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))
    return service, session_id


def test_unpack_recommend_routes_from_die_candidate(tmp_path: Path) -> None:
    service, session_id = _service_with_upx_die(tmp_path)

    result = service.unpack_recommend(session_id)

    assert result.ok and result.data is not None
    assert result.data["authoritative"] is False
    assert result.data["force_route"] is None
    assert "pe_vm_like" in result.data
    recommendation = result.data["recommendation"]
    assert isinstance(recommendation, dict)
    assert recommendation["route"] == "upx"
    candidates = result.data["candidates"]
    assert isinstance(candidates, list) and candidates


def test_unpack_recommend_honors_valid_force_route(tmp_path: Path) -> None:
    service, session_id = _plain_service(tmp_path)

    result = service.unpack_recommend(session_id, use_die=False, force_route="generic_dynamic")

    assert result.ok and result.data is not None
    assert result.data["force_route"] == "generic_dynamic"
    recommendation = result.data["recommendation"]
    assert isinstance(recommendation, dict)
    assert recommendation["route"] == "generic_dynamic"


def test_unpack_recommend_rejects_invalid_force_route(tmp_path: Path) -> None:
    service, session_id = _plain_service(tmp_path)

    result = service.unpack_recommend(session_id, use_die=False, force_route="teleport")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_unpack_recommend_propagates_classify_failure(tmp_path: Path) -> None:
    service, session_id = _plain_service(tmp_path)

    result = service.unpack_recommend(session_id, timeout=0)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_unpack_recommend_tolerates_non_list_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _plain_service(tmp_path)
    monkeypatch.setattr(
        service,
        "packer_classify",
        lambda *a, **k: Result[JsonObject](
            ok=True, data={"candidates": "not-a-list", "report_sha256": None}
        ),
    )

    result = service.unpack_recommend(session_id, use_die=False)

    assert result.ok and result.data is not None
    recommendation = result.data["recommendation"]
    assert isinstance(recommendation, dict)
    assert recommendation["route"] == "none"


def test_detect_scan_rechecks_state_after_scan(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    holder: dict[str, object] = {}

    def scanner(executable: Path, path: Path, *, mode: ScanMode, timeout: float) -> DieScanResult:
        del executable, mode, timeout
        service_ref = holder["service"]
        session_ref = holder["session_id"]
        assert isinstance(service_ref, AnalysisService)
        assert isinstance(session_ref, str)
        service_ref.close_session(session_ref)
        return _upx_die_result(path)

    service = AnalysisService(_settings(tmp_path, diec=diec), die_scanner=scanner)
    session_id = _session_id(service.create_session(str(binary)))
    holder["service"] = service
    holder["session_id"] = session_id
    try:
        result = service.detect_scan(session_id, use_die=True)
        assert not result.ok and result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_detect_scan_rejects_non_bool_flags(tmp_path: Path) -> None:
    service, session_id = _plain_service(tmp_path)

    bad_die = service.detect_scan(session_id, use_die="yes")  # type: ignore[arg-type]
    bad_exe = service.detect_scan(session_id, use_exeinfope=1)  # type: ignore[arg-type]

    assert not bad_die.ok and bad_die.error is not None
    assert not bad_exe.ok and bad_exe.error is not None


def test_detect_scan_reports_die_failure_but_keeps_builtin(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")

    def scanner(*args: object, **kwargs: object) -> DieScanResult:
        del args, kwargs
        raise DieScanError("timeout", "die boom")

    service = AnalysisService(_settings(tmp_path, diec=diec), die_scanner=scanner)
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id, use_die=True)

    assert result.ok and result.data is not None
    sources = {item["name"]: item["status"] for item in result.data["report"]["sources"]}
    assert sources["diec"] == "failed"
    assert any("Detect It Easy scan failed" in item for item in result.data["report"]["warnings"])


def test_detect_scan_warns_when_die_artifact_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service_with_upx_die(tmp_path)

    def boom(*args: object, **kwargs: object) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(service_detect_module, "_write_die_artifact", boom)
    result = service.detect_scan(session_id, use_die=True)

    assert result.ok and result.data is not None
    assert any(
        "could not persist bounded Detect It Easy artifact" in item
        for item in result.data["report"]["warnings"]
    )


def test_detect_scan_warns_when_exeinfope_artifact_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.detection.exeinfope import ExeinfopeScanResult

    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    exe = tmp_path / "Exeinfope.exe"
    exe.write_bytes(b"placeholder")

    def scanner(
        executable: Path, path: Path, *, log_path: Path, mode: ScanMode, timeout: float
    ) -> ExeinfopeScanResult:
        del executable, mode, timeout
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("sample - x64 UPX\n", encoding="utf-8")
        finding = DetectionFinding(
            id="exeinfope:0",
            category=FindingCategory.PACKER,
            name="UPX",
            summary="x64 UPX",
            confidence=0.55,
            source="exeinfope",
            evidence=(
                DetectionEvidence(
                    kind="exeinfope_log_line",
                    description="x64 UPX",
                    details={"raw_line": "sample - x64 UPX"},
                ),
            ),
        )
        return ExeinfopeScanResult(
            path=path,
            size=path.stat().st_size,
            mode=ScanMode.NORMAL,
            findings=(finding,),
            source=DetectionSource(
                name="exeinfope", status="completed", summary="fake", artifact=str(log_path)
            ),
            raw_log="sample - x64 UPX\n",
            log_path=log_path,
            stdout="",
            stderr="",
            returncode=0,
            scanned_at=datetime.now(UTC),
            claims_universal_unpack=False,
        )

    service = AnalysisService(_settings(tmp_path, exeinfope=exe), exeinfope_scanner=scanner)
    session_id = _session_id(service.create_session(str(binary)))

    def boom(*args: object, **kwargs: object) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(service_detect_module, "_write_exeinfope_artifact", boom)
    result = service.detect_scan(session_id, use_die=False, use_exeinfope=True)

    assert result.ok and result.data is not None
    assert any(
        "could not persist bounded Exeinfo PE artifact" in item
        for item in result.data["report"]["warnings"]
    )


def test_detect_scan_warns_when_artifact_registration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.core import service_ext

    service, session_id = _service_with_upx_die(tmp_path)
    monkeypatch.setattr(
        service_ext,
        "_register_capture",
        lambda *a, **k: {"artifact_error": "ledger full"},
    )

    result = service.detect_scan(session_id, use_die=True)

    assert result.ok and result.data is not None
    assert any(
        "could not register the bounded diec artifact for collection" in item
        for item in result.data["report"]["warnings"]
    )


def test_detect_scan_wraps_pe_format_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id = _plain_service(tmp_path)

    def boom(*args: object, **kwargs: object) -> object:
        raise PeFormatError("corrupt optional header")

    monkeypatch.setattr(service_detect_module, "scan_pe", boom)
    result = service.detect_scan(session_id, use_die=False)

    assert not result.ok and result.error is not None


def test_detect_explain_rejects_blank_finding_id(tmp_path: Path) -> None:
    service, session_id = _plain_service(tmp_path)

    result = service.detect_explain(session_id, "   ")

    assert not result.ok and result.error is not None


def test_detect_explain_propagates_scan_failure(tmp_path: Path) -> None:
    service, session_id = _plain_service(tmp_path)

    result = service.detect_explain(session_id, "die:0:0", timeout=0)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_detect_explain_returns_finding_not_found(tmp_path: Path) -> None:
    service, session_id = _service_with_upx_die(tmp_path)

    result = service.detect_explain(session_id, "die:9:9")

    assert not result.ok and result.error is not None
    assert result.error.code == "finding_not_found"


@pytest.mark.parametrize(
    "data",
    [
        {"report": "not-a-dict"},
        {"report": {"findings": "not-a-list"}},
    ],
    ids=("report-not-dict", "findings-not-list"),
)
def test_detect_explain_rejects_malformed_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: JsonObject
) -> None:
    service, session_id = _plain_service(tmp_path)
    monkeypatch.setattr(
        service, "detect_scan", lambda *a, **k: Result[JsonObject](ok=True, data=data)
    )

    result = service.detect_explain(session_id, "die:0:0")

    assert not result.ok and result.error is not None


@pytest.mark.parametrize(
    "data",
    [
        {"report": "not-a-dict"},
        {"report": {"findings": "not-a-list"}},
    ],
    ids=("report-not-dict", "findings-not-list"),
)
def test_packer_classify_rejects_malformed_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: JsonObject
) -> None:
    service, session_id = _plain_service(tmp_path)
    monkeypatch.setattr(
        service, "detect_scan", lambda *a, **k: Result[JsonObject](ok=True, data=data)
    )

    result = service.packer_classify(session_id)

    assert not result.ok and result.error is not None
