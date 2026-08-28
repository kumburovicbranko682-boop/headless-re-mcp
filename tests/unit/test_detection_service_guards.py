"""Guard-path cover for the detection service orchestration.

``service_detect`` merges a bounded built-in PE scan with optional external
Detect It Easy / Exeinfo PE second opinions. The happy merges are tested; what
was not is the fail-safe wiring that keeps a second opinion from ever sinking
the verdict: a scanner that raises, an artifact that will not persist, a
bookkeeping registration that fails, a session that closes mid-scan, and the
argument/report guards on the thin ``detect_explain`` / ``packer_classify`` /
``unpack_recommend`` wrappers. Each of these must degrade to a warning or a
structured error, never a dropped built-in finding or an unhandled exception.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_detect as service_detect
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError, SessionState
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_detect import DetectAnalysisMixin
from headless_re_mcp.detection import (
    DetectionEvidence,
    DetectionFinding,
    DetectionSource,
    FindingCategory,
    PeFormatError,
    ScanMode,
)
from headless_re_mcp.detection.die import DieScanError, DieScanResult
from headless_re_mcp.detection.exeinfope import ExeinfopeScanResult


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


def _session_id(result: Any) -> str:
    data = result.data
    assert isinstance(data, dict)
    return str(data["session"]["id"])


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
                kind="die_signature", description="Packer: UPX", details={"type": "Packer"}
            ),
        ),
    )
    return DieScanResult(
        path=path,
        size=path.stat().st_size,
        mode=ScanMode.NORMAL,
        findings=(finding,),
        source=DetectionSource(name="diec", status="completed", version="3.21", summary="fake"),
        raw={"detects": []},
        raw_json='{"detects": []}',
        stdout='{"detects": []}',
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def _exeinfo_result(path: Path, log_path: Path) -> ExeinfopeScanResult:
    finding = DetectionFinding(
        id="exeinfope:0",
        category=FindingCategory.PACKER,
        name="UPX",
        summary="x64 UPX",
        confidence=0.55,
        source="exeinfope",
        evidence=(
            DetectionEvidence(
                kind="exeinfope_log_line", description="x64 UPX", details={"raw_line": "x64 UPX"}
            ),
        ),
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("sample.exe - x64 UPX\n", encoding="utf-8")
    return ExeinfopeScanResult(
        path=path,
        size=path.stat().st_size,
        mode=ScanMode.NORMAL,
        findings=(finding,),
        source=DetectionSource(
            name="exeinfope", status="completed", summary="fake", artifact=str(log_path)
        ),
        raw_log="sample.exe - x64 UPX\n",
        log_path=log_path,
        stdout="",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
        claims_universal_unpack=False,
    )


def _service_with_die(tmp_path: Path, scanner: Any) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = AnalysisService(_settings(tmp_path, diec=diec), die_scanner=scanner)
    session_id = _session_id(service.create_session(str(binary)))
    return service, session_id


# ---- argument guards -----------------------------------------------------------


@pytest.mark.parametrize("kwargs", [{"use_die": 1}, {"use_exeinfope": 1}])
def test_non_boolean_scanner_toggles_are_rejected(tmp_path: Path, kwargs: dict[str, Any]) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    # Pass a bool for whichever toggle is not under test so only one guard fires.
    call = {"use_die": False, "use_exeinfope": False, **kwargs}
    result = service.detect_scan(session_id, **call)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert "must be a boolean" in result.error.message


# ---- second-opinion fail-safe --------------------------------------------------


def test_die_scan_failure_degrades_to_a_warning_keeping_builtin_findings(
    tmp_path: Path,
) -> None:
    def scanner(executable: Path, path: Path, *, mode: ScanMode, timeout: float) -> DieScanResult:
        raise DieScanError("timeout", "diec wedged")

    service, session_id = _service_with_die(tmp_path, scanner)
    result = service.detect_scan(session_id, use_die=True)

    assert result.ok and result.data is not None
    sources = {item["name"]: item["status"] for item in result.data["report"]["sources"]}
    assert sources["diec"] == "failed"
    assert any("Detect It Easy scan failed" in w for w in result.data["report"]["warnings"])


def test_die_artifact_write_failure_is_a_warning_not_a_lost_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def scanner(executable: Path, path: Path, *, mode: ScanMode, timeout: float) -> DieScanResult:
        return _die_result(path)

    def boom(*_args: Any, **_kwargs: Any) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(service_detect, "_write_die_artifact", boom)
    service, session_id = _service_with_die(tmp_path, scanner)
    result = service.detect_scan(session_id, use_die=True)

    assert result.ok and result.data is not None
    report = result.data["report"]
    assert any(f["id"] == "die:0:0" for f in report["findings"])  # finding kept
    assert any("could not persist bounded Detect It Easy artifact" in w for w in report["warnings"])


def test_die_artifact_registration_failure_is_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def scanner(executable: Path, path: Path, *, mode: ScanMode, timeout: float) -> DieScanResult:
        return _die_result(path)

    # The artifact writes fine, but collection bookkeeping refuses it: the scan
    # must still succeed, carrying the failure out as a warning.
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext._register_capture",
        lambda *a, **k: {"artifact_error": "store offline"},
    )
    service, session_id = _service_with_die(tmp_path, scanner)
    result = service.detect_scan(session_id, use_die=True)

    assert result.ok and result.data is not None
    assert any(
        "could not register the bounded diec artifact" in w
        for w in result.data["report"]["warnings"]
    )


def test_exeinfope_artifact_write_failure_is_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    exe = tmp_path / "Exeinfope.exe"
    exe.write_bytes(b"placeholder")

    def scanner(
        executable: Path, path: Path, *, log_path: Path, mode: ScanMode, timeout: float
    ) -> ExeinfopeScanResult:
        return _exeinfo_result(path, log_path)

    def boom(*_args: Any, **_kwargs: Any) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(service_detect, "_write_exeinfope_artifact", boom)
    service = AnalysisService(_settings(tmp_path, exeinfope=exe), exeinfope_scanner=scanner)
    session_id = _session_id(service.create_session(str(binary)))
    result = service.detect_scan(session_id, use_die=False, use_exeinfope=True)

    assert result.ok and result.data is not None
    report = result.data["report"]
    assert any(f["id"] == "exeinfope:0" for f in report["findings"])
    assert any("could not persist bounded Exeinfo PE artifact" in w for w in report["warnings"])


def test_a_session_closing_mid_scan_is_refused_after_the_scan(tmp_path: Path) -> None:
    holder: dict[str, str] = {}

    def scanner(executable: Path, path: Path, *, mode: ScanMode, timeout: float) -> DieScanResult:
        # Simulate the debuggee/session being torn down while the external
        # scanner ran; the post-scan state re-check must catch it.
        service.registry.transition(holder["sid"], SessionState.FAILED)
        return _die_result(path)

    service, session_id = _service_with_die(tmp_path, scanner)
    holder["sid"] = session_id
    result = service.detect_scan(session_id, use_die=True)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert "cannot run in failed state" in result.error.message


# ---- detect_explain guards -----------------------------------------------------


def test_detect_explain_rejects_a_blank_finding_id(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_explain(session_id, "   ")
    assert not result.ok and result.error is not None
    assert "finding_id must not be blank" in result.error.message


def test_detect_explain_reports_a_finding_that_is_not_present(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_explain(session_id, "no-such-finding:9", use_die=False)
    assert not result.ok and result.error is not None
    assert result.error.code == "finding_not_found"


# ---- malformed-report guards on the thin wrappers ------------------------------


class _StubScan(DetectAnalysisMixin):
    """A mixin instance whose detect_scan returns a caller-supplied envelope,
    so the wrappers' report/findings shape guards can be exercised directly."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def detect_scan(self, *_args: Any, **_kwargs: Any) -> Result[dict[str, Any]]:
        return Result[dict[str, Any]](ok=True, data=self._data)


def test_detect_explain_flags_a_non_dict_report() -> None:
    result = _StubScan({"report": 123}).detect_explain("s", "die:0:0")
    assert not result.ok and result.error is not None
    assert "invalid report" in result.error.message


def test_detect_explain_flags_a_non_list_findings() -> None:
    result = _StubScan({"report": {"findings": "not-a-list"}}).detect_explain("s", "die:0:0")
    assert not result.ok and result.error is not None
    assert "invalid findings list" in result.error.message


def test_packer_classify_flags_a_non_dict_report() -> None:
    result = _StubScan({"report": 123}).packer_classify("s")
    assert not result.ok and result.error is not None
    assert "invalid report" in result.error.message


def test_packer_classify_flags_a_non_list_findings() -> None:
    result = _StubScan({"report": {"findings": 5}}).packer_classify("s")
    assert not result.ok and result.error is not None
    assert "invalid findings list" in result.error.message


# ---- unpack_recommend non-authoritative route ----------------------------------


def test_unpack_recommend_returns_a_non_authoritative_route(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.unpack_recommend(session_id, use_die=False)
    assert result.ok and result.data is not None
    assert result.data["authoritative"] is False
    assert "recommendation" in result.data
    assert isinstance(result.data["candidates"], list)
    assert result.data["pe_vm_like"] in {True, False}


def test_unpack_recommend_accepts_a_forced_route(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.unpack_recommend(session_id, use_die=False, force_route="upx")
    assert result.ok and result.data is not None
    assert result.data["force_route"] == "upx"


# ---- failure propagation through the wrappers ----------------------------------


class _FailingScan(DetectAnalysisMixin):
    """detect_scan / packer_classify that fail, to prove the wrappers relay a
    failed envelope untouched rather than dereferencing a missing report."""

    def detect_scan(self, *_args: Any, **_kwargs: Any) -> Result[dict[str, Any]]:
        return Result[dict[str, Any]](ok=False, error=RpcError(code="boom", message="scan failed"))

    def packer_classify(self, *_args: Any, **_kwargs: Any) -> Result[dict[str, Any]]:
        return Result[dict[str, Any]](
            ok=False, error=RpcError(code="boom", message="classify failed")
        )


def test_detect_explain_relays_a_failed_scan() -> None:
    result = _FailingScan().detect_explain("s", "die:0:0")
    assert not result.ok and result.error is not None
    assert result.error.code == "boom"


def test_unpack_recommend_relays_a_failed_classification() -> None:
    result = _FailingScan().unpack_recommend("s")
    assert not result.ok and result.error is not None
    assert result.error.code == "boom"


def test_a_malformed_pe_becomes_a_structured_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """scan_pe raising PeFormatError must surface as a detection failure, not
    an unhandled exception out of the service."""
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    def raise_pe(*_args: Any, **_kwargs: Any) -> Any:
        raise PeFormatError("not a PE we can read")

    monkeypatch.setattr(service_detect, "scan_pe", raise_pe)
    result = service.detect_scan(session_id, use_die=False)
    assert not result.ok and result.error is not None
