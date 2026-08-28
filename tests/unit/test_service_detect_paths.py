"""Guard, error-arm, and recommend coverage for DetectAnalysisMixin.

detect.scan's happy paths are covered elsewhere; this file drives the branches
that need a scanner or a broken artifact write: the boolean argument guards,
the DIE-failure and DIE/Exeinfo artifact-write (OSError) arms, the artifact
registration warning helper, detect.explain / packer.classify validation and
lookup arms, and the unpack.recommend body (happy path, non-list candidates,
and the failure handler). Scanners and artifact writers are stubbed so nothing
external runs.
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_detect
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.detection.exeinfope import ExeinfopeScanError
from headless_re_mcp.detection.models import DetectionSource

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
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


def _service(
    tmp_path: Path,
    *,
    diec: Path | None = None,
    exeinfope: Path | None = None,
) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
        exeinfope=exeinfope,
    )
    return AnalysisService(settings)


def _session(service: AnalysisService, tmp_path: Path, name: str = "sample.exe") -> str:
    binary = tmp_path / name
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _die_result() -> SimpleNamespace:
    return SimpleNamespace(
        findings=(),
        source=DetectionSource(name="diec", status="ok", summary="stub"),
    )


def _exeinfo_result() -> SimpleNamespace:
    return SimpleNamespace(
        findings=(),
        source=DetectionSource(name="exeinfope", status="ok", summary="stub"),
    )


# --------------------------------------------------------------------------- #
# detect.scan argument guards
# --------------------------------------------------------------------------- #
def test_detect_scan_rejects_non_bool_use_die(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_scan(session_id, use_die="yes")  # type: ignore[arg-type]
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_detect_scan_rejects_non_bool_use_exeinfope(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_scan(session_id, use_exeinfope="yes")  # type: ignore[arg-type]
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# detect.scan DIE / Exeinfo failure and artifact arms
# --------------------------------------------------------------------------- #
def test_detect_scan_records_die_failure_as_warning(tmp_path: Path) -> None:
    service = _service(tmp_path, diec=tmp_path / "diec")

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise DieScanError("die_failed", "diec exploded")

    service._die_scanner = _boom
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_scan(session_id)
        assert result.ok and result.data is not None
        sources = result.data["report"]["sources"]
        assert any(s["name"] == "diec" and s["status"] == "failed" for s in sources)
    finally:
        service.close_all()


def test_detect_scan_warns_when_die_artifact_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, diec=tmp_path / "diec")
    service._die_scanner = lambda *a, **k: _die_result()  # type: ignore[assignment]

    def _raise(*_a: Any, **_k: Any) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(service_detect, "_write_die_artifact", _raise)
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_scan(session_id)
        assert result.ok and result.data is not None
        warnings = result.data["report"]["warnings"]
        assert any("Detect It Easy artifact" in w for w in warnings)
    finally:
        service.close_all()


def test_detect_scan_warns_when_exeinfope_artifact_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, exeinfope=tmp_path / "exeinfope")
    service._exeinfope_scanner = lambda *a, **k: _exeinfo_result()  # type: ignore[assignment]

    def _raise(*_a: Any, **_k: Any) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(service_detect, "_write_exeinfope_artifact", _raise)
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_scan(session_id, use_exeinfope=True)
        assert result.ok and result.data is not None
        warnings = result.data["report"]["warnings"]
        assert any("Exeinfo PE artifact" in w for w in warnings)
    finally:
        service.close_all()


def test_detect_scan_reports_exeinfope_failure_as_warning(tmp_path: Path) -> None:
    service = _service(tmp_path, exeinfope=tmp_path / "exeinfope")

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise ExeinfopeScanError("exeinfope_failed", "peid exploded")

    service._exeinfope_scanner = _boom
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_scan(session_id, use_exeinfope=True)
        assert result.ok and result.data is not None
        sources = result.data["report"]["sources"]
        assert any(s["name"] == "exeinfope" and s["status"] == "failed" for s in sources)
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# _register_detection_artifact warning helper
# --------------------------------------------------------------------------- #
def test_register_detection_artifact_returns_warning_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext._register_capture",
        lambda *a, **k: {"artifact_error": "registry offline"},
    )
    warnings = service_detect._register_detection_artifact(
        object(), "sid", "/tmp/x", kind="detection_die", tool="diec"
    )
    assert warnings == [
        "could not register the bounded diec artifact for collection: registry offline"
    ]


def test_register_detection_artifact_silent_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext._register_capture",
        lambda *a, **k: {},
    )
    assert (
        service_detect._register_detection_artifact(
            object(), "sid", "/tmp/x", kind="detection_die", tool="diec"
        )
        == []
    )


# --------------------------------------------------------------------------- #
# detect.explain
# --------------------------------------------------------------------------- #
def test_detect_explain_rejects_blank_finding_id(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_explain(session_id, "   ")
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_detect_explain_flags_invalid_report(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.detect_scan = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True, data={"report": "not-a-dict"}, error=None
        )
        result = service.detect_explain(session_id, "some.id")
        assert result.ok is False
    finally:
        service.close_all()


def test_detect_explain_flags_invalid_findings_list(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.detect_scan = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True, data={"report": {"findings": "nope"}}, error=None
        )
        result = service.detect_explain(session_id, "some.id")
        assert result.ok is False
    finally:
        service.close_all()


def test_detect_explain_reports_unknown_finding(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.detect_explain(session_id, "no-such-finding")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "finding_not_found"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# packer.classify invalid-report arms
# --------------------------------------------------------------------------- #
def test_packer_classify_flags_invalid_report(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.detect_scan = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True, data={"report": "not-a-dict"}, error=None
        )
        result = service.packer_classify(session_id)
        assert result.ok is False
    finally:
        service.close_all()


def test_packer_classify_flags_invalid_findings_list(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.detect_scan = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True, data={"report": {"findings": "nope"}}, error=None
        )
        result = service.packer_classify(session_id)
        assert result.ok is False
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# unpack.recommend
# --------------------------------------------------------------------------- #
def test_unpack_recommend_returns_non_authoritative_route(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.unpack_recommend(session_id)
        assert result.ok and result.data is not None
        assert result.data["authoritative"] is False
        assert "recommendation" in result.data
    finally:
        service.close_all()


def test_unpack_recommend_tolerates_non_list_candidates(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.packer_classify = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True, data={"candidates": "not-a-list"}, error=None
        )
        result = service.unpack_recommend(session_id)
        assert result.ok and result.data is not None
        assert result.data["candidates"] == []
    finally:
        service.close_all()


def test_unpack_recommend_wraps_unexpected_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.packer_classify = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True, data={"candidates": []}, error=None
        )

        def _raise(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("scan exploded")

        monkeypatch.setattr(service_detect, "scan_pe", _raise)
        result = service.unpack_recommend(session_id)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()
