from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection import (
    DetectionEvidence,
    DetectionFinding,
    DetectionSource,
    FindingCategory,
    ScanMode,
)
from headless_re_mcp.detection.exeinfope import ExeinfopeScanError, ExeinfopeScanResult


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


def _settings(tmp_path: Path, exeinfope: Path | None = None) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        exeinfope=exeinfope,
    )


def _session_id(result: object) -> str:
    data = result.data
    assert isinstance(data, dict)
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _exeinfo_result(path: Path, log_path: Path) -> ExeinfopeScanResult:
    finding = DetectionFinding(
        id="exeinfope:0",
        category=FindingCategory.PACKER,
        name="UPX",
        summary="x64 UPX v3.9 - 5.0",
        confidence=0.55,
        source="exeinfope",
        evidence=(
            DetectionEvidence(
                kind="exeinfope_log_line",
                description="x64 UPX v3.9 - 5.0",
                details={"raw_line": "sample - x64 UPX", "parser": "best_effort"},
            ),
        ),
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("sample.exe -  x64 UPX v3.9 - 5.0\n", encoding="utf-8")
    return ExeinfopeScanResult(
        path=path,
        size=path.stat().st_size,
        mode=ScanMode.NORMAL,
        findings=(finding,),
        source=DetectionSource(
            name="exeinfope",
            status="completed",
            summary="fake exeinfope",
            artifact=str(log_path),
        ),
        raw_log="sample.exe -  x64 UPX v3.9 - 5.0\n",
        log_path=log_path,
        stdout="",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
        claims_universal_unpack=False,
    )


def test_detect_scan_defaults_exeinfope_disabled(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id, use_die=False)

    assert result.ok and result.data is not None
    assert result.data["exeinfope_enabled"] is False
    assert result.data["claims_universal_unpack"] is False
    sources = {item["name"]: item["status"] for item in result.data["report"]["sources"]}
    assert sources["exeinfope"] == "disabled"


def test_detect_scan_exeinfope_unavailable_when_unconfigured(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id, use_die=False, use_exeinfope=True)

    assert result.ok and result.data is not None
    sources = {item["name"]: item["status"] for item in result.data["report"]["sources"]}
    assert sources["exeinfope"] == "unavailable"
    assert any("Exeinfo PE is unavailable" in item for item in result.data["report"]["warnings"])


def test_detect_scan_merges_exeinfope_alongside_builtin(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    exe = tmp_path / "Exeinfope.exe"
    exe.write_bytes(b"placeholder")

    def scanner(executable: Path, path: Path, *, log_path: Path, mode: ScanMode, timeout: float):
        del executable, mode, timeout
        return _exeinfo_result(path, log_path)

    service = AnalysisService(
        _settings(tmp_path, exe),
        exeinfope_scanner=scanner,
    )
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id, use_die=False, use_exeinfope=True)

    assert result.ok and result.data is not None
    report = result.data["report"]
    assert any(item["id"] == "exeinfope:0" for item in report["findings"])
    source = next(item for item in report["sources"] if item["name"] == "exeinfope")
    assert source["status"] == "completed"
    assert Path(source["artifact"]).is_file()
    assert result.data["claims_universal_unpack"] is False


def test_detect_scan_exeinfope_failure_does_not_drop_builtin(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    exe = tmp_path / "Exeinfope.exe"
    exe.write_bytes(b"placeholder")

    def scanner(*args: object, **kwargs: object) -> ExeinfopeScanResult:
        del args, kwargs
        raise ExeinfopeScanError("timeout", "boom")

    service = AnalysisService(
        _settings(tmp_path, exe),
        exeinfope_scanner=scanner,
    )
    session_id = _session_id(service.create_session(str(binary)))

    result = service.detect_scan(session_id, use_die=False, use_exeinfope=True)

    assert result.ok and result.data is not None
    sources = {item["name"]: item["status"] for item in result.data["report"]["sources"]}
    assert sources["exeinfope"] == "failed"
    assert any(item["status"] == "completed" for item in result.data["report"]["sources"])
    assert result.data["report"]["findings"]  # builtin findings remain
