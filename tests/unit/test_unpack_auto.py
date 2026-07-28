from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection import (
    DetectionEvidence,
    DetectionFinding,
    FindingCategory,
)
from headless_re_mcp.detection.die import DieScanResult
from headless_re_mcp.detection.models import DetectionSource, ScanMode
from headless_re_mcp.unpack.upx import UpxOperation, UpxResult


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


def _write_upx_like_pe(path: Path, *, truncate: bool = False) -> None:
    """PE with UPX0/UPX1 names (structural hint) but not a real UPX payload."""
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    # Two sections: UPX0 + UPX1
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 2, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x2000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b"UPX0\0\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0, 0)
    struct.pack_into("<I", image, section + 36, 0xE0000080)
    section2 = section + 40
    image[section2 : section2 + 8] = b"UPX1\0\0\0\0"
    struct.pack_into("<IIII", image, section2 + 8, 0x200, 0x2000, 0x200, 0x200)
    struct.pack_into("<I", image, section2 + 36, 0xE0000060)
    image[0x200:0x202] = b"\xC3\x90"
    # Modified/corrupt stub marker so this is clearly not official UPX.
    image[0x210:0x218] = b"NOTUPX!!"
    data = bytes(image)
    if truncate:
        # Keep PE headers/sections parseable; truncate a fake UPX trailer overlay.
        data = data + b"UPX!\x00" + b"\xff" * 96
        data = data[: len(bytes(image)) + 20]
    path.write_bytes(data)


def _settings(tmp_path: Path, *, upx: Path | None = None) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=upx,
    )


def _session_id(result: object) -> str:
    data = result.data
    assert isinstance(data, dict)
    return str(data["session"]["id"])


def test_unpack_auto_routes_non_upx_without_claiming_success(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    result = service.unpack_auto(session_id, use_die=False)

    assert result.ok and result.data is not None
    assert result.data["status"] == "not_upx"
    assert result.data["claims_universal_unpack"] is False
    assert result.data["recommendation"]["authoritative"] is False
    assert result.data["unpack"]["phase"] == "detected"


def test_unpack_auto_unpacks_when_die_reports_upx(tmp_path: Path) -> None:
    binary = tmp_path / "packed.exe"
    _write_pe(binary)
    upx = tmp_path / "upx.exe"
    upx.write_bytes(b"placeholder")
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")

    def fake_die(executable: Path, path: Path, *, mode: ScanMode, timeout: float) -> DieScanResult:
        del executable, mode, timeout
        finding = DetectionFinding(
            id="die:0:0",
            category=FindingCategory.PACKER,
            name="UPX",
            summary="Packer: UPX",
            confidence=1.0,
            source="diec",
            evidence=(
                DetectionEvidence(kind="die_signature", description="Packer: UPX", details={}),
            ),
        )
        return DieScanResult(
            path=path,
            size=path.stat().st_size,
            mode=ScanMode.NORMAL,
            findings=(finding,),
            source=DetectionSource(name="diec", status="completed", version="3.21"),
            raw={"detects": []},
            raw_json="{}",
            stdout="{}",
            stderr="",
            returncode=0,
            scanned_at=datetime.now(UTC),
        )

    def fake_test(executable: Path, path: Path, *, input_sha256: str, timeout: float) -> UpxResult:
        del executable, timeout
        return UpxResult(
            operation=UpxOperation.TEST,
            executable=upx,
            input_path=path,
            input_sha256=input_sha256,
            input_size=path.stat().st_size,
            version="5.2.0",
            ok=True,
            stdout="test ok",
            stderr="",
            returncode=0,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )

    def fake_unpack(
        executable: Path,
        path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float,
    ) -> UpxResult:
        del executable, timeout
        _write_pe(output_path)
        from headless_re_mcp.core.session import file_sha256

        return UpxResult(
            operation=UpxOperation.UNPACK,
            executable=upx,
            input_path=path,
            input_sha256=input_sha256,
            input_size=path.stat().st_size,
            output_path=output_path,
            output_sha256=file_sha256(output_path),
            output_size=output_path.stat().st_size,
            version="5.2.0",
            ok=True,
            stdout="unpacked",
            stderr="",
            returncode=0,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            diec=diec,
            upx=upx,
        ),
        die_scanner=fake_die,
        upx_tester=fake_test,
        upx_unpacker=fake_unpack,
    )
    session_id = _session_id(service.create_session(str(binary)))
    before = binary.read_bytes()

    result = service.unpack_auto(session_id)

    assert result.ok and result.data is not None
    assert result.data["status"] == "unpacked"
    assert result.data["unpack"]["input_unchanged"] is True
    assert binary.read_bytes() == before


def test_unpack_auto_modified_upx_like_does_not_claim_success(tmp_path: Path) -> None:
    """UPX0/UPX1 section names alone must not yield claimed unpack success."""
    from headless_re_mcp.unpack.upx import UpxErrorCode, UpxProcessError

    binary = tmp_path / "modified-upx.exe"
    _write_upx_like_pe(binary)
    upx = tmp_path / "upx.exe"
    upx.write_bytes(b"fake-upx")

    def failing_test(
        executable: Path, path: Path, *, input_sha256: str, timeout: float
    ) -> UpxResult:
        del executable, timeout
        raise UpxProcessError(
            UpxErrorCode.PROCESS_FAILED,
            "not packed by UPX (modified stub)",
            details={"path": str(path), "input_sha256": input_sha256},
            stderr="NotPackedException",
            returncode=1,
        )

    service = AnalysisService(
        _settings(tmp_path, upx=upx),
        upx_tester=failing_test,
    )
    session_id = _session_id(service.create_session(str(binary)))
    before = binary.read_bytes()

    tested = service.unpack_upx_test(session_id)
    assert tested.ok is False
    assert tested.error is not None
    assert tested.error.code == UpxErrorCode.PROCESS_FAILED

    auto = service.unpack_auto(session_id, use_die=False)
    assert auto.ok is False
    assert auto.error is not None
    details = auto.error.details or {}
    assert details.get("claims_universal_unpack") is False
    assert details.get("status") != "unpacked"
    assert details.get("status") in {"upx_test_failed", "upx_failed", "process_failed"} or (
        "upx" in str(details.get("status", "")).lower()
        or "fail" in str(auto.error.code).lower()
    )
    assert binary.read_bytes() == before


def test_unpack_auto_truncated_upx_like_does_not_claim_success(tmp_path: Path) -> None:
    """Truncated UPX-like PE must not claim unpack success via unpack.auto."""
    from headless_re_mcp.unpack.upx import UpxErrorCode, UpxProcessError

    binary = tmp_path / "truncated-upx.exe"
    _write_upx_like_pe(binary, truncate=True)
    upx = tmp_path / "upx.exe"
    upx.write_bytes(b"fake-upx")

    def failing_test(
        executable: Path, path: Path, *, input_sha256: str, timeout: float
    ) -> UpxResult:
        del executable, timeout
        raise UpxProcessError(
            UpxErrorCode.PROCESS_FAILED,
            "truncated / not a valid UPX file",
            details={"path": str(path), "input_sha256": input_sha256},
            returncode=1,
        )

    service = AnalysisService(
        _settings(tmp_path, upx=upx),
        upx_tester=failing_test,
    )
    session_id = _session_id(service.create_session(str(binary)))

    auto = service.unpack_auto(session_id, use_die=False)
    assert auto.ok is False
    assert auto.error is not None
    details = auto.error.details or {}
    assert details.get("claims_universal_unpack") is False
    assert details.get("status") != "unpacked"
    assert details.get("status") == "upx_test_failed" or "fail" in str(auto.error.code).lower()
