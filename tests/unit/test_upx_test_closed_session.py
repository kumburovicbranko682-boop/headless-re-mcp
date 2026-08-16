from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.upx import UpxOperation, UpxResult


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset:pe_offset + 4] = b"PE\0\0"
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
    image[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _service(tmp_path: Path, tester: Any) -> AnalysisService:
    upx = tmp_path / "upx.exe"
    upx.write_bytes(b"fake-upx")
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            upx=upx,
        ),
        upx_tester=tester,
    )


def _result(upx: Path, path: Path, input_sha256: str) -> UpxResult:
    return UpxResult(
        operation=UpxOperation.TEST,
        executable=upx,
        input_path=path,
        input_sha256=input_sha256,
        input_size=path.stat().st_size,
        ok=True,
        stdout="tested",
        stderr="",
        returncode=0,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )


def test_unpack_upx_test_on_a_closed_session_does_not_start_upx(tmp_path: Path) -> None:
    runs: list[Path] = []
    upx = tmp_path / "upx.exe"

    def tester(
        executable: Path,
        path: Path,
        *,
        input_sha256: str,
        timeout: float,
    ) -> UpxResult:
        del executable, timeout
        runs.append(path)
        return _result(upx, path, input_sha256)

    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, tester)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        result = service.unpack_upx_test(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert runs == []
    finally:
        service.close_all()


def test_unpack_upx_test_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service_box: dict[str, Any] = {}
    upx = tmp_path / "upx.exe"

    def tester(
        executable: Path,
        path: Path,
        *,
        input_sha256: str,
        timeout: float,
    ) -> UpxResult:
        del executable, timeout
        service_box["service"].close_session(service_box["session_id"])
        return _result(upx, path, input_sha256)

    service = _service(tmp_path, tester)
    service_box["service"] = service
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        service_box["session_id"] = session_id
        result = service.unpack_upx_test(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()