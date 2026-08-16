"""Hard assertions that unpack outputs stay under the session artifact tree."""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection import DetectionEvidence, DetectionFinding, FindingCategory
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


def test_upx_unpack_output_under_artifact_root(tmp_path: Path) -> None:
    binary = tmp_path / "packed.exe"
    _write_pe(binary)
    # section name already .text; rely on fake DIE instead
    upx = tmp_path / "upx.exe"
    upx.write_bytes(b"placeholder")
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    artifact_root = (tmp_path / "artifacts").resolve()

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
            artifact_root=artifact_root,
            diec=diec,
            upx=upx,
        ),
        die_scanner=fake_die,
        upx_tester=fake_test,
        upx_unpacker=fake_unpack,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.unpack_upx_unpack(session_id)
    assert result.ok and result.data is not None
    output = Path(str(result.data["output_path"])).resolve()
    assert artifact_root in output.parents or output.parent == artifact_root
    assert (artifact_root / "unpack" / session_id) in output.parents or output.parent == (
        artifact_root / "unpack" / session_id
    )
    assert result.data.get("artifact_id")
    listed = service.artifacts_list(session_id)
    assert listed.ok and listed.data is not None
    assert listed.data["total"] == 1
    assert listed.data["artifacts"][0]["kind"] == "upx_unpacked"
    read = service.artifacts_read(str(result.data["artifact_id"]), offset=0, limit=2)
    assert read.ok and read.data is not None
    assert read.data["data"].startswith("4d5a")
