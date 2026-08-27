"""``unpack.start``'s whole-run budget must not be replayed as a CLI timeout.

The tool's ``timeout`` (schema allows up to 600s) is the orchestration budget:
``create_unpack_session`` stores it as ``timeout_seconds`` and ``check_timeout``
enforces it across the multi-call workflow. But ``_run_upx_orchestration``
handed that same raw value to ``unpack_upx_test`` / ``unpack_upx_unpack``, whose
``_detection_timeout`` gate refuses anything over ``MAX_WORKFLOW_TIMEOUT``
(300s). An in-schema ``unpack.start(timeout=400)`` on the UPX route -- the
primary happy path for packed samples -- therefore failed the whole run with a
misleading ``upx_test_failed`` before UPX ever started, while the plan leg in
the very same function already received ``min(timeout, 60)``. These pin that
each CLI leg now gets at most the gate's ceiling while the session keeps the
full budget.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
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


def _upx_finding() -> DetectionFinding:
    return DetectionFinding(
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


def test_unpack_start_600s_budget_still_runs_upx_legs_within_the_cli_gate(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "packed.exe"
    _write_pe(binary)
    upx = tmp_path / "upx.exe"
    upx.write_bytes(b"placeholder")
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    cli_timeouts: dict[str, float] = {}

    def fake_die(
        executable: Path, path: Path, *, mode: ScanMode, timeout: float
    ) -> DieScanResult:
        del executable, mode, timeout
        return DieScanResult(
            path=path,
            size=path.stat().st_size,
            mode=ScanMode.NORMAL,
            findings=(_upx_finding(),),
            source=DetectionSource(name="diec", status="completed", version="3.21"),
            raw={"detects": []},
            raw_json="{}",
            stdout="{}",
            stderr="",
            returncode=0,
            scanned_at=datetime.now(UTC),
        )

    def fake_test(
        executable: Path, path: Path, *, input_sha256: str, timeout: float
    ) -> UpxResult:
        del executable
        cli_timeouts["test"] = timeout
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
        del executable
        cli_timeouts["unpack"] = timeout
        _write_pe(output_path)
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
    data = service.create_session(str(binary)).data
    assert isinstance(data, dict)
    session_id = str(data["session"]["id"])

    result = service.unpack_start(session_id, timeout=600.0)

    assert result.ok and result.data is not None
    unpack = result.data["unpack"]
    assert isinstance(unpack, dict)
    # Before the clamp this "succeeded" with phase=failed / upx_test_failed:
    # the CLI leg's _detection_timeout gate rejected the in-schema 600.
    assert unpack["failure"] is None
    assert unpack["phase"] == "verified"
    # The session keeps the full orchestration budget the caller asked for...
    assert unpack["timeout_seconds"] == 600.0
    # ...while each UPX CLI leg received a slice its gate accepts.
    assert cli_timeouts["test"] == MAX_WORKFLOW_TIMEOUT == 300.0
    assert cli_timeouts["unpack"] == MAX_WORKFLOW_TIMEOUT


def test_unpack_start_small_timeout_reaches_the_cli_legs_unclamped(
    tmp_path: Path,
) -> None:
    """A budget under the gate must pass through untouched, not get widened."""
    binary = tmp_path / "packed.exe"
    _write_pe(binary)
    upx = tmp_path / "upx.exe"
    upx.write_bytes(b"placeholder")
    cli_timeouts: dict[str, float] = {}

    def fake_test(
        executable: Path, path: Path, *, input_sha256: str, timeout: float
    ) -> UpxResult:
        del executable
        cli_timeouts["test"] = timeout
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
        del executable
        cli_timeouts["unpack"] = timeout
        _write_pe(output_path)
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
            upx=upx,
        ),
        upx_tester=fake_test,
        upx_unpacker=fake_unpack,
    )
    data = service.create_session(str(binary)).data
    assert isinstance(data, dict)
    session_id = str(data["session"]["id"])

    result = service.unpack_start(
        session_id, use_die=False, timeout=90.0, force_route="upx"
    )

    assert result.ok and result.data is not None
    unpack = result.data["unpack"]
    assert isinstance(unpack, dict)
    assert unpack["failure"] is None
    assert unpack["phase"] == "verified"
    assert unpack["timeout_seconds"] == 90.0
    assert cli_timeouts == {"test": 90.0, "unpack": 90.0}
