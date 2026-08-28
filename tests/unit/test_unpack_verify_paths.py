"""Branch coverage for UnpackMixin.unpack_verify.

unpack.verify re-parses a rebuilt PE and layers optional DIE rescans, an IDA
reopen/compare, and a live UI window gate on top. Those optional arms only run
with a detector configured, IDA available, or a Windows debuggee, so they never
executed on a hosted platform. These tests drive a real AnalysisService with a
PE session and planted artifact, injecting a fake DIE scanner and faking the
Win32 window enumeration so every arm runs on Linux.
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection.die import DieScanError


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


def _pe_session(
    tmp_path: Path,
    *,
    diec: Path | None = None,
    die_scanner: Any | None = None,
) -> tuple[AnalysisService, str, Path]:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
    )
    service = AnalysisService(settings, die_scanner=die_scanner)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    planted = settings.artifact_root / "unpack" / session_id / "rebuilt.exe"
    planted.parent.mkdir(parents=True, exist_ok=True)
    _write_pe(planted)
    return service, session_id, planted


# --- DIE arms ---


def test_verify_reports_die_unavailable_when_not_configured(tmp_path: Path) -> None:
    service, session_id, planted = _pe_session(tmp_path)
    try:
        result = service.unpack_verify(session_id, str(planted), use_die=True)
        assert result.ok is True and result.data is not None
        assert result.data["die"]["status"] == "unavailable"
        assert "DIE not configured" in result.data["unfixed"]
    finally:
        service.close_all()


def test_verify_records_a_die_scan_failure(tmp_path: Path) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise DieScanError("die_failed", "detector fell over")

    service, session_id, planted = _pe_session(
        tmp_path, diec=tmp_path / "diec", die_scanner=_boom
    )
    try:
        result = service.unpack_verify(session_id, str(planted), use_die=True)
        assert result.ok is True and result.data is not None
        assert result.data["die"]["status"] == "failed"
        assert any("DIE rescan failed" in item for item in result.data["unfixed"])
    finally:
        service.close_all()


def test_verify_summarizes_die_findings(tmp_path: Path) -> None:
    findings = [
        SimpleNamespace(
            category=SimpleNamespace(value="packer"),
            name="UPX",
            summary="upx signature",
        ),
        SimpleNamespace(category="plain-category", name="Note", summary="an aside"),
    ]

    def _scan(*_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(
            source=SimpleNamespace(version="3.09"),
            findings=findings,
        )

    service, session_id, planted = _pe_session(
        tmp_path, diec=tmp_path / "diec", die_scanner=_scan
    )
    try:
        result = service.unpack_verify(session_id, str(planted), use_die=True)
        assert result.ok is True and result.data is not None
        die = result.data["die"]
        assert die["status"] == "completed"
        assert die["version"] == "3.09"
        assert die["finding_count"] == 2
        categories = [f["category"] for f in die["findings"]]
        assert categories == ["packer", "plain-category"]
    finally:
        service.close_all()


# --- open_ida arms ---


def test_verify_open_ida_reopens_the_rebuilt_pe(tmp_path: Path) -> None:
    service, session_id, planted = _pe_session(tmp_path)
    try:
        result = service.unpack_verify(
            session_id, str(planted), use_die=False, open_ida=True
        )
        assert result.ok is True and result.data is not None
        ida = result.data["ida"]
        assert isinstance(ida, dict)
        assert "session_id" in ida
        assert ida["static_open_ok"] is False  # no IDA configured
    finally:
        service.close_all()


def test_verify_open_ida_with_baseline_records_function_snapshots(tmp_path: Path) -> None:
    service, session_id, planted = _pe_session(tmp_path)
    try:
        result = service.unpack_verify(
            session_id,
            str(planted),
            use_die=False,
            open_ida=True,
            baseline_session_id=session_id,
        )
        assert result.ok is True and result.data is not None
        ida = result.data["ida"]
        assert "baseline_functions" in ida
        assert "rebuilt_functions" in ida
    finally:
        service.close_all()


def test_verify_open_ida_handles_a_failed_child_session(tmp_path: Path) -> None:
    service, session_id, planted = _pe_session(tmp_path)

    def _fail(*_args: Any, **_kwargs: Any) -> Result[dict[str, Any]]:
        return Result(ok=False, error=RpcError(code="boom", message="no child"))

    service.create_session = _fail  # type: ignore[method-assign]
    try:
        result = service.unpack_verify(
            session_id, str(planted), use_die=False, open_ida=True
        )
        assert result.ok is True and result.data is not None
        ida = result.data["ida"]
        assert ida["static_open_ok"] is False
        assert "IDA reopen failed" in result.data["unfixed"]
    finally:
        service.close_all()


# --- UI window gate arms ---


def test_verify_ui_gate_skipped_without_a_pid(tmp_path: Path) -> None:
    service, session_id, planted = _pe_session(tmp_path)
    try:
        result = service.unpack_verify(
            session_id,
            str(planted),
            use_die=False,
            expect_window_title="MainWindow",
            ui_pid=None,
        )
        assert result.ok is True and result.data is not None
        gate = result.data["ui_gate"]
        assert gate["status"] == "skipped_no_pid"
        assert "UI window gate skipped: no pid" in result.data["unfixed"]
    finally:
        service.close_all()


def test_verify_ui_gate_checks_windows_and_finds_no_match(tmp_path: Path) -> None:
    service, session_id, planted = _pe_session(tmp_path)
    try:
        # On Linux list_process_windows returns [] so the gate checks but never
        # matches, exercising the not-matched tail.
        result = service.unpack_verify(
            session_id,
            str(planted),
            use_die=False,
            expect_window_title="MainWindow",
            ui_pid=4321,
        )
        assert result.ok is True and result.data is not None
        gate = result.data["ui_gate"]
        assert gate["checked"] is True
        assert gate["status"] == "not_matched"
        assert gate["matched"] is False
        assert "UI window title/class gate not matched" in result.data["unfixed"]
    finally:
        service.close_all()


def test_verify_ui_gate_matches_a_window(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id, planted = _pe_session(tmp_path)
    monkeypatch.setattr(
        service_unpack,
        "list_process_windows",
        lambda _pid: [
            {"title": "Other", "class_name": "Aux", "hwnd": 1},
            {"title": "My Target App", "class_name": "MainWnd", "hwnd": 2},
        ],
    )
    try:
        result = service.unpack_verify(
            session_id,
            str(planted),
            use_die=False,
            expect_window_title="target app",
            expect_window_class="MainWnd",
            ui_pid=4321,
        )
        assert result.ok is True and result.data is not None
        gate = result.data["ui_gate"]
        assert gate["matched"] is True
        assert gate["status"] == "matched"
        assert gate["match"]["hwnd"] == 2
    finally:
        service.close_all()


def test_verify_ui_gate_reports_an_enumeration_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id, planted = _pe_session(tmp_path)

    def _boom(_pid: int) -> Any:
        raise RuntimeError("enum blew up")

    monkeypatch.setattr(service_unpack, "list_process_windows", _boom)
    try:
        result = service.unpack_verify(
            session_id,
            str(planted),
            use_die=False,
            expect_window_title="MainWindow",
            ui_pid=4321,
        )
        assert result.ok is True and result.data is not None
        gate = result.data["ui_gate"]
        assert gate["status"] == "error"
        assert "enum blew up" in gate["error"]
    finally:
        service.close_all()
