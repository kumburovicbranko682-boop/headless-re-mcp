"""Cover unpack.verify's optional arms: the DIE rescan (completed / failed /
unavailable), the IDA reopen-and-compare, and the Win32 UI window gate
(matched / not-matched / skipped-no-pid / error).

These only run when their inputs are supplied, so the existing negative suites
(which pass ``use_die=False`` and no gate) never reach them. A real
AnalysisService is used with the static/dynamic workers and the DIE scanner
faked, and ``list_process_windows`` patched, so the gate logic is exercised
without a live process.
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_unpack as su
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection.die import DieScanError
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 2, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[section + 40 : section + 48] = b".rdata\0\0"
    struct.pack_into("<IIII", image, section + 48, 0x200, 0x2000, 0, 0)
    struct.pack_into("<I", image, section + 76, 0x40000040)
    image[0x200:0x202] = b"\xC3\x90"
    path.write_bytes(image)


def _fake_die_result() -> Any:
    finding = SimpleNamespace(
        category=SimpleNamespace(value="packer"),
        name="UPX",
        summary="UPX 3.9",
    )
    source = SimpleNamespace(version="1.0")
    return SimpleNamespace(source=source, findings=[finding])


def _service(
    tmp_path: Path,
    *,
    diec: Path | None,
    die_scanner: Any = None,
) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=diec,
    )
    return AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: FakeDynamicWorker(),
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
        die_scanner=die_scanner,
    )


def _open_pe_session(service: AnalysisService, tmp_path: Path) -> tuple[str, Path]:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = created.data["session"]["id"]
    unpack_dir = service.settings.artifact_root.expanduser().resolve() / "unpack" / session_id
    unpack_dir.mkdir(parents=True, exist_ok=True)
    target = unpack_dir / "rebuilt.exe"
    _write_pe(target)
    return session_id, target


def test_verify_reports_a_completed_die_rescan(tmp_path: Path) -> None:
    service = _service(
        tmp_path,
        diec=Path("/usr/bin/diec"),
        die_scanner=lambda diec, target, *, mode, timeout: _fake_die_result(),
    )
    session_id, target = _open_pe_session(service, tmp_path)
    try:
        result = service.unpack_verify(session_id, str(target), use_die=True, open_ida=False)
        assert result.ok and result.data is not None, result.error
        die = result.data["die"]
        assert die["status"] == "completed"
        assert die["version"] == "1.0"
        assert die["finding_count"] == 1
        assert die["findings"][0]["name"] == "UPX"
        assert result.data["claims_universal_unpack"] is False
    finally:
        service.close_all()


def test_verify_records_a_die_scan_failure(tmp_path: Path) -> None:
    def boom(diec: Path, target: Path, *, mode: Any, timeout: float) -> Any:
        raise DieScanError("die_failed", "detector fell over")

    service = _service(tmp_path, diec=Path("/usr/bin/diec"), die_scanner=boom)
    session_id, target = _open_pe_session(service, tmp_path)
    try:
        result = service.unpack_verify(session_id, str(target), use_die=True, open_ida=False)
        assert result.ok and result.data is not None, result.error
        assert result.data["die"]["status"] == "failed"
        assert any("DIE rescan failed" in item for item in result.data["unfixed"])
    finally:
        service.close_all()


def test_verify_notes_die_unavailable_when_not_configured(tmp_path: Path) -> None:
    service = _service(tmp_path, diec=None)
    session_id, target = _open_pe_session(service, tmp_path)
    try:
        result = service.unpack_verify(session_id, str(target), use_die=True, open_ida=False)
        assert result.ok and result.data is not None, result.error
        assert result.data["die"]["status"] == "unavailable"
        assert any("DIE not configured" in item for item in result.data["unfixed"])
    finally:
        service.close_all()


def test_verify_reopens_in_ida_and_compares_a_baseline(tmp_path: Path) -> None:
    service = _service(tmp_path, diec=None)
    session_id, target = _open_pe_session(service, tmp_path)
    try:
        result = service.unpack_verify(
            session_id,
            str(target),
            use_die=False,
            open_ida=True,
            baseline_session_id=session_id,
        )
        assert result.ok and result.data is not None, result.error
        ida = result.data["ida"]
        assert isinstance(ida, dict)
        assert "static_open_ok" in ida
        # A baseline was requested, so the compare keys are present.
        assert "baseline_functions" in ida
        assert "rebuilt_functions" in ida
    finally:
        service.close_all()


def test_verify_ui_gate_matches_a_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, diec=None)
    session_id, target = _open_pe_session(service, tmp_path)
    monkeypatch.setattr(
        su,
        "list_process_windows",
        lambda pid: [{"title": "MyApp Main", "class_name": "TForm1", "hwnd": 42}],
    )
    try:
        result = service.unpack_verify(
            session_id,
            str(target),
            use_die=False,
            open_ida=False,
            expect_window_title="myapp",
            expect_window_class="TForm1",
            ui_pid=1234,
        )
        assert result.ok and result.data is not None, result.error
        gate = result.data["ui_gate"]
        assert gate["matched"] is True
        assert gate["status"] == "matched"
        assert gate["match"]["hwnd"] == 42
    finally:
        service.close_all()


def test_verify_ui_gate_reports_no_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, diec=None)
    session_id, target = _open_pe_session(service, tmp_path)
    monkeypatch.setattr(
        su,
        "list_process_windows",
        lambda pid: [{"title": "Other", "class_name": "Other", "hwnd": 7}],
    )
    try:
        result = service.unpack_verify(
            session_id,
            str(target),
            use_die=False,
            open_ida=False,
            expect_window_title="not-present",
            ui_pid=1234,
        )
        assert result.ok and result.data is not None, result.error
        gate = result.data["ui_gate"]
        assert gate["matched"] is False
        assert gate["status"] == "not_matched"
        assert any("gate not matched" in item for item in result.data["unfixed"])
    finally:
        service.close_all()


def test_verify_ui_gate_skips_without_a_pid(tmp_path: Path) -> None:
    service = _service(tmp_path, diec=None)
    session_id, target = _open_pe_session(service, tmp_path)
    try:
        result = service.unpack_verify(
            session_id,
            str(target),
            use_die=False,
            open_ida=False,
            expect_window_class="TForm1",
        )
        assert result.ok and result.data is not None, result.error
        gate = result.data["ui_gate"]
        assert gate["status"] == "skipped_no_pid"
        assert any("no pid" in item for item in result.data["unfixed"])
    finally:
        service.close_all()


def test_verify_ui_gate_wraps_an_enumeration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, diec=None)
    session_id, target = _open_pe_session(service, tmp_path)

    def boom(pid: int) -> Any:
        raise OSError("enumeration failed")

    monkeypatch.setattr(su, "list_process_windows", boom)
    try:
        result = service.unpack_verify(
            session_id,
            str(target),
            use_die=False,
            open_ida=False,
            expect_window_title="anything",
            ui_pid=1234,
        )
        assert result.ok and result.data is not None, result.error
        gate = result.data["ui_gate"]
        assert gate["status"] == "error"
        assert "enumeration failed" in gate["error"]
    finally:
        service.close_all()
