"""unpack_verify: DIE rescan, IDA reopen/compare, and the UI window gate.

The existing M4 flow test runs verify with use_die=False and open_ida=False,
so the DIE branch, the IDA comparison, and the Win32 UI gate are all dark.
These drive them through the real service against fake workers, monkeypatching
the Win32 enumeration (which returns nothing off Windows).
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection import (
    DetectionFinding,
    DetectionSource,
    FindingCategory,
    ScanMode,
)
from headless_re_mcp.detection.die import DieScanError, DieScanResult
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker


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


def _die_result(path: Path) -> DieScanResult:
    finding = DetectionFinding(
        id="die:0:0",
        category=FindingCategory.PACKER,
        name="UPX",
        summary="Packer: UPX",
        confidence=1.0,
        source="diec",
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


def _service(
    tmp_path: Path,
    worker: FakeDynamicWorker,
    *,
    diec: Path | None = None,
    die_scanner: object = None,
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
        dynamic_worker_factory=lambda session, cfg: worker,
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
        die_scanner=die_scanner,  # type: ignore[arg-type]
    )


def _new_session(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _prepared_dump(service: AnalysisService, binary: Path) -> tuple[str, str]:
    """Create a session, dump a module, and leave a real PE at the dump path."""
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    dumped = service.unpack_dump_module(session_id, 0x140000000, size=0x200)
    assert dumped.ok and dumped.data is not None
    dump_path = str(dumped.data["output_path"])
    Path(dump_path).write_bytes(binary.read_bytes())
    return session_id, dump_path


def test_verify_runs_die_and_matches_a_ui_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    service = _service(
        tmp_path,
        worker,
        diec=diec,
        die_scanner=lambda executable, path, *, mode, timeout: _die_result(path),
    )
    session_id, dump_path = _prepared_dump(service, binary)
    monkeypatch.setattr(
        service_unpack,
        "list_process_windows",
        lambda pid: [{"title": "Target Sample v2", "class_name": "MainWnd", "hwnd": 42}],
    )

    result = service.unpack_verify(
        session_id,
        dump_path,
        use_die=True,
        expect_window_title="target sample",
        expect_window_class="MainWnd",
        ui_pid=4321,
    )

    assert result.ok and result.data is not None
    assert result.data["die"]["status"] == "completed"
    assert result.data["die"]["finding_count"] == 1
    gate = result.data["ui_gate"]
    assert gate["matched"] is True
    assert gate["status"] == "matched"
    assert gate["match"]["hwnd"] == 42
    assert result.data["claims_universal_unpack"] is False


def test_verify_reports_a_die_failure_and_an_unmatched_gate_via_runtime_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")

    def boom_die(*args: object, **kwargs: object) -> DieScanResult:
        raise DieScanError("diec_crashed", "diec crashed")

    service = _service(tmp_path, worker, diec=diec, die_scanner=boom_die)
    session_id, dump_path = _prepared_dump(service, binary)
    monkeypatch.setattr(
        service_unpack,
        "list_process_windows",
        lambda pid: [{"title": "Other", "class_name": "Nope"}],
    )

    # ui_pid=None forces the gate to resolve the pid from the live runtime,
    # which is the FakeDynamicWorker's pid.
    result = service.unpack_verify(
        session_id,
        dump_path,
        use_die=True,
        expect_window_title="target",
        ui_pid=None,
    )

    assert result.ok and result.data is not None
    assert result.data["die"]["status"] == "failed"
    assert any("DIE rescan failed" in note for note in result.data["unfixed"])
    gate = result.data["ui_gate"]
    assert gate["pid"] == worker.pid
    assert gate["checked"] is True
    assert gate["matched"] is False
    assert gate["status"] == "not_matched"


def test_verify_notes_die_unavailable_and_skips_a_pidless_gate(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)  # no diec configured
    session_id, dump_path = _prepared_dump(service, binary)

    result = service.unpack_verify(
        session_id,
        dump_path,
        use_die=True,
        expect_window_class="MainWnd",
        ui_pid=0,
    )

    assert result.ok and result.data is not None
    assert result.data["die"]["status"] == "unavailable"
    assert "DIE not configured" in result.data["unfixed"]
    gate = result.data["ui_gate"]
    assert gate["status"] == "skipped_no_pid"
    assert "UI window gate skipped: no pid" in result.data["unfixed"]


def test_verify_ui_gate_reports_an_enumeration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id, dump_path = _prepared_dump(service, binary)

    def boom(pid: int) -> list[dict[str, object]]:
        raise OSError("win32 enumeration failed")

    monkeypatch.setattr(service_unpack, "list_process_windows", boom)

    result = service.unpack_verify(
        session_id,
        dump_path,
        use_die=False,
        expect_window_title="anything",
        ui_pid=99,
    )

    assert result.ok and result.data is not None
    gate = result.data["ui_gate"]
    assert gate["status"] == "error"
    assert "win32 enumeration failed" in gate["error"]
    assert any("UI window gate failed" in note for note in result.data["unfixed"])


def test_verify_reopens_in_ida_and_compares_against_a_baseline(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id, dump_path = _prepared_dump(service, binary)

    baseline_id = _new_session(service, binary)
    assert service.open_static(baseline_id).ok

    result = service.unpack_verify(
        session_id,
        dump_path,
        use_die=False,
        open_ida=True,
        baseline_session_id=baseline_id,
    )

    assert result.ok and result.data is not None
    ida = result.data["ida"]
    assert ida["static_open_ok"] is True
    assert "baseline_functions" in ida
    assert "rebuilt_functions" in ida


def test_verify_records_an_ida_reopen_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id, dump_path = _prepared_dump(service, binary)

    from headless_re_mcp.core.models import Result, RpcError

    real_create = service.create_session

    def flaky_create(path: str):  # type: ignore[no-untyped-def]
        # Fail only the verify-triggered reopen of the rebuilt image; the
        # session and baseline creations above already happened.
        if Path(path).resolve() == Path(dump_path).resolve():
            return Result(ok=False, error=RpcError(code="ida_boot_failed", message="no ida"))
        return real_create(path)

    monkeypatch.setattr(service, "create_session", flaky_create)

    result = service.unpack_verify(session_id, dump_path, use_die=False, open_ida=True)

    assert result.ok and result.data is not None
    ida = result.data["ida"]
    assert ida["static_open_ok"] is False
    assert ida["error"]["code"] == "ida_boot_failed"
    assert "IDA reopen failed" in result.data["unfixed"]


def test_verify_records_a_baseline_compare_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id, dump_path = _prepared_dump(service, binary)
    baseline_id = _new_session(service, binary)
    assert service.open_static(baseline_id).ok

    def boom_functions(sid: str):  # type: ignore[no-untyped-def]
        raise RuntimeError("static server went away")

    monkeypatch.setattr(service, "static_functions", boom_functions)

    result = service.unpack_verify(
        session_id,
        dump_path,
        use_die=False,
        open_ida=True,
        baseline_session_id=baseline_id,
    )

    assert result.ok and result.data is not None
    assert "static server went away" in result.data["ida"]["compare_error"]
    assert "IDA function compare incomplete" in result.data["unfixed"]


def test_verify_rejects_a_path_outside_the_session_directory(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _new_session(service, binary)
    outsider = tmp_path / "loose.exe"
    _write_pe(outsider)

    result = service.unpack_verify(session_id, str(outsider), use_die=False)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_verify_of_an_unknown_session_fails_cleanly(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)

    result = service.unpack_verify("no-such-session", "/tmp/whatever.exe", use_die=False)

    assert not result.ok and result.error is not None


def test_verify_gate_prefers_the_debuggee_pid_from_last_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the worker reports a debuggee pid in its last state, the gate uses
    # that in preference to the worker's own pid.
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    worker.last_state = {"pid": 4321}  # type: ignore[attr-defined]
    service = _service(tmp_path, worker)
    session_id, dump_path = _prepared_dump(service, binary)
    seen: list[int] = []

    def record(pid: int) -> list[dict[str, object]]:
        seen.append(pid)
        return []

    monkeypatch.setattr(service_unpack, "list_process_windows", record)

    result = service.unpack_verify(
        session_id, dump_path, use_die=False, expect_window_title="x", ui_pid=None
    )

    assert result.ok and result.data is not None
    assert seen == [4321]
    assert result.data["ui_gate"]["pid"] == 4321


def test_verify_gate_skips_when_the_runtime_lookup_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id, dump_path = _prepared_dump(service, binary)

    def boom_runtime(sid: str, kind: object):  # type: ignore[no-untyped-def]
        raise RuntimeError("no live runtime")

    monkeypatch.setattr(service, "_runtime", boom_runtime)

    result = service.unpack_verify(
        session_id, dump_path, use_die=False, expect_window_title="x", ui_pid=None
    )

    assert result.ok and result.data is not None
    assert result.data["ui_gate"]["status"] == "skipped_no_pid"
