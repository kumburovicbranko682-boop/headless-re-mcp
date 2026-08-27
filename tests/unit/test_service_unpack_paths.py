"""Branch coverage for the AnalysisService unpack mixin.

Drives the self-contained arms of ``UnpackMixin`` that the happy-path suites
skip: the memory-fit and bounded-read helpers, the stub-coupling analysis,
the IAT-validate dump-path guards, and the verify stage's DIE / IDA-reopen /
UI-window-gate branches. The dynamic and static backends are the in-repo
fakes, so no real debugger or scanner is required.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_unpack as mod
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_unpack import (
    _read_dump_for_rebuild,
    _refuse_rebuild_that_will_not_fit,
)
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.pe_rebuild import PeRebuildError
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


def _runtime_dump() -> bytes:
    """A memory-style PE image parse_runtime_headers / stub analysis accept."""
    image = bytearray(0x3000)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x400)
    struct.pack_into("<HH", image, optional + 68, 3, 0)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b"CODE\0\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x1000:0x1010] = b"\xc3\x90" * 8
    return bytes(image)


def _service(
    tmp_path: Path,
    *,
    diec: Path | None = None,
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


def _session_unpack_dir(service: AnalysisService, session_id: str) -> Path:
    directory = service.settings.artifact_root / "unpack" / session_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _new_session(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


# ---------------------------------------------------------------------------
# module-level helpers
# ---------------------------------------------------------------------------


def test_refuse_rebuild_that_will_not_fit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"\0" * 4096)

    monkeypatch.setattr(mod, "rebuild_would_exhaust_memory", lambda size: (False, 0, 0))
    assert _refuse_rebuild_that_will_not_fit(dump) is None

    # A missing file with no observed size takes the OSError->None arm.
    assert _refuse_rebuild_that_will_not_fit(tmp_path / "absent.bin") is None

    monkeypatch.setattr(
        mod,
        "rebuild_would_exhaust_memory",
        lambda size: (True, 200 * 1048576, 10 * 1048576),
    )
    refused = _refuse_rebuild_that_will_not_fit(dump, observed_size=64 * 1048576)
    assert refused is not None and refused.error is not None
    assert refused.error.code == "dump_too_large"
    assert refused.error.details["dump_bytes"] == 64 * 1048576


def test_read_dump_for_rebuild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"MZ" + b"\0" * 100)

    monkeypatch.setattr(mod, "rebuild_would_exhaust_memory", lambda size: (False, 0, 0))
    payload, refusal = _read_dump_for_rebuild(dump)
    assert refusal is None
    assert payload is not None and payload.startswith(b"MZ")

    monkeypatch.setattr(mod, "rebuild_would_exhaust_memory", lambda size: (True, 1 << 40, 1 << 20))
    payload, refusal = _read_dump_for_rebuild(dump)
    assert payload is None
    assert refusal is not None and refusal.error is not None
    assert refusal.error.code == "dump_too_large"


def test_read_dump_for_rebuild_detects_a_size_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"MZ" + b"\0" * 100)
    monkeypatch.setattr(mod, "rebuild_would_exhaust_memory", lambda size: (False, 0, 0))
    # Report a stale, shorter size so the read returns more than expected.
    monkeypatch.setattr(os, "fstat", lambda fd: SimpleNamespace(st_size=8))
    with pytest.raises(PeRebuildError, match="changed size"):
        _read_dump_for_rebuild(dump)


# ---------------------------------------------------------------------------
# unpack_stub_coupling
# ---------------------------------------------------------------------------


def test_stub_coupling_rejects_a_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(_runtime_dump())
    result = service.unpack_stub_coupling(session_id, str(outside))
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_stub_coupling_reports_gate_and_pause(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    dump = _session_unpack_dir(service, session_id) / "dump.bin"
    dump.write_bytes(_runtime_dump())
    result = service.unpack_stub_coupling(
        session_id, str(dump), iat_va=0x140002000, iat_size=0x40, module_base=0x140000000
    )
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["stub_coupling"]["ok"] is True
    assert result.data["rebuild_gate_hint"] is not None
    assert result.data["pause_quality"] is not None


# ---------------------------------------------------------------------------
# unpack_iat_validate dump-path guards
# ---------------------------------------------------------------------------


def _armed_candidate(service: AnalysisService, tmp_path: Path) -> tuple[str, dict[str, Any]]:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    dumped = service.unpack_dump_module(session_id, 0x140000000, size=0x200)
    assert dumped.ok
    scanned = service.unpack_iat_scan(session_id, 0x140000000)
    assert scanned.ok and scanned.data is not None
    return session_id, scanned.data["candidates"][0]


def test_iat_validate_rejects_a_dump_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id, candidate = _armed_candidate(service, tmp_path)
    outside = tmp_path / "loose.bin"
    outside.write_bytes(_runtime_dump())
    result = service.unpack_iat_validate(
        session_id,
        iat_va=int(candidate["iat_va"]),
        size=int(candidate["size"]),
        module_base=0x140000000,
        dump_path=str(outside),
    )
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "artifact root" in result.error.message


def test_iat_validate_rejects_a_missing_dump_path(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id, candidate = _armed_candidate(service, tmp_path)
    missing = _session_unpack_dir(service, session_id) / "not-there.bin"
    result = service.unpack_iat_validate(
        session_id,
        iat_va=int(candidate["iat_va"]),
        size=int(candidate["size"]),
        module_base=0x140000000,
        dump_path=str(missing),
    )
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "does not exist" in result.error.message


# ---------------------------------------------------------------------------
# unpack_verify
# ---------------------------------------------------------------------------


def _verify_target(service: AnalysisService, session_id: str, binary: Path) -> Path:
    target = _session_unpack_dir(service, session_id) / "rebuilt.exe"
    target.write_bytes(binary.read_bytes())
    return target


def test_verify_rejects_a_path_outside_the_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_verify(session_id, str(binary), use_die=False)
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_verify_reports_die_unavailable_when_not_configured(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(session_id, str(target), use_die=True, open_ida=False)
    assert result.ok and result.data is not None
    assert result.data["die"]["status"] == "unavailable"
    assert any("DIE not configured" in item for item in result.data["unfixed"])


def test_verify_runs_a_configured_die_scan(tmp_path: Path) -> None:
    finding = SimpleNamespace(
        category=SimpleNamespace(value="packer"),
        name="UPX",
        summary="UPX packer",
    )
    die_result = SimpleNamespace(
        source=SimpleNamespace(version="4.2"),
        findings=[finding],
    )
    diec = tmp_path / "diec"
    diec.write_bytes(b"fake")
    service = _service(tmp_path, diec=diec, die_scanner=lambda *a, **k: die_result)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(session_id, str(target), use_die=True)
    assert result.ok and result.data is not None
    assert result.data["die"]["status"] == "completed"
    assert result.data["die"]["finding_count"] == 1
    assert result.data["die"]["findings"][0]["category"] == "packer"


def test_verify_reports_a_failing_die_scan(tmp_path: Path) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise DieScanError("protocol_error", "diec exploded")

    diec = tmp_path / "diec"
    diec.write_bytes(b"fake")
    service = _service(tmp_path, diec=diec, die_scanner=boom)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(session_id, str(target), use_die=True)
    assert result.ok and result.data is not None
    assert result.data["die"]["status"] == "failed"
    assert any("DIE rescan failed" in item for item in result.data["unfixed"])


def test_verify_reopens_in_ida_and_compares_a_baseline(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    baseline_id = _new_session(service, binary)
    assert service.open_static(baseline_id).ok
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(
        session_id,
        str(target),
        use_die=False,
        open_ida=True,
        baseline_session_id=baseline_id,
    )
    assert result.ok and result.data is not None
    assert result.data["ida"] is not None
    assert result.data["ida"]["static_open_ok"] is True


def test_verify_ui_gate_is_skipped_without_a_pid(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(
        session_id,
        str(target),
        use_die=False,
        expect_window_title="MainWindow",
    )
    assert result.ok and result.data is not None
    assert result.data["ui_gate"]["status"] == "skipped_no_pid"


def test_verify_ui_gate_matches_a_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mod,
        "list_process_windows",
        lambda pid: [{"title": "My Main Window", "class_name": "Qt5", "hwnd": 7}],
    )
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(
        session_id,
        str(target),
        use_die=False,
        expect_window_title="main window",
        expect_window_class="Qt5",
        ui_pid=4321,
    )
    assert result.ok and result.data is not None
    assert result.data["ui_gate"]["matched"] is True
    assert result.data["ui_gate"]["status"] == "matched"


def test_verify_ui_gate_reports_no_match_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)

    monkeypatch.setattr(
        mod, "list_process_windows", lambda pid: [{"title": "Other", "class_name": "X"}]
    )
    not_matched = service.unpack_verify(
        session_id,
        str(target),
        use_die=False,
        expect_window_title="absent",
        ui_pid=99,
    )
    assert not_matched.data is not None
    assert not_matched.data["ui_gate"]["status"] == "not_matched"

    def blow_up(pid: int) -> Any:
        raise RuntimeError("enum failed")

    monkeypatch.setattr(mod, "list_process_windows", blow_up)
    errored = service.unpack_verify(
        session_id,
        str(target),
        use_die=False,
        expect_window_title="absent",
        ui_pid=99,
    )
    assert errored.data is not None
    assert errored.data["ui_gate"]["status"] == "error"


# ---------------------------------------------------------------------------
# unpack_plan
# ---------------------------------------------------------------------------


def test_unpack_plan_builds_a_non_authoritative_plan(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_plan(session_id, use_die=False)
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert "plan" in result.data and "recommendation" in result.data


def test_unpack_plan_refuses_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.close_session(session_id).ok
    result = service.unpack_plan(session_id, use_die=False)
    assert not result.ok and result.error is not None


# ---------------------------------------------------------------------------
# unpack_start
# ---------------------------------------------------------------------------


def test_unpack_start_rejects_a_non_boolean_replace(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_start(session_id, replace="yes")  # type: ignore[arg-type]
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_unpack_start_refuses_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.close_session(session_id).ok
    result = service.unpack_start(session_id)
    assert not result.ok and result.error is not None


def test_unpack_start_runs_the_no_packer_route_and_guards_replacement(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    started = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert started.ok and started.data is not None
    assert started.data["claims_universal_unpack"] is False

    # A second start without replace is refused while the session is active.
    again = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert not again.ok and again.error is not None
    assert again.error.code == "unpack_already_active"

    # replace=True restarts the orchestration.
    replaced = service.unpack_start(session_id, use_die=False, execute_upx=False, replace=True)
    assert replaced.ok


# ---------------------------------------------------------------------------
# unpack_status / unpack_cancel / unpack_artifacts
# ---------------------------------------------------------------------------


def test_unpack_status_not_started_and_bad_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    not_started = service.unpack_status(session_id)
    assert not not_started.ok and not_started.error is not None
    assert not_started.error.code == "unpack_not_started"
    assert not service.unpack_status("no-such-session").ok


def test_unpack_artifacts_not_started_and_bad_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    not_started = service.unpack_artifacts(session_id)
    assert not not_started.ok and not_started.error is not None
    assert not_started.error.code == "unpack_not_started"
    assert not service.unpack_artifacts("no-such-session").ok


def test_unpack_cancel_not_started(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_cancel(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_not_started"


def test_unpack_cancel_attempts_a_pause_when_dynamic_is_open(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.unpack_start(session_id, use_die=False, execute_upx=False).ok
    result = service.unpack_cancel(session_id, reason="stop now")
    assert result.ok and result.data is not None
    assert result.data["debuggee_paused_attempted"] is True
    assert result.data["original_input_preserved"] is True
