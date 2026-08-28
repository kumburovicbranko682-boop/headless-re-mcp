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
from typing import Any, cast

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_unpack as mod
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_unpack import (
    _read_dump_for_rebuild,
    _refuse_rebuild_that_will_not_fit,
)
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.pe_rebuild import PeRebuildError
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    create_unpack_session,
    fail_unpack_session,
    transition,
)
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


def test_verify_reports_a_failure_for_a_bad_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    result = service.unpack_verify("no-such-session", "/tmp/whatever", use_die=False)
    assert not result.ok and result.error is not None


def test_verify_open_ida_without_a_baseline(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(session_id, str(target), use_die=False, open_ida=True)
    assert result.ok and result.data is not None
    assert result.data["ida"] is not None
    assert result.data["ida"]["static_open_ok"] is True


def test_verify_open_ida_reports_a_failed_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)
    monkeypatch.setattr(
        service,
        "create_session",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="reopen_failed", message="cannot reopen")
        ),
    )
    result = service.unpack_verify(session_id, str(target), use_die=False, open_ida=True)
    assert result.ok and result.data is not None
    assert result.data["ida"]["static_open_ok"] is False
    assert any("IDA reopen failed" in item for item in result.data["unfixed"])


def test_verify_baseline_compare_survives_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    baseline_id = _new_session(service, binary)
    assert service.open_static(baseline_id).ok
    session_id = _new_session(service, binary)
    target = _verify_target(service, session_id, binary)

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("static functions unavailable")

    monkeypatch.setattr(service, "static_functions", boom)
    result = service.unpack_verify(
        session_id,
        str(target),
        use_die=False,
        open_ida=True,
        baseline_session_id=baseline_id,
    )
    assert result.ok and result.data is not None
    assert any("compare incomplete" in item for item in result.data["unfixed"])


def test_verify_ui_gate_uses_the_runtime_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        mod,
        "list_process_windows",
        lambda pid: [{"title": "Runtime Window", "class_name": "W", "hwnd": 1}],
    )
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    target = _verify_target(service, session_id, binary)
    result = service.unpack_verify(
        session_id,
        str(target),
        use_die=False,
        expect_window_title="runtime window",
    )
    assert result.ok and result.data is not None
    assert result.data["ui_gate"]["pid"] is not None
    assert result.data["ui_gate"]["checked"] is True


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


# ---------------------------------------------------------------------------
# unpack_iat_rebuild / unpack_pe_rebuild guard and refusal arms
# ---------------------------------------------------------------------------


def _cancelled_session(service: AnalysisService, tmp_path: Path) -> tuple[str, Path]:
    """A session whose unpack orchestration is in a terminal (cancelled) phase."""
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.unpack_start(session_id, use_die=False, execute_upx=False).ok
    assert service.unpack_cancel(session_id).ok
    dump = _session_unpack_dir(service, session_id) / "dump.bin"
    dump.write_bytes(_runtime_dump())
    return session_id, dump


def test_iat_rebuild_is_blocked_on_a_terminal_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id, dump = _cancelled_session(service, tmp_path)
    result = service.unpack_iat_rebuild(session_id, str(dump), iat_va=0x140002000, size=0x40)
    assert not result.ok and result.error is not None
    assert result.error.code != "invalid_params"


def test_iat_rebuild_rejects_a_dump_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    outside = tmp_path / "loose.bin"
    outside.write_bytes(_runtime_dump())
    result = service.unpack_iat_rebuild(session_id, str(outside), iat_va=0x140002000, size=0x40)
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_iat_rebuild_rejects_non_list_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    dump = _session_unpack_dir(service, session_id) / "dump.bin"
    dump.write_bytes(_runtime_dump())
    monkeypatch.setattr(
        service,
        "imports_read",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"entries": "nope"}),
    )
    result = service.unpack_iat_rebuild(session_id, str(dump), iat_va=0x140002000, size=0x40)
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_iat"


def test_iat_rebuild_gate_refuses_an_unrecoverable_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    dump = _session_unpack_dir(service, session_id) / "dump.bin"
    dump.write_bytes(_runtime_dump())
    # No resolvable API entries: the rebuild gate must refuse the range.
    monkeypatch.setattr(
        service,
        "imports_read",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"entries": []}),
    )
    result = service.unpack_iat_rebuild(session_id, str(dump), iat_va=0x140002000, size=0x40)
    assert not result.ok and result.error is not None
    assert result.error.code == "iat_rebuild_blocked"


def test_pe_rebuild_is_blocked_on_a_terminal_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id, dump = _cancelled_session(service, tmp_path)
    result = service.unpack_pe_rebuild(session_id, str(dump), entry_point_rva=0x1000)
    assert not result.ok and result.error is not None
    assert result.error.code != "invalid_params"


def test_pe_rebuild_rejects_a_dump_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    outside = tmp_path / "loose.bin"
    outside.write_bytes(_runtime_dump())
    result = service.unpack_pe_rebuild(session_id, str(outside))
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_pe_rebuild_propagates_a_failed_imports_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    dump = _session_unpack_dir(service, session_id) / "dump.bin"
    dump.write_bytes(_runtime_dump())
    failure = Result[dict[str, Any]](
        ok=False, error=RpcError(code="imports_read_failed", message="boom")
    )
    monkeypatch.setattr(service, "imports_read", lambda *a, **k: failure)
    result = service.unpack_pe_rebuild(session_id, str(dump), iat_va=0x140002000, iat_size=0x40)
    assert not result.ok and result.error is not None
    assert result.error.code == "imports_read_failed"


def test_pe_rebuild_rejects_non_list_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    dump = _session_unpack_dir(service, session_id) / "dump.bin"
    dump.write_bytes(_runtime_dump())
    monkeypatch.setattr(
        service,
        "imports_read",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"entries": 5}),
    )
    result = service.unpack_pe_rebuild(session_id, str(dump), iat_va=0x140002000, iat_size=0x40)
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_iat"


# ---------------------------------------------------------------------------
# unpack_score_oep
# ---------------------------------------------------------------------------

_MODULE_BASE = 0x140000000
_MODULE_SIZE = 0x4000
_OBSERVATIONS = [{"kind": "rip", "rva": 0x1000, "in_module_code": True}]


def _running_unpack_state(service: AnalysisService, session_id: str) -> None:
    state = create_unpack_session(session_id, route="bounded_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="run")
    service._store_unpack_session(state)


def test_score_oep_without_a_session_scores_supplied_observations(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_score_oep(
        session_id,
        module_base=_MODULE_BASE,
        module_size=_MODULE_SIZE,
        observations=_OBSERVATIONS,
    )
    assert result.ok and result.data is not None
    assert result.data["authoritative"] is False
    assert result.data["auto_collected"] is False
    assert result.data["unpack"] is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"observations": 5},  # non-iterable: list(5) raised a TypeError
        {"observations": "abc"},  # a str iterated to ["a", "b", "c"] and scored nothing
        {"observations": {"a": 1}},  # a dict iterated to its keys
        {"observations": _OBSERVATIONS, "stub_rva_ranges": 5},
        {"previous_regions": 7},
        {"observations": _OBSERVATIONS, "max_candidates": "8"},  # "8" <= 0 raised TypeError
        {"observations": _OBSERVATIONS, "max_candidates": 1.5},  # candidates[:1.5] crashes
        {"observations": _OBSERVATIONS, "max_candidates": True},  # a bool is not a count
    ],
)
def test_score_oep_rejects_wrong_shaped_arguments(tmp_path: Path, kwargs: dict[str, Any]) -> None:
    """Malformed array/count arguments are the caller's mistake, not internal_error.

    A non-iterable observations/stub_rva_ranges/previous_regions escaped list(...)
    as a raw TypeError, a str/dict was silently iterated into an empty score, and a
    non-int max_candidates crashed the scorer's ``<= 0`` compare or ``candidates[:n]``
    slice. All must read as an invalid_request the caller can fix.
    """
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)

    result = service.unpack_score_oep(
        session_id,
        module_base=_MODULE_BASE,
        module_size=_MODULE_SIZE,
        **cast(Any, kwargs),
    )

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_score_oep_transitions_a_running_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    _running_unpack_state(service, session_id)
    result = service.unpack_score_oep(
        session_id,
        module_base=_MODULE_BASE,
        module_size=_MODULE_SIZE,
        observations=_OBSERVATIONS,
        stub_rva_ranges=[(0x2000, 0x100)],
    )
    assert result.ok and result.data is not None
    assert result.data["unpack"]["phase"] == UnpackPhase.OEP_CANDIDATE.value
    assert "stub_rva_ranges" in result.data


def test_score_oep_appends_timeline_for_a_non_running_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.unpack_start(session_id, use_die=False, execute_upx=False).ok
    result = service.unpack_score_oep(
        session_id,
        module_base=_MODULE_BASE,
        module_size=_MODULE_SIZE,
        observations=_OBSERVATIONS,
    )
    assert result.ok and result.data is not None
    assert result.data["unpack"] is not None


def test_score_oep_auto_collects_from_the_runtime(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    result = service.unpack_score_oep(
        session_id, module_base=_MODULE_BASE, module_size=_MODULE_SIZE
    )
    assert result.ok and result.data is not None
    assert result.data["auto_collected"] is True
    assert "note" in result.data


def test_score_oep_reports_a_missing_dynamic_backend(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_score_oep(
        session_id, module_base=_MODULE_BASE, module_size=_MODULE_SIZE
    )
    assert not result.ok and result.error is not None


def test_score_oep_is_blocked_on_a_terminal_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id, _dump = _cancelled_session(service, tmp_path)
    result = service.unpack_score_oep(
        session_id, module_base=_MODULE_BASE, module_size=_MODULE_SIZE
    )
    assert not result.ok and result.error is not None


def test_score_oep_surfaces_a_registers_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "dynamic_registers_read",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="frozen", message="registers frozen")
        ),
    )
    result = service.unpack_score_oep(
        session_id, module_base=_MODULE_BASE, module_size=_MODULE_SIZE
    )
    assert not result.ok and result.error is not None
    assert result.error.code == "frozen"


def test_score_oep_surfaces_a_memory_regions_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "memory_regions",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="frozen", message="regions frozen")
        ),
    )
    result = service.unpack_score_oep(
        session_id, module_base=_MODULE_BASE, module_size=_MODULE_SIZE
    )
    assert not result.ok and result.error is not None
    assert result.error.code == "frozen"


# ---------------------------------------------------------------------------
# unpack_confirm_oep
# ---------------------------------------------------------------------------


def test_confirm_oep_rejects_a_negative_rva(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_confirm_oep(session_id, oep_rva=-1)
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_confirm_oep_rejects_a_non_boolean_auto_dump(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_confirm_oep(
        session_id,
        oep_rva=0x1000,
        auto_dump="yes",  # type: ignore[arg-type]
    )
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_confirm_oep_requires_a_started_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)
    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_not_started"


def test_confirm_oep_rejects_a_wrong_phase(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.unpack_start(session_id, use_die=False, execute_upx=False).ok
    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_phase"


def test_confirm_oep_accepts_a_running_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    _running_unpack_state(service, session_id)
    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000, module_base=_MODULE_BASE)
    assert result.ok and result.data is not None
    assert result.data["confirmed_oep_rva"] == 0x1000
    assert result.data["role"] == "confirmed"


def test_confirm_oep_accepts_an_oep_candidate_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    state = create_unpack_session(session_id, route="bounded_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="run")
    state = transition(state, UnpackPhase.OEP_CANDIDATE, event="scored", message="scored")
    service._store_unpack_session(state)
    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000, module_base=_MODULE_BASE)
    assert result.ok and result.data is not None
    assert result.data["confirmed_oep_rva"] == 0x1000


def test_confirm_oep_auto_dump_requires_a_module_base(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    _running_unpack_state(service, session_id)
    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000, auto_dump=True, module_base=0)
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_confirm_oep_auto_dump_runs_the_dump(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    _running_unpack_state(service, session_id)
    result = service.unpack_confirm_oep(
        session_id,
        oep_rva=0x1000,
        auto_dump=True,
        module_base=_MODULE_BASE,
    )
    assert result.ok and result.data is not None
    assert result.data["auto_dump"] is True
    assert result.data["dump"] is not None


# ---------------------------------------------------------------------------
# _bounded_runtime_probe
# ---------------------------------------------------------------------------


def _probe_state(session_id: str) -> Any:
    state = create_unpack_session(session_id, route="bounded_dynamic")
    return transition(state, UnpackPhase.RUNNING, event="run", message="run")


def test_bounded_probe_skips_when_dynamic_is_closed(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    state, probe = service._bounded_runtime_probe(
        _probe_state(session_id), session_id, route="bounded_dynamic"
    )
    assert probe["dynamic_open"] is False


def test_bounded_probe_reports_a_modules_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="modules_failed", message="boom")
        ),
    )
    _state, probe = service._bounded_runtime_probe(
        _probe_state(session_id), session_id, route="bounded_dynamic"
    )
    assert probe["modules_error"] is not None


def test_bounded_probe_handles_an_empty_module_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"modules": []}),
    )
    _state, probe = service._bounded_runtime_probe(
        _probe_state(session_id), session_id, route="bounded_dynamic"
    )
    assert probe["module_base"] is None


def test_bounded_probe_rejects_a_non_dict_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"modules": [42]}),
    )
    _state, probe = service._bounded_runtime_probe(
        _probe_state(session_id), session_id, route="bounded_dynamic"
    )
    assert probe["module_base"] is None


def test_bounded_probe_rejects_a_bad_module_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda *a, **k: Result[dict[str, Any]](
            ok=True, data={"modules": [{"base": "nope", "size": 16}]}
        ),
    )
    _state, probe = service._bounded_runtime_probe(
        _probe_state(session_id), session_id, route="bounded_dynamic"
    )
    assert probe["module_base"] is None


def test_bounded_probe_defers_when_oep_score_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda *a, **k: Result[dict[str, Any]](
            ok=True, data={"modules": [{"base": _MODULE_BASE, "size": _MODULE_SIZE}]}
        ),
    )
    monkeypatch.setattr(
        service,
        "unpack_score_oep",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="not_paused", message="target running")
        ),
    )
    _state, probe = service._bounded_runtime_probe(
        _probe_state(session_id), session_id, route="bounded_dynamic"
    )
    assert probe["module_base"] == _MODULE_BASE
    assert probe["oep_scored"] is False
    assert probe["oep_score_error"] is not None


# ---------------------------------------------------------------------------
# _run_upx_orchestration
# ---------------------------------------------------------------------------


def _upx_state(session_id: str) -> Any:
    return create_unpack_session(session_id, route="upx")


def test_run_upx_orchestration_fails_when_test_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "unpack_upx_test",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="upx_test", message="not upx")
        ),
    )
    state = service._run_upx_orchestration(
        _upx_state(session_id), session_id, timeout=1.0, open_ida=False
    )
    assert state.phase == UnpackPhase.FAILED
    assert state.failure is not None and state.failure.code == "upx_test_failed"


def test_run_upx_orchestration_fails_when_unpack_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "unpack_upx_test",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"tested": True}),
    )
    monkeypatch.setattr(
        service,
        "unpack_upx_unpack",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="upx_unpack", message="unpack failed")
        ),
    )
    state = service._run_upx_orchestration(
        _upx_state(session_id), session_id, timeout=1.0, open_ida=False
    )
    assert state.phase == UnpackPhase.FAILED
    assert state.failure is not None and state.failure.code == "upx_unpack_failed"


def test_run_upx_orchestration_verifies_and_reanalyzes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    unpacked = _session_unpack_dir(service, session_id) / "unpacked.exe"
    unpacked.write_bytes(binary.read_bytes())
    monkeypatch.setattr(
        service,
        "unpack_upx_test",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"tested": True}),
    )
    monkeypatch.setattr(
        service,
        "unpack_upx_unpack",
        lambda *a, **k: Result[dict[str, Any]](
            ok=True,
            data={
                "output_path": str(unpacked),
                "comparison": {"changed": True},
                "die_rescan": {"status": "completed"},
                "reanalyze": {"static_open_ok": True},
            },
        ),
    )
    state = service._run_upx_orchestration(
        _upx_state(session_id), session_id, timeout=1.0, open_ida=True
    )
    assert state.phase == UnpackPhase.REANALYZED


# ---------------------------------------------------------------------------
# unpack_start forced routes
# ---------------------------------------------------------------------------


def test_unpack_start_forces_the_dotnet_route_and_records_inspect_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "dotnet_inspect",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="not_dotnet", message="not a managed assembly")
        ),
    )
    started = service.unpack_start(
        session_id, use_die=False, execute_upx=False, force_route="dotnet"
    )
    assert started.ok and started.data is not None
    assert started.data["unpack"]["phase"] == UnpackPhase.FAILED.value
    probe = started.data.get("bounded_probe")
    assert isinstance(probe, dict)
    assert probe["dotnet_inspect_ok"] is False


def test_unpack_start_forces_the_generic_dynamic_route(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    started = service.unpack_start(
        session_id, use_die=False, execute_upx=False, force_route="generic_dynamic"
    )
    assert started.ok and started.data is not None
    probe = started.data.get("bounded_probe")
    assert isinstance(probe, dict)
    assert probe["route"] == "generic_dynamic"


# ---------------------------------------------------------------------------
# _advance_* helpers ignore a failed session
# ---------------------------------------------------------------------------


def _store_failed_state(service: AnalysisService, session_id: str) -> None:
    state = create_unpack_session(session_id, route="upx")
    state = fail_unpack_session(state, code="boom", message="already failed")
    service._store_unpack_session(state)


def test_advance_after_dump_ignores_a_failed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    _store_failed_state(service, session_id)
    service._advance_unpack_after_dump(session_id, path="/tmp/x", sha256="abc")
    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.FAILED


def test_advance_after_imports_rebuilt_ignores_a_failed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    _store_failed_state(service, session_id)
    service._advance_unpack_after_imports_rebuilt(
        session_id, path="/tmp/x", sha256="abc", kind="pe_rebuilt"
    )
    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.FAILED


def test_advance_after_verify_ignores_a_failed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    _store_failed_state(service, session_id)
    service._advance_unpack_after_verify(
        session_id, path="/tmp/x", sha256="abc", open_ida=False, ida_ok=False
    )
    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.FAILED


# ---------------------------------------------------------------------------
# unpack_iat_scan / unpack_iat_validate validation arms
# ---------------------------------------------------------------------------


def test_iat_scan_is_blocked_on_a_terminal_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id, _dump = _cancelled_session(service, tmp_path)
    result = service.unpack_iat_scan(session_id, _MODULE_BASE)
    assert not result.ok and result.error is not None


def test_iat_scan_propagates_a_failed_imports_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "imports_scan",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="scan_failed", message="boom")
        ),
    )
    result = service.unpack_iat_scan(session_id, _MODULE_BASE)
    assert not result.ok and result.error is not None
    assert result.error.code == "scan_failed"


def test_iat_scan_tolerates_non_list_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "imports_scan",
        lambda *a, **k: Result[dict[str, Any]](
            ok=True, data={"candidates": "nope", "module_size": 0x1000}
        ),
    )
    result = service.unpack_iat_scan(session_id, _MODULE_BASE)
    assert result.ok and result.data is not None
    assert result.data["candidate_count"] == 0


def test_iat_validate_is_blocked_on_a_terminal_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id, _dump = _cancelled_session(service, tmp_path)
    result = service.unpack_iat_validate(session_id, iat_va=_MODULE_BASE, size=0x40)
    assert not result.ok and result.error is not None


def test_iat_validate_propagates_a_failed_imports_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "imports_read",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="read_failed", message="boom")
        ),
    )
    result = service.unpack_iat_validate(session_id, iat_va=_MODULE_BASE, size=0x40)
    assert not result.ok and result.error is not None
    assert result.error.code == "read_failed"


def test_iat_validate_tolerates_non_list_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "imports_read",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"entries": "nope"}),
    )
    result = service.unpack_iat_validate(session_id, iat_va=_MODULE_BASE, size=0x40)
    assert result.ok and result.data is not None
    assert result.data["confirmed"] is False


def test_iat_validate_analyses_a_supplied_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    dump = _session_unpack_dir(service, session_id) / "dump.bin"
    dump.write_bytes(_runtime_dump())
    monkeypatch.setattr(
        service,
        "imports_read",
        lambda *a, **k: Result[dict[str, Any]](
            ok=True,
            data={
                "entries": [
                    {"kind": "api", "module": "kernel32.dll", "name": f"Api{i}"} for i in range(12)
                ]
            },
        ),
    )
    result = service.unpack_iat_validate(
        session_id,
        iat_va=0x140002000,
        size=0x40,
        module_base=_MODULE_BASE,
        dump_path=str(dump),
    )
    assert result.ok and result.data is not None
    assert result.data["stub_coupling"] is not None


# ---------------------------------------------------------------------------
# unpack_plan / unpack_start propagation arms
# ---------------------------------------------------------------------------


def test_plan_propagates_a_failed_classify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "packer_classify",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="classify_failed", message="boom")
        ),
    )
    result = service.unpack_plan(session_id, use_die=False)
    assert not result.ok and result.error is not None
    assert result.error.code == "classify_failed"


def test_plan_tolerates_non_list_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "packer_classify",
        lambda *a, **k: Result[dict[str, Any]](ok=True, data={"candidates": "nope"}),
    )
    result = service.unpack_plan(session_id, use_die=False)
    assert result.ok and result.data is not None


def test_unpack_start_propagates_a_failed_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    monkeypatch.setattr(
        service,
        "unpack_plan",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="plan_failed", message="boom")
        ),
    )
    result = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert not result.ok and result.error is not None
    assert result.error.code == "plan_failed"


def test_unpack_start_forces_the_upx_route(tmp_path: Path) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    started = service.unpack_start(session_id, use_die=False, execute_upx=True, force_route="upx")
    assert started.ok and started.data is not None
    # No UPX binary is configured, so the orchestration fails closed.
    assert started.data["unpack"]["phase"] == UnpackPhase.FAILED.value


# ---------------------------------------------------------------------------
# unpack_dump_module fail-closed guard arms
# ---------------------------------------------------------------------------


def test_dump_module_propagates_a_failed_modules_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "modules_dump",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="dump_failed", message="boom")
        ),
    )
    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)
    assert not result.ok and result.error is not None
    assert result.error.code == "dump_failed"


def test_dump_module_records_a_headers_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr(
        service,
        "pe_headers_runtime",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="headers_failed", message="no headers")
        ),
    )
    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)
    assert result.ok and result.data is not None
    assert result.data["headers_ok"] is False
    assert "headers_error" in result.data


def _counting_guard(service: AnalysisService, block_on: int) -> None:
    """Make _guard_unpack_active return a block Result on the Nth call only."""
    calls = {"n": 0}

    def fake_guard(session_id: str, *, stage: str) -> Any:
        calls["n"] += 1
        if calls["n"] == block_on:
            return Result[dict[str, Any]](
                ok=False,
                error=RpcError(code="unpack_cancelled", message=f"blocked at {stage}"),
                meta={"unpack": {"phase": "cancelled"}},
            )
        return None

    service._guard_unpack_active = fake_guard  # type: ignore[method-assign]


def test_dump_module_aborts_after_the_dump_when_the_second_guard_blocks(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    _counting_guard(service, block_on=2)
    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)
    assert not result.ok and result.data is not None
    assert result.data["aborted_after_dump"] is True
    assert result.data["safe_rollback"] is False


def test_dump_module_aborts_before_phase_advance_when_the_third_guard_blocks(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    assert service.open_dynamic(session_id).ok
    _counting_guard(service, block_on=3)
    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)
    assert not result.ok and result.data is not None
    assert result.data["aborted_before_phase_advance"] is True


def test_confirm_oep_auto_dump_reports_a_dump_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    session_id = _new_session(service, binary)
    _running_unpack_state(service, session_id)
    monkeypatch.setattr(
        service,
        "unpack_dump_module",
        lambda *a, **k: Result[dict[str, Any]](
            ok=False, error=RpcError(code="dump_failed", message="no dump")
        ),
    )
    result = service.unpack_confirm_oep(
        session_id, oep_rva=0x1000, auto_dump=True, module_base=_MODULE_BASE
    )
    assert not result.ok and result.error is not None
    assert result.error.code == "dump_failed"
