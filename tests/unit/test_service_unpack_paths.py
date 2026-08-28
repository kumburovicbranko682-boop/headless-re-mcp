"""Guard, status, cancel, and stub-coupling arms of the unpack orchestration.

The happy path (dump -> scan -> validate -> rebuild -> verify) is covered by
test_m4_unpack_service against the fake workers. This file adds the arms that
never ran there: the cooperative-preempt guard that refuses work once an unpack
session is terminal, the timeout refresh in status, cancel's not-started and
debuggee-pause branches, and the standalone stub-coupling analysis (both its
real-dump success and its artifact-root path guard).
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    cancel_unpack_session,
    create_unpack_session,
    transition,
)
from tests.unit.test_dynamic_service import FakeDynamicWorker
from tests.unit.test_m4_unpack_service import _service, _write_pe


def _open_session(tmp_path: Path) -> tuple[AnalysisService, FakeDynamicWorker, str]:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    created = service.create_session(str(binary))
    assert created.data is not None
    session_id = str(created.data["session"]["id"])
    assert service.open_dynamic(session_id).ok
    return service, worker, session_id


def _plant(service: AnalysisService, session_id: str, *, cancelled: bool) -> None:
    state = create_unpack_session(session_id, route="upx")
    if cancelled:
        state = cancel_unpack_session(state, reason="test cancel")
    service._store_unpack_session(state)


def _plant_phase(
    service: AnalysisService, session_id: str, phase: UnpackPhase
) -> None:
    state = create_unpack_session(session_id, route="unpack")
    if phase in {UnpackPhase.RUNNING, UnpackPhase.OEP_CANDIDATE}:
        state = transition(state, UnpackPhase.RUNNING, event="running", message="under way")
    if phase == UnpackPhase.OEP_CANDIDATE:
        state = transition(
            state, UnpackPhase.OEP_CANDIDATE, event="scored", message="candidates"
        )
    service._store_unpack_session(state)


# --- stub coupling (standalone dump analysis) --------------------------------


def test_stub_coupling_reports_analysis_for_a_real_dump(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)
    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x200)
    assert dumped.ok and dumped.data is not None
    dump_path = str(dumped.data["output_path"])
    # A parseable PE image so the analyzer resolves sections and reports ok.
    Path(dump_path).write_bytes((tmp_path / "sample.exe").read_bytes())

    result = service.unpack_stub_coupling(session_id, dump_path, module_base=worker.module_base)

    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert "stub_coupling" in result.data
    assert result.data["stub_coupling"]["ok"] is True
    assert result.data["rebuild_gate_hint"] is not None
    assert result.data["pause_quality"] is not None


def test_stub_coupling_refuses_a_dump_outside_the_artifact_root(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"MZ" + b"\0" * 0x100)

    result = service.unpack_stub_coupling(session_id, str(outside))

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


# --- cooperative-preempt guard -----------------------------------------------


def test_guard_refuses_every_mcp_method_on_a_cancelled_session(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)
    _plant(service, session_id, cancelled=True)
    base = worker.module_base

    outcomes = [
        service.unpack_stub_coupling(session_id, "ignored.bin"),
        service.unpack_iat_scan(session_id, base),
        service.unpack_iat_validate(session_id, iat_va=base + 0x2000, size=0x40),
        service.unpack_iat_rebuild(session_id, "ignored.bin", iat_va=base + 0x2000, size=0x40),
        service.unpack_pe_rebuild(
            session_id, "ignored.bin", entry_point_rva=0x1000, iat_va=base + 0x2000, iat_size=0x40
        ),
        service.unpack_score_oep(session_id, module_base=base, module_size=0x1000),
    ]

    for result in outcomes:
        assert not result.ok and result.error is not None
        assert result.error.code == "unpack_cancelled"


# --- status timeout refresh --------------------------------------------------


def test_status_fails_a_session_that_passed_its_deadline(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    state = create_unpack_session(session_id, route="upx", timeout_seconds=120.0)
    state = dataclasses.replace(
        state, deadline_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    service._store_unpack_session(state)

    result = service.unpack_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["unpack"]["phase"] == UnpackPhase.FAILED.value


# --- cancel arms -------------------------------------------------------------


def test_cancel_without_a_session_reports_not_started(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)

    result = service.unpack_cancel(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_not_started"


def test_cancel_pauses_an_open_debuggee_and_retains_artifacts(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    _plant(service, session_id, cancelled=False)

    result = service.unpack_cancel(session_id, reason="operator stop")

    assert result.ok and result.data is not None
    assert result.data["debuggee_paused_attempted"] is True
    assert result.data["artifacts_retained"] is True
    assert result.data["unpack"]["phase"] == UnpackPhase.CANCELLED.value


# --- score_oep auto-collection from runtime snapshots ------------------------


def test_score_oep_auto_collects_when_no_session_is_tracked(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)

    result = service.unpack_score_oep(
        session_id, module_base=worker.module_base, module_size=worker.module_size
    )

    assert result.ok and result.data is not None
    assert result.data["auto_collected"] is True
    assert result.data["authoritative"] is False
    assert result.data["unpack"] is None


def test_score_oep_advances_a_running_session_to_oep_candidate(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)
    state = create_unpack_session(session_id, route="unpack")
    state = transition(
        state, UnpackPhase.RUNNING, event="running", message="under way"
    )
    service._store_unpack_session(state)

    result = service.unpack_score_oep(
        session_id, module_base=worker.module_base, module_size=worker.module_size
    )

    assert result.ok and result.data is not None
    assert result.data["unpack"]["phase"] == UnpackPhase.OEP_CANDIDATE.value


def test_score_oep_appends_timeline_for_a_non_running_session(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)
    _plant(service, session_id, cancelled=False)  # stays in DETECTED

    result = service.unpack_score_oep(
        session_id, module_base=worker.module_base, module_size=worker.module_size
    )

    assert result.ok and result.data is not None
    assert result.data["unpack"]["phase"] == UnpackPhase.DETECTED.value


# --- confirm_oep arms --------------------------------------------------------


def test_confirm_oep_rejects_a_non_boolean_auto_dump(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000, auto_dump="yes")  # type: ignore[arg-type]

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_confirm_oep_fails_a_timed_out_session(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    state = create_unpack_session(session_id, route="unpack")
    state = transition(state, UnpackPhase.RUNNING, event="running", message="under way")
    state = dataclasses.replace(
        state, deadline_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    service._store_unpack_session(state)

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_timeout"


def test_confirm_oep_refuses_a_phase_before_running(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    _plant_phase(service, session_id, UnpackPhase.DETECTED)

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_phase"


def test_confirm_oep_records_confirmation_in_oep_candidate_phase(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)
    _plant_phase(service, session_id, UnpackPhase.OEP_CANDIDATE)

    result = service.unpack_confirm_oep(
        session_id, oep_rva=0x1000, module_base=worker.module_base
    )

    assert result.ok and result.data is not None
    assert result.data["role"] == "confirmed"
    assert result.data["auto_dump"] is False
    assert result.data["confirmed_oep_rva"] == 0x1000


def test_confirm_oep_running_with_auto_dump_advances_to_dumped(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)
    _plant_phase(service, session_id, UnpackPhase.RUNNING)

    result = service.unpack_confirm_oep(
        session_id, oep_rva=0x1000, module_base=worker.module_base, auto_dump=True
    )

    assert result.ok and result.data is not None
    assert result.data["auto_dump"] is True
    assert result.data["dump"] is not None
    assert result.data["unpack"]["phase"] == UnpackPhase.DUMPED.value


def test_confirm_oep_auto_dump_requires_a_module_base(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    _plant_phase(service, session_id, UnpackPhase.RUNNING)

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000, auto_dump=True)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


# --- unpack_plan / unpack_start orchestration --------------------------------


def test_unpack_plan_builds_a_non_authoritative_plan(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)

    result = service.unpack_plan(session_id, use_die=False)

    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert isinstance(result.data["plan"], dict)
    assert "recommendation" in result.data


def test_unpack_start_generic_dynamic_route_probes_the_runtime(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)

    result = service.unpack_start(
        session_id, use_die=False, force_route="generic_dynamic"
    )

    assert result.ok and result.data is not None
    probe = result.data["bounded_probe"]
    assert probe["dynamic_open"] is True
    assert probe["module_base"] == worker.module_base
    assert probe["oep_scored"] is True
    assert result.data["unpack"]["phase"] == UnpackPhase.RUNNING.value


def test_unpack_start_none_route_prefers_static(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)

    result = service.unpack_start(session_id, use_die=False, force_route="none")

    assert result.ok and result.data is not None
    assert result.data.get("bounded_probe") is None
    assert result.data["unpack"]["route"] == "none"


def test_unpack_start_dotnet_route_hands_off_to_inspect(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)

    result = service.unpack_start(session_id, use_die=False, force_route="dotnet")

    assert result.ok and result.data is not None
    assert result.data["bounded_probe"]["route"] == "dotnet"


def test_unpack_start_upx_route_fails_closed_without_a_upx_tool(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)

    result = service.unpack_start(
        session_id, use_die=False, force_route="upx", execute_upx=True
    )

    assert result.ok and result.data is not None
    assert result.data["unpack"]["phase"] == UnpackPhase.FAILED.value


def test_unpack_start_rejects_a_non_boolean_replace(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)

    result = service.unpack_start(session_id, replace="please")  # type: ignore[arg-type]

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_unpack_start_refuses_an_active_session_without_replace(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    _plant_phase(service, session_id, UnpackPhase.RUNNING)

    result = service.unpack_start(session_id, use_die=False)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_already_active"


def test_unpack_start_restarts_a_terminal_session(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    _plant(service, session_id, cancelled=True)

    result = service.unpack_start(session_id, use_die=False, force_route="none")

    assert result.ok and result.data is not None
    assert result.data["unpack"]["route"] == "none"


def test_unpack_start_generic_dynamic_skips_probe_without_a_debugger(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    created = service.create_session(str(binary))
    assert created.data is not None
    session_id = str(created.data["session"]["id"])
    # No open_dynamic: the bounded probe must record the skip, not raise.

    result = service.unpack_start(
        session_id, use_die=False, force_route="generic_dynamic"
    )

    assert result.ok and result.data is not None
    assert result.data["bounded_probe"]["dynamic_open"] is False


def test_confirm_oep_reports_a_failed_auto_dump(tmp_path: Path) -> None:
    service, worker, session_id = _open_session(tmp_path)
    _plant_phase(service, session_id, UnpackPhase.RUNNING)
    # A backend that now rejects every request makes the auto-dump fail.
    worker.failure = XdbgRpcError("worker_gone", "backend unreachable")

    result = service.unpack_confirm_oep(
        session_id, oep_rva=0x1000, module_base=worker.module_base, auto_dump=True
    )

    assert not result.ok and result.error is not None


def test_unpack_start_dotnet_route_fails_when_inspect_fails(tmp_path: Path) -> None:
    service, _worker, session_id = _open_session(tmp_path)
    service.dotnet_inspect = lambda _sid, **_k: Result(  # type: ignore[method-assign]
        ok=False, error=RpcError(code="dotnet_broken", message="no CLR metadata")
    )

    result = service.unpack_start(session_id, use_die=False, force_route="dotnet")

    assert result.ok and result.data is not None
    assert result.data["unpack"]["phase"] == UnpackPhase.FAILED.value
    assert result.data["bounded_probe"]["dotnet_inspect_ok"] is False
