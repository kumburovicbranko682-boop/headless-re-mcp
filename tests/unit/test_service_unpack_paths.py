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
