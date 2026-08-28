"""Coverage for the recovery, reopen, and close error arms of ``AnalysisService``.

The happy-path recovery and close tests never take the defensive branches these
helpers carry: a recovery asked for a closed session, a reopen that fails, a
replacement whose first backend dies (cascading a skip), malformed knowledge
replayed onto a rebuilt session, a backend factory that hands back nothing, a
registration that throws after the runtime is live, and the close/close-all
failure reporting. This file drives each of those directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import (
    BackendKind,
    Result,
    RpcError,
    Session,
    SessionState,
)
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.core.session import InvalidStateTransition
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _service,
    _settings,
    _write_minimal_pe,
)


def _service_with_static_factory(
    tmp_path: Path,
    dynamic: FakeDynamicWorker,
    static_factory: Any,
) -> AnalysisService:
    def dynamic_factory(session: Session, settings: Settings) -> FakeDynamicWorker:
        del session, settings
        return dynamic

    return AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=dynamic_factory,
        static_worker_factory=static_factory,
    )


def _open_dynamic_session(tmp_path: Path, worker: FakeDynamicWorker) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id


# --- session_recover guards -----------------------------------------------------


def test_session_recover_is_rejected_for_a_closed_session(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id = _open_dynamic_session(tmp_path, worker)
    assert service.close_session(session_id).ok

    rejected = service.session_recover(session_id, ["x64dbg"])

    assert not rejected.ok and rejected.error is not None
    assert rejected.error.code == "invalid_request"


def test_recover_outcome_defaults_a_non_numeric_failed_count() -> None:
    # ``failed`` is always an int in real callers; the guard defends against a
    # hand-built payload, so a non-numeric value must degrade to "nothing failed".
    outcome = AnalysisService._recover_outcome({"failed": "lots"}, session_id="s1")

    assert outcome.ok and outcome.data is not None
    assert outcome.data["failed"] == "lots"


def test_session_recover_reports_a_backend_that_fails_to_reopen(tmp_path: Path) -> None:
    def static_factory(session: Session, settings: Settings) -> FakeStaticWorker:
        del session, settings
        raise XdbgRpcError("backend_unavailable", "ida refused to start")

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service_with_static_factory(tmp_path, FakeDynamicWorker(), static_factory)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    recovered = service.session_recover(session_id, ["ida"])

    assert not recovered.ok and recovered.error is not None
    assert recovered.error.code == "recovery_failed"
    assert recovered.data is not None
    entry = recovered.data["backends"][0]
    assert entry["backend"] == BackendKind.IDA.value
    assert entry["action"] == "reopened" and entry["ok"] is False
    assert entry["error"]["code"] == "backend_unavailable"


def test_replacement_skips_backends_after_an_earlier_one_fails(tmp_path: Path) -> None:
    def static_factory(session: Session, settings: Settings) -> FakeStaticWorker:
        del session, settings
        raise XdbgRpcError("backend_unavailable", "ida refused to start")

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service_with_static_factory(tmp_path, FakeDynamicWorker(), static_factory)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    # FAILED forces a rebuild; IDA is asked for first and cannot come back, so the
    # x64dbg reopen is skipped rather than cascading a second confusing error.
    service._fail_runtime(session_id, BackendKind.X64DBG)

    recovered = service.session_recover(session_id, ["ida", "x64dbg"])

    assert not recovered.ok and recovered.error is not None
    assert recovered.data is not None
    assert recovered.data["replaced"] is True
    ida_entry, xdbg_entry = recovered.data["backends"]
    assert ida_entry["backend"] == BackendKind.IDA.value and ida_entry["ok"] is False
    assert xdbg_entry["action"] == "skipped" and xdbg_entry["ok"] is False
    assert "earlier backend failed" in xdbg_entry["reason"]


def test_rebind_recovered_knowledge_ignores_malformed_snapshots(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, _session_id = _open_dynamic_session(tmp_path, worker)

    # A non-list entries payload is dropped whole; individual non-dict entries and
    # entries with non-string kind/key are skipped. None are well-formed, so the
    # replacement id never receives a knowledge row.
    service._rebind_recovered_knowledge({"entries": "not-a-list"}, "replacement")
    service._rebind_recovered_knowledge(
        {
            "entries": [
                "not-a-dict",
                {"kind": 7, "key": "k", "value": {}},
                {"kind": "function", "key": 9, "value": {}},
            ]
        },
        "replacement",
    )

    stored = service.services.artifacts.list_knowledge("replacement", limit=10)
    assert stored["total"] == 0


def test_recover_by_replacement_surfaces_a_failed_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker()
    service, session_id = _open_dynamic_session(tmp_path, worker)
    service._fail_runtime(session_id, BackendKind.X64DBG)

    def failing_create(*_args: object, **_kwargs: object) -> Result[JsonObject]:
        return Result[JsonObject](
            ok=False,
            error=RpcError(code="create_refused", message="no room"),
        )

    monkeypatch.setattr(service, "create_session", failing_create)

    recovered = service.session_recover(session_id, ["x64dbg"])

    assert not recovered.ok and recovered.error is not None
    assert recovered.error.code == "create_refused"


def test_recover_by_replacement_rejects_a_non_dict_session_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker()
    service, session_id = _open_dynamic_session(tmp_path, worker)
    service._fail_runtime(session_id, BackendKind.X64DBG)

    def bad_create(*_args: object, **_kwargs: object) -> Result[JsonObject]:
        return Result[JsonObject](ok=True, data={"session": "not-a-dict"})

    monkeypatch.setattr(service, "create_session", bad_create)

    recovered = service.session_recover(session_id, ["x64dbg"])

    assert not recovered.ok and recovered.error is not None
    assert recovered.error.code == "rpc_protocol_error"


# --- _open_backend edge cases ---------------------------------------------------


def test_open_backend_reuses_an_already_open_backend(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id = _open_dynamic_session(tmp_path, worker)

    reopened = service.open_dynamic(session_id)

    assert reopened.ok and reopened.data is not None
    assert reopened.data["reused"] is True


def test_open_backend_rejects_a_factory_that_returns_no_worker(tmp_path: Path) -> None:
    def none_factory(session: Session, settings: Settings) -> Any:
        del session, settings
        return None

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=none_factory,
    )
    session_id = _create(service, binary)

    opened = service.open_dynamic(session_id)

    assert not opened.ok and opened.error is not None
    assert service.registry.get(session_id).state == SessionState.FAILED


def test_open_backend_stops_the_drain_when_registration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker()
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("metadata store is down")

    monkeypatch.setattr(service.registry, "update_metadata", boom)

    opened = service.open_dynamic(session_id)

    assert not opened.ok and opened.error is not None
    # The runtime was registered before the throw, so its event drain/log is torn
    # down and the worker terminated rather than leaked.
    assert worker.terminated
    assert service.registry.get(session_id).state == SessionState.FAILED


# --- misc guards ----------------------------------------------------------------


def test_session_work_dir_rejects_a_traversing_session_id(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, _session_id = _open_dynamic_session(tmp_path, worker)

    assert service._session_work_dir("jadx", "../escape") is None


def test_session_health_reports_an_unknown_session(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, _session_id = _open_dynamic_session(tmp_path, worker)

    health = service.session_health("no-such-session")

    assert not health.ok and health.error is not None


def test_readiness_reports_an_internal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker()
    service, _session_id = _open_dynamic_session(tmp_path, worker)

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("disk probe exploded")

    monkeypatch.setattr("headless_re_mcp.core.service.readiness_report", boom)

    ready = service.readiness()

    assert not ready.ok and ready.error is not None


# --- close_session / close_all failure reporting --------------------------------


def test_close_session_reports_a_transition_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker()
    service, session_id = _open_dynamic_session(tmp_path, worker)
    original = service.registry.transition

    def transition(sid: str, target: SessionState) -> Session:
        if target == SessionState.CLOSED:
            raise InvalidStateTransition("registry rejected the close")
        return original(sid, target)

    monkeypatch.setattr(service.registry, "transition", transition)

    closed = service.close_session(session_id)

    assert not closed.ok and closed.error is not None


class _FailingCloseWorker(FakeDynamicWorker):
    def close(self, *, timeout: float = 15.0) -> None:
        del timeout
        raise XdbgRpcError("worker_close_failed", "userdir still held")


def test_close_all_reports_a_session_that_failed_to_close(tmp_path: Path) -> None:
    worker = _FailingCloseWorker()
    service, _session_id = _open_dynamic_session(tmp_path, worker)

    result = service.close_all()

    assert not result.ok and result.error is not None
    assert result.error.code == "close_all_failed"
    details = result.error.details
    assert isinstance(details, dict)
    assert details["errors"]
