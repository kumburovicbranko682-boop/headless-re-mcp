"""Branch coverage for ``AnalysisService`` lifecycle and dynamic-surface guards.

The session open/close/recover machinery, the durable event poll, and the
workflow/runtime failure helpers carry defensive arms that the end-to-end
dynamic tests never take: a backend recovered before it was ever opened, a
session closed while a second backend is launching, an event poll whose budget
is already spent, a run-control wait against a backend without ``events.read``,
and the several shapes ``_fail_runtime`` must survive. This file drives those
arms directly against the fakes in :mod:`tests.unit.test_dynamic_service`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind, Session, SessionState
from headless_re_mcp.core.service import (
    AnalysisService,
    JsonObject,
    _BackendRuntime,
    _recover_backend_kinds,
)
from headless_re_mcp.core.session import InvalidStateTransition
from headless_re_mcp.workflows.runtime import (
    WorkflowRunStatus,
    fail_workflow_runtime,
)
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _debug_batch,
    _service,
    _service_with_dynamic_workers,
    _settings,
    _state,
    _write_minimal_pe,
)


def _open_dynamic(
    tmp_path: Path, worker: FakeDynamicWorker
) -> tuple[AnalysisService, str, _BackendRuntime]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    runtime = service._runtime(session_id, BackendKind.X64DBG)
    return service, session_id, runtime


# --- session_recover / _open_backend / _abandon_open ----------------------------


def test_session_recover_reopens_a_backend_that_was_never_open(tmp_path: Path) -> None:
    # Only x64dbg is open, so recovering "ida" finds no runtime for that kind and
    # must skip the dead-runtime discard and go straight to reopening it.
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    recovered = service.session_recover(session_id, ["ida"])

    assert recovered.ok and recovered.data is not None
    entry = recovered.data["backends"][0]
    assert entry["backend"] == BackendKind.IDA.value
    assert entry["action"] == "reopened" and entry["ok"]
    assert recovered.data["recovered"] == 1
    assert BackendKind.IDA in service.registry.get(session_id).backends


def test_open_backend_rejects_reuse_after_the_session_failed(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, _ = _open_dynamic(tmp_path, worker)
    # The runtime is still registered, but the session went terminal, so a second
    # open must refuse rather than hand back the doomed backend as reused.
    service.registry.transition(session_id, SessionState.FAILED)

    reopened = service.open_dynamic(session_id)

    assert not reopened.ok and reopened.error is not None
    assert "failed" in reopened.error.message


def test_open_backend_aborts_when_the_session_closes_mid_open(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    static = FakeStaticWorker()
    dynamic = FakeDynamicWorker()
    holder: dict[str, AnalysisService] = {}

    def dynamic_factory(session: Session, settings: Settings) -> FakeDynamicWorker:
        del settings
        # The service lock is released across the launch, so a close can land in
        # this window. Flip the session into CLOSING while the worker "starts".
        holder["service"].registry.transition(session.id, SessionState.CLOSING)
        return dynamic

    def static_factory(session: Session, settings: Settings) -> FakeStaticWorker:
        del session, settings
        return static

    service = AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=dynamic_factory,
        static_worker_factory=static_factory,
    )
    holder["service"] = service
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok  # session is READY, so opening=False

    opened = service.open_dynamic(session_id)

    assert not opened.ok and opened.error is not None
    # The half-built worker and its event log are torn down, and nothing is
    # registered against the session that was closing underneath it.
    assert dynamic.terminated
    assert BackendKind.X64DBG not in service.registry.get(session_id).backends


def test_open_backend_skips_health_start_when_the_monitor_is_disabled(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    service._health.interval_s = 0.0

    session_id = _create(service, binary)
    opened = service.open_dynamic(session_id)

    assert opened.ok
    assert service._health._thread is None


# --- close_session / close_all --------------------------------------------------


def test_close_session_tolerates_missing_optional_backends(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    # A service built without the web/proxy composition never sets these; the
    # close path must treat their absence as "nothing to tear down".
    del service._web_backend
    del service._proxy_backend

    closed = service.close_session(session_id)

    assert closed.ok
    assert worker.closed
    assert service.registry.get(session_id).state == SessionState.CLOSED


def test_close_session_keeps_health_running_while_another_backend_lives(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.exe"
    second = tmp_path / "second.exe"
    _write_minimal_pe(first)
    _write_minimal_pe(second)
    service = _service_with_dynamic_workers(
        tmp_path, [FakeDynamicWorker(), FakeDynamicWorker()]
    )
    first_session = _create(service, first)
    second_session = _create(service, second)
    assert service.open_dynamic(first_session).ok
    assert service.open_dynamic(second_session).ok

    assert service.close_session(first_session).ok

    # The second session still owns a runtime, so the sweep thread must keep
    # running rather than being stopped as if the last backend had gone.
    assert service._runtime_owner.snapshot()
    assert service._health._thread is not None
    assert service.close_session(second_session).ok


def test_close_all_tolerates_missing_optional_backends(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    del service._web_backend
    del service._proxy_backend
    del service._adb_backend

    result = service.close_all()

    assert result.ok and result.data is not None
    assert result.data["closed"] == 1
    assert worker.closed


# --- dynamic_events / dynamic_wait / dynamic_attach -----------------------------


class _ClockBurningWorker(FakeDynamicWorker):
    """Advances a simulated clock by a fixed amount on every native read."""

    def __init__(self, clock: dict[str, float], delta: float) -> None:
        super().__init__()
        self._clock = clock
        self._delta = delta

    def read_events(
        self,
        cursor: int,
        *,
        limit: int = 100,
        timeout: float = 10.0,
    ):  # type: ignore[no-untyped-def]
        batch = super().read_events(cursor, limit=limit, timeout=timeout)
        self._clock["now"] += self._delta
        return batch


def test_dynamic_events_skips_the_long_poll_when_the_budget_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    clock = {"now": 0.0}
    worker = _ClockBurningWorker(clock, delta=20.0)
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    monkeypatch.setattr("headless_re_mcp.core.service.monotonic", lambda: clock["now"])

    polled = service.dynamic_events(session_id, timeout=10.0)

    assert polled.ok, polled.error
    # The 50 ms catch-up drain alone burns 20 simulated seconds, so the deadline
    # is already past and the optional long poll is skipped entirely.
    assert [read[2] for read in worker.event_reads] == [0.05]


def test_dynamic_wait_resolves_a_valid_target_state(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    worker.current_state = _state("paused")
    service, session_id, _ = _open_dynamic(tmp_path, worker)

    waited = service.dynamic_wait(session_id, "paused", timeout=5.0)

    assert waited.ok and waited.data is not None
    assert waited.data["state"]["state"] == "paused"


def test_dynamic_attach_leaves_an_already_paused_target_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker()
    service, session_id, _ = _open_dynamic(tmp_path, worker)
    monkeypatch.setattr("headless_re_mcp.core.service.is_pid_alive", lambda pid: True)

    attached = service.dynamic_attach(session_id, 4321, pause_after_attach=True)

    assert attached.ok and attached.data is not None
    # wait_for={"paused"} already parked the target, so no extra pause is issued.
    assert attached.data["state"]["state"] == "paused"
    assert "debug.pause" not in {command for command, _ in worker.requests}


# --- _dynamic_request / _require_current_runtime --------------------------------


class _NoEventsReadWorker(FakeDynamicWorker):
    """Advertises the run-control surface but not ``events.read``."""

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(c for c in super().capabilities if c != "events.read")


def test_run_control_wait_requires_events_read(tmp_path: Path) -> None:
    worker = _NoEventsReadWorker()
    worker.current_state = _state("paused")
    service, session_id, _ = _open_dynamic(tmp_path, worker)

    stepped = service.dynamic_step_into(session_id, timeout=2.0)

    assert not stepped.ok and stepped.error is not None
    assert stepped.error.code == "capability_unavailable"
    assert stepped.error.details["capability"] == "events.read"
    assert stepped.error.details["method"] == "debug.step_into"


def test_require_current_runtime_rejects_a_stale_runtime(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, _ = _open_dynamic(tmp_path, worker)
    ghost = _BackendRuntime(worker)  # never registered against the session

    with pytest.raises(InvalidStateTransition):
        service._require_current_runtime(session_id, BackendKind.X64DBG, ghost)


# --- _workflow_request / _consume_workflow_batch_locked / _navigate_locked -------


def test_workflow_request_fails_the_runtime_on_a_fatal_error(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, _ = _open_dynamic(tmp_path, worker)

    def action(_runtime: _BackendRuntime) -> JsonObject:
        raise XdbgRpcError("worker_exited", "x64dbg died", retryable=False)

    result = service._workflow_request(session_id, action)

    assert not result.ok and result.error is not None
    assert result.error.code == "worker_exited"
    # A fatal worker error tears the runtime down rather than leaving it half-dead.
    assert worker.terminated
    assert BackendKind.X64DBG not in service.registry.get(session_id).backends


def test_consume_batch_returns_early_for_a_failed_workflow(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, runtime = _open_dynamic(tmp_path, worker)
    workflow = service._workflow_owner.get(session_id)
    assert workflow is not None
    service._workflow_owner.put(
        session_id,
        fail_workflow_runtime(workflow, code="boom", message="already failed"),
    )

    # A failed workflow is inert; consuming into it is a no-op, not a crash.
    service._consume_workflow_batch_locked(
        session_id, runtime, _debug_batch(0), timeout=5.0
    )

    after = service._workflow_owner.get(session_id)
    assert after is not None and after.status == WorkflowRunStatus.FAILED


def test_consume_batch_rejects_a_diverged_cursor(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, runtime = _open_dynamic(tmp_path, worker)

    with pytest.raises(XdbgRpcError) as exc:
        service._consume_workflow_batch_locked(
            session_id, runtime, _debug_batch(5), timeout=5.0
        )

    assert exc.value.code == "event_cursor_inconsistent"


def test_consume_batch_fails_the_workflow_when_consume_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker()
    service, session_id, runtime = _open_dynamic(tmp_path, worker)

    def boom(*_args: object, **_kwargs: object) -> object:
        raise ValueError("event stream is malformed")

    monkeypatch.setattr(
        "headless_re_mcp.core.service.consume_workflow_events", boom
    )

    with pytest.raises(ValueError):
        service._consume_workflow_batch_locked(
            session_id, runtime, _debug_batch(0), timeout=5.0
        )

    failed = service._workflow_owner.get(session_id)
    assert failed is not None and failed.status == WorkflowRunStatus.FAILED


def test_navigate_rejects_a_backend_without_events_read(tmp_path: Path) -> None:
    worker = _NoEventsReadWorker()
    worker.current_state = _state("paused")
    service, session_id, _ = _open_dynamic(tmp_path, worker)

    navigated = service.workflow_navigate_to_event(
        session_id,
        "breakpoint.hit",
        timeout=2.0,
        event_budget=8,
    )

    assert not navigated.ok and navigated.error is not None
    assert navigated.error.code == "capability_unavailable"
    assert navigated.error.details["capability"] == "events.read"


def test_navigate_times_out_without_a_matching_event(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    worker.current_state = _state("paused")
    service, session_id, _ = _open_dynamic(tmp_path, worker)

    navigated = service.workflow_navigate_to_event(
        session_id,
        "breakpoint.hit",
        timeout=0.3,
        event_budget=8,
    )

    assert navigated.ok and navigated.data is not None
    workflow = navigated.data["workflow"]
    assert isinstance(workflow, dict)
    navigation = workflow["state"]["navigation"]
    assert isinstance(navigation, dict)
    assert navigation["status"] == "timed_out"
    # A timed-out navigation leaves the target parked for the next command.
    assert worker.current_state["state"] == "paused"


# --- _fail_runtime shapes -------------------------------------------------------


def test_fail_runtime_without_a_workflow(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, _ = _open_dynamic(tmp_path, worker)
    service._workflow_owner.clear(session_id)

    service._fail_runtime(session_id, BackendKind.X64DBG)

    assert worker.terminated
    assert BackendKind.X64DBG not in service.registry.get(session_id).backends


def test_fail_runtime_leaves_an_already_failed_workflow_alone(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, _ = _open_dynamic(tmp_path, worker)
    workflow = service._workflow_owner.get(session_id)
    assert workflow is not None
    service._workflow_owner.put(
        session_id,
        fail_workflow_runtime(
            workflow, code="prior", message="failed earlier", retryable=True
        ),
    )

    service._fail_runtime(session_id, BackendKind.X64DBG)

    terminal = service._workflow_owner.get_terminal(session_id)
    assert terminal is not None
    # The pre-existing failure is preserved, not overwritten by the runtime loss.
    assert terminal.failure is not None
    assert terminal.failure.code == "prior"


def test_fail_runtime_without_a_registered_runtime(tmp_path: Path) -> None:
    worker = FakeDynamicWorker()
    service, session_id, _ = _open_dynamic(tmp_path, worker)

    # IDA was never opened, so there is no runtime to fail; the session is still
    # marked failed and the (absent) backend detach is tolerated.
    service._fail_runtime(session_id, BackendKind.IDA)

    assert service.registry.get(session_id).state == SessionState.FAILED


# --- _recover_backend_kinds -----------------------------------------------------


def test_recover_backend_kinds_dedupes_aliases() -> None:
    assert _recover_backend_kinds(["ida", "static"]) == (BackendKind.IDA,)
    assert _recover_backend_kinds(["x64dbg", "dynamic"]) == (BackendKind.X64DBG,)
    assert _recover_backend_kinds(["dynamic", "ida", "static", "x64dbg"]) == (
        BackendKind.X64DBG,
        BackendKind.IDA,
    )
