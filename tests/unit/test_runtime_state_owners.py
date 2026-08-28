"""Edge/guard coverage for the in-process runtime state owners.

``test_architecture_state_repository.py`` covers the backend runtime transition
machine and the workflow/unpack/trace terminal separation. These pin the
remaining branches of ``core/runtime_state.py``: popping an absent backend,
clearing a terminal workflow, failing a live workflow that is not there, and the
debuggee state owner's snapshot/clear plus its idle-while-running projection.
"""

from __future__ import annotations

from headless_re_mcp.core.models import BackendKind, SessionState, TargetKind
from headless_re_mcp.core.runtime_state import (
    BackendRuntimeOwner,
    BackendRuntimePhase,
    DebuggeeStateOwner,
    WorkflowStateOwner,
)
from headless_re_mcp.core.session import SessionRegistry


def test_popping_an_absent_backend_returns_none_and_stays_absent() -> None:
    owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()
    # Never opened: there is nothing to hand back and no phase to advance to
    # CLOSED, so the key must stay ABSENT rather than be marked closed.
    assert owner.pop("s", BackendKind.IDA) is None
    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.ABSENT


def test_failing_after_pop_session_does_not_resurrect_a_phase() -> None:
    """A close that wins the race against an open must stay forgotten.

    close() reaps the session with pop_session while the backend is still
    inside its factory; the completing open then unwinds through fail(). That
    fail() used to write a fresh FAILED phase for a session that never
    reopens, so a server closing sessions all day accumulated one phantom
    entry per lost race -- the exact leak pop_session exists to prevent.
    """
    owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()
    owner.begin_open("s", BackendKind.X64DBG)
    assert owner.pop_session("s") == []  # close ran before put(); nothing live
    assert owner.fail("s", BackendKind.X64DBG) is None
    assert owner.phase("s", BackendKind.X64DBG) is BackendRuntimePhase.ABSENT
    assert owner.phases == {}


def test_failing_a_never_opened_backend_stays_absent() -> None:
    owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()
    assert owner.fail("s", BackendKind.IDA) is None
    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.ABSENT


def test_failing_a_claimed_or_ready_backend_still_marks_failed() -> None:
    owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()

    # An open that dies in its factory: the OPENING claim must turn FAILED so
    # the operator can see what went wrong and a retry can reclaim the key.
    owner.begin_open("s", BackendKind.IDA)
    assert owner.fail("s", BackendKind.IDA) is None
    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.FAILED

    # A live runtime failing later must still be handed back for teardown.
    owner.begin_open("s", BackendKind.X64DBG)
    runtime = object()
    owner.put("s", BackendKind.X64DBG, runtime)
    assert owner.fail("s", BackendKind.X64DBG) is runtime
    assert owner.phase("s", BackendKind.X64DBG) is BackendRuntimePhase.FAILED


def test_clear_terminal_drops_only_the_terminal_snapshot() -> None:
    owner: WorkflowStateOwner[str] = WorkflowStateOwner()
    owner.put("s", "live")
    owner.put_terminal("s", "done")  # moves it out of live and into terminal
    assert owner.get("s") is None
    assert owner.get_terminal("s") == "done"

    owner.clear_terminal("s")
    assert owner.get_terminal("s") is None


def test_fail_live_returns_none_without_a_live_workflow() -> None:
    owner: WorkflowStateOwner[str] = WorkflowStateOwner()
    called: list[str] = []

    def failer(workflow: str) -> str:
        called.append(workflow)
        return workflow + "!"

    assert owner.fail_live("missing", failer) is None
    assert called == [], "the failure projector must not run when nothing is live"


def _web_session(registry: SessionRegistry) -> str:
    session = registry.create("http://example.test/app", target=TargetKind.WEB)
    return session.id


def test_debuggee_snapshot_is_stored_annotated_and_cleared() -> None:
    registry = SessionRegistry()
    session_id = _web_session(registry)
    owner = DebuggeeStateOwner(registry)

    assert owner.snapshot(session_id) is None

    annotated = owner.observe(session_id, {"state": "paused", "process_id": 4321}, debugger_pid=7)
    assert annotated["debuggee_pid"] == 4321
    assert annotated["debugger_pid"] == 7

    snapshot = owner.snapshot(session_id)
    assert snapshot is not None
    assert snapshot.state == "paused"
    assert snapshot.debuggee_pid == 4321
    assert snapshot.debugger_pid == 7

    owner.clear(session_id)
    assert owner.snapshot(session_id) is None


def test_observing_idle_while_running_settles_the_session_to_ready() -> None:
    registry = SessionRegistry()
    session_id = _web_session(registry)
    registry.transition(session_id, SessionState.OPENING)
    registry.transition(session_id, SessionState.READY)
    registry.transition(session_id, SessionState.RUNNING)

    owner = DebuggeeStateOwner(registry)
    owner.observe(session_id, {"state": "idle"}, debugger_pid=None)

    # idle collapses a running session through SUSPENDED and back to READY.
    assert registry.get(session_id).state is SessionState.READY
