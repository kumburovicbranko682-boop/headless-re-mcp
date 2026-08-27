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
