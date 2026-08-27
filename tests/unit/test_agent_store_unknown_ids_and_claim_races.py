"""AgentStore guards: unknown ids, decided approvals, and mission-claim races."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent import store as store_module
from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.store import AgentStore, canonical_args_sha256


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "agent.db")


def test_writes_against_an_unknown_thread_are_refused(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.add_message("no-such-thread", "user", "hello")
    with pytest.raises(KeyError):
        store.create_run("no-such-thread", provider_profile="p", model=None, deadline_seconds=60.0)
    with pytest.raises(KeyError):
        store.create_mission("no-such-thread", "objective")


def test_operations_against_an_unknown_run_or_mission_are_refused(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.transition("no-such-run", RunStatus.STREAMING)
    with pytest.raises(KeyError):
        store.request_cancel("no-such-run")
    with pytest.raises(KeyError):
        store.decide_tool_call("no-such-run", "no-such-call", "0" * 64, approved=True)
    # Consuming is the orchestrator's hot path; an unknown run is a quiet no,
    # not an exception, because the run may have been trimmed mid-flight.
    assert store.consume_approval("no-such-run", "call", "0" * 64) is False
    with pytest.raises(KeyError):
        store.set_mission_status("no-such-mission", MissionStatus.RUNNING)
    with pytest.raises(KeyError):
        store.cancel_mission("no-such-mission")


def test_a_thread_deleted_after_the_bind_commit_is_reported_missing(
    store: AgentStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The bind commits, then reads the thread back outside the transaction. A
    # concurrent delete_thread landing in between must surface as the same
    # KeyError the caller would have gotten a moment later, not as a None
    # smuggled into the return type.
    thread = store.create_thread()
    monkeypatch.setattr(store, "get_thread", lambda thread_id: None)

    with pytest.raises(KeyError):
        store.bind_thread_session(thread.id, "session-1")


def test_an_illegal_run_transition_is_refused(store: AgentStore) -> None:
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60.0)

    with pytest.raises(ValueError, match="illegal run transition"):
        store.transition(run.id, RunStatus.COMPLETED)


def test_cancelling_a_finished_run_does_not_rewrite_it(store: AgentStore) -> None:
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60.0)
    store.transition(run.id, RunStatus.FAILED, error="boom")

    cancelled = store.request_cancel(run.id)

    assert cancelled.status is RunStatus.FAILED
    assert cancelled.cancel_requested is False


def test_an_approval_cannot_be_decided_twice(store: AgentStore) -> None:
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60.0)
    arguments = {"path": "C:/sample.exe"}
    digest = canonical_args_sha256(arguments)
    store.propose_tool_call(run.id, "call-1", "unpack.run", arguments, ["state_change"])
    store.decide_tool_call(run.id, "call-1", digest, approved=True)

    with pytest.raises(ValueError, match="already decided or consumed"):
        store.decide_tool_call(run.id, "call-1", digest, approved=False)


def test_an_oversized_tool_result_is_stored_as_a_truncated_summary(store: AgentStore) -> None:
    # A tool result over the row cap must not be stored verbatim (the SSE
    # layer would then try to send it in one frame) nor dropped silently:
    # the summary keeps a prefix and says how large the original was.
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60.0)
    store.propose_tool_call(run.id, "call-1", "memory.read", {"n": 1}, ["read_only"])

    store.complete_tool_call(run.id, "call-1", {"blob": "x" * 300_000}, ok=True)

    stored = store.get_tool_call(run.id, "call-1")
    assert stored["result"]["truncated"] is True
    assert stored["result"]["original_bytes"] > 262_144


def test_missions_can_be_listed_by_status(store: AgentStore) -> None:
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "find the OEP")

    pending = store.list_missions(status=MissionStatus.PENDING)
    assert [item.id for item in pending] == [mission.id]
    assert store.list_missions(status=MissionStatus.CANCELLED) == []


def test_a_terminal_mission_refuses_a_new_status_and_a_second_cancel_is_a_no_op(
    store: AgentStore,
) -> None:
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "find the OEP")
    store.cancel_mission(mission.id)

    with pytest.raises(ValueError, match="already cancelled"):
        store.set_mission_status(mission.id, MissionStatus.RUNNING)

    again = store.cancel_mission(mission.id)
    assert again.status is MissionStatus.CANCELLED


def test_marking_cancel_by_run_id_alone_flags_just_that_run(store: AgentStore) -> None:
    # cancel_mission always passes the thread; the run-only form exists for
    # callers that know the exact run and nothing else about the thread.
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60.0)

    with store.transaction() as con:
        store._mark_runs_cancel_requested(con, run_id=run.id)

    refreshed = store.get_run(run.id)
    assert refreshed is not None
    assert refreshed.cancel_requested is True


class _Interfering:
    """Passthrough connection that runs one extra statement after a trigger.

    This is the interleaving a second scheduler process produces between two
    statements of the claim transaction.
    """

    def __init__(self, real: Any, trigger: str, interference: str) -> None:
        self._real = real
        self._trigger = trigger
        self._interference = interference
        self._fired = False

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        cursor = self._real.execute(sql, params)
        if not self._fired and sql.startswith(self._trigger):
            self._fired = True
            self._real.execute(self._interference)
        return cursor


def _interfere(
    store: AgentStore, monkeypatch: pytest.MonkeyPatch, trigger: str, interference: str
) -> None:
    original = store.transaction

    @contextmanager
    def wrapped() -> Iterator[Any]:
        with original() as con:
            yield _Interfering(con, trigger, interference)

    monkeypatch.setattr(store, "transaction", wrapped)


def test_a_claim_that_loses_the_update_race_comes_back_empty(
    store: AgentStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Another scheduler flips the mission to running between our SELECT and
    # our guarded UPDATE. The UPDATE matches nothing, and the claim must
    # report no work rather than hand both schedulers the same objective.
    thread = store.create_thread()
    store.create_mission(thread.id, "find the OEP")
    _interfere(
        store,
        monkeypatch,
        trigger="SELECT * FROM missions WHERE status=?",
        interference="UPDATE missions SET status='running'",
    )

    assert store.claim_next_mission() is None


def test_a_mission_deleted_after_the_claiming_update_comes_back_empty(
    store: AgentStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The claim succeeded, then the row vanished (an operator cancel that
    # trimmed terminal missions) before the read-back. Returning a mission
    # built from the stale pre-update row would resurrect deleted work.
    thread = store.create_thread()
    store.create_mission(thread.id, "find the OEP")
    _interfere(
        store,
        monkeypatch,
        trigger="UPDATE missions SET status=?,updated_at=? WHERE id=? AND status=?",
        interference="DELETE FROM missions",
    )

    assert store.claim_next_mission() is None


def test_a_claim_never_returns_a_mission_the_terminal_set_disowns(
    store: AgentStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Belt over braces: whatever the terminal set says -- including a future
    # edit that overlaps it with the claimable states -- claim must never
    # hand out a mission it itself considers finished.
    thread = store.create_thread()
    store.create_mission(thread.id, "find the OEP")
    monkeypatch.setattr(
        store_module, "TERMINAL_MISSION_STATUSES", frozenset({MissionStatus.PENDING})
    )

    assert store.claim_next_mission() is None
