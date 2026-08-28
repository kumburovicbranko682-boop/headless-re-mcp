"""Error guards and rarely-hit branches of the Agent persistence store."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.store import AgentStore

JsonObject = dict[str, Any]


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "agent.db")


def _run(store: AgentStore) -> str:
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=30.0
    )
    return run.id


# ---------------------------------------------------------------------------
# thread / message / run guards


def test_binding_or_messaging_an_unknown_thread_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.bind_thread_session("nope", "session-1")
    with pytest.raises(KeyError):
        store.add_message("nope", "user", "hi")
    with pytest.raises(KeyError):
        store.delete_thread("nope")


def test_creating_a_run_on_an_unknown_thread_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.create_run("nope", provider_profile="default", model="fake", deadline_seconds=30.0)


def test_a_message_over_one_mebibyte_is_refused(store: AgentStore) -> None:
    thread = store.create_thread()
    with pytest.raises(ValueError, match="exceeds 1 MiB"):
        store.add_message(thread.id, "user", "x" * (1_048_576 + 1))


def test_bind_then_clear_reports_the_session_and_then_none(store: AgentStore) -> None:
    thread = store.create_thread()
    bound = store.bind_thread_session(thread.id, "analysis-7")
    assert bound.session_id == "analysis-7"
    cleared = store.bind_thread_session(thread.id, None)
    assert cleared.session_id is None


def test_transitioning_a_missing_run_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.transition("nope", RunStatus.STREAMING)


def test_an_illegal_run_transition_is_refused(store: AgentStore) -> None:
    run_id = _run(store)
    # QUEUED may only go to STREAMING or a terminal state, never straight to
    # EXECUTING_TOOL.
    with pytest.raises(ValueError, match="illegal run transition"):
        store.transition(run_id, RunStatus.EXECUTING_TOOL)


def test_a_transition_to_the_same_status_is_a_no_op_not_an_error(store: AgentStore) -> None:
    run_id = _run(store)
    same = store.transition(run_id, RunStatus.QUEUED)
    assert same.status is RunStatus.QUEUED


# ---------------------------------------------------------------------------
# request_cancel


def test_request_cancel_on_a_missing_run_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.request_cancel("nope")


def test_request_cancel_leaves_a_terminal_run_untouched(store: AgentStore) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    store.transition(run_id, RunStatus.COMPLETED)

    dumped = store.request_cancel(run_id)

    assert dumped.status is RunStatus.COMPLETED
    assert dumped.cancel_requested is False


# ---------------------------------------------------------------------------
# tool-call decision guards


def test_deciding_an_unknown_tool_call_raises(store: AgentStore) -> None:
    run_id = _run(store)
    with pytest.raises(KeyError):
        store.decide_tool_call(run_id, "ghost", "0" * 64, approved=True)


def test_a_tool_call_cannot_be_decided_twice(store: AgentStore) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "dynamic.resume", {"x": 1}, ["state_change"])
    sha = proposed["args_sha256"]
    store.decide_tool_call(run_id, "c1", sha, approved=True)

    with pytest.raises(ValueError, match="already decided or consumed"):
        store.decide_tool_call(run_id, "c1", sha, approved=False)


def test_a_completed_unattended_call_cannot_be_decided_afterwards(store: AgentStore) -> None:
    """decide() must not rewrite history for a call that already ran.

    Auto-approved and read-only calls keep ``approved``/``consumed_at`` NULL,
    so the "already decided or consumed" guard never fired for them: a decide
    arriving after completion was accepted, flipping the status back to
    approved/rejected while the stored result proved the work had run
    (verified before the fix -- the row read ``rejected`` with its result kept).
    """
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "static.strings", {"x": 1}, ["read_only"])
    store.complete_tool_call(run_id, "c1", {"ok": True, "data": {}}, ok=True)

    with pytest.raises(ValueError, match="already started or finished"):
        store.decide_tool_call(run_id, "c1", str(proposed["args_sha256"]), approved=False)

    after = store.get_tool_call(run_id, "c1")
    assert after["status"] == "completed"
    assert after["approved"] is None


def test_begin_unattended_execution_blocks_decides_while_the_tool_runs(
    store: AgentStore,
) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "dynamic.resume", {"x": 1}, ["state_change"])
    sha = str(proposed["args_sha256"])

    assert store.begin_unattended_execution(run_id, "c1", sha) is True

    row = store.get_tool_call(run_id, "c1")
    assert row["status"] == "executing"
    assert row["consumed_at"] is not None
    # No human decided, and none may pretend to have afterwards.
    assert row["approved"] is None
    with pytest.raises(ValueError, match="already decided or consumed"):
        store.decide_tool_call(run_id, "c1", sha, approved=False)


def test_begin_unattended_execution_yields_to_a_human_veto(store: AgentStore) -> None:
    """A rejection landing in the propose->execute window wins over the grant."""
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "dynamic.resume", {"x": 1}, ["state_change"])
    sha = str(proposed["args_sha256"])
    store.decide_tool_call(run_id, "c1", sha, approved=False)

    assert store.begin_unattended_execution(run_id, "c1", sha) is False


def test_begin_unattended_execution_proceeds_past_a_redundant_human_approval(
    store: AgentStore,
) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "dynamic.resume", {"x": 1}, ["state_change"])
    sha = str(proposed["args_sha256"])
    store.decide_tool_call(run_id, "c1", sha, approved=True)

    assert store.begin_unattended_execution(run_id, "c1", sha) is True


def test_begin_unattended_execution_is_false_for_missing_mismatched_or_cancelled(
    store: AgentStore,
) -> None:
    assert store.begin_unattended_execution("nope", "c1", "0" * 64) is False

    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "dynamic.resume", {"x": 1}, ["state_change"])
    sha = str(proposed["args_sha256"])
    assert store.begin_unattended_execution(run_id, "c1", "0" * 64) is False
    assert store.begin_unattended_execution(run_id, "c1", sha) is True
    # Already consumed: a second begin must not re-enter.
    assert store.begin_unattended_execution(run_id, "c1", sha) is False

    other = _run(store)
    store.transition(other, RunStatus.STREAMING)
    queued = store.propose_tool_call(other, "c2", "dynamic.resume", {"x": 1}, ["state_change"])
    store.request_cancel(other)
    assert store.begin_unattended_execution(other, "c2", str(queued["args_sha256"])) is False


def test_consume_approval_is_false_for_terminal_cancelled_or_unapproved_calls(
    store: AgentStore,
) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "dynamic.resume", {"x": 1}, ["state_change"])
    sha = str(proposed["args_sha256"])

    # Proposed but never approved: nothing to consume.
    assert store.consume_approval(run_id, "c1", sha) is False

    # A hash that does not match the stored one is refused even once approved.
    store.decide_tool_call(run_id, "c1", sha, approved=True)
    assert store.consume_approval(run_id, "c1", "0" * 64) is False

    # A cancel request blocks the consume even though approval stands.
    store.request_cancel(run_id)
    assert store.consume_approval(run_id, "c1", sha) is False


def test_consume_approval_is_false_once_the_run_is_terminal(store: AgentStore) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "dynamic.resume", {"x": 1}, ["state_change"])
    sha = str(proposed["args_sha256"])
    store.decide_tool_call(run_id, "c1", sha, approved=True)
    store.transition(run_id, RunStatus.FAILED, error="x")

    assert store.consume_approval(run_id, "c1", sha) is False


def test_consume_approval_is_false_for_a_missing_run(store: AgentStore) -> None:
    assert store.consume_approval("nope", "c1", "0" * 64) is False


def test_getting_an_unknown_tool_call_raises(store: AgentStore) -> None:
    run_id = _run(store)
    with pytest.raises(KeyError):
        store.get_tool_call(run_id, "ghost")


# ---------------------------------------------------------------------------
# complete_tool_call oversize summarisation


def test_an_oversized_tool_result_is_summarised_not_stored_whole(store: AgentStore) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "test.read", {}, ["read_only"])
    sha = str(proposed["args_sha256"])
    store.decide_tool_call(run_id, "c1", sha, approved=True)

    huge = {"ok": True, "data": {"blob": "x" * 300_000}}
    store.complete_tool_call(run_id, "c1", huge, ok=True)

    stored = store.get_tool_call(run_id, "c1")
    assert stored["result"]["truncated"] is True
    assert stored["result"]["original_bytes"] > 262_144
    assert len(stored["result"]["summary"]) <= 16_384


def test_a_small_tool_result_is_stored_verbatim(store: AgentStore) -> None:
    run_id = _run(store)
    store.transition(run_id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run_id, "c1", "test.read", {}, ["read_only"])
    store.decide_tool_call(run_id, "c1", str(proposed["args_sha256"]), approved=True)

    store.complete_tool_call(run_id, "c1", {"ok": True, "data": {"value": 7}}, ok=True)

    stored = store.get_tool_call(run_id, "c1")
    assert stored["result"] == {"ok": True, "data": {"value": 7}}
    assert stored["status"] == "completed"


# ---------------------------------------------------------------------------
# mission guards


def test_creating_a_mission_on_an_unknown_thread_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.create_mission("nope", "reverse the target")


def test_setting_status_on_a_missing_mission_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.set_mission_status("nope", MissionStatus.COMPLETED)


def test_a_terminal_mission_cannot_be_moved_to_another_status(store: AgentStore) -> None:
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "objective")
    store.set_mission_status(mission.id, MissionStatus.COMPLETED)

    with pytest.raises(ValueError, match="already completed"):
        store.set_mission_status(mission.id, MissionStatus.FAILED)


def test_re_marking_a_terminal_mission_with_the_same_status_is_allowed(
    store: AgentStore,
) -> None:
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "objective")
    store.set_mission_status(mission.id, MissionStatus.COMPLETED)

    again = store.set_mission_status(mission.id, MissionStatus.COMPLETED)
    assert again.status is MissionStatus.COMPLETED


def test_cancelling_a_missing_mission_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.cancel_mission("nope")


def test_cancelling_a_running_mission_also_flags_its_last_run(store: AgentStore) -> None:
    """cancel_mission marks the mission's recorded last_run_id cancel_requested."""
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "objective")
    run = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=30.0
    )
    store.note_mission_run(mission.id, run.id)

    cancelled = store.cancel_mission(mission.id)

    assert cancelled.status is MissionStatus.CANCELLED
    flagged = store.get_run(run.id)
    assert flagged is not None and flagged.cancel_requested is True


def test_cancelling_an_already_terminal_mission_leaves_it_alone(store: AgentStore) -> None:
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "objective")
    store.set_mission_status(mission.id, MissionStatus.COMPLETED)

    cancelled = store.cancel_mission(mission.id)

    assert cancelled.status is MissionStatus.COMPLETED
    assert cancelled.error is None


def test_list_missions_filters_by_status(store: AgentStore) -> None:
    thread = store.create_thread()
    done = store.create_mission(thread.id, "finished objective")
    store.set_mission_status(done.id, MissionStatus.COMPLETED)
    store.create_mission(thread.id, "pending objective")

    pending = store.list_missions(status=MissionStatus.PENDING)
    succeeded = store.list_missions(status=MissionStatus.COMPLETED)

    assert [m.objective for m in pending] == ["pending objective"]
    assert [m.objective for m in succeeded] == ["finished objective"]


def test_claim_next_mission_takes_the_oldest_pending_and_then_none(
    store: AgentStore,
) -> None:
    thread = store.create_thread()
    first = store.create_mission(thread.id, "first")
    store.create_mission(thread.id, "second")

    claimed = store.claim_next_mission()
    assert claimed is not None and claimed.id == first.id
    assert claimed.status is MissionStatus.RUNNING

    store.claim_next_mission()  # claim the second so none stay pending
    assert store.claim_next_mission() is None


# ---------------------------------------------------------------------------
# bind_thread_session post-update read guard (defensive KeyError)


def test_bind_thread_session_raises_if_the_row_vanishes_mid_update(
    store: AgentStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row is checked inside the transaction; a concurrent delete between
    the update and the read-back is the one path that returns None here."""
    thread = store.create_thread()
    monkeypatch.setattr(store, "get_thread", lambda thread_id: None)

    with pytest.raises(KeyError):
        store.bind_thread_session(thread.id, "session-1")
