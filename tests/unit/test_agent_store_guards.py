"""Guard branches of the agent store that the flow-driven suites never hit.

test_agent_store.py and its siblings drive complete happy flows -- create a
thread, run it, approve a call, finish a mission -- so the identity guards
(an unknown thread, run, mission, or tool call), the illegal-state rejections
(a second decision on a decided approval, a transition the run state machine
forbids, a status change on a finished mission), and the terminal no-ops
(cancelling what already ended) stay unexecuted. Those are the branches that
decide whether a caller holding a stale id gets a clean KeyError or a silent
half-write. This file pins each one against a real SQLite-backed store.

The claim-race arms inside claim_next_mission and bind_thread_session are
deliberately not covered here: they only fire when a second writer interleaves
mid-transaction, which a single-threaded unit test cannot arrange honestly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.store import AgentStore, canonical_args_sha256


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "agent.db")


def _run(store: AgentStore) -> tuple[str, str]:
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    return thread.id, run.id


def _approved_call(store: AgentStore, run_id: str, call_id: str = "call-1") -> str:
    proposed = store.propose_tool_call(run_id, call_id, "dynamic.step", {"n": 1}, [])
    sha = str(proposed["args_sha256"])
    store.decide_tool_call(run_id, call_id, sha, approved=True)
    return sha


# --------------------------------------------------------------------------- #
# unknown-identity guards: a stale id must raise, not half-write              #
# --------------------------------------------------------------------------- #
def test_adding_a_message_to_an_unknown_thread_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.add_message("no-such-thread", "user", "hello")


def test_creating_a_run_on_an_unknown_thread_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.create_run(
            "no-such-thread", provider_profile="default", model=None, deadline_seconds=30
        )


def test_transitioning_an_unknown_run_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.transition("no-such-run", RunStatus.STREAMING)


def test_deciding_an_unknown_tool_call_raises(store: AgentStore) -> None:
    _, run_id = _run(store)
    with pytest.raises(KeyError):
        store.decide_tool_call(run_id, "no-such-call", "0" * 64, approved=True)


def test_cancelling_an_unknown_run_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.request_cancel("no-such-run")


def test_creating_a_mission_on_an_unknown_thread_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.create_mission("no-such-thread", "find the OEP")


def test_setting_status_on_an_unknown_mission_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.set_mission_status("no-such-mission", MissionStatus.COMPLETED)


def test_cancelling_an_unknown_mission_raises(store: AgentStore) -> None:
    with pytest.raises(KeyError):
        store.cancel_mission("no-such-mission")


# --------------------------------------------------------------------------- #
# run state machine                                                           #
# --------------------------------------------------------------------------- #
def test_an_illegal_run_transition_is_rejected_and_leaves_the_run_alone(
    store: AgentStore,
) -> None:
    """QUEUED cannot jump straight to COMPLETED; the row must not move either."""
    _, run_id = _run(store)
    with pytest.raises(ValueError, match="illegal run transition: queued->completed"):
        store.transition(run_id, RunStatus.COMPLETED)
    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.QUEUED


def test_cancelling_a_terminal_run_is_a_noop(store: AgentStore) -> None:
    """A cancel after the run ended must not resurrect the cancel flag."""
    _, run_id = _run(store)
    store.transition(run_id, RunStatus.CANCELLED)

    run = store.request_cancel(run_id)

    assert run.status is RunStatus.CANCELLED
    assert run.cancel_requested is False


# --------------------------------------------------------------------------- #
# approval lifecycle guards                                                   #
# --------------------------------------------------------------------------- #
def test_a_second_decision_on_a_decided_approval_is_rejected(store: AgentStore) -> None:
    _, run_id = _run(store)
    sha = _approved_call(store, run_id)
    with pytest.raises(ValueError, match="already decided"):
        store.decide_tool_call(run_id, "call-1", sha, approved=False)
    call = store.get_tool_call(run_id, "call-1")
    assert call["approved"] is True, "the rejected re-decision must not flip the verdict"


def test_an_approval_cannot_be_consumed_for_a_missing_run(store: AgentStore) -> None:
    assert store.consume_approval("no-such-run", "call-1", "0" * 64) is False


def test_an_approval_cannot_be_consumed_once_the_run_ended(store: AgentStore) -> None:
    """The approval was granted, but the run finished first: execution must not start."""
    _, run_id = _run(store)
    sha = _approved_call(store, run_id)
    store.transition(run_id, RunStatus.CANCELLED)

    assert store.consume_approval(run_id, "call-1", sha) is False
    assert store.get_tool_call(run_id, "call-1")["consumed_at"] is None


# --------------------------------------------------------------------------- #
# oversized tool results are truncated honestly                               #
# --------------------------------------------------------------------------- #
def test_an_oversized_tool_result_is_stored_as_a_marked_summary(store: AgentStore) -> None:
    """A result past the 256 KiB cap must say so instead of ballooning the row."""
    _, run_id = _run(store)
    sha = _approved_call(store, run_id)
    store.transition(run_id, RunStatus.STREAMING)
    assert store.consume_approval(run_id, "call-1", sha) is True

    store.complete_tool_call(run_id, "call-1", {"blob": "x" * 300_000}, ok=True)

    stored = store.get_tool_call(run_id, "call-1")["result"]
    assert stored["truncated"] is True
    assert stored["original_bytes"] > 262_144
    assert len(stored["summary"]) <= 16_384
    assert stored["summary"].startswith('{"blob"')


# --------------------------------------------------------------------------- #
# mission status guards and filtered listing                                  #
# --------------------------------------------------------------------------- #
def _mission(store: AgentStore) -> str:
    thread = store.create_thread()
    return store.create_mission(thread.id, "unpack the sample").id


def test_a_finished_mission_refuses_a_different_status(store: AgentStore) -> None:
    mission_id = _mission(store)
    store.set_mission_status(mission_id, MissionStatus.COMPLETED)
    with pytest.raises(ValueError, match="already completed"):
        store.set_mission_status(mission_id, MissionStatus.FAILED)
    mission = store.get_mission(mission_id)
    assert mission is not None and mission.status is MissionStatus.COMPLETED


def test_restating_the_same_terminal_status_is_allowed(store: AgentStore) -> None:
    """Idempotent completion: a retried COMPLETED write must not raise."""
    mission_id = _mission(store)
    store.set_mission_status(mission_id, MissionStatus.COMPLETED)
    mission = store.set_mission_status(mission_id, MissionStatus.COMPLETED)
    assert mission.status is MissionStatus.COMPLETED


def test_cancelling_a_finished_mission_leaves_its_outcome_alone(store: AgentStore) -> None:
    """cancel_mission after completion must not rewrite history to 'cancelled'."""
    mission_id = _mission(store)
    store.set_mission_status(mission_id, MissionStatus.COMPLETED)

    mission = store.cancel_mission(mission_id)

    assert mission.status is MissionStatus.COMPLETED
    assert mission.error is None


def test_listing_missions_by_status_returns_only_that_status(store: AgentStore) -> None:
    pending_id = _mission(store)
    finished_id = _mission(store)
    store.set_mission_status(finished_id, MissionStatus.COMPLETED)

    pending = store.list_missions(status=MissionStatus.PENDING)
    completed = store.list_missions(status=MissionStatus.COMPLETED)

    assert [mission.id for mission in pending] == [pending_id]
    assert [mission.id for mission in completed] == [finished_id]


# --------------------------------------------------------------------------- #
# the canonical hash used by every guard above                                #
# --------------------------------------------------------------------------- #
def test_the_decision_hash_must_match_what_was_proposed(store: AgentStore) -> None:
    """A decision carrying different arguments than proposed is a mismatch."""
    _, run_id = _run(store)
    proposed = store.propose_tool_call(run_id, "call-1", "dynamic.step", {"n": 1}, [])
    tampered = canonical_args_sha256({"n": 2})
    assert tampered != proposed["args_sha256"]
    with pytest.raises(ValueError, match="hash mismatch"):
        store.decide_tool_call(run_id, "call-1", tampered, approved=True)
