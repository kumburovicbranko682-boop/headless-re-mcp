"""Not-found, limit, and illegal-transition branches of the agent store.

The store is the durable backbone the scheduler and orchestrator drive; its
guards are what turn a vanished thread, a replayed approval, or an illegal run
transition into a clean error instead of a corrupt row. The happy lifecycle is
covered in ``test_agent_store.py``; this file drives the raise/return edges so
a missing parent or a double decision fails loudly rather than silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.store import AgentStore, canonical_args_sha256


def _store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "agent.db")


# --------------------------------------------------------------------------
# messages / runs
# --------------------------------------------------------------------------


def test_add_message_refuses_a_payload_over_one_mebibyte(tmp_path: Path) -> None:
    store = _store(tmp_path)
    thread = store.create_thread()
    with pytest.raises(ValueError, match="1 MiB"):
        store.add_message(thread.id, "user", "x" * (1_048_576 + 1))


def test_add_message_to_a_missing_thread_is_a_key_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError):
        store.add_message("no-such-thread", "user", "hi")


def test_create_run_on_a_missing_thread_is_a_key_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError):
        store.create_run(
            "no-such-thread", provider_profile="default", model=None, deadline_seconds=30
        )


def test_transition_of_a_missing_run_is_a_key_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError):
        store.transition("no-such-run", RunStatus.STREAMING)


def test_an_illegal_run_transition_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=30
    )
    # QUEUED must reach STREAMING before it can complete.
    with pytest.raises(ValueError, match="illegal run transition"):
        store.transition(run.id, RunStatus.COMPLETED)


# --------------------------------------------------------------------------
# tool-call approval lifecycle
# --------------------------------------------------------------------------


def _run(store: AgentStore) -> str:
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=30
    )
    store.transition(run.id, RunStatus.STREAMING)
    return run.id


def test_deciding_an_unknown_tool_call_is_a_key_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    with pytest.raises(KeyError):
        store.decide_tool_call(run_id, "no-such-call", "0" * 64, approved=True)


def test_deciding_a_tool_call_twice_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    args = {"session_id": "s"}
    proposed = store.propose_tool_call(run_id, "call-1", "dynamic.resume", args, ["state_change"])
    store.decide_tool_call(run_id, "call-1", proposed["args_sha256"], approved=True)
    with pytest.raises(ValueError, match="already decided"):
        store.decide_tool_call(run_id, "call-1", proposed["args_sha256"], approved=False)


def test_consuming_an_approval_for_a_missing_run_returns_false(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert store.consume_approval("no-such-run", "call-1", "0" * 64) is False


def test_complete_tool_call_truncates_an_oversized_result(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    args = {"session_id": "s"}
    store.propose_tool_call(run_id, "call-1", "dynamic.resume", args, ["state_change"])
    store.decide_tool_call(run_id, "call-1", canonical_args_sha256(args), approved=True)
    store.consume_approval(run_id, "call-1", canonical_args_sha256(args))

    store.complete_tool_call(run_id, "call-1", {"blob": "y" * 300_000}, ok=True)

    stored = store.get_tool_call(run_id, "call-1")
    assert stored["status"] == "completed"
    assert stored["result"]["truncated"] is True
    assert stored["result"]["original_bytes"] > 262_144


def test_complete_tool_call_stores_a_small_result_verbatim(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    args = {"session_id": "s"}
    store.propose_tool_call(run_id, "call-1", "dynamic.resume", args, ["state_change"])
    store.decide_tool_call(run_id, "call-1", canonical_args_sha256(args), approved=True)
    store.consume_approval(run_id, "call-1", canonical_args_sha256(args))

    store.complete_tool_call(run_id, "call-1", {"ok": True}, ok=False)

    stored = store.get_tool_call(run_id, "call-1")
    assert stored["status"] == "failed"
    assert stored["result"] == {"ok": True}


# --------------------------------------------------------------------------
# missions
# --------------------------------------------------------------------------


def test_create_mission_on_a_missing_thread_is_a_key_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError):
        store.create_mission("no-such-thread", "do the thing")


def test_list_missions_can_filter_by_status(tmp_path: Path) -> None:
    store = _store(tmp_path)
    thread = store.create_thread()
    store.create_mission(thread.id, "objective one")
    claimed = store.claim_next_mission()
    assert claimed is not None  # now RUNNING, so a PENDING filter excludes it

    assert store.list_missions(status=MissionStatus.PENDING) == []
    running = store.list_missions(status=MissionStatus.RUNNING)
    assert [m.id for m in running] == [claimed.id]


def test_set_status_on_a_missing_mission_is_a_key_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError):
        store.set_mission_status("no-such-mission", MissionStatus.RUNNING)


def test_set_status_refuses_to_move_a_terminal_mission(tmp_path: Path) -> None:
    store = _store(tmp_path)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "objective")
    store.set_mission_status(mission.id, MissionStatus.COMPLETED)
    with pytest.raises(ValueError, match="already completed"):
        store.set_mission_status(mission.id, MissionStatus.RUNNING)


def test_cancel_of_a_missing_mission_is_a_key_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError):
        store.cancel_mission("no-such-mission")


def test_cancel_flags_the_last_run_then_is_idempotent(tmp_path: Path) -> None:
    # A mission with a run in flight: cancel flips the mission terminal and
    # marks that run cancel-requested; a second cancel is a no-op read.
    store = _store(tmp_path)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "objective")
    run = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=30
    )
    store.note_mission_run(mission.id, run.id)

    cancelled = store.cancel_mission(mission.id)
    assert cancelled.status is MissionStatus.CANCELLED
    assert store.get_run(run.id).cancel_requested is True

    again = store.cancel_mission(mission.id)
    assert again.status is MissionStatus.CANCELLED
