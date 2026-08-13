from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.store import AgentStore, canonical_args_sha256


def test_agent_store_seq_approval_and_restart(tmp_path: Path) -> None:
    path = tmp_path / "agent.db"
    store = AgentStore(path)
    thread = store.create_thread(session_id="analysis-session")
    run = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    store.transition(run.id, RunStatus.STREAMING)
    first = store.append_event(run.id, "message.delta", {"delta": "a"})
    second = store.append_event(run.id, "message.delta", {"delta": "b"})
    assert second.seq == first.seq + 1

    arguments = {"session_id": "s", "value": 7}
    proposed = store.propose_tool_call(run.id, "call-1", "dynamic.resume", arguments, ["state_change"])
    assert proposed["args_sha256"] == canonical_args_sha256(arguments)
    with pytest.raises(ValueError, match="hash mismatch"):
        store.decide_tool_call(run.id, "call-1", "0" * 64, approved=True)
    store.decide_tool_call(run.id, "call-1", proposed["args_sha256"], approved=True)
    assert store.consume_approval(run.id, "call-1", proposed["args_sha256"])
    assert not store.consume_approval(run.id, "call-1", proposed["args_sha256"])

    reopened = AgentStore(path)
    reopened.recover_after_restart()
    interrupted = reopened.get_run(run.id)
    assert interrupted is not None and interrupted.status is RunStatus.INTERRUPTED
    events = reopened.list_events(run.id)
    assert [event.seq for event in events] == sorted({event.seq for event in events})


def test_tool_call_identity_is_run_scoped_and_arguments_are_redacted(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    first_thread = store.create_thread()
    second_thread = store.create_thread()
    first = store.create_run(
        first_thread.id,
        provider_profile="default",
        model="fake",
        deadline_seconds=30,
    )
    second = store.create_run(
        second_thread.id,
        provider_profile="default",
        model="fake",
        deadline_seconds=30,
    )
    for run in (first, second):
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.AWAITING_APPROVAL)

    first_args = {"nested": {"api_key": "first-secret"}, "value": 1}
    second_args = {"nested": {"api_key": "second-secret"}, "value": 2}
    first_call = store.propose_tool_call(
        first.id,
        "provider-reused-id",
        "dynamic.resume",
        first_args,
        ["state_change"],
    )
    second_call = store.propose_tool_call(
        second.id,
        "provider-reused-id",
        "dynamic.resume",
        second_args,
        ["state_change"],
    )

    store.decide_tool_call(
        first.id,
        "provider-reused-id",
        str(first_call["args_sha256"]),
        approved=True,
    )
    assert store.get_tool_call(first.id, "provider-reused-id")["approved"] is True
    assert store.get_tool_call(second.id, "provider-reused-id")["approved"] is None
    assert store.get_tool_call(first.id, "provider-reused-id")["arguments"] == {
        "nested": {"api_key": "***REDACTED***"},
        "value": 1,
    }
    assert store.get_tool_call(second.id, "provider-reused-id")["arguments"] == {
        "nested": {"api_key": "***REDACTED***"},
        "value": 2,
    }
    assert store.consume_approval(
        first.id,
        "provider-reused-id",
        str(first_call["args_sha256"]),
    )
    assert not store.consume_approval(
        second.id,
        "provider-reused-id",
        str(second_call["args_sha256"]),
    )


def test_the_message_window_keeps_the_recent_end_of_a_long_thread(tmp_path: Path) -> None:
    """A capped history has to be the latest messages, not the earliest.

    Returning the oldest `limit` froze a long thread at its 500th message: the
    orchestrator rebuilt that same stale conversation for the provider on every
    subsequent run, so the agent never saw a later turn on a thread that only
    grows -- which is what an unattended thread does.
    """
    store = AgentStore(tmp_path / "window.db")
    thread = store.create_thread()
    for index in range(1, 621):
        store.add_message(thread.id, "user", f"message {index}")

    window = store.list_messages(thread.id)

    assert len(window) == 500
    assert window[-1].content == "message 620", "the newest message must be present"
    assert window[0].content == "message 121", "the window slides, oldest first"
    assert [m.content for m in window] == [f"message {i}" for i in range(121, 621)]


def test_a_message_written_now_is_visible_on_an_already_long_thread(tmp_path: Path) -> None:
    """The scheduler reads back the marker its own run just wrote.

    With the window pinned to the oldest messages this returned nothing once a
    thread passed the cap, so every mission burned its full budget and was then
    reported as "objective not met" -- for an objective that had been met.
    """
    store = AgentStore(tmp_path / "marker.db")
    thread = store.create_thread()
    for index in range(700):
        store.add_message(thread.id, "user", f"filler {index}")

    store.add_message(thread.id, "assistant", "MISSION_COMPLETE done", run_id="run-xyz")

    mine = [m for m in store.list_messages(thread.id) if m.run_id == "run-xyz"]
    assert len(mine) == 1
    assert mine[0].content.startswith("MISSION_COMPLETE")


def test_a_short_thread_is_returned_whole(tmp_path: Path) -> None:
    """The window only bites past the cap; below it nothing is dropped."""
    store = AgentStore(tmp_path / "short.db")
    thread = store.create_thread()
    for index in range(5):
        store.add_message(thread.id, "user", f"m{index}")

    assert [m.content for m in store.list_messages(thread.id)] == ["m0", "m1", "m2", "m3", "m4"]
    assert [m.content for m in store.list_messages(thread.id, limit=2)] == ["m3", "m4"]

def test_opening_the_database_does_not_disturb_a_running_service(tmp_path: Path) -> None:
    """Reading the state of a live service must not be what stops it.

    recover_after_restart declares every non-terminal run dead and requeues
    every RUNNING mission. That is right for a process adopting an abandoned
    database and catastrophic for anything else, and it used to happen inside
    __init__ -- so an operator opening the database to see what the service was
    doing, or any second tool pointed at it, silently killed the work in flight.
    """
    path = tmp_path / "live.db"
    live = AgentStore(path)
    live.recover_after_restart()
    thread = live.create_thread()
    run = live.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=600)
    live.transition(run.id, RunStatus.STREAMING)
    mission = live.create_mission(thread.id, "in flight")
    live.claim_next_mission()

    observer = AgentStore(path)
    assert len(observer.list_missions(limit=10)) == 1, "the observer can still read"

    assert live.get_run(run.id).status is RunStatus.STREAMING
    assert live.get_mission(mission.id).status is MissionStatus.RUNNING


def test_recovery_is_still_available_and_still_adopts_orphans(tmp_path: Path) -> None:
    """Moving it out of __init__ must not have moved it out of reach."""
    path = tmp_path / "orphans.db"
    previous = AgentStore(path)
    thread = previous.create_thread()
    run = previous.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=600)
    previous.transition(run.id, RunStatus.STREAMING)
    mission = previous.create_mission(thread.id, "abandoned")
    previous.claim_next_mission()

    successor = AgentStore(path)
    adopted = successor.recover_after_restart()

    assert adopted == 1
    assert successor.get_run(run.id).status is RunStatus.INTERRUPTED
    assert successor.get_mission(mission.id).status is MissionStatus.PENDING