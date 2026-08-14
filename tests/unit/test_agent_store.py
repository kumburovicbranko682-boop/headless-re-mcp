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

def test_every_capped_list_keeps_the_end_it_says_it_keeps(tmp_path: Path) -> None:
    """Pin which end of an over-full collection each list method returns.

    This is the contract the list_messages bug broke, and it broke invisibly:
    below the cap every one of these looks identical, so the first sign of
    trouble is an agent that has quietly stopped seeing anything recent. Each
    method is named here with the end it is supposed to keep, so changing one
    is a decision rather than an accident.
    """
    store = AgentStore(tmp_path / "ends.db")
    store.recover_after_restart()

    # A recency window: over the cap, the newest item must be present.
    thread = store.create_thread()
    for index in range(1, 61):
        store.add_message(thread.id, "user", f"message {index}")
    window = store.list_messages(thread.id, limit=10)
    assert [m.content for m in window] == [f"message {i}" for i in range(51, 61)], (
        "list_messages is a recency window and must end at the newest message"
    )

    # Also a recency window, ordered newest first.
    for _ in range(12):
        store.create_thread(title="later")
    newest_threads = store.list_threads(limit=5)
    assert len(newest_threads) == 5
    assert all(item.title == "later" for item in newest_threads), (
        "list_threads is newest-first, so a cap must drop the oldest"
    )

    # Missions are newest-first too.
    for index in range(1, 21):
        store.create_mission(thread.id, f"objective {index}")
    missions = store.list_missions(limit=3)
    assert [m.objective for m in missions] == [
        "objective 20",
        "objective 19",
        "objective 18",
    ], "list_missions is newest-first"

    # The queue is the exception, and deliberately so: it is FIFO.
    claimed = store.claim_next_mission()
    assert claimed is not None and claimed.objective == "objective 1", (
        "claim_next_mission takes the oldest, which is what makes it a queue"
    )

    # Events are a cursor page, not a window: they run forward from `after`.
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    for index in range(30):
        store.append_event(run.id, "message.delta", {"n": index})
    first_page = store.list_events(run.id, after=0, limit=5)
    assert [event.seq for event in first_page] == sorted(event.seq for event in first_page)
    assert first_page[0].seq < first_page[-1].seq, (
        "list_events pages forward from the cursor; the caller advances it"
    )
    second_page = store.list_events(run.id, after=first_page[-1].seq, limit=5)
    assert second_page[0].seq > first_page[-1].seq, "a cursor page must not repeat itself"

def test_a_failed_transaction_reports_what_failed_not_the_cleanup(tmp_path: Path) -> None:
    """The rollback must not become the error report.

    Seen for real when a soak filled the disk: BEGIN IMMEDIATE returned "disk
    I/O error", the rollback in the handler then raised "cannot rollback - no
    transaction is active" because no transaction had started, and that is what
    reached the incident log. The recorded cause described the cleanup and
    pointed nowhere near the disk -- on an unattended box, where that record is
    the only account anyone gets.
    """
    import sqlite3

    class BeginFails:
        """A connection whose BEGIN fails the way a full disk makes it fail."""

        def __init__(self, con: object) -> None:
            self._con = con

        def execute(self, sql: str, *args: object, **kwargs: object) -> object:
            if sql == "BEGIN IMMEDIATE":
                raise sqlite3.OperationalError("disk I/O error")
            return self._con.execute(sql, *args, **kwargs)  # type: ignore[attr-defined]

        def __getattr__(self, name: str) -> object:
            return getattr(self._con, name)

    store = AgentStore(tmp_path / "full.db")
    store.recover_after_restart()
    thread = store.create_thread()

    real_connect = store._connect
    store._connect = lambda: BeginFails(real_connect())  # type: ignore[assignment, return-value]

    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        store.create_mission(thread.id, "will not fit on disk")


def _finish_one(store: AgentStore, title: str) -> str:
    thread = store.create_thread(title=title)
    mission = store.create_mission(thread.id, "look")
    run = store.create_run(
        thread.id, provider_profile="p", model="m", deadline_seconds=30
    )
    store.transition(run.id, RunStatus.STREAMING)
    store.transition(run.id, RunStatus.COMPLETED)
    store.set_mission_status(mission.id, MissionStatus.COMPLETED)
    return thread.id


def test_a_run_error_is_clipped_like_a_mission_error(tmp_path: Path) -> None:
    """Mission errors already stop at 1000 characters; run errors did not.

    A 2 MiB failure string made the database 2.16 MB. The run still ends;
    only the stored text is cut.
    """
    store = AgentStore(tmp_path / "run-error.db")
    thread = store.create_thread()
    fat = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    store.transition(fat.id, RunStatus.STREAMING)
    store.transition(fat.id, RunStatus.FAILED, error="x" * 8192)
    got = store.get_run(fat.id)
    assert got is not None
    assert got.status is RunStatus.FAILED
    assert got.error == "x" * 1000

    thin = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    store.transition(thin.id, RunStatus.FAILED, error="short")
    assert store.get_run(thin.id).error == "short"


def test_oversized_tool_call_arguments_are_refused_not_stored(tmp_path: Path) -> None:
    """The orchestrator already refuses 256 KiB; the store itself did not.

    2 MiB of arguments made the database 2.16 MB. A truncated argument is a
    different instruction, so the write must fail and leave no row.
    """
    store = AgentStore(tmp_path / "args.db")
    store.tool_argument_max_bytes = 2048
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)

    with pytest.raises(ValueError, match="2048"):
        store.propose_tool_call(run.id, "call-fat", "static.functions", {"blob": "x" * 8192}, ["read"])

    with pytest.raises(KeyError):
        store.get_tool_call(run.id, "call-fat")
    store.propose_tool_call(run.id, "call-ok", "static.functions", {"session_id": "s"}, ["read"])
    assert store.get_tool_call(run.id, "call-ok")["name"] == "static.functions"


def test_a_run_event_too_large_to_store_is_cut_not_written_whole(tmp_path: Path) -> None:
    """Messages refuse 1 MiB and tool results cut at 256 KiB; events did neither.

    One 2 MiB delta made the database 2.16 MB, and list_events then handed the
    whole thing to SSE in a single frame.
    """
    store = AgentStore(tmp_path / "fat-event.db")
    store.event_data_max_bytes = 8_192
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    store.append_event(run.id, "message.delta", {"delta": "x" * (512 * 1024)})
    store.append_event(run.id, "message.delta", {"delta": "ok"})

    events = [event for event in store.list_events(run.id, after=0, limit=50) if event.type == "message.delta"]
    fat, thin = events
    assert fat.data["truncated"] is True
    assert fat.data["original_bytes"] > 8_192
    assert thin.data == {"delta": "ok"}
    assert store.path.stat().st_size < 100_000


def test_a_run_does_not_keep_every_streamed_delta(tmp_path: Path) -> None:
    """list_events pages at most 5000; the table itself did not stop writing.

    2000 deltas of 20 bytes were 414 KB and still climbing. A live mission
    keeps every run until it finishes, so a night of streamed tokens grew the
    file with a prefix no SSE client pages in one reply.
    """
    store = AgentStore(tmp_path / "events.db")
    store.retained_events_per_run = 5
    thread = store.create_thread()
    other = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    store.append_event(other.id, "message.delta", {"delta": "leave me"})
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    for index in range(12):
        store.append_event(run.id, "message.delta", {"n": index})

    remaining = store.list_events(run.id, after=0, limit=50)
    assert [event.data.get("n") for event in remaining] == [7, 8, 9, 10, 11]
    kept = store.list_events(other.id, after=0, limit=50)
    assert any(event.data.get("delta") == "leave me" for event in kept)


def test_a_live_thread_does_not_keep_every_message_it_ever_wrote(tmp_path: Path) -> None:
    """list_messages already windows at 2000; the table itself did not.

    1500 messages of 200 bytes were 831 KB and still climbing. A live mission
    is never finished-thread-trimmed, and each message may be 1 MiB, so a
    night of unattended turns would grow the file without anyone reading the
    dropped prefix.
    """
    store = AgentStore(tmp_path / "messages.db")
    store.retained_messages_per_thread = 5
    kept = store.create_thread(title="other")
    store.add_message(kept.id, "user", "leave me")
    thread = store.create_thread(title="live")
    for index in range(1, 13):
        store.add_message(thread.id, "user", f"message {index}")

    window = store.list_messages(thread.id, limit=50)
    assert [m.content for m in window] == [f"message {i}" for i in range(8, 13)]
    other = store.list_messages(kept.id, limit=50)
    assert [m.content for m in other] == ["leave me"]


def test_finished_threads_are_trimmed_and_live_ones_are_not(tmp_path: Path) -> None:
    """Every completed mission used to leave its thread in the database forever.

    Measured at 250 tiny missions: 459 KB and still climbing, about 1.8 KB each
    with almost no tool output. A night of unattended runs has no one to empty
    that table. Live missions and threads that have not started one stay.
    """
    store = AgentStore(tmp_path / "agent.db")
    store.retained_finished_threads = 3
    store.finished_trim_interval = 1

    idle = store.create_thread(title="inbox")
    live = store.create_thread(title="live")
    store.create_mission(live.id, "still going")

    finished = [_finish_one(store, f"done-{index}") for index in range(6)]

    remaining = {thread.id for thread in store.list_threads(limit=500)}
    assert idle.id in remaining, "a thread with no mission is an inbox, not history"
    assert live.id in remaining, "a pending mission must not be collected"
    assert remaining & set(finished) == set(finished[-3:]), (
        "only the newest finished threads survive"
    )
    assert len(remaining) == 5
