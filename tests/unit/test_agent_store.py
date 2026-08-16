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


def test_a_streamed_run_does_not_keep_every_event_on_disk(tmp_path: Path) -> None:
    """The event page was capped; the table itself was not.

    Measured: 80 message.delta rows of 20_000 characters, plus the run.started
    create_run writes, left the database at 1_703_936 bytes and list_events
    still returned all 81. A streamed unattended run writes one row per token.
    """
    import sqlite3

    path = tmp_path / "events.db"
    store = AgentStore(path)
    store.event_retained_rows = 20
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=30)
    payload = {"delta": "y" * 20_000}
    for _ in range(80):
        store.append_event(run.id, "message.delta", payload)

    listed = store.list_events(run.id, after=0, limit=5000)
    assert len(listed) == 20
    with sqlite3.connect(path) as con:
        stored = con.execute("SELECT COUNT(*) FROM run_events WHERE run_id=?", (run.id,)).fetchone()[0]
    assert stored == 20, "the write path must drop rows, not only hide them from list_events"
    assert listed[-1].seq == 81, "the newest event must survive"
    assert path.stat().st_size < 800_000, (
        f"bounded run still filled the file: {path.stat().st_size} bytes"
    )


def test_a_long_thread_does_not_keep_every_message_on_disk(tmp_path: Path) -> None:
    """The read window was capped; the table itself was not.

    Measured: 80 messages of 50_000 characters left agent.db at 4_091_904 bytes
    and list_messages(limit=2000) still returned all 80. An unattended mission
    writes on every turn, so the file only grew. The store now drops the oldest
    rows in the same transaction as the insert.
    """
    import sqlite3

    path = tmp_path / "grow.db"
    store = AgentStore(path)
    store.message_retained_rows = 20
    thread = store.create_thread()
    payload = "x" * 50_000
    for _ in range(80):
        store.add_message(thread.id, "user", payload)

    window = store.list_messages(thread.id, limit=2000)
    assert len(window) == 20
    with sqlite3.connect(path) as con:
        stored = con.execute("SELECT COUNT(*) FROM messages WHERE thread_id=?", (thread.id,)).fetchone()[0]
    assert stored == 20, "the write path must drop rows, not only hide them from list_messages"
    assert path.stat().st_size < 2_000_000, (
        f"bounded thread still filled the file: {path.stat().st_size} bytes"
    )


def test_a_long_run_does_not_keep_every_tool_call_on_disk(tmp_path: Path) -> None:
    """Each result was truncated; the table itself was not.

    Measured: 80 completed calls with a 20_000-character blob left agent.db
    at 1_703_936 bytes and COUNT(*) was still 80. An unattended run writes
    one row per tool, so the file only grew.
    """
    import sqlite3

    path = tmp_path / "tools.db"
    store = AgentStore(path)
    store.tool_call_retained_rows = 20
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=30)
    payload = {"blob": "x" * 20_000}
    for index in range(80):
        store.propose_tool_call(run.id, f"c{index}", "test.tool", {"i": index}, ["read_only"])
        store.complete_tool_call(run.id, f"c{index}", payload, ok=True)

    with sqlite3.connect(path) as con:
        stored = con.execute("SELECT COUNT(*) FROM tool_calls WHERE run_id=?", (run.id,)).fetchone()[0]
        newest = con.execute(
            "SELECT id FROM tool_calls WHERE run_id=? ORDER BY created_at DESC, id DESC LIMIT 1",
            (run.id,),
        ).fetchone()[0]
    assert stored == 20, "the write path must drop rows, not only hide them"
    assert newest == "c79", "the newest tool call must survive"
    assert path.stat().st_size < 800_000, (
        f"bounded run still filled the file: {path.stat().st_size} bytes"
    )


def test_an_oversized_failed_tool_result_keeps_its_verdict(tmp_path: Path) -> None:
    """The second cut dropped ok from result_json.

    Status was already 'failed', but anything that reads the stored result
    (SSE, a later run reconstructing the call) saw no ok and no error.
    Measured: 300 KiB backend_error stored, read back keys were only
    truncated / summary / original_bytes.
    """
    store = AgentStore(tmp_path / "cut.db")
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model="x", deadline_seconds=30)
    store.propose_tool_call(run.id, "c1", "test.tool", {}, ["read_only"])
    store.complete_tool_call(
        run.id,
        "c1",
        {
            "ok": False,
            "error": {"code": "backend_error", "message": "worker died"},
            "blob": "x" * 300_000,
        },
        ok=False,
    )
    got = store.get_tool_call(run.id, "c1")
    assert got["status"] == "failed"
    assert got["result"]["ok"] is False
    assert got["result"]["truncated"] is True
    assert got["result"]["error"]["code"] == "backend_error"