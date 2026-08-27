from __future__ import annotations

import json
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


def test_list_events_page_cut_by_bytes_is_visible_via_has_events_after(
    tmp_path: Path,
) -> None:
    """A byte-capped event page must not read as the whole history.

    list_events bounds a page by count and by serialized bytes. When the byte
    cap trims the page, the events beyond it still exist and are retrievable, so
    has_events_after has to report they are there -- otherwise a client handed a
    full page cannot tell a complete run from one it only saw the start of.
    """
    store = AgentStore(tmp_path / "events.db")
    store.event_page_max_bytes = 1024
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=30
    )
    for index in range(50):
        store.append_event(run.id, "message.delta", {"delta": "x" * 200, "n": index})

    page = store.list_events(run.id)
    assert page  # the first row is always kept
    assert len(page) < 50  # the byte cap cut the page short
    last_seq = page[-1].seq
    assert store.has_events_after(run.id, last_seq) is True

    # Draining to the end flips has_more off, so a caller knows when to stop.
    cursor = last_seq
    while store.has_events_after(run.id, cursor):
        nxt = store.list_events(run.id, after=cursor)
        assert nxt
        cursor = nxt[-1].seq
    assert store.has_events_after(run.id, cursor) is False


def test_list_missions_pages_and_reports_the_true_total(tmp_path: Path) -> None:
    """A capped mission page must expose the total so it is not read as the queue.

    The mission queue is durable and can outgrow a single page. Without a total
    and an offset, the page size reads as the whole queue and missions past the
    cap are unreachable.
    """
    store = AgentStore(tmp_path / "missions.db")
    thread = store.create_thread()
    made = [
        store.create_mission(thread.id, f"objective {index}", max_runs=2)
        for index in range(3)
    ]

    assert store.count_missions() == 3

    first = store.list_missions(limit=2, offset=0)
    assert len(first) == 2
    second = store.list_missions(limit=2, offset=2)
    assert len(second) == 1
    # No overlap, and every mission is reachable across the two pages.
    assert {mission.id for mission in (*first, *second)} == {m.id for m in made}

    # A status filter counts within that status only, so has_more stays honest
    # per filter rather than against the whole queue.
    store.set_mission_status(made[0].id, MissionStatus.CANCELLED)
    assert store.count_missions(status=MissionStatus.CANCELLED) == 1
    assert store.count_missions(status=MissionStatus.PENDING) == 2


def test_canonical_args_hash_is_key_order_independent() -> None:
    """The approval gate compares two independently computed hashes.

    The orchestrator hashes the arguments it proposed; the console hashes the
    arguments it reconstructs to approve. Both call canonical_args_sha256, so
    the hash must depend on the argument *values*, not on the key order a JSON
    serializer happened to use -- otherwise a reordered but identical payload
    would fail the mismatch check and block a legitimate approval. Nesting must
    canonicalize too, and a genuinely different value must still differ.
    """
    a = {"session_id": "s", "value": 7, "opts": {"x": 1, "y": 2}}
    reordered = {"opts": {"y": 2, "x": 1}, "value": 7, "session_id": "s"}
    assert canonical_args_sha256(a) == canonical_args_sha256(reordered)

    changed = {"session_id": "s", "value": 8, "opts": {"x": 1, "y": 2}}
    assert canonical_args_sha256(a) != canonical_args_sha256(changed)


def test_a_reordered_argument_payload_still_approves_the_call(tmp_path: Path) -> None:
    """End-to-end: recomputing the hash on reordered args matches the stored one."""
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread(session_id="s")
    run = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    store.transition(run.id, RunStatus.STREAMING)

    proposed = store.propose_tool_call(
        run.id, "call-1", "dynamic.resume", {"session_id": "s", "value": 7}, ["state_change"]
    )
    # A client that rebuilt the same arguments in a different key order arrives
    # at the identical canonical hash the store recorded, so approval matches.
    client_hash = canonical_args_sha256({"value": 7, "session_id": "s"})
    assert client_hash == proposed["args_sha256"]
    decided = store.decide_tool_call(run.id, "call-1", client_hash, approved=True)
    assert decided["approved"] is True
    assert store.consume_approval(run.id, "call-1", client_hash)


def test_list_thread_events_keeps_finished_run_history(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "thread-events.db")
    thread = store.create_thread()
    other = store.create_thread()
    first = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    second = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    stray = store.create_run(other.id, provider_profile="default", model="fake", deadline_seconds=30)
    store.append_event(first.id, "llm.started", {"round": 1})
    store.append_event(second.id, "llm.started", {"round": 1})
    store.append_event(stray.id, "llm.started", {"round": 9})
    store.transition(first.id, RunStatus.STREAMING)
    store.transition(first.id, RunStatus.COMPLETED)
    listed = store.list_thread_events(thread.id)
    assert [event.type for event in listed].count("llm.started") == 2
    assert all(event.run_id != stray.id for event in listed)
    dumped = listed[0].dump()
    assert isinstance(dumped.get("created_ms"), int)
    assert dumped["created_ms"] > 0


def test_count_thread_events_totals_every_run_and_stops_at_the_thread(tmp_path: Path) -> None:
    """The event window spans a thread's runs; the count is all of them.

    list_thread_events returns a newest window capped by count and by bytes, so
    a busy thread's full page reads as the whole run log. count_thread_events
    gives the total behind that window, and only for this thread's runs. When
    nothing is capped the count matches an unbounded listing exactly.
    """
    store = AgentStore(tmp_path / "count-thread-events.db")
    thread = store.create_thread()
    other = store.create_thread()
    first = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=30)
    second = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=30)
    stray = store.create_run(other.id, provider_profile="p", model=None, deadline_seconds=30)
    for index in range(4):
        store.append_event(first.id, "message.delta", {"n": index})
    for index in range(3):
        store.append_event(second.id, "message.delta", {"n": index})
    store.append_event(stray.id, "message.delta", {"n": 0})

    # Nothing is capped here, so the count is exactly what a full listing holds.
    assert store.count_thread_events(thread.id) == len(
        store.list_thread_events(thread.id, limit=8000)
    )
    assert store.count_thread_events(other.id) == len(
        store.list_thread_events(other.id, limit=8000)
    )
    # The thread's own runs carry more events than the single stray run, and the
    # stray run's events never fall inside this thread's total.
    assert store.count_thread_events(thread.id) > store.count_thread_events(other.id)
    assert all(event.run_id != stray.id for event in store.list_thread_events(thread.id))


def test_count_thread_events_exceeds_a_byte_capped_window(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "count-thread-events-bytes.db")
    store.event_page_max_bytes = 2048
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=30)
    for index in range(20):
        store.append_event(run.id, "message.delta", {"index": index, "delta": "x" * 500})

    window = store.list_thread_events(thread.id, limit=8000)
    total = store.count_thread_events(thread.id)
    assert len(window) < total
    # 20 deltas plus the run.started event create_run appends.
    assert total == 21


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


def test_count_messages_reports_the_total_a_capped_window_hides(tmp_path: Path) -> None:
    """The message window is a newest slice; the count is the whole thread.

    A caller handed a full page cannot tell a complete thread from one the cap
    cut short. count_messages answers that so the thread endpoint can flag the
    window as truncated instead of passing a slice off as the conversation.
    """
    store = AgentStore(tmp_path / "count-messages.db")
    store.retained_messages_per_thread = 100
    thread = store.create_thread()
    for index in range(40):
        store.add_message(thread.id, "user", f"message {index}")

    assert store.count_messages(thread.id) == 40
    window = store.list_messages(thread.id, limit=10)
    assert len(window) == 10
    assert store.count_messages(thread.id) > len(window)


def test_count_messages_is_scoped_to_its_own_thread(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "count-scope.db")
    mine = store.create_thread()
    other = store.create_thread()
    for index in range(3):
        store.add_message(mine.id, "user", f"m{index}")
    store.add_message(other.id, "user", "not mine")

    assert store.count_messages(mine.id) == 3
    assert store.count_messages(other.id) == 1

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


def test_oversized_tool_call_effects_are_refused_not_stored(tmp_path: Path) -> None:
    """Arguments already refuse 4 MiB; effects_json did not.

    Measured: 2000 labels of 1000 characters made the database 2.07 MB. A
    truncated effects list is a different permission set, so the write must
    fail and leave no row.
    """
    store = AgentStore(tmp_path / "effects.db")
    store.tool_effects_max_bytes = 256
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)

    with pytest.raises(ValueError, match="256"):
        store.propose_tool_call(
            run.id,
            "call-fat",
            "static.functions",
            {"session_id": "s"},
            ["x" * 80] * 8,
        )

    with pytest.raises(KeyError):
        store.get_tool_call(run.id, "call-fat")
    store.propose_tool_call(run.id, "call-ok", "static.functions", {"session_id": "s"}, ["read"])
    assert store.get_tool_call(run.id, "call-ok")["effects"] == ["read"]
    assert store.path.stat().st_size < 200_000


def test_oversized_tool_call_names_are_refused_not_stored(tmp_path: Path) -> None:
    """Arguments and effects already refuse oversized payloads; the name did not.

    Measured: a 100,000 character name was stored and grew the database by
    about 100 KB in one call. Truncating it would point at a different tool,
    so the write must fail and leave no row.
    """
    store = AgentStore(tmp_path / "name.db")
    store.tool_name_max_chars = 32
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)

    with pytest.raises(ValueError, match="32"):
        store.propose_tool_call(run.id, "call-fat", "n" * 80, {"session_id": "s"}, ["read"])

    with pytest.raises(KeyError):
        store.get_tool_call(run.id, "call-fat")
    store.propose_tool_call(run.id, "call-ok", "static.functions", {"session_id": "s"}, ["read"])
    assert store.get_tool_call(run.id, "call-ok")["name"] == "static.functions"


def test_oversized_tool_call_ids_are_refused_not_stored(tmp_path: Path) -> None:
    """The name already refuses 128 characters; the row id did not.

    Measured: a 100,000 character tool_call_id was stored and made the
    database 266 KB. Truncating it would be a different call, so the write
    must fail and leave no row.
    """
    store = AgentStore(tmp_path / "call-id.db")
    store.tool_call_id_max_chars = 32
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)

    with pytest.raises(ValueError, match="32"):
        store.propose_tool_call(run.id, "i" * 80, "static.functions", {"session_id": "s"}, ["read"])

    with pytest.raises(KeyError):
        store.get_tool_call(run.id, "i" * 80)
    store.propose_tool_call(run.id, "call-ok", "static.functions", {"session_id": "s"}, ["read"])
    assert store.get_tool_call(run.id, "call-ok")["id"] == "call-ok"


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


def test_run_event_preview_obeys_budget_after_json_escaping(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "escaped-event.db")
    store.event_data_max_bytes = 1024
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="p", model=None, deadline_seconds=60
    )

    event = store.append_event(
        run.id,
        "message.delta",
        {"delta": "\x00" * (64 * 1024)},
    )

    encoded = json.dumps(event.data, ensure_ascii=False).encode("utf-8")
    assert len(encoded) <= 1024
    assert event.data["truncated"] is True
    assert event.data["summary"]


def test_event_pages_apply_a_byte_budget_in_addition_to_the_count_limit(
    tmp_path: Path,
) -> None:
    store = AgentStore(tmp_path / "event-pages.db")
    store.event_page_max_bytes = 1024
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="p", model=None, deadline_seconds=60
    )
    for index in range(3):
        store.append_event(
            run.id,
            "message.delta",
            {"index": index, "delta": "x" * 700},
        )

    first_page = [
        event
        for event in store.list_events(run.id, limit=5000)
        if event.type == "message.delta"
    ]
    assert [event.data["index"] for event in first_page] == [0]
    second_page = [
        event
        for event in store.list_events(
            run.id, after=first_page[-1].seq, limit=5000
        )
        if event.type == "message.delta"
    ]
    assert [event.data["index"] for event in second_page] == [1]

    # Thread history is a newest window rather than a cursor page.
    thread_page = store.list_thread_events(thread.id, limit=8000)
    assert [event.data["index"] for event in thread_page] == [2]


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


def test_message_pages_apply_a_utf8_byte_budget(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "message-pages.db")
    store.message_page_max_bytes = 1024
    thread = store.create_thread()
    for index in range(3):
        store.add_message(thread.id, "user", f"{index}:" + "界" * 300)

    messages = store.list_messages(thread.id, limit=2000)

    assert len(messages) == 1
    assert messages[0].content.startswith("2:")


def test_a_live_thread_message_bytes_are_bounded_not_just_message_count(
    tmp_path: Path,
) -> None:
    """A count cap still permits a multi-gigabyte live thread.

    Every message is individually capped at 1 MiB, but the old retention rule
    kept 2,000 of them.  The database therefore grew to roughly 2 GiB while
    ``list_messages`` only ever read its newest 2,000 rows.  Retention must
    bound the bytes as well as the row count and keep the recent end intact.
    """
    store = AgentStore(tmp_path / "message-bytes.db")
    store.retained_messages_per_thread = 200
    store.retained_message_bytes_per_thread = 2_048
    thread = store.create_thread()

    for index in range(1, 8):
        store.add_message(thread.id, "user", f"message {index}" + "x" * 900)

    messages = store.list_messages(thread.id, limit=50)
    assert [item.content.split("x", 1)[0] for item in messages] == [
        "message 6",
        "message 7",
    ]
    assert sum(len(item.content.encode("utf-8")) for item in messages) <= 2_048
    assert store.path.stat().st_size < 100_000


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


def test_a_live_thread_does_not_keep_every_run_it_ever_finished(tmp_path: Path) -> None:
    """Finished-thread trim never collects a thread that still has a mission.

    Measured: 400 completed runs on one still-pending mission were 278 KB of
    empty rows and still climbing. Each run may also hold 5000 events. A
    caller looking up a run id from last week is not why the file grows.
    """
    store = AgentStore(tmp_path / "runs.db")
    store.retained_terminal_runs_per_thread = 5
    other = store.create_thread(title="other")
    keep = store.create_run(other.id, provider_profile="p", model=None, deadline_seconds=60)
    store.transition(keep.id, RunStatus.STREAMING)
    store.transition(keep.id, RunStatus.COMPLETED)

    thread = store.create_thread(title="live")
    store.create_mission(thread.id, "still going")
    finished: list[str] = []
    for _ in range(12):
        run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.COMPLETED)
        finished.append(run.id)
    inflight = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    store.transition(inflight.id, RunStatus.STREAMING)

    with store._reading() as con:
        live_ids = [
            str(row["id"])
            for row in con.execute(
                "SELECT id FROM runs WHERE thread_id=? ORDER BY created_at, id",
                (thread.id,),
            )
        ]
        other_ids = [
            str(row["id"])
            for row in con.execute(
                "SELECT id FROM runs WHERE thread_id=?",
                (other.id,),
            )
        ]
        live_events = con.execute(
            "SELECT COUNT(*) FROM run_events WHERE run_id IN "
            "(SELECT id FROM runs WHERE thread_id=?)",
            (thread.id,),
        ).fetchone()[0]

    assert live_ids == finished[-5:] + [inflight.id]
    assert other_ids == [keep.id]
    assert store.get_run(finished[0]) is None
    assert store.get_run(inflight.id) is not None
    assert live_events == 6


def test_a_live_thread_does_not_keep_every_mission_it_ever_finished(tmp_path: Path) -> None:
    """Finished-thread trim never collects a thread that still has a mission.

    Measured: 400 completed missions on one still-pending objective were
    192 KB and still climbing. A caller looking up a mission id from last
    week is not why the file grows.
    """
    store = AgentStore(tmp_path / "missions.db")
    store.retained_terminal_missions_per_thread = 5
    other = store.create_thread(title="other")
    keep = store.create_mission(other.id, "leave me")
    store.set_mission_status(keep.id, MissionStatus.COMPLETED)

    thread = store.create_thread(title="live")
    pending = store.create_mission(thread.id, "still going")
    finished: list[str] = []
    for index in range(12):
        mission = store.create_mission(thread.id, f"done-{index}")
        store.set_mission_status(mission.id, MissionStatus.COMPLETED)
        finished.append(mission.id)

    with store._reading() as con:
        live_ids = [
            str(row["id"])
            for row in con.execute(
                "SELECT id FROM missions WHERE thread_id=? ORDER BY created_at, id",
                (thread.id,),
            )
        ]
        other_ids = [
            str(row["id"])
            for row in con.execute(
                "SELECT id FROM missions WHERE thread_id=?",
                (other.id,),
            )
        ]

    assert live_ids == [pending.id] + finished[-5:]
    assert other_ids == [keep.id]
    assert store.get_mission(finished[0]) is None
    assert store.get_mission(pending.id) is not None


def test_oversized_run_profile_and_model_are_refused_not_stored(tmp_path: Path) -> None:
    """Tool names already refuse 128 characters; run identity strings did not.

    Measured: 100,000 character provider_profile and model values made the
    database 262 KB. Truncating a profile id would select a different
    provider, so the write must fail and leave no row.
    """
    store = AgentStore(tmp_path / "run-id.db")
    store.run_profile_max_chars = 32
    store.run_model_max_chars = 32
    thread = store.create_thread()

    with pytest.raises(ValueError, match="provider profile"):
        store.create_run(thread.id, provider_profile="p" * 80, model=None, deadline_seconds=60)
    with pytest.raises(ValueError, match="run model"):
        store.create_run(thread.id, provider_profile="ok", model="m" * 80, deadline_seconds=60)

    run = store.create_run(thread.id, provider_profile="ok", model="gpt-4.1-mini", deadline_seconds=60)
    assert store.get_run(run.id) is not None
    with store._reading() as con:
        assert con.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1


def test_oversized_mission_profile_and_model_are_refused_not_stored(tmp_path: Path) -> None:
    """create_run already refuses 128-character identity strings; missions did not.

    Measured: 100,000 character provider_profile and model values made the
    database 262 KB. Truncating a profile id would select a different
    provider, so the write must fail and leave no row.
    """
    store = AgentStore(tmp_path / "mission-id.db")
    store.run_profile_max_chars = 32
    store.run_model_max_chars = 32
    thread = store.create_thread()

    with pytest.raises(ValueError, match="provider profile"):
        store.create_mission(thread.id, "look", provider_profile="p" * 80)
    with pytest.raises(ValueError, match="run model"):
        store.create_mission(thread.id, "look", model="m" * 80)

    mission = store.create_mission(thread.id, "look", provider_profile="ok", model="gpt-4.1-mini")
    assert store.get_mission(mission.id) is not None
    with store._reading() as con:
        assert con.execute("SELECT COUNT(*) FROM missions").fetchone()[0] == 1


def test_oversized_mission_objectives_are_refused_not_silently_truncated(
    tmp_path: Path,
) -> None:
    """A queued objective must be either intact or rejected.

    Measured: an 8001-character objective returned a pending mission while
    storing only 8000 characters. Completion criteria commonly live at the
    end, so the unattended scheduler then worked on a different instruction
    without telling its caller.
    """
    store = AgentStore(tmp_path / "mission-objective.db")
    store.mission_objective_max_chars = 32
    thread = store.create_thread()

    with pytest.raises(ValueError, match="mission objective"):
        store.create_mission(thread.id, "x" * 33)

    with store._reading() as con:
        assert con.execute("SELECT COUNT(*) FROM missions").fetchone()[0] == 0
    objective = "x" * 32
    mission = store.create_mission(thread.id, objective)
    assert mission.objective == objective


def test_oversized_thread_session_ids_are_refused_not_stored(tmp_path: Path) -> None:
    """Thread titles already clip at 200 characters; session_id did not.

    Measured: a 100,000 character session_id made the database 163 KB.
    Truncating it would point at a different session, so the write must fail
    and leave no row.
    """
    store = AgentStore(tmp_path / "thread-sid.db")
    store.thread_session_id_max_chars = 32

    with pytest.raises(ValueError, match="session_id"):
        store.create_thread(session_id="s" * 80)

    with store._reading() as con:
        assert con.execute("SELECT COUNT(*) FROM threads").fetchone()[0] == 0
    thread = store.create_thread(session_id="abc123")
    assert store.get_thread(thread.id) is not None
    assert store.get_thread(thread.id).session_id == "abc123"


def test_bind_thread_session_updates_and_clears(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "bind-thread.db")
    thread = store.create_thread()
    bound = store.bind_thread_session(thread.id, "session-one")
    assert bound.session_id == "session-one"
    cleared = store.bind_thread_session(thread.id, None)
    assert cleared.session_id is None
    with pytest.raises(KeyError):
        store.bind_thread_session("missing", "session-one")


def test_delete_thread_removes_messages(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "delete-thread.db")
    thread = store.create_thread(title="scratch")
    store.add_message(thread.id, "user", "hello")
    store.delete_thread(thread.id)
    assert store.get_thread(thread.id) is None
    assert store.list_threads() == []
    with pytest.raises(KeyError):
        store.delete_thread(thread.id)
