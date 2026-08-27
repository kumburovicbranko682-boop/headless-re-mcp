"""Disk-backed replay paths of the persistent debug-event log.

``test_event_log_edges`` covers the conn-None arcs and the input guards, and
``test_events`` covers the in-memory happy paths. What is left is the behaviour
that only appears once events actually leave memory for SQLite: eviction moving
the oldest out of the window, a later read fetching them back through
``_row_to_event``, a recorded unrecovered gap surviving into a read, and a
reopened database rebuilding its bounds/window/gap from the table rather than
replaying every row. Those are what a lagged consumer and a console restart
depend on, so they are pinned directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import event_log as event_log_module
from headless_re_mcp.core.event_log import PersistentDebugEventLog
from headless_re_mcp.core.events import DebugEvent


def _event(seq: int, *, kind: str = "debug.paused") -> DebugEvent:
    return DebugEvent(
        sequence=seq,
        timestamp_unix_ms=1_700_000_000_000 + seq,
        source="x64dbg.plugin_callback",
        kind=kind,
        data={"seq": seq},
    )


def test_note_unrecovered_gap_records_a_valid_range(tmp_path: Path) -> None:
    log = PersistentDebugEventLog(tmp_path / "events.db")
    log.append_events([_event(seq) for seq in range(1, 6)])
    # The drain lost 2..4 before it could copy them out of the native ring.
    log.note_unrecovered_gap(2, 4)
    served = log.read_after(1, limit=10)
    assert served.unrecovered_gap is True
    assert served.batch.dropped == 3
    # The read resumes after the hole, at the next event that is still held.
    assert [event.sequence for event in served.batch.events] == [5]
    log.close()


def test_eviction_moves_old_events_to_disk_and_reads_them_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Shrink the memory window so a small append still forces eviction; the DB
    # keeps every row, so a read that reaches below the window must fetch the
    # evicted events back through _row_to_event.
    monkeypatch.setattr(event_log_module, "MEMORY_WINDOW_EVENTS", 2)
    log = PersistentDebugEventLog(tmp_path / "events.db")
    log.append_events([_event(seq) for seq in range(1, 5)])

    # Only the newest two remain resident; 1 and 2 were evicted to disk.
    assert set(log._memory) == {3, 4}
    assert log._evicted_through == 2

    served = log.read_after(0, limit=10)
    assert [event.sequence for event in served.batch.events] == [1, 2, 3, 4]
    # The two disk-sourced events round-trip their payload intact.
    replayed = {event.sequence: event.data for event in served.batch.events}
    assert replayed[1] == {"seq": 1}
    assert replayed[2] == {"seq": 2}

    # A cursor past the window, with no gap, reads as a store replay.
    resumed = log.read_after(1, limit=10)
    assert resumed.replayed_from_store is True
    assert [event.sequence for event in resumed.batch.events] == [2, 3, 4]
    log.close()


def test_reopening_a_populated_database_restores_bounds_and_gap(tmp_path: Path) -> None:
    path = tmp_path / "events.db"
    first = PersistentDebugEventLog(path)
    # A contiguity hole (2 is never appended) records a gap the meta table keeps.
    first.append_events([_event(1), _event(3), _event(4)])
    assert first._gap_through == 2
    first.close()

    reopened = PersistentDebugEventLog(path)
    # Bounds come from the table, not from replaying every row.
    assert reopened.latest_sequence == 4
    assert reopened._oldest == 1
    assert reopened._stored == 3
    assert set(reopened._memory) == {1, 3, 4}
    # The recorded gap survives the restart, so a fresh read still reports it.
    served = reopened.read_after(0, limit=10)
    assert served.unrecovered_gap is True
    assert served.batch.dropped == 2
    assert [event.sequence for event in served.batch.events] == [3, 4]
    reopened.close()


def test_reopening_reloads_only_the_newest_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "events.db"
    first = PersistentDebugEventLog(path)
    first.append_events([_event(seq) for seq in range(1, 6)])
    first.close()

    # Reopen with a window of two: the bounds still span 1..5, but only the two
    # newest sequences are resident and everything below is flagged on-disk.
    monkeypatch.setattr(event_log_module, "MEMORY_WINDOW_EVENTS", 2)
    reopened = PersistentDebugEventLog(path)
    assert reopened.latest_sequence == 5
    assert set(reopened._memory) == {4, 5}
    assert reopened._evicted_through == 3
    # A read from the start still returns the whole contiguous range by pulling
    # the below-window sequences from disk.
    served = reopened.read_after(0, limit=10)
    assert [event.sequence for event in served.batch.events] == [1, 2, 3, 4, 5]
    reopened.close()
