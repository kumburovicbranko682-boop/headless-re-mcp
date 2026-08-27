"""Event-log trim guards against external mutation of the shared database.

The database file lives on disk under the artifact root, so another process
(or an operator's sqlite shell) can delete rows behind the in-process
counters. These tests induce exactly that drift and pin that the trim and
read paths degrade instead of crashing or spinning.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core import event_log as event_log_module
from headless_re_mcp.core.event_log import PersistentDebugEventLog
from headless_re_mcp.core.events import DebugEvent


def _event(seq: int) -> DebugEvent:
    return DebugEvent(
        sequence=seq,
        timestamp_unix_ms=1_700_000_000_000 + seq,
        source="x64dbg.plugin_callback",
        kind="debug.paused",
        data={},
    )


def test_a_trim_finding_fewer_rows_than_the_counter_backs_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An external cleanup emptied the table while the in-memory counter still
    # says the retention cap is exceeded. The cutoff probe then finds nothing
    # at the offset; trimming must stop there rather than treat the drifted
    # counter as truth and index into rows that no longer exist.
    monkeypatch.setattr(event_log_module, "DISK_RETAINED_EVENTS", 4)
    log = PersistentDebugEventLog(tmp_path / "events.db")
    try:
        log.append_events([_event(seq) for seq in range(1, 5)])
        assert log._conn is not None
        log._conn.execute("DELETE FROM debug_events")
        log._conn.commit()

        log.append_events([_event(5)])

        # The memory window still holds every event, so reads keep working.
        read = log.read_after(0, limit=10)
        assert [event.sequence for event in read.batch.events] == [1, 2, 3, 4, 5]
    finally:
        log.close()


class _RacingConn:
    """Passthrough connection that wipes the table right after the trim's DELETE.

    This is the interleaving a second process produces when it clears the
    database between the trim's own DELETE and its bounds query.
    """

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        cursor = self._real.execute(sql, params)
        if sql.startswith("DELETE FROM debug_events WHERE sequence <"):
            self._real.execute("DELETE FROM debug_events")
        return cursor

    def executemany(self, sql: str, rows: list[tuple[Any, ...]]) -> sqlite3.Cursor:
        return self._real.executemany(sql, rows)

    def commit(self) -> None:
        self._real.commit()

    def close(self) -> None:
        self._real.close()


def test_a_table_emptied_mid_trim_resets_the_bounds_and_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With the rows gone, MIN(sequence) comes back NULL. The bounds must reset
    # to "nothing held on disk" -- not raise on int(None) -- and the eviction
    # mark must stay put, because nothing was proven to be safely on disk.
    monkeypatch.setattr(event_log_module, "DISK_RETAINED_EVENTS", 4)
    log = PersistentDebugEventLog(tmp_path / "events.db")
    try:
        assert log._conn is not None
        monkeypatch.setattr(log, "_conn", _RacingConn(log._conn))

        log.append_events([_event(seq) for seq in range(1, 6)])

        assert log._stored == 0
        assert log._oldest == 0
        assert log._evicted_through == 0
        # The memory window is untouched, so the events are still readable.
        read = log.read_after(0, limit=10)
        assert [event.sequence for event in read.batch.events] == [1, 2, 3, 4, 5]
    finally:
        log.close()


def test_a_read_stops_at_a_tail_hole_instead_of_spinning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A consumer reopens the log, then an external cleanup deletes the newest
    # rows. Walking past the hole finds no present event anywhere after it;
    # without the break the read loop would never advance seq again.
    writer = PersistentDebugEventLog(tmp_path / "events.db")
    writer.append_events([_event(seq) for seq in range(1, 6)])
    writer.close()

    # Reopen with no memory window so every lookup goes to the database.
    monkeypatch.setattr(event_log_module, "MEMORY_WINDOW_EVENTS", 0)
    reader = PersistentDebugEventLog(tmp_path / "events.db")
    try:
        assert reader._conn is not None
        assert reader.latest_sequence == 5
        reader._conn.execute("DELETE FROM debug_events WHERE sequence >= 3")
        reader._conn.commit()

        read = reader.read_after(0, limit=10)

        assert [event.sequence for event in read.batch.events] == [1, 2]
        assert read.batch.next_cursor == 2
        assert read.batch.latest_sequence == 5
    finally:
        reader.close()
