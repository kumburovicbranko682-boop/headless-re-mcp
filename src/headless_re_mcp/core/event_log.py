"""Session-scoped durable debug-event log for true sequence replay.

Native x64dbg keeps a 1024-slot ring. This log is filled by a drain cursor that
runs ahead of the MCP consumer cursor, so consumers that lag past the ring
window can still read contiguous events by sequence (until an unrecovered gap).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.core.events import (
    DEBUG_EVENT_CAPACITY,
    DebugEvent,
    DebugEventBatch,
    DebugEventProtocolError,
)

JsonObject = dict[str, Any]

# How many events stay in memory. The rest live in SQLite and are read back when
# a consumer asks for them. Measured at roughly 400 bytes each, keeping all of
# them cost 79 MB of heap per 200k events and a session gave none of it back
# while it ran -- about 340 MB a day at ten events a second. Sixty-four times
# the native ring, so ordinary lag is still served without touching disk.
MEMORY_WINDOW_EVENTS = 65_536
# Memory is a window; the sqlite file used to keep every row. A dynamic
# session always opens this file (persist_debug_events only mirrors the
# timeline). Measured: 2000 events left 528_384 bytes on disk and COUNT(*)
# was still 2000.
DISK_RETAINED_EVENTS = 500_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS debug_events (
  sequence INTEGER PRIMARY KEY NOT NULL,
  timestamp_unix_ms INTEGER NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS debug_event_meta (
  key TEXT PRIMARY KEY NOT NULL,
  value INTEGER NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class EventLogRead:
    """Consumer-facing slice from the durable log."""

    batch: DebugEventBatch
    replayed_from_store: bool
    unrecovered_gap: bool


class PersistentDebugEventLog:
    """Append-only event log with optional SQLite durability for one session."""

    def __init__(
        self, path: Path | None = None, *, disk_retained_events: int = DISK_RETAINED_EVENTS
    ) -> None:
        self._lock = RLock()
        self._memory: dict[int, DebugEvent] = {}
        self._latest = 0
        self._gap_through = 0  # highest sequence known missing (inclusive), 0 = none
        self._oldest = 0  # lowest sequence held anywhere, 0 = none
        self._stored = 0  # how many sequences are held, in memory or on disk
        self._evicted_through = 0  # at or below this, look on disk rather than in memory
        self._path = path
        self.disk_retained_events = disk_retained_events
        self._conn: sqlite3.Connection | None = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            self._load_from_db()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    @property
    def latest_sequence(self) -> int:
        with self._lock:
            return self._latest

    def note_unrecovered_gap(self, first_missing: int, last_missing: int) -> None:
        """Record that native ring overwritten sequences before drain could copy them."""
        if first_missing <= 0 or last_missing < first_missing:
            return
        with self._lock:
            self._gap_through = max(self._gap_through, last_missing)

    def append_events(self, events: tuple[DebugEvent, ...] | list[DebugEvent]) -> None:
        if not events:
            return
        with self._lock:
            rows: list[tuple[int, int, str, str, str]] = []
            for event in events:
                # At or below the eviction mark the event is on disk, not gone,
                # so re-appending it would double-count what is already held.
                if event.sequence in self._memory or event.sequence <= self._evicted_through:
                    continue
                if self._latest and event.sequence > self._latest + 1:
                    # Contiguity hole relative to what we already stored.
                    self._gap_through = max(self._gap_through, event.sequence - 1)
                self._memory[event.sequence] = event
                self._latest = max(self._latest, event.sequence)
                self._oldest = (
                    event.sequence if not self._oldest else min(self._oldest, event.sequence)
                )
                self._stored += 1
                rows.append(
                    (
                        event.sequence,
                        event.timestamp_unix_ms,
                        event.source,
                        event.kind,
                        json.dumps(event.data, ensure_ascii=False, separators=(",", ":")),
                    )
                )
            if self._conn is not None and rows:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO debug_events"
                    "(sequence, timestamp_unix_ms, source, kind, data_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    rows,
                )
                self._conn.execute(
                    "INSERT INTO debug_event_meta(key, value) VALUES('latest', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (self._latest,),
                )
                self._conn.execute(
                    "INSERT INTO debug_event_meta(key, value) VALUES('gap_through', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (self._gap_through,),
                )
                self._conn.commit()
                self._evict_to_window()
                self._trim_disk()

    def _trim_disk(self) -> None:
        """Drop the oldest persisted events once the file is over the retain cap.

        read_after already treats a missing prefix as dropped, so a consumer
        that lagged past the cap sees a gap rather than a silent hole.
        """
        if self._conn is None:
            return
        retain = max(1, int(self.disk_retained_events))
        if self._stored <= retain:
            return
        kept = self._conn.execute(
            "SELECT sequence FROM debug_events ORDER BY sequence DESC LIMIT 1 OFFSET ?",
            (retain - 1,),
        ).fetchone()
        if kept is None:
            return
        oldest_kept = int(kept[0])
        self._conn.execute("DELETE FROM debug_events WHERE sequence < ?", (oldest_kept,))
        self._conn.commit()
        for sequence in [seq for seq in self._memory if seq < oldest_kept]:
            del self._memory[sequence]
        self._oldest = oldest_kept
        self._stored = int(self._conn.execute("SELECT COUNT(*) FROM debug_events").fetchone()[0])
        self._evicted_through = max(self._evicted_through, oldest_kept - 1)

    def _evict_to_window(self) -> None:
        """Drop the oldest events from memory once they are safely on disk.

        Only with a database behind them: without one this map is the only copy,
        and dropping from it would lose events rather than move them. Insertion
        order tracks sequence for the drain that fills this, so the front of the
        map is the oldest without having to sort 65k keys on every batch.
        """
        if self._conn is None:
            return
        while len(self._memory) > MEMORY_WINDOW_EVENTS:
            sequence = next(iter(self._memory))
            del self._memory[sequence]
            self._evicted_through = max(self._evicted_through, sequence)

    def _row_to_event(self, row: tuple[Any, ...]) -> DebugEvent:
        data = json.loads(row[4])
        return DebugEvent(
            sequence=int(row[0]),
            timestamp_unix_ms=int(row[1]),
            source=str(row[2]),
            kind=str(row[3]),
            data=data if isinstance(data, dict) else {},
        )

    def _lookup(self, sequence: int) -> DebugEvent | None:
        """One event by sequence, from the window or from the database."""
        event = self._memory.get(sequence)
        if event is not None or self._conn is None:
            return event
        row = self._conn.execute(
            "SELECT sequence, timestamp_unix_ms, source, kind, data_json "
            "FROM debug_events WHERE sequence=?",
            (sequence,),
        ).fetchone()
        return None if row is None else self._row_to_event(row)

    def _next_present(self, sequence: int) -> int | None:
        """The lowest sequence above ``sequence`` that is held anywhere."""
        found = min((key for key in self._memory if key > sequence), default=None)
        if self._conn is not None:
            row = self._conn.execute(
                "SELECT MIN(sequence) FROM debug_events WHERE sequence > ?",
                (sequence,),
            ).fetchone()
            if row is not None and row[0] is not None:
                on_disk = int(row[0])
                found = on_disk if found is None else min(found, on_disk)
        return found

    def read_after(self, cursor: int, *, limit: int) -> EventLogRead:
        if type(cursor) is not int or cursor < 0:
            raise DebugEventProtocolError("cursor must be a non-negative integer")
        if type(limit) is not int or limit < 1:
            raise DebugEventProtocolError("limit must be a positive integer")

        with self._lock:
            latest = self._latest
            if latest == 0:
                batch = DebugEventBatch(
                    events=(),
                    cursor=cursor,
                    next_cursor=cursor,
                    oldest_sequence=0,
                    latest_sequence=0,
                    dropped=0,
                    dropped_total=0,
                    has_more=False,
                    capacity=DEBUG_EVENT_CAPACITY,
                )
                return EventLogRead(batch=batch, replayed_from_store=False, unrecovered_gap=False)

            want_start = cursor + 1
            unrecovered = False
            dropped = 0
            if self._gap_through >= want_start:
                # Skip past known unrecovered hole.
                dropped = self._gap_through - cursor
                want_start = self._gap_through + 1
                unrecovered = dropped > 0

            selected: list[DebugEvent] = []
            seq = want_start
            while seq <= latest and len(selected) < limit:
                event = self._lookup(seq)
                if event is None:
                    # Soft hole: treat as unrecovered gap until next present event.
                    nxt = self._next_present(seq)
                    if nxt is None:
                        break
                    dropped += nxt - seq
                    unrecovered = True
                    seq = nxt
                    continue
                selected.append(event)
                seq += 1

            events = tuple(selected)
            next_cursor = events[-1].sequence if events else cursor + dropped
            batch = DebugEventBatch(
                events=events,
                cursor=cursor,
                next_cursor=next_cursor,
                oldest_sequence=self._oldest,
                latest_sequence=latest,
                dropped=dropped,
                # Counted against everything held rather than everything in
                # memory, or moving an event to disk would read as losing it.
                dropped_total=max(0, latest - self._stored),
                has_more=next_cursor < latest,
                capacity=DEBUG_EVENT_CAPACITY,
            )
            replayed = bool(events) and dropped == 0 and cursor > 0
            return EventLogRead(
                batch=batch,
                replayed_from_store=replayed,
                unrecovered_gap=unrecovered,
            )

    def _load_from_db(self) -> None:
        """Take the bounds from the table and only the newest events from it.

        Reading every row back was how a reopened session paid for its whole
        history before it would answer anything: 2.4 seconds and 79 MB for a
        table of 200k. The rows are still there, and a read that reaches past
        the window fetches what it needs.
        """
        assert self._conn is not None
        bounds = self._conn.execute(
            "SELECT MIN(sequence), MAX(sequence), COUNT(*) FROM debug_events"
        ).fetchone()
        if bounds is not None and bounds[1] is not None:
            self._oldest = int(bounds[0])
            self._latest = int(bounds[1])
            self._stored = int(bounds[2])
        newest = self._conn.execute(
            "SELECT sequence, timestamp_unix_ms, source, kind, data_json FROM debug_events "
            "ORDER BY sequence DESC LIMIT ?",
            (MEMORY_WINDOW_EVENTS,),
        ).fetchall()
        for row in reversed(newest):
            event = self._row_to_event(row)
            self._memory[event.sequence] = event
        if self._memory:
            # Everything below what was loaded is on disk, not missing.
            self._evicted_through = min(self._memory) - 1
        gap = self._conn.execute(
            "SELECT value FROM debug_event_meta WHERE key='gap_through'"
        ).fetchone()
        if gap is not None:
            self._gap_through = int(gap[0])
