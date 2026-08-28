"""Pin the disk-trim arms that only a pruned or raced database can reach.

``test_events.py`` drives the trim's happy path and ``test_event_log_edges.py``
its memory bookkeeping, but both leave the degradation arms unexecuted: the
event database lives outside the artifact quota, so an operator or an external
cleaner deleting its rows is survivable vandalism the trim must absorb, not a
state the log may crash in. Two arms matter: a trim whose cutoff query finds
fewer rows than the retention count (the table was pruned behind the log's
back) must return quietly, and a trim whose own DELETE races a concurrent
pruner that empties the rest of the table must record zero holdings and keep
serving the memory window rather than raise off ``int(None)`` mid-append.
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


def test_trim_survives_a_database_pruned_behind_the_logs_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fewer rows on disk than the log believes it holds must not kill append.

    ``_stored`` says the retention cap is exceeded, but the cutoff query finds
    no row at the retention offset because someone else already emptied the
    table. Unguarded, the trim would index ``None`` -- and it runs inside
    ``append_events``, so the crash would take the drain thread with it.
    """
    monkeypatch.setattr(event_log_module, "DISK_RETAINED_EVENTS", 4)
    path = tmp_path / "events.db"
    log = PersistentDebugEventLog(path)
    log.append_events([_event(1), _event(2), _event(3)])

    pruner = sqlite3.connect(path)
    pruner.execute("DELETE FROM debug_events")
    pruner.commit()
    pruner.close()

    # Pushes the believed count past the cap of 4, so the trim runs against a
    # table that now holds only these two rows.
    log.append_events([_event(4), _event(5)])

    served = log.read_after(3, limit=10)
    assert [event.sequence for event in served.batch.events] == [4, 5]
    log.close()


class _RacedConnection:
    """Passes everything through, except that the moment the trim's own DELETE
    lands, a concurrent pruner empties the rest of the table -- so the bounds
    query that follows sees nothing at all."""

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real

    def execute(self, sql: str, parameters: Any = ()) -> Any:
        cursor = self._real.execute(sql, parameters)
        if sql.startswith("DELETE FROM debug_events"):
            self._real.execute("DELETE FROM debug_events")
        return cursor

    def executemany(self, sql: str, rows: Any) -> Any:
        return self._real.executemany(sql, rows)

    def executescript(self, script: str) -> Any:
        return self._real.executescript(script)

    def commit(self) -> None:
        self._real.commit()

    def close(self) -> None:
        self._real.close()


def test_a_pruner_racing_the_trim_leaves_the_memory_window_serving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty bounds result means zero holdings, not a crash.

    Between the trim's DELETE and its MIN/COUNT query another connection can
    empty the table. The trim must record that nothing is held on disk, leave
    the in-memory window alone (those events are real and still servable), and
    leave the log appendable.
    """
    monkeypatch.setattr(event_log_module, "DISK_RETAINED_EVENTS", 4)
    real_connect = sqlite3.connect

    def connect_raced(*args: Any, **kwargs: Any) -> Any:
        return _RacedConnection(real_connect(*args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", connect_raced)
    log = PersistentDebugEventLog(tmp_path / "events.db")

    # Five events exceed the cap of 4: the trim deletes below its cutoff, the
    # racing pruner then empties the table before the bounds query runs.
    log.append_events([_event(i) for i in range(1, 6)])

    served = log.read_after(0, limit=10)
    assert [event.sequence for event in served.batch.events] == [1, 2, 3, 4, 5], (
        "the memory window must keep serving after the disk copy vanished"
    )

    # The log is still alive: a later append lands and is readable.
    log.append_events([_event(6)])
    tail = log.read_after(5, limit=10)
    assert [event.sequence for event in tail.batch.events] == [6]
    log.close()
