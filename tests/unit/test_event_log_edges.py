"""Edge/guard coverage for the persistent debug-event log.

``test_events.py`` covers replay, the memory window and the disk trim happy
paths. This file pins the remaining guards: closing a memory-only log, invalid
gap notes, empty/duplicate appends, the contiguity-hole gap on append, the
``_evict_to_window``/``_next_present`` conn-None arcs, ``read_after`` input
validation, and the disk trim dropping below-oldest events from memory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import event_log as event_log_module
from headless_re_mcp.core.event_log import PersistentDebugEventLog
from headless_re_mcp.core.events import DebugEvent, DebugEventProtocolError


def _event(seq: int) -> DebugEvent:
    return DebugEvent(
        sequence=seq,
        timestamp_unix_ms=1_700_000_000_000 + seq,
        source="x64dbg.plugin_callback",
        kind="debug.paused",
        data={},
    )


def test_close_is_a_noop_for_a_memory_only_log() -> None:
    log = PersistentDebugEventLog()
    log.close()  # conn is None -> nothing to close
    log.close()  # idempotent


def test_note_unrecovered_gap_ignores_invalid_ranges() -> None:
    log = PersistentDebugEventLog()
    log.note_unrecovered_gap(0, 5)  # first_missing <= 0
    log.note_unrecovered_gap(5, 2)  # last_missing < first_missing
    served = log.read_after(0, limit=10)
    assert served.unrecovered_gap is False
    assert served.batch.dropped == 0


def test_append_of_no_events_is_a_noop() -> None:
    log = PersistentDebugEventLog()
    log.append_events([])
    assert log.latest_sequence == 0


def test_append_skips_a_duplicate_sequence() -> None:
    log = PersistentDebugEventLog()
    log.append_events([_event(1)])
    log.append_events([_event(1)])  # already in memory -> skipped
    served = log.read_after(0, limit=10)
    assert [event.sequence for event in served.batch.events] == [1]


def test_append_with_a_contiguity_hole_records_a_gap() -> None:
    log = PersistentDebugEventLog()
    log.append_events([_event(1)])
    log.append_events([_event(3)])  # 3 > latest(1)+1 -> gap through 2
    served = log.read_after(0, limit=10)
    assert served.unrecovered_gap is True
    assert served.batch.dropped == 2
    assert [event.sequence for event in served.batch.events] == [3]


def test_evict_to_window_is_a_noop_without_a_database() -> None:
    log = PersistentDebugEventLog()
    log.append_events([_event(1), _event(2)])
    log._evict_to_window()  # conn is None -> returns without touching memory
    assert set(log._memory) == {1, 2}


def test_next_present_reads_memory_when_there_is_no_database() -> None:
    log = PersistentDebugEventLog()
    log.append_events([_event(2), _event(4)])
    assert log._next_present(0) == 2
    assert log._next_present(2) == 4
    assert log._next_present(4) is None


def test_next_present_returns_none_past_the_end_with_a_database(tmp_path: Path) -> None:
    log = PersistentDebugEventLog(tmp_path / "events.db")
    log.append_events([_event(1), _event(2)])
    assert log._next_present(5) is None
    log.close()


@pytest.mark.parametrize(
    ("cursor", "limit"),
    [(-1, 10), (True, 10), (0, 0), (0, -5)],
)
def test_read_after_rejects_invalid_cursor_or_limit(cursor: object, limit: object) -> None:
    log = PersistentDebugEventLog()
    with pytest.raises(DebugEventProtocolError):
        log.read_after(cursor, limit=limit)  # type: ignore[arg-type]


def test_disk_trim_drops_below_oldest_events_from_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Shrink only the disk retention so the memory window keeps every event;
    # the trim must then drop the below-oldest sequences from memory too.
    monkeypatch.setattr(event_log_module, "DISK_RETAINED_EVENTS", 3)
    log = PersistentDebugEventLog(tmp_path / "events.db")

    log.append_events([_event(i) for i in range(1, 7)])

    assert log._oldest == 4
    assert min(log._memory) >= 4
    served = log.read_after(0, limit=10)
    assert served.batch.oldest_sequence == 4
    assert [event.sequence for event in served.batch.events] == [4, 5, 6]
    log.close()
