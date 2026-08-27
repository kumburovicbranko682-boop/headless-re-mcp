"""Edge/guard coverage for the native-event drain and its background pump.

``test_events.py`` covers the multi-round copy, the drain_once failure/recovery
counter and the alert edge-triggering. These pin the remaining branches of
``core/event_drain.py``: a zero-round drain that returns without reading, the
per-event ``debug.unrecovered_gap`` note, and the pump's ``_run`` backoff after a
failed attempt.
"""

from __future__ import annotations

import threading
from typing import cast

import pytest

from headless_re_mcp.core import event_drain as drain_module
from headless_re_mcp.core.event_drain import EventDrainPump, drain_native_into_log
from headless_re_mcp.core.event_log import PersistentDebugEventLog
from headless_re_mcp.core.events import (
    DEBUG_EVENT_CAPACITY,
    DebugEvent,
    DebugEventBatch,
    DebugEventCursor,
)


class _RecordingLog:
    """A stand-in log that records what the drain asks it to persist."""

    def __init__(self) -> None:
        self.appended: list[DebugEvent] = []
        self.gaps: list[tuple[int, int]] = []

    def append_events(self, events: object) -> None:
        self.appended.extend(cast("list[DebugEvent]", list(cast("list[object]", events))))

    def note_unrecovered_gap(self, first_missing: int, last_missing: int) -> None:
        self.gaps.append((first_missing, last_missing))


def _as_log(log: _RecordingLog) -> PersistentDebugEventLog:
    return cast(PersistentDebugEventLog, log)


def test_zero_rounds_returns_without_reading_the_worker() -> None:
    class _NeverReads:
        def read_events(
            self, cursor: int, *, limit: int = 100, timeout: float = 10.0
        ) -> DebugEventBatch:
            raise AssertionError("max_rounds=0 must not read the native ring")

    log = _RecordingLog()
    appended = drain_native_into_log(
        _NeverReads(), DebugEventCursor(), _as_log(log), timeout=0.05, max_rounds=0
    )
    assert appended == 0
    assert log.appended == []


def test_an_unrecovered_gap_event_is_noted_per_event() -> None:
    gap_event = DebugEvent(
        sequence=1,
        timestamp_unix_ms=1,
        source="x64dbg.plugin_callback",
        kind="debug.unrecovered_gap",
        data={},
    )

    class _OneGapBatch:
        def read_events(
            self, cursor: int, *, limit: int = 100, timeout: float = 10.0
        ) -> DebugEventBatch:
            return DebugEventBatch(
                events=(gap_event,),
                cursor=cursor,
                next_cursor=1,
                oldest_sequence=1,
                latest_sequence=1,
                dropped=0,  # not a ring-loss gap; the gap comes from the event itself
                dropped_total=0,
                has_more=False,
                capacity=DEBUG_EVENT_CAPACITY,
            )

    log = _RecordingLog()
    appended = drain_native_into_log(_OneGapBatch(), DebugEventCursor(), _as_log(log), timeout=0.05)

    assert appended == 1
    assert [event.kind for event in log.appended] == ["debug.unrecovered_gap"]
    # The gap is recorded for the event's own sequence, not from batch.dropped.
    assert log.gaps == [(1, 1)]


def test_dropped_events_record_a_ring_loss_gap() -> None:
    event = DebugEvent(
        sequence=3,
        timestamp_unix_ms=3,
        source="x64dbg.plugin_callback",
        kind="debug.paused",
        data={},
    )

    class _DroppedBatch:
        def read_events(
            self, cursor: int, *, limit: int = 100, timeout: float = 10.0
        ) -> DebugEventBatch:
            return DebugEventBatch(
                events=(event,),
                cursor=cursor,
                next_cursor=3,
                oldest_sequence=3,
                latest_sequence=3,
                dropped=2,  # sequences 1..2 wrapped out of the ring before we read
                dropped_total=2,
                has_more=False,
                capacity=DEBUG_EVENT_CAPACITY,
            )

    log = _RecordingLog()
    appended = drain_native_into_log(
        _DroppedBatch(), DebugEventCursor(), _as_log(log), timeout=0.05
    )

    assert appended == 1
    # The overwritten window before the surviving event is recorded as lost.
    assert log.gaps == [(1, 2)]


def test_drain_loops_across_rounds_until_no_more() -> None:
    first = DebugEvent(
        sequence=1,
        timestamp_unix_ms=1,
        source="x64dbg.plugin_callback",
        kind="debug.paused",
        data={},
    )
    second = DebugEvent(
        sequence=2,
        timestamp_unix_ms=2,
        source="x64dbg.plugin_callback",
        kind="debug.paused",
        data={},
    )

    class _TwoRoundNative:
        def read_events(
            self, cursor: int, *, limit: int = 100, timeout: float = 10.0
        ) -> DebugEventBatch:
            if cursor == 0:
                return DebugEventBatch(
                    events=(first,),
                    cursor=0,
                    next_cursor=1,
                    oldest_sequence=1,
                    latest_sequence=2,
                    dropped=0,
                    dropped_total=0,
                    has_more=True,  # forces a second round
                    capacity=DEBUG_EVENT_CAPACITY,
                )
            return DebugEventBatch(
                events=(second,),
                cursor=1,
                next_cursor=2,
                oldest_sequence=1,
                latest_sequence=2,
                dropped=0,
                dropped_total=0,
                has_more=False,
                capacity=DEBUG_EVENT_CAPACITY,
            )

    cursor = DebugEventCursor()
    log = _RecordingLog()
    appended = drain_native_into_log(_TwoRoundNative(), cursor, _as_log(log), timeout=0.05)

    assert appended == 2
    assert cursor.value == 2
    assert [event.sequence for event in log.appended] == [1, 2]


class _EmptyNative:
    """A worker that answers every read with an empty, terminating batch."""

    def read_events(
        self, cursor: int, *, limit: int = 100, timeout: float = 10.0
    ) -> DebugEventBatch:
        return DebugEventBatch(
            events=(),
            cursor=cursor,
            next_cursor=cursor,
            oldest_sequence=0,
            latest_sequence=cursor,
            dropped=0,
            dropped_total=0,
            has_more=False,
            capacity=DEBUG_EVENT_CAPACITY,
        )


def _pump(worker: object, *, interval_s: float = 0.05) -> EventDrainPump:
    return EventDrainPump(
        worker,  # type: ignore[arg-type]
        DebugEventCursor(),
        PersistentDebugEventLog(),
        lock=threading.RLock(),
        interval_s=interval_s,
    )


def test_a_clean_drain_once_leaves_the_failure_counter_at_zero() -> None:
    pump = _pump(_EmptyNative())
    assert pump.drain_once() is True
    assert pump.consecutive_failures == 0


def test_run_waits_the_plain_interval_after_a_clean_iteration() -> None:
    pump = _pump(_EmptyNative(), interval_s=0.07)
    stop = _OneShotStop()
    pump._stop = stop

    pump._run()  # one clean iteration: no failure, so no backoff -- just the interval

    assert pump.consecutive_failures == 0
    assert stop.waited == [pytest.approx(0.07)]


def test_pump_start_and_stop_are_safe() -> None:
    pump = _pump(_EmptyNative(), interval_s=0.01)
    pump.start()
    pump.stop(timeout=1.0)
    assert pump.consecutive_failures == 0


class _OneShotStop(threading.Event):
    """A stop event that lets ``_run`` execute exactly one iteration."""

    def __init__(self) -> None:
        super().__init__()
        self._checks = 0
        self.waited: list[float] = []

    def is_set(self) -> bool:
        self._checks += 1
        return self._checks > 1

    def wait(self, timeout: float | None = None) -> bool:
        self.waited.append(float(timeout or 0.0))
        return True


def test_run_backs_off_after_a_failed_drain(monkeypatch: pytest.MonkeyPatch) -> None:
    alerts: list[str] = []
    monkeypatch.setattr(drain_module, "record_alert", lambda kind, **kwargs: alerts.append(kind))

    class _BrokenNative:
        def read_events(
            self, cursor: int, *, limit: int = 100, timeout: float = 10.0
        ) -> DebugEventBatch:
            raise OSError("pipe is gone")

    pump = EventDrainPump(
        _BrokenNative(),
        DebugEventCursor(),
        PersistentDebugEventLog(),
        lock=threading.RLock(),
        interval_s=0.05,
    )
    stop = _OneShotStop()
    pump._stop = stop

    pump._run()  # one iteration: drain fails, backoff computed, wait recorded

    assert pump.consecutive_failures == 1
    assert alerts == ["event_drain_failing"]
    # shift = min(0, 6) = 0 -> the first backoff is one interval, not the ceiling.
    assert stop.waited == [pytest.approx(0.05)]
