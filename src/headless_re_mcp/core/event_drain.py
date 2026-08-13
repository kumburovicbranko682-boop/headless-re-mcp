"""Drain native x64dbg ring events into PersistentDebugEventLog."""

from __future__ import annotations

import threading
from typing import Protocol

from headless_re_mcp.core.event_log import PersistentDebugEventLog
from headless_re_mcp.core.events import (
    MAX_DEBUG_EVENT_BATCH,
    DebugEventBatch,
    DebugEventCursor,
)
from headless_re_mcp.telemetry import record_alert

# Ceiling for the retry wait once draining starts failing.
_MAX_DRAIN_BACKOFF_S = 2.0


class _EventReader(Protocol):
    def read_events(
        self,
        cursor: int,
        *,
        limit: int = ...,
        timeout: float = ...,
    ) -> DebugEventBatch: ...


def drain_native_into_log(
    worker: _EventReader,
    drain_cursor: DebugEventCursor,
    event_log: PersistentDebugEventLog,
    *,
    timeout: float,
    max_rounds: int = 64,
) -> int:
    """Copy available native events into ``event_log``; return appended count.

    When the native ring reports ``dropped > 0``, the overwritten sequences are
    recorded as an unrecovered gap (true replay cannot invent them). Events that
    remain in the ring are still appended so subsequent consumer reads can replay.
    """
    appended = 0
    rounds = 0
    while rounds < max_rounds:
        rounds += 1
        batch = worker.read_events(
            drain_cursor.value,
            limit=MAX_DEBUG_EVENT_BATCH,
            timeout=timeout if rounds == 1 else 0.05,
        )
        if batch.dropped > 0:
            first_missing = drain_cursor.value + 1
            last_missing = drain_cursor.value + batch.dropped
            event_log.note_unrecovered_gap(first_missing, last_missing)
        if batch.events:
            event_log.append_events(batch.events)
            appended += len(batch.events)
        if batch.next_cursor == drain_cursor.value and not batch.events:
            break
        drain_cursor.advance(batch)
        if not batch.has_more:
            break
    return appended


class EventDrainPump:
    """Background drain so idle consumers still persist events before ring wrap."""

    def __init__(
        self,
        worker: _EventReader,
        drain_cursor: DebugEventCursor,
        event_log: PersistentDebugEventLog,
        *,
        lock: threading.RLock,
        interval_s: float = 0.05,
    ) -> None:
        self._worker = worker
        self._drain_cursor = drain_cursor
        self._event_log = event_log
        self._lock = lock
        self._interval_s = interval_s
        self.consecutive_failures = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="debug-event-drain",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop.set()
        self._thread.join(timeout=timeout)

    def drain_once(self) -> bool:
        """One drain attempt. Never raises; answers whether it worked.

        A failure used to be swallowed whole. This pump is what keeps the log
        ahead of the 1024-slot native ring, and a gap is only ever recorded by a
        drain that ran -- so a pump that had stopped working left the log
        claiming an unbroken sequence while events were being overwritten, which
        is the one thing true replay is supposed to guarantee.
        """
        try:
            with self._lock:
                drain_native_into_log(
                    self._worker,
                    self._drain_cursor,
                    self._event_log,
                    timeout=0.05,
                    max_rounds=8,
                )
        except Exception as exc:  # noqa: BLE001 - the pump must not end the session
            self.consecutive_failures += 1
            if self.consecutive_failures == 1:
                # Edge-triggered: at twenty attempts a second, one alert per
                # failure would bury the log it is meant to draw attention to.
                record_alert(
                    "event_drain_failing",
                    fields={"error": f"{type(exc).__name__}: {exc}"},
                )
            return False
        if self.consecutive_failures:
            record_alert(
                "event_drain_recovered",
                severity="info",
                fields={"failed_attempts": self.consecutive_failures},
            )
            self.consecutive_failures = 0
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            delay = self._interval_s
            if not self.drain_once():
                # Every attempt takes the runtime lock that tool calls need, so
                # a worker that is not answering must not be retried twenty
                # times a second while holding it.
                shift = min(self.consecutive_failures - 1, 6)
                delay = min(_MAX_DRAIN_BACKOFF_S, max(self._interval_s, 0.05) * (1 << shift))
            self._stop.wait(delay)
