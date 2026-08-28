"""Watch open backends and rebuild connections that dropped underneath them."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.telemetry import record_alert

JsonObject = dict[str, Any]


class _Repairable(Protocol):
    """The part of a backend worker health monitoring relies on."""

    @property
    def exit_code(self) -> int | None: ...


@dataclass(slots=True)
class BackendHealth:
    """What the last check saw for one backend, and what it did about it."""

    session_id: str
    backend: str
    worker_alive: bool
    connected: bool
    checked_at: float
    reconnects: int = 0
    failures: int = 0
    last_error: str | None = None

    def as_json(self) -> JsonObject:
        return {
            "session_id": self.session_id,
            "backend": self.backend,
            "worker_alive": self.worker_alive,
            "connected": self.connected,
            "healthy": self.worker_alive and self.connected,
            "checked_at": self.checked_at,
            "reconnects": self.reconnects,
            "failures": self.failures,
            "last_error": self.last_error,
        }


class _RuntimeSource(Protocol):
    def snapshot(self) -> list[tuple[str, BackendKind, Any]]: ...

    def is_current(self, session_id: str, kind: BackendKind, runtime: Any) -> bool: ...


# Skip this many checks after the nth consecutive reconnect failure. The first
# failure is retried immediately, because the common case is a transient drop
# that the very next attempt repairs; the cap is what a pipe that is never
# coming back settles down to.
_MAX_SKIPPED_CHECKS = 60


def _checks_to_skip(consecutive_failures: int) -> int:
    if consecutive_failures <= 1:
        return 0
    # Shifted rather than raised to a power: the result stays an int, and the
    # shift is bounded so a long-dead backend cannot ask for a huge one.
    shift = min(consecutive_failures - 1, 16)
    return min((1 << shift) - 1, _MAX_SKIPPED_CHECKS)


@dataclass(slots=True)
class BackendHealthMonitor:
    """Repair dropped connections without waiting for the caller to notice.

    Deliberately passive: it reads process and connection state and never issues
    an RPC of its own, so a healthy session never contends with it and a long
    running operation is never interrupted by a probe. It also never restarts a
    dead worker, because a restarted debugger comes back attached to nothing and
    only the caller can decide whether relaunching is acceptable; those are
    reported so that session.recover can be called deliberately.
    """

    runtimes: _RuntimeSource
    interval_s: float = 5.0
    _entries: dict[tuple[str, str], BackendHealth] = field(default_factory=dict)
    # Consecutive reconnect failures, and how many checks to sit out before the
    # next attempt. Keyed like _entries and cleared by forget().
    _reconnect_backoff: dict[tuple[str, str], tuple[int, int]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _previous: threading.Thread | None = None
    _restart_pending: bool = False

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            # A sweep can sit inside a reconnect for far longer than stop() waits,
            # so the previous thread may still be running. Clearing the stop flag
            # now would un-cancel it and leave two sweepers running forever.
            # Remember the request and start the replacement from _run's finally
            # once that thread has observed the stop flag.
            if self._previous is not None and self._previous.is_alive():
                self._restart_pending = True
                return
            self._launch_unlocked()

    def stop(self, *, timeout: float = 2.0) -> None:
        with self._lock:
            self._restart_pending = False
            self._stop.set()
            thread = self._thread
            self._thread = None
        if thread is None:
            return
        thread.join(timeout=timeout)
        # Remembered rather than discarded: it is still winding down and must be
        # allowed to see the stop flag before a restart clears it.
        with self._lock:
            self._previous = thread if thread.is_alive() else None

    def _launch_unlocked(self) -> None:
        self._previous = None
        self._restart_pending = False
        self._stop.clear()
        thread = threading.Thread(target=self._run, name="backend-health", daemon=True)
        self._thread = thread
        thread.start()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                # A monitor that can raise would take down the session it exists to
                # protect; per-backend failures are already recorded in the report.
                try:
                    self.check_once()
                except Exception as exc:  # noqa: BLE001 - the sweep must not die
                    record_alert(
                        "health_sweep_failed",
                        fields={"error": f"{type(exc).__name__}: {exc}"},
                    )
                self._stop.wait(self.interval_s)
        finally:
            with self._lock:
                if self._restart_pending and self._thread is None:
                    self._launch_unlocked()

    def check_once(self, *, repair: bool = True) -> list[BackendHealth]:
        """Inspect every open backend once, optionally repairing transports."""
        results: list[BackendHealth] = []
        for session_id, kind, runtime in self.runtimes.snapshot():
            # The snapshot is a copy taken under the owner lock and released, so
            # a session can be closed while we hold a runtime from it. Repairing
            # one that is no longer registered would hold its request lock inside
            # a reconnect for the full timeout while close_session waits for the
            # same lock, and would resurrect a health entry that was forgotten.
            if not self.runtimes.is_current(session_id, kind, runtime):
                continue
            worker = getattr(runtime, "worker", runtime)
            results.append(self._check_backend(session_id, kind, worker, repair=repair))
        return results

    def _check_backend(
        self,
        session_id: str,
        kind: BackendKind,
        worker: object,
        *,
        repair: bool = True,
    ) -> BackendHealth:
        key = (session_id, kind.value)
        with self._lock:
            previous = self._entries.get(key)
            reconnects = previous.reconnects if previous else 0
            failures = previous.failures if previous else 0
            last_error = previous.last_error if previous else None

        # A worker that never reports an exit code cannot be judged dead, so
        # treat the unknown case as alive rather than inventing a failure.
        worker_alive = getattr(worker, "exit_code", None) is None
        connected = bool(getattr(worker, "transport_connected", True))
        reconnect = getattr(worker, "reconnect", None)
        if repair and worker_alive and not connected and callable(reconnect):
            if self._reconnect_is_due(key):
                try:
                    reconnect()
                except BaseException as exc:  # noqa: BLE001 - recorded, not raised
                    failures += 1
                    last_error = f"{type(exc).__name__}: {exc}"
                    self._note_reconnect_failed(key)
                else:
                    reconnects += 1
                    last_error = None
                    with self._lock:
                        self._reconnect_backoff.pop(key, None)
                    connected = bool(getattr(worker, "transport_connected", True))
        elif connected:
            with self._lock:
                self._reconnect_backoff.pop(key, None)

        # Published as one finished value: a reader must never see a row that is
        # half updated, for instance connected already true but the repair not
        # yet counted.
        entry = BackendHealth(
            session_id=session_id,
            backend=kind.value,
            worker_alive=worker_alive,
            connected=connected,
            checked_at=time.time(),
            reconnects=reconnects,
            failures=failures,
            last_error=last_error,
        )
        with self._lock:
            self._entries[key] = entry
        return entry

    def _reconnect_is_due(self, key: tuple[str, str]) -> bool:
        """Whether to attempt a reconnect on this check, or sit this one out.

        A pipe that cannot be rebuilt was being retried every interval for as
        long as the process lived -- 17,280 attempts a day at the default five
        seconds. The cost is not the attempts but the queue behind them: checks
        run serially on one thread, and XdbgClient gives a reconnect thirty
        seconds, so one unreachable backend delays every other session's health
        check by that much on every sweep.
        """
        # Under the lock like every other touch of this map. The sweep mutates
        # it here and in _note_reconnect_failed/the pops above, all off the
        # entries lock, while forget() iterates it under that lock on a session
        # close from another thread -- so an unlocked mutation here raced the
        # iteration into "dictionary changed size during iteration" and killed
        # the close. threading.Lock is not reentrant, but none of these run
        # while the lock is already held.
        with self._lock:
            failures, skip_remaining = self._reconnect_backoff.get(key, (0, 0))
            if skip_remaining > 0:
                self._reconnect_backoff[key] = (failures, skip_remaining - 1)
                return False
            return True

    def _note_reconnect_failed(self, key: tuple[str, str]) -> None:
        with self._lock:
            failures, _ = self._reconnect_backoff.get(key, (0, 0))
            failures += 1
            self._reconnect_backoff[key] = (failures, _checks_to_skip(failures))

    def forget(self, session_id: str) -> None:
        with self._lock:
            for key in [item for item in self._entries if item[0] == session_id]:
                del self._entries[key]
            for key in [item for item in self._reconnect_backoff if item[0] == session_id]:
                del self._reconnect_backoff[key]

    def report(self, session_id: str | None = None) -> list[JsonObject]:
        with self._lock:
            entries = [
                entry
                for entry in self._entries.values()
                if session_id is None or entry.session_id == session_id
            ]
        return [entry.as_json() for entry in sorted(entries, key=lambda item: item.backend)]
