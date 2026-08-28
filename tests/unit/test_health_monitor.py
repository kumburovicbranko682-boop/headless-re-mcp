from __future__ import annotations

import threading
import time

from headless_re_mcp.core.health import BackendHealthMonitor
from headless_re_mcp.core.models import BackendKind


class FakeWorker:
    def __init__(self, *, exit_code: int | None = None, connected: bool = True) -> None:
        self.exit_code = exit_code
        self.transport_connected = connected
        self.reconnects = 0
        self.reconnect_error: BaseException | None = None

    def reconnect(self) -> None:
        self.reconnects += 1
        if self.reconnect_error is not None:
            raise self.reconnect_error
        self.transport_connected = True


class PlainWorker:
    """A backend that reports neither liveness nor connection state."""


class FakeRuntimes:
    def __init__(self, entries: list[tuple[str, BackendKind, object]]) -> None:
        self.entries = entries

    def snapshot(self) -> list[tuple[str, BackendKind, object]]:
        return list(self.entries)

    def is_current(self, session_id: str, kind: BackendKind, runtime: object) -> bool:
        return (session_id, kind, runtime) in self.entries


def _monitor(*entries: tuple[str, BackendKind, object]) -> BackendHealthMonitor:
    return BackendHealthMonitor(FakeRuntimes(list(entries)), interval_s=0.01)


def test_a_dropped_connection_is_rebuilt_and_counted() -> None:
    worker = FakeWorker(connected=False)
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))

    monitor.check_once()

    assert worker.reconnects == 1
    report = monitor.report("s1")[0]
    assert report["healthy"] is True
    assert report["connected"] is True
    assert report["reconnects"] == 1
    assert report["last_error"] is None


def test_a_healthy_backend_is_never_touched() -> None:
    worker = FakeWorker()
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))

    monitor.check_once()

    # Probing a healthy backend would contend with a long running operation for
    # no benefit, so the monitor must stay entirely passive here.
    assert worker.reconnects == 0
    assert monitor.report("s1")[0]["healthy"] is True


def test_a_dead_worker_is_reported_but_never_restarted() -> None:
    worker = FakeWorker(exit_code=1, connected=False)
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))

    monitor.check_once()

    # Restarting would hand back a debugger attached to nothing while looking
    # like a recovery, so this stays a report for session.recover to act on.
    assert worker.reconnects == 0
    report = monitor.report("s1")[0]
    assert report["worker_alive"] is False
    assert report["healthy"] is False


def test_a_failing_reconnect_is_recorded_rather_than_raised() -> None:
    worker = FakeWorker(connected=False)
    worker.reconnect_error = RuntimeError("pipe never came back")
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))

    monitor.check_once()

    report = monitor.report("s1")[0]
    assert report["healthy"] is False
    assert report["failures"] == 1
    assert report["last_error"] == "RuntimeError: pipe never came back"


def test_a_backend_without_health_signals_counts_as_healthy() -> None:
    monitor = _monitor(("s1", BackendKind.IDA, PlainWorker()))

    monitor.check_once()

    # Treating an unknown backend as broken would invent failures for workers
    # that simply do not expose the attributes.
    assert monitor.report("s1")[0]["healthy"] is True


def test_report_is_scoped_and_cleared_per_session() -> None:
    monitor = _monitor(
        ("s1", BackendKind.X64DBG, FakeWorker()),
        ("s2", BackendKind.IDA, FakeWorker()),
    )
    monitor.check_once()

    assert len(monitor.report()) == 2
    assert [item["session_id"] for item in monitor.report("s2")] == ["s2"]

    monitor.forget("s1")

    assert [item["session_id"] for item in monitor.report()] == ["s2"]


class VanishingRuntimes(FakeRuntimes):
    """Hands out a runtime that the owner drops before it gets used."""

    def is_current(self, session_id: str, kind: BackendKind, runtime: object) -> bool:
        del session_id, kind, runtime
        return False


def test_a_runtime_closed_after_the_snapshot_is_left_alone() -> None:
    worker = FakeWorker(connected=False)
    monitor = BackendHealthMonitor(
        VanishingRuntimes([("s1", BackendKind.X64DBG, worker)]),
        interval_s=0.01,
    )

    monitor.check_once()

    # Reconnecting a runtime the owner already dropped holds its request lock for
    # the whole reconnect timeout while close_session waits for the same lock,
    # and resurrects a health row that close_session just forgot.
    assert worker.reconnects == 0
    assert monitor.report("s1") == []


def test_restarting_after_a_timed_out_stop_does_not_leave_two_sweepers() -> None:
    worker = FakeWorker()
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))
    monitor.start()
    first = monitor._thread
    assert first is not None

    monitor.stop(timeout=0.0)
    monitor.start()

    try:
        # Clearing the stop flag for a restart would un-cancel a sweep that is
        # still winding down, leaving two threads looping forever.
        assert monitor._thread is None or monitor._thread is not first
        alive = [t for t in (first, monitor._thread) if t is not None and t.is_alive()]
        assert len(alive) <= 1
    finally:
        monitor.stop(timeout=2.0)
        first.join(timeout=2.0)


def test_a_timed_out_stop_then_start_brings_the_sweeper_back() -> None:
    worker = FakeWorker()
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))
    monitor.interval_s = 0.01
    monitor.start()
    first = monitor._thread
    assert first is not None

    monitor.stop(timeout=0.0)
    monitor.start()
    first.join(timeout=2.0)
    try:
        assert monitor._thread is not None
        assert monitor._thread.is_alive()
        assert monitor._thread is not first
    finally:
        monitor.stop(timeout=2.0)


def test_the_background_sweep_repairs_without_being_asked() -> None:
    worker = FakeWorker(connected=False)
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))
    monitor.start()
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and worker.reconnects == 0:
            time.sleep(0.01)
    finally:
        monitor.stop()

    # The whole point of the monitor is that nobody had to call it first.
    assert worker.reconnects >= 1
    assert worker.transport_connected is True


def test_a_reconnect_that_keeps_failing_backs_off() -> None:
    """A pipe that cannot be rebuilt must not be retried every five seconds.

    The cost is not the attempts, it is the queue behind them: checks run
    serially on one thread and XdbgClient allows a reconnect thirty seconds, so
    one unreachable backend delayed every other session's health check by that
    much, on every sweep, for as long as the process lived -- 17,280 attempts a
    day at the default interval.
    """
    worker = FakeWorker(connected=False)
    worker.reconnect_error = ConnectionError("pipe is gone")
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))

    for _ in range(120):  # ten minutes at the default five-second interval
        monitor.check_once()

    assert worker.reconnects < 15, (
        f"attempted {worker.reconnects} reconnects in 120 checks; it is not backing off"
    )
    assert worker.reconnects >= 5, "it must keep trying occasionally, not give up for good"
    row = monitor.report("s1")[0]
    assert row["connected"] is False
    assert row["failures"] == worker.reconnects


def test_backing_off_never_delays_a_connection_that_can_be_rebuilt() -> None:
    """The common drop is transient, and the very next attempt repairs it."""
    worker = FakeWorker(connected=False)
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))

    monitor.check_once()

    assert worker.reconnects == 1
    assert monitor.report("s1")[0]["connected"] is True


def test_a_backend_that_recovers_starts_from_zero_if_it_drops_again() -> None:
    """Backoff describes the current failure, not the backend's history."""
    worker = FakeWorker(connected=False)
    worker.reconnect_error = ConnectionError("pipe is gone")
    monitor = _monitor(("s1", BackendKind.X64DBG, worker))

    for _ in range(30):
        monitor.check_once()
    while_failing = worker.reconnects

    worker.reconnect_error = None
    for _ in range(70):  # let the backoff elapse, then it repairs
        monitor.check_once()
        if worker.transport_connected:
            break
    assert worker.transport_connected, "it must eventually try again and succeed"

    worker.transport_connected = False
    worker.reconnect_error = ConnectionError("gone again")
    before = worker.reconnects
    monitor.check_once()

    assert worker.reconnects == before + 1, (
        "a fresh drop must be retried at once, not held back by the previous failure"
    )
    assert while_failing < 15


def test_reconnect_backoff_survives_a_concurrent_forget() -> None:
    """A close must never tear the backoff walk that a sweep is writing.

    forget() runs on a close thread and walks _reconnect_backoff to drop a
    session's entries; check_once() writes that same dict on the sweep thread
    and again on a caller's session.health request. If those writes skip the
    lock forget() takes, the walk hits "dictionary changed size during
    iteration" and close_session raises for a reason that has nothing to do
    with the session being closed. Every writer of _reconnect_backoff must
    share the lock so the walk is always over a stable dict.

    Non-vacuous: a large stable population makes forget()'s walk long enough
    that a concurrent insert reliably lands inside it, so an off-lock writer
    trips the RuntimeError this asserts against.
    """
    monitor = _monitor()
    for index in range(2000):
        monitor._reconnect_backoff[("stable", f"b{index}")] = (1, 0)

    errors: list[BaseException] = []
    stop = threading.Event()

    def churn() -> None:
        counter = 0
        while not stop.is_set():
            key = ("live", f"b{counter}")
            counter += 1
            try:
                monitor._note_reconnect_failed(key)
                monitor._reconnect_is_due(key)
            except BaseException as exc:  # noqa: BLE001 - captured for the assert
                errors.append(exc)
                return

    def sweep_forget() -> None:
        for _ in range(2000):
            try:
                monitor.forget("live")
            except BaseException as exc:  # noqa: BLE001 - captured for the assert
                errors.append(exc)
                return

    writer = threading.Thread(target=churn, name="churn")
    forgetter = threading.Thread(target=sweep_forget, name="forget")
    writer.start()
    forgetter.start()
    forgetter.join(timeout=30)
    stop.set()
    writer.join(timeout=30)

    assert not errors, f"a concurrent forget tore the backoff walk: {errors!r}"
    assert not writer.is_alive() and not forgetter.is_alive()
    # The stable population is untouched: forget only drops the named session.
    assert monitor._reconnect_backoff.get(("stable", "b0")) == (1, 0)