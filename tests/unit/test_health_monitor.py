from __future__ import annotations

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
