"""Two arcs the broader monitor suite leaves open.

``test_health_monitor.py`` exercises check_once, reconnect back-off and the
happy-path background sweep, but never (1) makes a sweep iteration raise, so the
``except`` that keeps the daemon alive by recording an alert is untested, nor
(2) forgets a session that has a recorded reconnect back-off entry, so the arm
of ``forget`` that clears that book-keeping never runs. Both are pinned here.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.core.health as health
from headless_re_mcp.core.health import BackendHealthMonitor
from headless_re_mcp.core.models import BackendKind


class _FailingReconnectWorker:
    """A backend that is dropped and refuses to reconnect."""

    def __init__(self) -> None:
        self.exit_code: int | None = None
        self.transport_connected = False
        self.reconnects = 0

    def reconnect(self) -> None:
        self.reconnects += 1
        raise RuntimeError("pipe never came back")


class _Runtimes:
    def __init__(self, entries: list[tuple[str, BackendKind, object]]) -> None:
        self.entries = entries

    def snapshot(self) -> list[tuple[str, BackendKind, object]]:
        return list(self.entries)

    def is_current(
        self, session_id: str, kind: BackendKind, runtime: object
    ) -> bool:
        return (session_id, kind, runtime) in self.entries


def test_a_raising_sweep_records_an_alert_instead_of_killing_the_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitor = BackendHealthMonitor(_Runtimes([]), interval_s=0.0)

    alerts: list[tuple[str, dict[str, Any] | None]] = []

    def _capture(name: str, *, fields: dict[str, Any] | None = None) -> None:
        alerts.append((name, fields))

    monkeypatch.setattr(health, "record_alert", _capture)

    def _boom(self: BackendHealthMonitor, *, repair: bool = True) -> Any:
        # Stop the loop from the inside so _run makes exactly one pass, then
        # fail: the except arm must swallow this and record it.
        self._stop.set()
        raise RuntimeError("sweep exploded")

    monkeypatch.setattr(BackendHealthMonitor, "check_once", _boom)

    # Runs synchronously: one iteration, the raise, the alert, then the stop
    # flag ends the loop. It must return rather than propagate.
    monitor._run()

    assert alerts, "a sweep that raised must leave an audible alert"
    name, fields = alerts[0]
    assert name == "health_sweep_failed"
    assert fields is not None
    assert "sweep exploded" in fields["error"]


def test_forget_clears_a_recorded_reconnect_backoff_entry() -> None:
    worker = _FailingReconnectWorker()
    monitor = BackendHealthMonitor(
        _Runtimes([("s1", BackendKind.X64DBG, worker)]), interval_s=0.01
    )

    # A failed reconnect records a back-off entry keyed by the session.
    monitor.check_once()
    assert any(
        key[0] == "s1" for key in monitor._reconnect_backoff
    ), "a failing reconnect should have recorded a back-off entry to clear"

    monitor.forget("s1")

    assert not any(key[0] == "s1" for key in monitor._reconnect_backoff)
    assert monitor.report("s1") == []
