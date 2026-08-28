"""Coverage for the health monitor's sweep-failure alert arc.

``test_health_monitor.py`` drives the sweep, restart and backoff behaviour.
This pins the one arc it does not reach: the guard in ``_run`` that turns an
unexpected ``check_once`` exception into a ``health_sweep_failed`` alert instead
of letting the background thread die and stop protecting the session. ``_run``
is driven synchronously with a one-shot stop event so no daemon thread starts.
A separate file keeps this off the concurrently edited ``test_health_monitor``.
"""

from __future__ import annotations

import threading
from typing import cast

import pytest

import headless_re_mcp.core.health as health
from headless_re_mcp.core.health import BackendHealthMonitor, _RuntimeSource


class _OneShotStop(threading.Event):
    """A stop event that lets ``_run`` execute exactly one iteration."""

    def __init__(self) -> None:
        super().__init__()
        self._checks = 0

    def is_set(self) -> bool:
        self._checks += 1
        return self._checks > 1

    def wait(self, timeout: float | None = None) -> bool:
        return True


def test_run_alerts_and_keeps_sweeping_when_check_once_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        health,
        "record_alert",
        lambda kind, **kwargs: alerts.append((kind, kwargs.get("fields", {}))),
    )

    def _boom(self: BackendHealthMonitor) -> None:
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(BackendHealthMonitor, "check_once", _boom)

    monitor = BackendHealthMonitor(runtimes=cast(_RuntimeSource, object()))
    monitor._stop = _OneShotStop()

    # A raising check_once must be swallowed into an alert, not allowed to kill
    # the sweep thread; _run returns normally after the one-shot stop.
    monitor._run()

    assert len(alerts) == 1
    kind, fields = alerts[0]
    assert kind == "health_sweep_failed"
    assert fields["error"] == "RuntimeError: probe blew up"
