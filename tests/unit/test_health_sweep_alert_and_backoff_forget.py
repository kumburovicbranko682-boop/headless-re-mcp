"""The health sweep must outlive a crashing check, and forget() must clear backoff.

The sweep thread exists to repair sessions; a check_once that raises (a runtime
source torn down mid-snapshot, an unexpected transport error) must be recorded
as an alert rather than silently killing the only thread that would ever notice
future drops. Separately, forget() must clear a session's reconnect backoff as
well as its entries: a session that is closed and reopened under the same id
must start with a clean retry budget, not sit out checks earned by its
predecessor's dead pipe.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from headless_re_mcp.core import health
from headless_re_mcp.core.health import BackendHealth, BackendHealthMonitor


class _ExplodingSource:
    """A runtime source torn down underneath the sweep: snapshot() raises."""

    def snapshot(self) -> list[tuple[str, Any, Any]]:
        raise RuntimeError("runtime source torn down")

    def is_current(self, session_id: str, kind: Any, runtime: Any) -> bool:
        return False


class _IdleSource:
    def snapshot(self) -> list[tuple[str, Any, Any]]:
        return []

    def is_current(self, session_id: str, kind: Any, runtime: Any) -> bool:
        return False


def test_a_crashing_check_records_an_alert_and_the_sweep_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitor = BackendHealthMonitor(runtimes=_ExplodingSource(), interval_s=30.0)
    alerts: list[tuple[str, dict[str, Any]]] = []
    seen = threading.Event()

    def capture(name: str, *, fields: dict[str, Any]) -> None:
        alerts.append((name, fields))
        # Stop after the first alert so the test observes exactly one loop
        # iteration; Event.wait returns immediately once set, so the 30s
        # interval never delays the test.
        monitor._stop.set()
        seen.set()

    monkeypatch.setattr(health, "record_alert", capture)

    monitor.start()
    try:
        assert seen.wait(timeout=5.0), "the sweep never reported the crash"
    finally:
        monitor.stop(timeout=5.0)

    assert alerts == [
        ("health_sweep_failed", {"error": "RuntimeError: runtime source torn down"})
    ]


def test_forget_clears_reconnect_backoff_for_that_session_only() -> None:
    monitor = BackendHealthMonitor(runtimes=_IdleSource())
    monitor._entries[("gone", "x64dbg")] = BackendHealth(
        session_id="gone",
        backend="x64dbg",
        worker_alive=True,
        connected=True,
        checked_at=0.0,
    )
    monitor._reconnect_backoff[("gone", "x64dbg")] = (3, 2)
    monitor._reconnect_backoff[("kept", "windbg")] = (1, 0)

    monitor.forget("gone")

    # The closed session's failure history is gone -- a new session under the
    # same id starts with a clean retry budget -- while the other session's
    # backoff is untouched.
    assert monitor._entries == {}
    assert monitor._reconnect_backoff == {("kept", "windbg"): (1, 0)}
