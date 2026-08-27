"""forget() must also drop a session's recorded reconnect back-off.

``test_health_monitor.py`` forgets a session that only has a health entry, and
``test_health_sweep_failure.py`` covers the sweep-failure alert; neither forgets
a session that has an outstanding reconnect back-off entry, so the arm of
``forget`` that clears that book-keeping stays untested. A stale back-off left
behind would make a brand-new session reusing the same id sit out reconnect
attempts it never earned.
"""

from __future__ import annotations

from headless_re_mcp.core.health import BackendHealthMonitor
from headless_re_mcp.core.models import BackendKind


class _FailingReconnectWorker:
    """A dropped backend that refuses to reconnect, so a back-off is recorded."""

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
