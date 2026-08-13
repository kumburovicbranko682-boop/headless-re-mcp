from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from headless_re_mcp.core.watchdog import Watchdog, WatchdogPolicy

JsonObject = dict[str, Any]


@dataclass
class FakeResult:
    ok: bool
    data: JsonObject | None = None
    error: Any = None


def _row(session: str, backend: str, *, alive: bool = True, connected: bool = True) -> JsonObject:
    return {
        "session_id": session,
        "backend": backend,
        "worker_alive": alive,
        "connected": connected,
        "healthy": alive and connected,
        "last_error": None if connected else "pipe dropped",
    }


class FakeHealth:
    def __init__(self, rows: list[JsonObject], recover_ok: bool = True) -> None:
        self.rows = rows
        self.recover_ok = recover_ok
        self.recover_calls: list[tuple[str, list[str] | None]] = []

    def session_health(self, session_id: str | None = None) -> FakeResult:
        return FakeResult(True, {"backends": self.rows, "count": len(self.rows)})

    def session_recover(self, session_id: str, backends: list[str] | None = None) -> FakeResult:
        self.recover_calls.append((session_id, backends))
        if self.recover_ok:
            return FakeResult(True, {"recovered": 1, "failed": 0})
        return FakeResult(False, None, error=type("E", (), {"message": "no headless configured"})())


def test_a_healthy_sweep_raises_nothing() -> None:
    health = FakeHealth([_row("s1", "ida"), _row("s2", "x64dbg")])
    watchdog = Watchdog(health)

    report = watchdog.sweep()

    assert report["checked"] == 2
    assert report["dead"] == 0
    assert watchdog.recent_alerts() == []


def test_a_dead_backend_is_reported_but_not_touched_by_default() -> None:
    """Correction is opt-in: a recovered debugger is attached to nothing.

    Reporting is not, because under 24/7 operation a dead worker that nobody
    notices fails every mission that needs it until the budget runs out.
    """
    health = FakeHealth([_row("s1", "x64dbg", alive=False, connected=False)])
    watchdog = Watchdog(health)

    report = watchdog.sweep()

    assert report["dead"] == 1
    assert report["actions"][0]["action"] == "reported"
    assert health.recover_calls == []
    alert = watchdog.recent_alerts()[0]
    assert alert["kind"] == "backend_dead"
    assert alert["session_id"] == "s1"


def test_a_dead_backend_is_recovered_once_the_operator_opts_in() -> None:
    health = FakeHealth([_row("s1", "x64dbg", alive=False, connected=False)])
    watchdog = Watchdog(health, policy=WatchdogPolicy(auto_recover_backends=True))

    report = watchdog.sweep()

    assert health.recover_calls == [("s1", ["x64dbg"])]
    assert report["actions"][0]["action"] == "recovered"
    assert watchdog.recovered == 1
    alert = watchdog.recent_alerts()[0]
    assert alert["kind"] == "backend_recovered"
    # Recovery is reported at info: it is a fact to record, not a page.
    assert alert["severity"] == "info"


def test_a_failed_recovery_is_escalated_rather_than_swallowed() -> None:
    health = FakeHealth([_row("s1", "ida", alive=False, connected=False)], recover_ok=False)
    watchdog = Watchdog(health, policy=WatchdogPolicy(auto_recover_backends=True))

    report = watchdog.sweep()

    assert report["actions"][0]["action"] == "recovery_failed"
    assert watchdog.recovered == 0
    assert watchdog.recent_alerts()[0]["kind"] == "backend_recovery_failed"


def test_a_reconnecting_backend_is_noted_without_being_recovered() -> None:
    """The health monitor rebuilds connections; a flapping one is still a signal."""
    health = FakeHealth([_row("s1", "x64dbg", alive=True, connected=False)])
    watchdog = Watchdog(health, policy=WatchdogPolicy(auto_recover_backends=True))

    report = watchdog.sweep()

    assert report["disconnected"] == 1
    assert report["dead"] == 0
    assert health.recover_calls == []
    assert watchdog.recent_alerts()[0]["kind"] == "backend_disconnected"


def test_a_sweep_that_explodes_is_recorded_instead_of_raised() -> None:
    """A watchdog that dies stops watching, which nobody would notice."""

    class Exploding:
        def session_health(self, session_id: str | None = None) -> FakeResult:
            raise RuntimeError("health probe blew up")

        def session_recover(self, session_id: str, backends: list[str] | None = None) -> FakeResult:
            raise AssertionError("must not be reached")

    watchdog = Watchdog(Exploding())

    alert = watchdog.sweep()

    assert alert["kind"] == "watchdog_failed"
    assert "health probe blew up" in str(alert["detail"])


def test_alert_history_is_bounded_and_newest_first() -> None:
    rows = [_row(f"s{i}", "ida", alive=False, connected=False) for i in range(5)]
    watchdog = Watchdog(FakeHealth(rows))

    watchdog.sweep()
    recent = watchdog.recent_alerts(limit=2)

    assert len(recent) == 2
    assert recent[0]["session_id"] == "s4"
    assert watchdog.alerts.maxlen is not None


def test_policy_defaults_keep_reporting_on_and_correction_off() -> None:
    policy = WatchdogPolicy()
    assert policy.enabled is True
    assert policy.auto_recover_backends is False


def test_policy_reads_settings_and_can_be_disabled(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    from headless_re_mcp.config import Settings

    base = replace(Settings.load(), artifact_root=tmp_path)
    on = WatchdogPolicy.from_settings(
        replace(base, watchdog_interval_s=5.0, watchdog_auto_recover_backends=True)
    )
    assert on.enabled is True
    assert on.auto_recover_backends is True

    off = WatchdogPolicy.from_settings(replace(base, watchdog_interval_s=0.0))
    assert off.enabled is False

def test_one_dead_backend_is_reported_once_not_on_every_sweep() -> None:
    """A failure that persists is one alert, not one per sweep.

    At the default thirty-second interval a backend that stays dead produced
    2,880 identical alerts a day. The cost is not the alerts themselves but
    what they bury: an operator or a collector looking for the alert that is
    not identical has to find it in that.
    """
    health = FakeHealth([_row("s1", "ida", alive=False, connected=False)])
    watchdog = Watchdog(health, policy=WatchdogPolicy(interval_s=30.0))

    for _ in range(120):  # an hour
        report = watchdog.sweep()

    assert watchdog.raised == 1, f"raised {watchdog.raised} alerts for one dead backend"
    assert report["dead"] == 1, "it must still be reported as dead every sweep"
    assert report["actions"][0]["action"] == "still_dead"


def test_recovery_gives_up_on_a_backend_that_will_not_come_back() -> None:
    """Relaunching forever is not recovery, it is a loop.

    The supervisor already refuses to restart a child that keeps dying
    immediately; a backend that has refused to start five times running gets
    the same treatment, because the reasons it does not come back -- an
    uninstalled IDA, a deleted binary, an expired licence -- are not the kind
    that a sixth attempt fixes.
    """
    health = FakeHealth([_row("s1", "ida", alive=False, connected=False)], recover_ok=False)
    watchdog = Watchdog(
        health,
        policy=WatchdogPolicy(auto_recover_backends=True, interval_s=30.0, max_recovery_attempts=5),
    )

    for _ in range(120):
        report = watchdog.sweep()

    assert len(health.recover_calls) == 5, "it must stop trying"
    assert report["actions"][0]["action"] == "abandoned"
    kinds = [alert["kind"] for alert in watchdog.recent_alerts(limit=20)]
    assert "backend_recovery_abandoned" in kinds, "giving up has to be said out loud"
    assert kinds.count("backend_recovery_abandoned") == 1, "and said once"


def test_a_backend_that_comes_back_and_dies_again_is_treated_as_new() -> None:
    """Giving up applies to one failure, not to the backend forever."""
    row = _row("s1", "ida", alive=False, connected=False)
    health = FakeHealth([row], recover_ok=True)
    watchdog = Watchdog(health, policy=WatchdogPolicy(auto_recover_backends=True))

    watchdog.sweep()
    assert len(health.recover_calls) == 1

    row["worker_alive"] = True
    row["connected"] = True
    watchdog.sweep()

    row["worker_alive"] = False
    row["connected"] = False
    watchdog.sweep()

    assert len(health.recover_calls) == 2, "a fresh failure deserves a fresh attempt"