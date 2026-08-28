"""Edge coverage for the backend watchdog's pruning and recovery parsing.

``test_watchdog.py`` covers the sweep/report/recover behaviours. These pin the
remaining guards: pruning a dead streak once the backend is alive again, and the
defensive parsing in the recovery-outcome and row readers.
"""

from __future__ import annotations

from headless_re_mcp.core.watchdog import Watchdog, WatchdogPolicy
from tests.unit.test_watchdog import FakeHealth, FakeResult, _row


def test_dead_streak_is_pruned_when_the_backend_comes_back() -> None:
    health = FakeHealth([_row("s1", "ida", alive=False, connected=False)])
    watchdog = Watchdog(health, policy=WatchdogPolicy(interval_s=30.0))

    watchdog.sweep()  # dead -> streak recorded, reported once
    health.rows = [_row("s1", "ida", alive=True, connected=True)]
    revived = watchdog.sweep()  # alive again -> streak pruned
    assert revived["dead"] == 0

    health.rows = [_row("s1", "ida", alive=False, connected=False)]
    again = watchdog.sweep()  # dead again -> a *fresh* failure, not a continuation
    assert again["actions"][0]["action"] == "reported"

    kinds = [alert["kind"] for alert in watchdog.recent_alerts()]
    assert kinds.count("backend_dead") == 2


def test_recovery_success_needs_a_dict_payload() -> None:
    # ok=True but the data is not an object -> cannot claim success.
    assert Watchdog._recovery_succeeded(FakeResult(True, data=None)) is False


def test_recovery_success_rejects_non_integer_counts() -> None:
    outcome = FakeResult(True, data={"recovered": "one", "failed": 0})
    assert Watchdog._recovery_succeeded(outcome) is False


def test_recovery_failure_detail_falls_back_when_counts_are_unparsable() -> None:
    # No error message and a non-integer "failed" count -> the generic reason.
    outcome = FakeResult(True, data={"failed": "many"}, error=None)
    assert Watchdog._recovery_failure_detail(outcome) == "recovery returned no error"


def test_recovery_failure_detail_falls_back_when_there_is_no_payload() -> None:
    # No error message and no data object at all -> the generic reason.
    outcome = FakeResult(True, data=None, error=None)
    assert Watchdog._recovery_failure_detail(outcome) == "recovery returned no error"


def test_rows_is_empty_when_the_payload_is_not_an_object() -> None:
    assert Watchdog._rows(FakeResult(True, data=None)) == []
