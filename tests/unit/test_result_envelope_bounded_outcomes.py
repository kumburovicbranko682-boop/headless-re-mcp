"""The canonical error envelope must name bounded outcomes, not bury them.

``_failure`` is the one place every service mixin turns an exception into an
RpcError. A caller cancel (``BoundedCancelled``) and a deadline
(``TimedOut``) are control signals from the bounded-run machinery, not
unexpected faults -- but until they were named here they fell through to the
generic branch and came back as ``internal_error`` with a logged incident.

That is exactly the miscasting the upx and net_reactor_slayer adapters each
carried until they grew their own re-raise: a caller cancel reported as a
server defect. Every current endpoint handles these before reaching
``_failure``; these tests pin the envelope itself so a path that forgets the
re-raise still answers honestly rather than filing an incident for a cancel.

Cross-platform: this is pure envelope construction, identical on POSIX and
Windows, so it runs and gates on both.
"""

from __future__ import annotations

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut
from headless_re_mcp.core.results import _failure


def test_bounded_cancelled_is_a_clean_cancel_not_an_internal_error() -> None:
    result = _failure(BoundedCancelled([4321, 4322]), session_id="s", backend="upx")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "cancelled"
    # The whole point: a caller cancel must never be filed as an internal_error,
    # which would log a spurious incident and imply a server defect.
    assert result.error.code != "internal_error"
    assert result.error.retryable is True
    # Passed-through call details survive, and the killed tree is reported.
    assert result.error.details["session_id"] == "s"
    assert result.error.details["backend"] == "upx"
    assert result.error.details["killed_pids"] == [4321, 4322]
    # No incident id is minted for a control signal.
    assert "incident_id" not in result.error.details


def test_bounded_cancelled_with_no_killed_pids_still_reports_cleanly() -> None:
    result = _failure(BoundedCancelled())

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "cancelled"
    assert result.error.details["killed_pids"] == []


def test_timed_out_is_a_timeout_not_an_internal_error() -> None:
    result = _failure(TimedOut(30.0, [999]), session_id="s")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.code != "internal_error"
    assert result.error.retryable is True
    assert result.error.details["timeout_s"] == 30.0
    assert result.error.details["killed_pids"] == [999]
    assert "incident_id" not in result.error.details


def test_a_genuinely_unexpected_error_is_still_an_internal_error() -> None:
    """The bounded-outcome cases must not weaken the catch-all.

    A plain exception the envelope does not recognise still becomes an
    internal_error with an incident, so a real fault is not quietly downgraded.
    """
    result = _failure(RuntimeError("something genuinely unexpected"))

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"
    assert "incident_id" in result.error.details
