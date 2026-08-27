"""The executor's deadline arithmetic must refuse a budget that is spent."""

from __future__ import annotations

from time import monotonic

import pytest

from headless_re_mcp.workflows.executor import _remaining


def test_a_spent_deadline_raises_instead_of_returning_a_negative_budget() -> None:
    # _remaining feeds per-step timeouts; a zero or negative value passed on
    # to a wait primitive means "no timeout" to some backends, which would
    # turn an expired workflow into an unbounded one.
    with pytest.raises(TimeoutError, match="workflow execution timed out"):
        _remaining(monotonic() - 1.0)


def test_a_live_deadline_returns_the_time_still_left() -> None:
    remaining = _remaining(monotonic() + 60.0)

    assert 0.0 < remaining <= 60.0
