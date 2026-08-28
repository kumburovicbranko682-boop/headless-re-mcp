"""Cover the shared-deadline helper in the workflow executor.

``_remaining`` converts an absolute monotonic deadline into the time left and
raises ``TimeoutError`` the moment the deadline has passed, so a multi-step
workflow stops rather than issuing a call with a non-positive timeout.
"""

from __future__ import annotations

from time import monotonic

import pytest

from headless_re_mcp.workflows.executor import _remaining


def test_remaining_raises_once_the_deadline_has_passed() -> None:
    with pytest.raises(TimeoutError, match="workflow execution timed out"):
        _remaining(monotonic() - 1.0)


def test_remaining_raises_exactly_at_the_deadline() -> None:
    # remaining <= 0 is the raise condition, so a deadline of "now" also trips it.
    with pytest.raises(TimeoutError):
        _remaining(monotonic())


def test_remaining_returns_time_left_before_the_deadline() -> None:
    remaining = _remaining(monotonic() + 5.0)
    assert 0 < remaining <= 5.0
