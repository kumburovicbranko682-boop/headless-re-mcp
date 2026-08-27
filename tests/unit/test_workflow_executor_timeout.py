"""Pin the workflow executor's deadline guard.

Every step of a workflow run is bounded by ``_remaining(deadline)``, which turns
the shared deadline into the per-step timeout handed to the debugger. Once the
deadline is spent it must raise ``TimeoutError`` rather than return a zero or
negative timeout -- a non-positive timeout would otherwise be passed straight to
a blocking debugger call. The happy path (a positive budget) runs throughout the
workflow suite; this pins the expiry branch it never reaches on its own.
"""

from __future__ import annotations

from time import monotonic

import pytest

from headless_re_mcp.workflows.executor import _remaining


def test_remaining_returns_the_budget_before_the_deadline() -> None:
    remaining = _remaining(monotonic() + 5.0)
    assert 0.0 < remaining <= 5.0


def test_remaining_raises_once_the_deadline_is_spent() -> None:
    with pytest.raises(TimeoutError, match="workflow execution timed out"):
        _remaining(monotonic() - 0.001)
