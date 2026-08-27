"""``frida._bound_timeout`` must fail closed on a NaN caller timeout.

The frida.* tool schemas declare ``0 < timeout <= MAX_WORKFLOW_TIMEOUT``, but the
agent transport invokes handlers straight from model arguments with no schema
enforcement (``CommandCatalog.invoke`` -> ``spec.handler``). ``_bound_timeout`` is
the boundary that stops a bad value from becoming the deadline: a NaN slips past
``value <= 0`` (``nan <= 0`` is False) and ``min(nan, MAX)`` stays nan, so it used
to reach ``_run_deadline`` -> ``Future.result(nan)``, which returns immediately
with a timeout -- tearing down the just-created session and racing the worker's
``sessions.append`` so a live frida session could leak on the daemon thread.
"""

from __future__ import annotations

import math

import pytest

from headless_re_mcp.backends.frida.client import (
    MAX_WORKFLOW_TIMEOUT,
    FridaError,
    _bound_timeout,
)


def test_bound_timeout_passes_and_caps_finite_values() -> None:
    assert _bound_timeout(1.0) == 1.0
    assert _bound_timeout(30.0) == 30.0
    assert _bound_timeout(MAX_WORKFLOW_TIMEOUT) == MAX_WORKFLOW_TIMEOUT
    # inf is finite-unsafe but greater than the ceiling, so it caps rather than
    # raising -- the "park the worker" case the clamp is meant to bound.
    assert _bound_timeout(float("inf")) == MAX_WORKFLOW_TIMEOUT
    assert _bound_timeout(10**9) == MAX_WORKFLOW_TIMEOUT


@pytest.mark.parametrize("bad", [0.0, -1.0, -100.0])
def test_bound_timeout_rejects_nonpositive(bad: float) -> None:
    with pytest.raises(FridaError) as info:
        _bound_timeout(bad)
    assert info.value.code == "invalid_params"


def test_bound_timeout_rejects_nan() -> None:
    with pytest.raises(FridaError) as info:
        _bound_timeout(float("nan"))
    assert info.value.code == "invalid_params"
    # The returned value must never itself be NaN when it does not raise.
    assert not math.isnan(_bound_timeout(5.0))
