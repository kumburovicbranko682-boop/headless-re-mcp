"""Pin the healthz probe's deadline-budget guards.

``probe_our_healthz`` detects an already-running console before the launcher
tries to bind. It must never hand a non-positive timeout to a blocking socket
call, so it rechecks the remaining budget before connecting and again before
sending, bailing with ``None`` when the deadline is already spent. Both guards
sit on a clock the happy path never drives to expiry; these pin them with a
controlled clock and a socket that fails loudly if it is used past the budget.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterable

import pytest

from headless_re_mcp.web import launch_util


class _Clock:
    """Deterministic monotonic() that yields the given values then holds the last."""

    def __init__(self, values: Iterable[float]) -> None:
        self._values = list(values)
        self._i = 0

    def __call__(self) -> float:
        value = self._values[min(self._i, len(self._values) - 1)]
        self._i += 1
        return value


def test_probe_bails_before_connecting_when_the_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # deadline computed at t=0 (0.6s), rechecked at t=1.0 -> already expired.
    monkeypatch.setattr(time, "monotonic", _Clock([0.0, 1.0]))

    def _must_not_connect(*args: object, **kwargs: object) -> object:
        raise AssertionError("connect attempted with an expired budget")

    monkeypatch.setattr(socket, "create_connection", _must_not_connect)

    assert launch_util.probe_our_healthz("127.0.0.1", 65535, timeout=0.6) is None


def test_probe_bails_after_connecting_when_the_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # deadline at t=0 (0.6s); first recheck at t=0 passes; post-connect recheck
    # at t=1.0 is expired, so the probe returns before setting a socket timeout.
    monkeypatch.setattr(time, "monotonic", _Clock([0.0, 0.0, 1.0]))
    closed = {"close": False}

    class _FakeSock:
        def settimeout(self, timeout: float) -> None:
            raise AssertionError("a non-positive socket timeout must never be set")

        def sendall(self, payload: bytes) -> None:
            raise AssertionError("must not send once the budget is spent")

        def shutdown(self, how: int) -> None:
            pass

        def close(self) -> None:
            closed["close"] = True

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: _FakeSock(),
    )

    assert launch_util.probe_our_healthz("127.0.0.1", 65535, timeout=0.6) is None
    assert closed["close"] is True
