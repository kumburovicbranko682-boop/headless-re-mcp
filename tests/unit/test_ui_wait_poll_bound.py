"""wait_for_window must never sleep past its own validated timeout.

The timeout argument has always been range-checked, but poll_interval -- the
other caller-controlled duration -- was only bounded by the MCP tool schema
(le=5.0). A ui.drive wait step (``{"action": "wait", "poll_interval": ...}``)
and an agent-path ui.wait call both reach wait_for_window without that schema,
and the retry sleep used the interval verbatim: poll_interval=3600 with
timeout=1 parked the service thread for an hour, and 1e9 for decades.
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from headless_re_mcp.core import ui_win32
from headless_re_mcp.core.windows import UiPidBoundaryError


class _FakeTime:
    """Deterministic clock: sleep() advances monotonic() and records requests."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _never_found(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    raise UiPidBoundaryError("not_found", "no matching window")


def test_poll_sleep_is_clamped_to_the_remaining_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A poll_interval larger than the budget must not outlive the deadline.

    Before the clamp, the first failed resolve slept the full interval
    (here 30s against a 1s timeout), so the recorded sleep equalled
    poll_interval and the call returned long after the timeout it validated.
    """
    fake = _FakeTime()
    monkeypatch.setattr(ui_win32, "time", fake)
    monkeypatch.setattr(ui_win32, "resolve_hwnd", _never_found)

    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_win32.wait_for_window(
            frozenset({123}),
            timeout=1.0,
            poll_interval=30.0,
            title="never-appears",
        )

    assert excinfo.value.code == "timeout"
    assert fake.sleeps, "the wait loop should have slept at least once"
    assert max(fake.sleeps) <= 1.0
    assert fake.now <= 1.0 + 1e-9


def test_small_poll_interval_still_polls_repeatedly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clamp must not change the ordinary case: many short sleeps."""
    fake = _FakeTime()
    monkeypatch.setattr(ui_win32, "time", fake)
    monkeypatch.setattr(ui_win32, "resolve_hwnd", _never_found)

    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_win32.wait_for_window(
            frozenset({123}),
            timeout=1.0,
            poll_interval=0.1,
            title="never-appears",
        )

    assert excinfo.value.code == "timeout"
    assert len(fake.sleeps) >= 5
    assert all(s <= 1.0 for s in fake.sleeps)


def test_match_after_one_poll_returns_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A window that appears while polling is still returned as before."""
    fake = _FakeTime()
    calls = {"n": 0}

    def found_second_try(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise UiPidBoundaryError("not_found", "not yet")
        return {"hwnd": 4242, "title": "target"}

    monkeypatch.setattr(ui_win32, "time", fake)
    monkeypatch.setattr(ui_win32, "resolve_hwnd", found_second_try)

    result = ui_win32.wait_for_window(
        frozenset({123}),
        timeout=5.0,
        poll_interval=0.1,
        title="target",
    )

    assert result["matched"] is True
    assert result["window"] == {"hwnd": 4242, "title": "target"}
    assert result["waited_ms"] >= 0


@pytest.mark.parametrize(
    "poll_interval",
    [0, -1, 0.0, ui_win32._MAX_WAIT_SECONDS + 1, 1e9, math.inf, math.nan, True, "0.1", None],
    ids=["zero", "negative", "zero-float", "over-max", "huge", "inf", "nan", "bool", "str", "none"],
)
def test_out_of_range_poll_interval_is_refused_up_front(
    monkeypatch: pytest.MonkeyPatch,
    poll_interval: Any,
) -> None:
    """Garbage intervals get invalid_params before any window enumeration.

    inf and NaN matter here because both survive a naive min/max clamp:
    min(inf, remaining) is fine but time.sleep(inf) is not, and every
    comparison against NaN is False. The range comparison rejects both.
    """
    fake = _FakeTime()
    monkeypatch.setattr(ui_win32, "time", fake)
    monkeypatch.setattr(ui_win32, "resolve_hwnd", _never_found)

    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_win32.wait_for_window(
            frozenset({123}),
            timeout=1.0,
            poll_interval=poll_interval,
            title="never-appears",
        )

    assert excinfo.value.code == "invalid_params"
    assert fake.sleeps == []
