"""Input bounds for wait_for_window's timeout and poll_interval.

The ui.wait tool schema declares ``0 < timeout <= 30`` and
``0 < poll_interval <= 5``, but the agent and OpenAI-bridge transports call
the handler straight from model arguments with no pydantic validation, and
ui_drive builds ``poll_interval`` with a bare ``float(step["poll_interval"])``
from a caller script. The bound therefore has to hold inside wait_for_window
itself. These arms run everywhere: the validation precedes the first
resolve_hwnd call, so no Win32 stack is needed to exercise them.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.core.ui_win32 as ui
from headless_re_mcp.core.ui_win32 import (
    _MAX_POLL_INTERVAL_SECONDS,
    _MAX_WAIT_SECONDS,
    wait_for_window,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({4242})


@pytest.mark.parametrize(
    "bad",
    [
        1e9,  # finite but far past the timeout: time.sleep(1e9) is ~31 years
        float("inf"),  # time.sleep(inf) raises OverflowError
        float("nan"),  # every comparison False, so max(0.05, nan) hid it before
        0,
        -5.0,
        _MAX_POLL_INTERVAL_SECONDS + 1,
        True,  # a bool is an int subclass but never a valid interval
        "0.1",
        None,
    ],
    ids=[
        "huge-finite",
        "inf",
        "nan",
        "zero",
        "negative",
        "over-ceiling",
        "bool",
        "string",
        "none",
    ],
)
def test_wait_for_window_rejects_a_bad_poll_interval_before_sleeping(
    monkeypatch: pytest.MonkeyPatch, bad: Any
) -> None:
    # If validation ever slipped, these would reach the loop; make both the
    # resolver and the sleep loud so a regression cannot pass silently.
    monkeypatch.setattr(
        ui, "resolve_hwnd", lambda *a, **k: pytest.fail("resolve_hwnd must not run")
    )
    monkeypatch.setattr(
        ui.time, "sleep", lambda s: pytest.fail(f"slept for {s!r} on a bad interval")
    )
    with pytest.raises(UiPidBoundaryError) as caught:
        wait_for_window(_PIDS, timeout=1.0, poll_interval=bad)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"
    assert "poll_interval" in caught.value.message


@pytest.mark.parametrize("bad", [0, -1.0, _MAX_WAIT_SECONDS + 1, float("nan"), True, "1"])
def test_wait_for_window_still_rejects_a_bad_timeout(
    monkeypatch: pytest.MonkeyPatch, bad: Any
) -> None:
    monkeypatch.setattr(
        ui, "resolve_hwnd", lambda *a, **k: pytest.fail("resolve_hwnd must not run")
    )
    with pytest.raises(UiPidBoundaryError) as caught:
        wait_for_window(_PIDS, timeout=bad, poll_interval=0.1)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"
    assert "timeout" in caught.value.message


def test_wait_for_window_accepts_a_valid_interval_and_returns_a_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A resolver that answers on the first poll returns matched without sleeping,
    # so the happy path is exercised cross-platform.
    window = {"hwnd": 0x1234, "pid": 4242}
    monkeypatch.setattr(ui, "resolve_hwnd", lambda *a, **k: dict(window))
    monkeypatch.setattr(
        ui.time, "sleep", lambda s: pytest.fail("a first-poll match must not sleep")
    )
    result = wait_for_window(_PIDS, timeout=5.0, poll_interval=_MAX_POLL_INTERVAL_SECONDS)
    assert result["matched"] is True
    assert result["window"] == window
