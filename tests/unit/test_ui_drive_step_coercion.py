"""Numeric coercion bounds for run_drive_step's client-supplied step fields.

A ui.drive step is raw client JSON: the ui.* tool schemas bound ``timeout_ms`` to
1..30000 and ``timeout`` / ``poll_interval`` to the wait ranges, but a drive step
never runs that pydantic validation. run_drive_step used a bare
``int(step["timeout_ms"])`` / ``float(step["timeout"])`` that mapped a JSON 1e400
(decoded to inf) to OverflowError and null/{} to TypeError -- neither the
UiPidBoundaryError the _ui_drive loop catches, so both fell through to
``except BaseException`` and became an internal_error incident for what is only a
bad parameter. Every arm here runs cross-platform: the coercion precedes the
Win32 call, so no Win32 stack is needed to exercise it.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.core.ui_drive as ui_drive
from headless_re_mcp.core.ui_drive import run_drive_step
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({4242})


@pytest.mark.parametrize(
    "bad",
    [float("inf"), float("nan"), None, {}, [], "abc"],
    ids=["inf", "nan", "none", "dict", "list", "non-numeric"],
)
def test_click_rejects_an_uncoercible_timeout_ms(bad: Any) -> None:
    # int(inf) raises OverflowError, int(None)/int({}) raise TypeError, int("abc")
    # raises ValueError; the raw exception used to escape as an internal_error.
    with pytest.raises(UiPidBoundaryError) as caught:
        run_drive_step(
            {"action": "click", "hwnd": 123, "timeout_ms": bad},
            allowed_pids=_PIDS,
            handles={},
        )
    assert caught.value.code == "invalid_params"
    assert "timeout_ms" in caught.value.message


@pytest.mark.parametrize("bad", [0, -5, 30_001, 10**20], ids=["zero", "negative", "over", "huge"])
def test_click_rejects_an_out_of_range_timeout_ms(bad: int) -> None:
    # int() would accept these, but _send_timeout only casts to c_uint and never
    # range-checks: a huge finite value wraps mod 2**32 rather than failing.
    with pytest.raises(UiPidBoundaryError) as caught:
        run_drive_step(
            {"action": "click", "hwnd": 123, "timeout_ms": bad},
            allowed_pids=_PIDS,
            handles={},
        )
    assert caught.value.code == "invalid_params"
    assert "between 1 and 30000" in caught.value.message


@pytest.mark.parametrize("good", [5000, 5000.0, "5000", 1, 30_000])
def test_click_passes_a_valid_timeout_ms_through_as_int(
    monkeypatch: pytest.MonkeyPatch, good: Any
) -> None:
    captured: dict[str, Any] = {}

    def fake_click(hwnd: int, allowed: frozenset[int], *, timeout_ms: int) -> dict[str, Any]:
        captured["timeout_ms"] = timeout_ms
        return {"action": "click", "ok": True}

    monkeypatch.setattr(ui_drive, "click_hwnd", fake_click)
    run_drive_step(
        {"action": "click", "hwnd": 123, "timeout_ms": good},
        allowed_pids=_PIDS,
        handles={},
    )
    assert captured["timeout_ms"] == int(float(good))
    assert type(captured["timeout_ms"]) is int


def test_click_uses_the_schema_default_when_timeout_ms_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        ui_drive,
        "click_hwnd",
        lambda hwnd, allowed, *, timeout_ms: captured.setdefault("timeout_ms", timeout_ms),
    )
    run_drive_step({"action": "click", "hwnd": 123}, allowed_pids=_PIDS, handles={})
    assert captured["timeout_ms"] == 5000


@pytest.mark.parametrize("field", ["timeout", "poll_interval"])
@pytest.mark.parametrize(
    "bad",
    [None, {}, "abc", float("inf"), float("nan")],
    ids=["none", "dict", "non-numeric", "inf", "nan"],
)
def test_wait_rejects_an_uncoercible_or_nonfinite_float(field: str, bad: Any) -> None:
    # float(None)/float({}) raise TypeError and float("abc") raises ValueError
    # before wait_for_window ever runs; inf/nan coerce fine but a nan defeats
    # every range comparison and an inf reaches time.sleep(inf), so reject both
    # here rather than downstream.
    step: dict[str, Any] = {"action": "wait", "timeout": 1.0, "poll_interval": 0.1, "title": "x"}
    step[field] = bad
    with pytest.raises(UiPidBoundaryError) as caught:
        run_drive_step(step, allowed_pids=_PIDS, handles={})
    assert caught.value.code == "invalid_params"
    assert field in caught.value.message


def test_wait_passes_valid_finite_floats_through(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_wait(allowed: frozenset[int], **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"matched": True, "window": {"hwnd": 1, "pid": 4242}}

    monkeypatch.setattr(ui_drive, "wait_for_window", fake_wait)
    run_drive_step(
        {"action": "wait", "timeout": "2.5", "poll_interval": 0.25, "title": "x"},
        allowed_pids=_PIDS,
        handles={},
    )
    assert captured["timeout"] == 2.5
    assert captured["poll_interval"] == 0.25
