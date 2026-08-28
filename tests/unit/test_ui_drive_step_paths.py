"""Unit coverage for the UI drive step normalizer and dispatcher."""

from __future__ import annotations

from time import monotonic
from typing import Any

import pytest

import headless_re_mcp.core.ui_drive as ui_drive
from headless_re_mcp.core.ui_drive import (
    drive_deadline,
    normalize_drive_steps,
    run_drive_step,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({1234})


# --------------------------------------------------------------------------
# normalize_drive_steps
# --------------------------------------------------------------------------


def test_normalize_accepts_none_as_no_steps() -> None:
    assert normalize_drive_steps(None) == []


def test_normalize_rejects_a_non_list_payload() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        normalize_drive_steps("click")  # type: ignore[arg-type]
    assert info.value.code == "invalid_params"


def test_normalize_rejects_too_many_steps() -> None:
    with pytest.raises(UiPidBoundaryError):
        normalize_drive_steps([{"action": "wait"}] * 33)


def test_normalize_rejects_a_non_object_step() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        normalize_drive_steps([{"action": "wait"}, "click"])  # type: ignore[list-item]
    assert info.value.details["index"] == 1


def test_normalize_rejects_an_unknown_action() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        normalize_drive_steps([{"action": "explode"}])
    assert info.value.details["action"] == "explode"
    assert "wait" in info.value.details["allowed"]  # type: ignore[operator]


def test_normalize_casefolds_actions_and_keeps_fields() -> None:
    steps = normalize_drive_steps([{"action": " Click ", "hwnd": 7}])
    assert steps == [{"action": "click", "hwnd": 7}]


# --------------------------------------------------------------------------
# run_drive_step: resolve / wait
# --------------------------------------------------------------------------


def _capture_resolve(monkeypatch: pytest.MonkeyPatch, hwnd: int) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_resolve(allowed_pids: frozenset[int], **kwargs: Any) -> dict[str, Any]:
        calls.append(dict(kwargs))
        return {"hwnd": hwnd, "title": "win"}

    monkeypatch.setattr(ui_drive, "resolve_hwnd", fake_resolve)
    return calls


def test_resolve_records_last_and_first_root(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture_resolve(monkeypatch, hwnd=100)
    handles: dict[str, int] = {}

    result = run_drive_step(
        {"action": "resolve", "title": "App"}, allowed_pids=_PIDS, handles=handles
    )

    assert result == {"action": "resolve", "window": {"hwnd": 100, "title": "win"}}
    assert handles == {"last": 100, "root": 100}
    assert calls[0]["title"] == "App"
    assert calls[0]["hwnd"] is None and calls[0]["parent_hwnd"] is None


def test_resolve_keeps_an_existing_root_unless_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _capture_resolve(monkeypatch, hwnd=200)
    handles = {"root": 50, "last": 50}

    run_drive_step({"action": "resolve"}, allowed_pids=_PIDS, handles=handles)
    assert handles == {"root": 50, "last": 200}

    run_drive_step({"action": "resolve", "as_root": True}, allowed_pids=_PIDS, handles=handles)
    assert handles == {"root": 200, "last": 200}


def test_resolve_parent_defaults_from_root_and_last(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_resolve(monkeypatch, hwnd=300)

    run_drive_step(
        {"action": "resolve", "parent_from": "root"},
        allowed_pids=_PIDS,
        handles={"root": 10, "last": 20},
    )
    run_drive_step(
        {"action": "resolve", "parent_from": "last", "hwnd": 33},
        allowed_pids=_PIDS,
        handles={"root": 10, "last": 20},
    )
    run_drive_step(
        {"action": "resolve", "parent_hwnd": 44, "parent_from": "root"},
        allowed_pids=_PIDS,
        handles={"root": 10, "last": 20},
    )

    assert calls[0]["parent_hwnd"] == 10
    assert calls[1]["parent_hwnd"] == 20 and calls[1]["hwnd"] == 33
    assert calls[2]["parent_hwnd"] == 44


def _capture_wait(monkeypatch: pytest.MonkeyPatch, result: dict[str, Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_wait(allowed_pids: frozenset[int], **kwargs: Any) -> dict[str, Any]:
        calls.append(dict(kwargs))
        return result

    monkeypatch.setattr(ui_drive, "wait_for_window", fake_wait)
    return calls


def test_wait_records_the_matched_window_as_last(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_wait(monkeypatch, {"matched": True, "window": {"hwnd": 77, "title": "dlg"}})
    handles: dict[str, int] = {}

    result = run_drive_step(
        {"action": "wait", "title_contains": "dlg", "timeout": 2.0},
        allowed_pids=_PIDS,
        handles=handles,
    )

    assert result["action"] == "wait" and result["matched"] is True
    assert handles == {"last": 77}
    assert calls[0]["timeout"] == 2.0
    assert calls[0]["parent_hwnd"] is None


def test_wait_without_a_match_leaves_handles_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _capture_wait(monkeypatch, {"matched": False, "window": None})
    handles: dict[str, int] = {"last": 5}

    result = run_drive_step({"action": "wait"}, allowed_pids=_PIDS, handles=handles)

    assert result["matched"] is False
    assert handles == {"last": 5}


def test_wait_parent_defaults_from_root_and_last(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_wait(monkeypatch, {"matched": False, "window": None})
    handles = {"root": 11, "last": 22}

    run_drive_step({"action": "wait", "parent_from": "root"}, allowed_pids=_PIDS, handles=handles)
    run_drive_step({"action": "wait", "parent_from": "last"}, allowed_pids=_PIDS, handles=handles)
    run_drive_step(
        {"action": "wait", "parent_hwnd": 33, "parent_from": "last"},
        allowed_pids=_PIDS,
        handles=handles,
    )

    assert [call["parent_hwnd"] for call in calls] == [11, 22, 33]


# --------------------------------------------------------------------------
# run_drive_step: hwnd-bound actions
# --------------------------------------------------------------------------


def test_hwnd_actions_refuse_to_run_without_a_target() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles={})
    assert info.value.details["action"] == "click"


def test_click_defaults_to_the_last_resolved_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[int, int]] = []

    def fake_click(hwnd: int, allowed_pids: frozenset[int], *, timeout_ms: int) -> dict[str, Any]:
        seen.append((hwnd, timeout_ms))
        return {"clicked": True}

    monkeypatch.setattr(ui_drive, "click_hwnd", fake_click)

    result = run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles={"last": 42})

    assert result == {"clicked": True}
    assert seen == [(42, 5000)]


def test_click_at_requires_integer_coordinates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ui_drive,
        "click_hwnd_at",
        lambda hwnd, allowed_pids, *, x, y, timeout_ms: {"x": x, "y": y},
    )

    result = run_drive_step(
        {"action": "click_at", "hwnd": 9, "x": 3, "y": 4, "timeout_ms": 100},
        allowed_pids=_PIDS,
        handles={},
    )
    assert result == {"x": 3, "y": 4}

    for bad in ({"x": 1.5, "y": 2}, {"x": 1, "y": True}, {"x": 1}):
        with pytest.raises(UiPidBoundaryError):
            run_drive_step(
                {"action": "click_at", "hwnd": 9, **bad},
                allowed_pids=_PIDS,
                handles={},
            )


def test_close_forwards_the_method(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ui_drive,
        "close_hwnd",
        lambda hwnd, allowed_pids, *, method, timeout_ms: {
            "hwnd": hwnd,
            "method": method,
        },
    )

    result = run_drive_step(
        {"action": "close", "hwnd": 8, "method": "wm_close"},
        allowed_pids=_PIDS,
        handles={},
    )
    assert result == {"hwnd": 8, "method": "wm_close"}

    default = run_drive_step({"action": "close", "hwnd": 8}, allowed_pids=_PIDS, handles={})
    assert default["method"] == "nc_close"


def test_text_set_requires_a_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ui_drive,
        "set_window_text",
        lambda hwnd, text, allowed_pids, *, timeout_ms: {"text": text},
    )

    result = run_drive_step(
        {"action": "text.set", "hwnd": 6, "text": "hello"},
        allowed_pids=_PIDS,
        handles={},
    )
    assert result == {"text": "hello"}

    with pytest.raises(UiPidBoundaryError):
        run_drive_step(
            {"action": "text.set", "hwnd": 6, "text": 12},
            allowed_pids=_PIDS,
            handles={},
        )


def test_key_forwards_text_and_vk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ui_drive,
        "send_key",
        lambda hwnd, *, allowed_pids, text, vk, timeout_ms: {
            "text": text,
            "vk": vk,
        },
    )

    result = run_drive_step(
        {"action": "key", "hwnd": 5, "text": "a", "vk": 65},
        allowed_pids=_PIDS,
        handles={},
    )
    assert result == {"text": "a", "vk": 65}


def test_invoke_forwards_the_invoke_action(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ui_drive,
        "invoke_hwnd",
        lambda hwnd, allowed_pids, *, action, text, control_id, timeout_ms: {
            "action": action,
            "control_id": control_id,
        },
    )

    result = run_drive_step(
        {"action": "invoke", "hwnd": 4, "invoke_action": "toggle", "control_id": 3},
        allowed_pids=_PIDS,
        handles={},
    )
    assert result == {"action": "toggle", "control_id": 3}

    default = run_drive_step({"action": "invoke", "hwnd": 4}, allowed_pids=_PIDS, handles={})
    assert default["action"] == "click"


def test_an_unknown_action_with_a_target_still_fails_closed() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        run_drive_step({"action": "bogus", "hwnd": 3}, allowed_pids=_PIDS, handles={})
    assert info.value.details["action"] == "bogus"


# --------------------------------------------------------------------------
# drive_deadline
# --------------------------------------------------------------------------


def test_drive_deadline_offsets_the_monotonic_clock() -> None:
    before = monotonic()
    deadline = drive_deadline(5.0)
    assert before + 4.5 < deadline <= monotonic() + 5.0
