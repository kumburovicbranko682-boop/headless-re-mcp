"""ui_drive step normalisation and dispatch, driven on faked ui_win32 seams.

``run_drive_step`` is the interpreter behind the batched UI-drive tool: it
validates each step, threads resolved handles forward (``last``/``root``), and
dispatches to the pid-bounded ui_win32 primitives. None of it ran on a hosted
platform because the primitives need live windows, so it sat at 26%. Faking
exactly those primitives drives the real normalise/parent-resolution/handle
threading and every action branch, including the guards that refuse a step with
no handle, non-integer click coordinates, or missing text. A step that clicked
the wrong (stale) handle, or one that dispatched an unvalidated action, is the
failure these pin.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.core.ui_drive as ui_drive
from headless_re_mcp.core.ui_drive import (
    drive_deadline,
    normalize_drive_steps,
    run_drive_step,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({100})


@pytest.fixture
def w32(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch every ui_win32 primitive with a recorder and return the call log."""
    calls: dict[str, Any] = {}

    def rec(name: str, ret: Any) -> Any:
        def fn(*args: Any, **kwargs: Any) -> Any:
            calls[name] = {"args": args, "kwargs": kwargs}
            return ret

        return fn

    monkeypatch.setattr(ui_drive, "resolve_hwnd", rec("resolve", {"hwnd": 0x10, "title": "R"}))
    monkeypatch.setattr(ui_drive, "wait_for_window", rec("wait", {"window": {"hwnd": 0x20}}))
    monkeypatch.setattr(ui_drive, "click_hwnd", rec("click", {"did": "click"}))
    monkeypatch.setattr(ui_drive, "click_hwnd_at", rec("click_at", {"did": "click_at"}))
    monkeypatch.setattr(ui_drive, "close_hwnd", rec("close", {"did": "close"}))
    monkeypatch.setattr(ui_drive, "set_window_text", rec("text", {"did": "text"}))
    monkeypatch.setattr(ui_drive, "send_key", rec("key", {"did": "key"}))
    monkeypatch.setattr(ui_drive, "invoke_hwnd", rec("invoke", {"did": "invoke"}))
    return calls


# ---------------------------------------------------------------------------
# normalize_drive_steps


def test_normalize_none_is_empty() -> None:
    assert normalize_drive_steps(None) == []


def test_normalize_rejects_a_non_sequence() -> None:
    with pytest.raises(UiPidBoundaryError, match="steps must be a list"):
        normalize_drive_steps("click")  # type: ignore[arg-type]


def test_normalize_rejects_too_many_steps() -> None:
    with pytest.raises(UiPidBoundaryError, match="at most"):
        normalize_drive_steps([{"action": "click"}] * 33)


def test_normalize_rejects_a_non_object_step() -> None:
    with pytest.raises(UiPidBoundaryError, match="each step must be an object"):
        normalize_drive_steps([123])  # type: ignore[list-item]


def test_normalize_rejects_an_unknown_action() -> None:
    with pytest.raises(UiPidBoundaryError, match="unsupported drive step action"):
        normalize_drive_steps([{"action": "frobnicate"}])


def test_normalize_casefolds_and_copies_each_step() -> None:
    out = normalize_drive_steps([{"action": "  CLICK ", "hwnd": 5}])
    assert out == [{"action": "click", "hwnd": 5}]


# ---------------------------------------------------------------------------
# run_drive_step: resolve


def test_resolve_sets_last_and_seeds_root(w32: dict[str, Any]) -> None:
    handles: dict[str, int] = {}
    result = run_drive_step({"action": "resolve", "hwnd": 5}, allowed_pids=_PIDS, handles=handles)
    assert result["action"] == "resolve"
    assert handles["last"] == 0x10
    assert handles["root"] == 0x10  # first resolve seeds root
    assert w32["resolve"]["kwargs"]["hwnd"] == 5
    assert w32["resolve"]["kwargs"]["parent_hwnd"] is None


def test_resolve_uses_root_parent_reference(w32: dict[str, Any]) -> None:
    handles = {"root": 0x99}
    run_drive_step(
        {"action": "resolve", "parent_from": "root"}, allowed_pids=_PIDS, handles=handles
    )
    assert w32["resolve"]["kwargs"]["parent_hwnd"] == 0x99
    assert w32["resolve"]["kwargs"]["hwnd"] is None  # non-int hwnd becomes None


def test_resolve_uses_last_parent_reference(w32: dict[str, Any]) -> None:
    handles = {"last": 0x88}
    run_drive_step(
        {"action": "resolve", "parent_from": "last"}, allowed_pids=_PIDS, handles=handles
    )
    assert w32["resolve"]["kwargs"]["parent_hwnd"] == 0x88


def test_resolve_accepts_an_explicit_parent_hwnd(w32: dict[str, Any]) -> None:
    run_drive_step(
        {"action": "resolve", "hwnd": 5, "parent_hwnd": 7},
        allowed_pids=_PIDS,
        handles={},
    )
    assert w32["resolve"]["kwargs"]["parent_hwnd"] == 7


def test_resolve_as_root_overwrites_an_existing_root(w32: dict[str, Any]) -> None:
    handles = {"root": 0x99}
    run_drive_step(
        {"action": "resolve", "hwnd": 5, "as_root": True},
        allowed_pids=_PIDS,
        handles=handles,
    )
    assert handles["root"] == 0x10  # as_root re-seeds it


def test_resolve_keeps_an_existing_root_without_as_root(w32: dict[str, Any]) -> None:
    handles = {"root": 0x99}
    run_drive_step({"action": "resolve", "hwnd": 5}, allowed_pids=_PIDS, handles=handles)
    assert handles["root"] == 0x99  # not overwritten
    assert handles["last"] == 0x10


# ---------------------------------------------------------------------------
# run_drive_step: wait


def test_wait_threads_the_found_window_into_last(w32: dict[str, Any]) -> None:
    handles: dict[str, int] = {}
    result = run_drive_step({"action": "wait", "title": "Dlg"}, allowed_pids=_PIDS, handles=handles)
    assert result["action"] == "wait"
    assert handles["last"] == 0x20


def test_wait_without_a_window_leaves_last_untouched(
    monkeypatch: pytest.MonkeyPatch, w32: dict[str, Any]
) -> None:
    monkeypatch.setattr(ui_drive, "wait_for_window", lambda *a, **k: {"timed_out": True})
    handles: dict[str, int] = {}
    result = run_drive_step({"action": "wait", "title": "Dlg"}, allowed_pids=_PIDS, handles=handles)
    assert result["timed_out"] is True
    assert "last" not in handles


def test_wait_uses_root_parent_reference(w32: dict[str, Any]) -> None:
    handles = {"root": 0x99}
    run_drive_step({"action": "wait", "parent_from": "root"}, allowed_pids=_PIDS, handles=handles)
    assert w32["wait"]["kwargs"]["parent_hwnd"] == 0x99


def test_wait_uses_last_parent_reference(w32: dict[str, Any]) -> None:
    handles = {"last": 0x88}
    run_drive_step({"action": "wait", "parent_from": "last"}, allowed_pids=_PIDS, handles=handles)
    assert w32["wait"]["kwargs"]["parent_hwnd"] == 0x88


# ---------------------------------------------------------------------------
# run_drive_step: handle-bearing actions


def test_click_defaults_to_the_last_handle(w32: dict[str, Any]) -> None:
    handles = {"last": 0x30}
    result = run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles=handles)
    assert result["did"] == "click"
    assert w32["click"]["args"][0] == 0x30


def test_click_uses_an_explicit_handle(w32: dict[str, Any]) -> None:
    run_drive_step({"action": "click", "hwnd": 0x40}, allowed_pids=_PIDS, handles={})
    assert w32["click"]["args"][0] == 0x40


def test_action_without_a_handle_is_refused(w32: dict[str, Any]) -> None:
    with pytest.raises(UiPidBoundaryError, match="requires hwnd or prior resolve"):
        run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles={})


def test_click_at_requires_integer_coordinates(w32: dict[str, Any]) -> None:
    ok = run_drive_step(
        {"action": "click_at", "hwnd": 5, "x": 1, "y": 2}, allowed_pids=_PIDS, handles={}
    )
    assert ok["did"] == "click_at"
    with pytest.raises(UiPidBoundaryError, match="integer x/y"):
        run_drive_step(
            {"action": "click_at", "hwnd": 5, "x": "1", "y": 2},
            allowed_pids=_PIDS,
            handles={},
        )


def test_close_dispatches(w32: dict[str, Any]) -> None:
    result = run_drive_step({"action": "close", "hwnd": 5}, allowed_pids=_PIDS, handles={})
    assert result["did"] == "close"


def test_text_set_requires_text(w32: dict[str, Any]) -> None:
    ok = run_drive_step(
        {"action": "text.set", "hwnd": 5, "text": "hi"}, allowed_pids=_PIDS, handles={}
    )
    assert ok["did"] == "text"
    with pytest.raises(UiPidBoundaryError, match="text.set requires text"):
        run_drive_step({"action": "text.set", "hwnd": 5}, allowed_pids=_PIDS, handles={})


def test_key_dispatches(w32: dict[str, Any]) -> None:
    result = run_drive_step(
        {"action": "key", "hwnd": 5, "text": "a"}, allowed_pids=_PIDS, handles={}
    )
    assert result["did"] == "key"


def test_invoke_dispatches(w32: dict[str, Any]) -> None:
    result = run_drive_step(
        {"action": "invoke", "hwnd": 5, "invoke_action": "toggle"},
        allowed_pids=_PIDS,
        handles={},
    )
    assert result["did"] == "invoke"
    assert w32["invoke"]["kwargs"]["action"] == "toggle"


def test_unknown_action_with_a_handle_is_refused(w32: dict[str, Any]) -> None:
    with pytest.raises(UiPidBoundaryError, match="unsupported drive step"):
        run_drive_step({"action": "frob", "hwnd": 5}, allowed_pids=_PIDS, handles={})


# ---------------------------------------------------------------------------
# drive_deadline


def test_drive_deadline_is_now_plus_timeout() -> None:
    from time import monotonic

    before = monotonic()
    deadline = drive_deadline(5.0)
    assert before + 5.0 <= deadline <= monotonic() + 5.0
