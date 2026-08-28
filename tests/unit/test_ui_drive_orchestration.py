"""Cross-platform coverage for the UI-drive step orchestrator.

``core.ui_drive`` normalizes an untrusted step list and routes each step to the
Win32 helpers in ``core.ui_win32``. The routing, handle-threading (``last`` /
``root``), and per-action guards are pure Python; the actual Win32 calls are
replaced with recorders so the POSIX test host exercises every branch without a
real window. Each ``ui_win32`` name is patched on the ``ui_drive`` module, since
that is where the orchestrator looks them up.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.core.ui_drive as drive
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({4321})


class _Recorder:
    """Captures the arguments each ui_win32 helper was called with."""

    def __init__(self, return_value: Any) -> None:
        self.return_value = return_value
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return self.return_value


def _patch(monkeypatch: pytest.MonkeyPatch, name: str, return_value: Any) -> _Recorder:
    rec = _Recorder(return_value)
    monkeypatch.setattr(drive, name, rec)
    return rec


# ---------------------------------------------------------------------------
# normalize_drive_steps
# ---------------------------------------------------------------------------


def test_none_normalizes_to_empty() -> None:
    assert drive.normalize_drive_steps(None) == []


def test_a_non_list_is_refused() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.normalize_drive_steps({"action": "click"})  # type: ignore[arg-type]
    assert exc.value.code == "invalid_params"


def test_too_many_steps_are_refused() -> None:
    steps = [{"action": "click"}] * (drive._MAX_STEPS + 1)
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.normalize_drive_steps(steps)
    assert "at most" in exc.value.message


def test_a_non_object_step_is_refused_with_its_index() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.normalize_drive_steps([{"action": "click"}, "nope"])  # type: ignore[list-item]
    assert exc.value.details["index"] == 1


def test_an_unknown_action_is_refused() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.normalize_drive_steps([{"action": "frobnicate"}])
    assert exc.value.code == "invalid_params"
    assert exc.value.details["action"] == "frobnicate"
    allowed = exc.value.details["allowed"]
    assert isinstance(allowed, list) and "click" in allowed


def test_actions_are_casefolded_and_rows_copied() -> None:
    source = [{"action": "  Click  ", "hwnd": 5}]
    out = drive.normalize_drive_steps(source)
    assert out == [{"action": "click", "hwnd": 5}]
    # The returned dict must be a copy, not an alias of the caller's mapping.
    out[0]["hwnd"] = 99
    assert source[0]["hwnd"] == 5


def test_tuple_of_steps_is_accepted() -> None:
    out = drive.normalize_drive_steps(({"action": "wait"},))
    assert out == [{"action": "wait"}]


# ---------------------------------------------------------------------------
# run_drive_step: resolve
# ---------------------------------------------------------------------------


def test_resolve_records_last_and_first_root(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "resolve_hwnd", {"hwnd": 777})
    handles: dict[str, int] = {}

    result = drive.run_drive_step(
        {"action": "resolve", "title": "OK"},
        allowed_pids=_PIDS,
        handles=handles,
    )

    assert result == {"action": "resolve", "window": {"hwnd": 777}}
    assert handles == {"last": 777, "root": 777}, "the first resolve seeds root"
    # The allowed pid set is forwarded positionally.
    assert rec.calls[0][0] == (_PIDS,)


def test_resolve_does_not_overwrite_existing_root(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, "resolve_hwnd", {"hwnd": 42})
    handles = {"root": 1}
    drive.run_drive_step({"action": "resolve"}, allowed_pids=_PIDS, handles=handles)
    assert handles["root"] == 1, "an existing root survives a later resolve"
    assert handles["last"] == 42


def test_resolve_as_root_forces_root(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, "resolve_hwnd", {"hwnd": 88})
    handles = {"root": 1, "last": 2}
    drive.run_drive_step(
        {"action": "resolve", "as_root": True}, allowed_pids=_PIDS, handles=handles
    )
    assert handles["root"] == 88


def test_resolve_parent_from_root_and_last(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "resolve_hwnd", {"hwnd": 5})
    drive.run_drive_step(
        {"action": "resolve", "parent_from": "root"},
        allowed_pids=_PIDS,
        handles={"root": 100},
    )
    assert rec.calls[0][1]["parent_hwnd"] == 100

    rec2 = _patch(monkeypatch, "resolve_hwnd", {"hwnd": 6})
    drive.run_drive_step(
        {"action": "resolve", "parent_from": "last"},
        allowed_pids=_PIDS,
        handles={"last": 200},
    )
    assert rec2.calls[0][1]["parent_hwnd"] == 200


def test_resolve_explicit_parent_wins_over_parent_from(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "resolve_hwnd", {"hwnd": 5})
    drive.run_drive_step(
        {"action": "resolve", "parent_hwnd": 55, "parent_from": "root"},
        allowed_pids=_PIDS,
        handles={"root": 100},
    )
    assert rec.calls[0][1]["parent_hwnd"] == 55


# ---------------------------------------------------------------------------
# run_drive_step: wait
# ---------------------------------------------------------------------------


def test_wait_threads_the_found_window_into_last(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(
        monkeypatch,
        "wait_for_window",
        {"found": True, "window": {"hwnd": 909}},
    )
    handles: dict[str, int] = {}

    result = drive.run_drive_step(
        {"action": "wait", "title_contains": "Loading", "timeout": 3, "poll_interval": 0.2},
        allowed_pids=_PIDS,
        handles=handles,
    )

    assert result["action"] == "wait"
    assert result["found"] is True
    assert handles["last"] == 909
    assert rec.calls[0][1]["timeout"] == 3.0
    assert rec.calls[0][1]["poll_interval"] == 0.2


def test_wait_without_a_window_leaves_last_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, "wait_for_window", {"found": False, "window": None})
    handles = {"last": 7}
    drive.run_drive_step({"action": "wait"}, allowed_pids=_PIDS, handles=handles)
    assert handles["last"] == 7


def test_wait_parent_from_root_and_last(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "wait_for_window", {"found": False, "window": None})
    drive.run_drive_step(
        {"action": "wait", "parent_from": "root"},
        allowed_pids=_PIDS,
        handles={"root": 111},
    )
    assert rec.calls[0][1]["parent_hwnd"] == 111

    rec2 = _patch(monkeypatch, "wait_for_window", {"found": False, "window": None})
    drive.run_drive_step(
        {"action": "wait", "parent_from": "last"},
        allowed_pids=_PIDS,
        handles={"last": 222},
    )
    assert rec2.calls[0][1]["parent_hwnd"] == 222


def test_wait_does_not_default_parent_to_root(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "wait_for_window", {"found": False, "window": None})
    drive.run_drive_step(
        {"action": "wait", "title": "top"}, allowed_pids=_PIDS, handles={"root": 500}
    )
    assert rec.calls[0][1]["parent_hwnd"] is None


# ---------------------------------------------------------------------------
# run_drive_step: hwnd defaulting and the missing-hwnd guard
# ---------------------------------------------------------------------------


def test_click_defaults_hwnd_to_last_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "click_hwnd", {"ok": True})
    drive.run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles={"last": 321})
    assert rec.calls[0][0][0] == 321


def test_a_step_without_hwnd_or_prior_resolve_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles={})
    assert exc.value.code == "invalid_params"
    assert exc.value.details["action"] == "click"


# ---------------------------------------------------------------------------
# run_drive_step: per-action routing and guards
# ---------------------------------------------------------------------------


def test_click_forwards_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "click_hwnd", {"ok": True})
    drive.run_drive_step(
        {"action": "click", "hwnd": 10, "timeout_ms": 1234}, allowed_pids=_PIDS, handles={}
    )
    assert rec.calls[0][0][0] == 10
    assert rec.calls[0][1]["timeout_ms"] == 1234


def test_click_at_requires_integer_coordinates(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, "click_hwnd_at", {"ok": True})
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.run_drive_step(
            {"action": "click_at", "hwnd": 10, "x": 1.5, "y": 2},
            allowed_pids=_PIDS,
            handles={},
        )
    assert "integer x/y" in exc.value.message


def test_click_at_forwards_coordinates(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "click_hwnd_at", {"ok": True})
    drive.run_drive_step(
        {"action": "click_at", "hwnd": 10, "x": 3, "y": 4}, allowed_pids=_PIDS, handles={}
    )
    assert rec.calls[0][1]["x"] == 3 and rec.calls[0][1]["y"] == 4


def test_close_forwards_method(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "close_hwnd", {"ok": True})
    drive.run_drive_step(
        {"action": "close", "hwnd": 10, "method": "wm_close"}, allowed_pids=_PIDS, handles={}
    )
    assert rec.calls[0][1]["method"] == "wm_close"


def test_text_set_requires_a_string(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, "set_window_text", {"ok": True})
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.run_drive_step(
            {"action": "text.set", "hwnd": 10, "text": 5}, allowed_pids=_PIDS, handles={}
        )
    assert "requires text" in exc.value.message


def test_text_set_forwards_text(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "set_window_text", {"ok": True})
    drive.run_drive_step(
        {"action": "text.set", "hwnd": 10, "text": "hello"}, allowed_pids=_PIDS, handles={}
    )
    assert rec.calls[0][0][:2] == (10, "hello")


def test_key_forwards_text_and_vk(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "send_key", {"ok": True})
    drive.run_drive_step(
        {"action": "key", "hwnd": 10, "text": "a", "vk": 65}, allowed_pids=_PIDS, handles={}
    )
    assert rec.calls[0][1]["text"] == "a"
    assert rec.calls[0][1]["vk"] == 65


def test_invoke_defaults_action_to_click(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "invoke_hwnd", {"ok": True})
    drive.run_drive_step({"action": "invoke", "hwnd": 10}, allowed_pids=_PIDS, handles={})
    assert rec.calls[0][1]["action"] == "click"


def test_invoke_forwards_explicit_action(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch(monkeypatch, "invoke_hwnd", {"ok": True})
    drive.run_drive_step(
        {"action": "invoke", "hwnd": 10, "invoke_action": "toggle", "control_id": 3},
        allowed_pids=_PIDS,
        handles={},
    )
    assert rec.calls[0][1]["action"] == "toggle"
    assert rec.calls[0][1]["control_id"] == 3


def test_an_unhandled_action_with_hwnd_is_refused() -> None:
    # normalize would reject this, but run_drive_step is defensive on its own:
    # an int hwnd passes the boundary guard, so the trailing raise must fire.
    with pytest.raises(UiPidBoundaryError) as exc:
        drive.run_drive_step({"action": "teleport", "hwnd": 10}, allowed_pids=_PIDS, handles={})
    assert exc.value.details["action"] == "teleport"


# ---------------------------------------------------------------------------
# drive_deadline
# ---------------------------------------------------------------------------


def test_drive_deadline_is_monotonic_plus_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drive, "monotonic", lambda: 1000.0)
    assert drive.drive_deadline(2.5) == 1002.5
