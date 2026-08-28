"""Routing contract for the UI drive-step dispatcher.

``run_drive_step`` forwards to the Win32 window primitives, which cannot run on
the Linux CI host, but the routing *around* those calls is pure logic: which
handle a bare action inherits, how ``parent_from`` resolves, that the first
resolve becomes the root, and which malformed steps are refused before any
window is touched. The Win32 primitives are stubbed so these decisions are
pinned on every platform; without this the whole dispatcher (and the boundary
guards it enforces) is only exercised by Windows-gated integration tests.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.core import ui_drive
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({4242})


class _Recorder:
    """Capture calls to the stubbed Win32 primitives and hand back canned results."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.results: dict[str, Any] = {}

    def make(self, name: str):
        def _stub(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args, kwargs))
            return self.results.get(name, {"action": name})

        return _stub

    def last(self, name: str) -> tuple[tuple[Any, ...], dict[str, Any]]:
        for call_name, args, kwargs in reversed(self.calls):
            if call_name == name:
                return args, kwargs
        raise AssertionError(f"{name} was never called")


@pytest.fixture
def win32(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()
    for name in (
        "resolve_hwnd",
        "wait_for_window",
        "click_hwnd",
        "click_hwnd_at",
        "close_hwnd",
        "set_window_text",
        "send_key",
        "invoke_hwnd",
    ):
        monkeypatch.setattr(ui_drive, name, recorder.make(name))
    return recorder


# --------------------------------------------------------------------------- #
# normalize_drive_steps
# --------------------------------------------------------------------------- #


def test_normalize_none_returns_empty_list() -> None:
    assert ui_drive.normalize_drive_steps(None) == []


def test_normalize_casefolds_action_and_preserves_other_keys() -> None:
    out = ui_drive.normalize_drive_steps([{"action": "  Text.Set  ", "text": "hi"}])
    assert out == [{"action": "text.set", "text": "hi"}]


def test_normalize_rejects_non_sequence() -> None:
    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_drive.normalize_drive_steps({"action": "click"})  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


def test_normalize_rejects_too_many_steps() -> None:
    steps = [{"action": "click"}] * 33
    with pytest.raises(UiPidBoundaryError):
        ui_drive.normalize_drive_steps(steps)


def test_normalize_accepts_exactly_the_max() -> None:
    steps = [{"action": "click"}] * 32
    assert len(ui_drive.normalize_drive_steps(steps)) == 32


def test_normalize_rejects_non_mapping_step() -> None:
    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_drive.normalize_drive_steps([{"action": "click"}, "nope"])  # type: ignore[list-item]
    assert excinfo.value.details.get("index") == 1


def test_normalize_rejects_unknown_action() -> None:
    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_drive.normalize_drive_steps([{"action": "teleport"}])
    assert excinfo.value.details.get("action") == "teleport"
    assert "resolve" in excinfo.value.details.get("allowed", [])


# --------------------------------------------------------------------------- #
# resolve / wait: handle bookkeeping
# --------------------------------------------------------------------------- #


def test_resolve_records_last_and_first_resolve_becomes_root(win32: _Recorder) -> None:
    win32.results["resolve_hwnd"] = {"hwnd": 111, "title": "Main"}
    handles: dict[str, int] = {}

    out = ui_drive.run_drive_step(
        {"action": "resolve", "title": "Main"}, allowed_pids=_PIDS, handles=handles
    )

    assert out == {"action": "resolve", "window": {"hwnd": 111, "title": "Main"}}
    assert handles == {"last": 111, "root": 111}


def test_second_resolve_keeps_root_unless_as_root(win32: _Recorder) -> None:
    handles: dict[str, int] = {"root": 10, "last": 10}
    win32.results["resolve_hwnd"] = {"hwnd": 222}

    ui_drive.run_drive_step({"action": "resolve"}, allowed_pids=_PIDS, handles=handles)
    assert handles == {"root": 10, "last": 222}

    win32.results["resolve_hwnd"] = {"hwnd": 333}
    ui_drive.run_drive_step(
        {"action": "resolve", "as_root": True}, allowed_pids=_PIDS, handles=handles
    )
    assert handles == {"root": 333, "last": 333}


def test_resolve_parent_from_root_and_last(win32: _Recorder) -> None:
    win32.results["resolve_hwnd"] = {"hwnd": 900}

    # Fresh handles per case: a resolve rewrites ``last``, so sharing state
    # between the two would make the second lookup read the just-resolved hwnd.
    ui_drive.run_drive_step(
        {"action": "resolve", "parent_from": "root"},
        allowed_pids=_PIDS,
        handles={"root": 10, "last": 20},
    )
    assert win32.last("resolve_hwnd")[1]["parent_hwnd"] == 10

    ui_drive.run_drive_step(
        {"action": "resolve", "parent_from": "last"},
        allowed_pids=_PIDS,
        handles={"root": 10, "last": 20},
    )
    assert win32.last("resolve_hwnd")[1]["parent_hwnd"] == 20


def test_resolve_explicit_parent_wins_over_parent_from(win32: _Recorder) -> None:
    win32.results["resolve_hwnd"] = {"hwnd": 901}
    handles: dict[str, int] = {"root": 10, "last": 20}

    ui_drive.run_drive_step(
        {"action": "resolve", "parent_hwnd": 77, "parent_from": "root"},
        allowed_pids=_PIDS,
        handles=handles,
    )
    assert win32.last("resolve_hwnd")[1]["parent_hwnd"] == 77


def test_wait_records_last_when_found(win32: _Recorder) -> None:
    win32.results["wait_for_window"] = {"status": "found", "window": {"hwnd": 444}}
    handles: dict[str, int] = {}

    out = ui_drive.run_drive_step(
        {"action": "wait", "title": "Dlg"}, allowed_pids=_PIDS, handles=handles
    )

    assert out["action"] == "wait"
    assert out["status"] == "found"
    assert handles == {"last": 444}
    # wait must not default parent to root, and must not seed root itself.
    assert "root" not in handles


def test_wait_timeout_leaves_last_untouched(win32: _Recorder) -> None:
    win32.results["wait_for_window"] = {"status": "timeout", "window": None}
    handles: dict[str, int] = {"last": 5}

    out = ui_drive.run_drive_step(
        {"action": "wait", "title": "Dlg"}, allowed_pids=_PIDS, handles=handles
    )

    assert out["status"] == "timeout"
    assert handles == {"last": 5}


def test_wait_parent_from_last(win32: _Recorder) -> None:
    win32.results["wait_for_window"] = {"status": "timeout", "window": None}
    handles: dict[str, int] = {"root": 10, "last": 20}

    ui_drive.run_drive_step(
        {"action": "wait", "parent_from": "last"}, allowed_pids=_PIDS, handles=handles
    )
    assert win32.last("wait_for_window")[1]["parent_hwnd"] == 20


def test_wait_parent_from_root(win32: _Recorder) -> None:
    win32.results["wait_for_window"] = {"status": "timeout", "window": None}
    handles: dict[str, int] = {"root": 10, "last": 20}

    ui_drive.run_drive_step(
        {"action": "wait", "parent_from": "root"}, allowed_pids=_PIDS, handles=handles
    )
    assert win32.last("wait_for_window")[1]["parent_hwnd"] == 10


# --------------------------------------------------------------------------- #
# handle-bound actions: inheritance and guards
# --------------------------------------------------------------------------- #


def test_click_uses_explicit_hwnd(win32: _Recorder) -> None:
    ui_drive.run_drive_step(
        {"action": "click", "hwnd": 501, "timeout_ms": 1234},
        allowed_pids=_PIDS,
        handles={},
    )
    args, kwargs = win32.last("click_hwnd")
    assert args[0] == 501
    assert kwargs["timeout_ms"] == 1234


def test_click_inherits_last_handle(win32: _Recorder) -> None:
    ui_drive.run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles={"last": 502})
    args, kwargs = win32.last("click_hwnd")
    assert args[0] == 502
    assert kwargs["timeout_ms"] == 5000  # documented default


def test_click_without_any_handle_is_refused(win32: _Recorder) -> None:
    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_drive.run_drive_step({"action": "click"}, allowed_pids=_PIDS, handles={})
    assert excinfo.value.code == "invalid_params"
    assert not win32.calls  # refused before touching any window


def test_click_at_requires_integer_coordinates(win32: _Recorder) -> None:
    with pytest.raises(UiPidBoundaryError):
        ui_drive.run_drive_step(
            {"action": "click_at", "hwnd": 1, "x": 1.5, "y": 2},
            allowed_pids=_PIDS,
            handles={},
        )
    # A bool is not an acceptable coordinate even though bool subclasses int.
    with pytest.raises(UiPidBoundaryError):
        ui_drive.run_drive_step(
            {"action": "click_at", "hwnd": 1, "x": True, "y": 2},
            allowed_pids=_PIDS,
            handles={},
        )
    assert not win32.calls


def test_click_at_forwards_valid_coordinates(win32: _Recorder) -> None:
    ui_drive.run_drive_step(
        {"action": "click_at", "hwnd": 3, "x": 12, "y": 34},
        allowed_pids=_PIDS,
        handles={},
    )
    _, kwargs = win32.last("click_hwnd_at")
    assert kwargs["x"] == 12
    assert kwargs["y"] == 34


def test_close_defaults_method_and_forwards_override(win32: _Recorder) -> None:
    ui_drive.run_drive_step({"action": "close", "hwnd": 9}, allowed_pids=_PIDS, handles={})
    assert win32.last("close_hwnd")[1]["method"] == "nc_close"

    ui_drive.run_drive_step(
        {"action": "close", "hwnd": 9, "method": "wm_close"},
        allowed_pids=_PIDS,
        handles={},
    )
    assert win32.last("close_hwnd")[1]["method"] == "wm_close"


def test_text_set_requires_string(win32: _Recorder) -> None:
    with pytest.raises(UiPidBoundaryError):
        ui_drive.run_drive_step(
            {"action": "text.set", "hwnd": 1, "text": 123},
            allowed_pids=_PIDS,
            handles={},
        )
    assert not win32.calls


def test_text_set_forwards_text(win32: _Recorder) -> None:
    ui_drive.run_drive_step(
        {"action": "text.set", "hwnd": 1, "text": "hello"},
        allowed_pids=_PIDS,
        handles={},
    )
    args, _ = win32.last("set_window_text")
    assert args[0] == 1
    assert args[1] == "hello"


def test_key_forwards_text_and_vk(win32: _Recorder) -> None:
    ui_drive.run_drive_step(
        {"action": "key", "hwnd": 2, "vk": 13},
        allowed_pids=_PIDS,
        handles={},
    )
    _, kwargs = win32.last("send_key")
    assert kwargs["vk"] == 13
    assert kwargs["allowed_pids"] is _PIDS


def test_invoke_defaults_action(win32: _Recorder) -> None:
    ui_drive.run_drive_step({"action": "invoke", "hwnd": 4}, allowed_pids=_PIDS, handles={})
    assert win32.last("invoke_hwnd")[1]["action"] == "click"

    ui_drive.run_drive_step(
        {"action": "invoke", "hwnd": 4, "invoke_action": "toggle"},
        allowed_pids=_PIDS,
        handles={},
    )
    assert win32.last("invoke_hwnd")[1]["action"] == "toggle"


def test_unknown_action_with_handle_is_refused(win32: _Recorder) -> None:
    # A step that skipped normalization but still carries a handle reaches the
    # final fail-closed guard rather than any window primitive.
    with pytest.raises(UiPidBoundaryError) as excinfo:
        ui_drive.run_drive_step({"action": "frobnicate", "hwnd": 7}, allowed_pids=_PIDS, handles={})
    assert excinfo.value.code == "invalid_params"
    assert not win32.calls


def test_drive_deadline_is_monotonic_plus_timeout() -> None:
    from time import monotonic

    before = monotonic()
    deadline = ui_drive.drive_deadline(2.5)
    assert before + 2.5 <= deadline <= monotonic() + 2.5
