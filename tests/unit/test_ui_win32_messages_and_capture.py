"""Deterministic coverage for the Win32 message backend (``core.ui_win32``).

Everything here drives the real module logic against a scripted ``user32`` /
``gdi32``: message sends and posts are recorded (with byref results written
back), window tables answer the enumeration and geometry queries, and the GDI
capture path renders scripted pixel buffers so the blank-frame retry and the
BMP writer run for real.
"""

from __future__ import annotations

import ctypes
import os
import struct
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_win32 as uw
from headless_re_mcp.core.windows import UiPidBoundaryError

ALLOWED = frozenset({100})


class _OsProxy:
    """Pin ``name`` for ui_win32 while forwarding the rest to the real os.

    Pinning "posix" lets the off-Windows refusal test run (not skip) on a real
    Windows host: the guard arm is selected by what ui_win32 reads, not by the
    ambient platform.
    """

    def __init__(self, name: str = "nt") -> None:
        self.name = name

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


def _as_int(value: Any) -> int:
    if isinstance(value, ctypes.c_void_p):
        return int(value.value or 0)
    if hasattr(value, "value"):
        return int(value.value or 0)
    return int(value or 0)


class _FakeUser32:
    """Scripted user32: window table, recorded sends/posts, byref write-backs."""

    def __init__(
        self,
        windows: dict[int, dict[str, Any]],
        *,
        send_ok: bool = True,
        send_result: int = 7,
        post_ok: bool = True,
        rect_ok: bool = True,
        client_rect_ok: bool = True,
    ) -> None:
        self.windows = windows
        self.shown: list[tuple[int, int]] = []
        self.sent: list[tuple[int, int, int]] = []
        self.posted: list[tuple[int, int, int, int]] = []

        def SendMessageTimeoutW(
            hwnd: Any, msg: Any, wparam: Any, lp: Any, flags: Any, timeout: Any, out: Any
        ) -> int:
            self.sent.append((_as_int(hwnd), _as_int(msg), _as_int(wparam)))
            if not send_ok:
                return 0
            out._obj.value = send_result
            return 1

        def PostMessageW(hwnd: Any, msg: Any, wparam: Any, lparam: Any) -> int:
            self.posted.append((_as_int(hwnd), _as_int(msg), _as_int(wparam), _as_int(lparam)))
            return 1 if post_ok else 0

        self.SendMessageTimeoutW = SendMessageTimeoutW
        self.PostMessageW = PostMessageW
        self._rect_ok = rect_ok
        self._client_rect_ok = client_rect_ok

    def _row(self, hwnd: Any) -> dict[str, Any]:
        return self.windows[_as_int(hwnd)]

    def IsWindow(self, hwnd: Any) -> int:
        return int(_as_int(hwnd) in self.windows)

    def GetWindowThreadProcessId(self, hwnd: Any, owner_ref: Any) -> int:
        owner_ref._obj.value = int(self._row(hwnd).get("pid", 0))
        return 1

    def GetWindowTextLengthW(self, hwnd: Any) -> int:
        return len(str(self._row(hwnd).get("title", "")))

    def GetWindowTextW(self, hwnd: Any, buffer: Any, size: int) -> int:
        buffer.value = str(self._row(hwnd).get("title", ""))[: max(0, size - 1)]
        return len(buffer.value)

    def GetClassNameW(self, hwnd: Any, buffer: Any, size: int) -> int:
        buffer.value = str(self._row(hwnd).get("class_name", ""))[: max(0, size - 1)]
        return len(buffer.value)

    def GetDlgCtrlID(self, hwnd: Any) -> int:
        return int(self._row(hwnd).get("control_id", 0))

    def IsWindowVisible(self, hwnd: Any) -> int:
        return int(bool(self._row(hwnd).get("visible", True)))

    def IsWindowEnabled(self, hwnd: Any) -> int:
        return int(bool(self._row(hwnd).get("enabled", True)))

    def IsIconic(self, hwnd: Any) -> int:
        return int(bool(self._row(hwnd).get("iconic", False)))

    def GetParent(self, hwnd: Any) -> int:
        return int(self._row(hwnd).get("parent", 0))

    def ShowWindow(self, hwnd: Any, mode: int) -> int:
        self.shown.append((_as_int(hwnd), mode))
        return 1

    def GetWindowRect(self, hwnd: Any, rect_ref: Any) -> int:
        if not self._rect_ok:
            return 0
        rect = rect_ref._obj
        rect.left, rect.top, rect.right, rect.bottom = self._row(hwnd).get("rect", (0, 0, 100, 100))
        return 1

    def GetClientRect(self, hwnd: Any, rect_ref: Any) -> int:
        if not self._client_rect_ok:
            return 0
        rect = rect_ref._obj
        rect.left, rect.top, rect.right, rect.bottom = self._row(hwnd).get(
            "client_rect", (0, 0, 100, 100)
        )
        return 1

    def EnumChildWindows(self, parent: Any, callback: Any, lparam: int) -> int:
        for child in self._row(parent).get("children", []):
            if not callback(child, lparam):
                break
        return 1


class _CtypesProxy:
    def __init__(self, user32: Any, *, dlls: dict[str, Any] | None = None) -> None:
        self.windll = SimpleNamespace(user32=user32)
        self._dlls = dict(dlls or {})

    def WinDLL(self, name: str, *, use_last_error: bool = False) -> Any:
        return self._dlls[name]

    def get_last_error(self) -> int:
        return 5

    def __getattr__(self, attribute: str) -> Any:
        return getattr(ctypes, attribute)


def _pin(
    monkeypatch: pytest.MonkeyPatch,
    user32: _FakeUser32,
    *,
    dlls: dict[str, Any] | None = None,
) -> None:
    monkeypatch.setattr(uw, "os", _OsProxy())
    monkeypatch.setattr(uw, "ctypes", _CtypesProxy(user32, dlls=dlls))


_BASE = {
    5: {
        "pid": 100,
        "title": "Debuggee",
        "class_name": "Notepad",
        "control_id": 0,
        "rect": (10, 10, 210, 110),
        "children": [6, 7, 9],
    },
    6: {
        "pid": 100,
        "title": "OK",
        "class_name": "Button",
        "control_id": 1,
        "parent": 5,
        "rect": (20, 20, 60, 40),
    },
    7: {
        "pid": 100,
        "title": "Cancel",
        "class_name": "Button",
        "control_id": 2,
        "parent": 5,
        "rect": (70, 20, 110, 40),
    },
    9: {
        "pid": 999,
        "title": "Intruder",
        "class_name": "Button",
        "control_id": 3,
        "parent": 5,
    },
}


def _table() -> dict[int, dict[str, Any]]:
    return {hwnd: dict(row) for hwnd, row in _BASE.items()}


# ---------------------------------------------------------------------------
# Platform gate, ownership, and the hwnd guard.
# ---------------------------------------------------------------------------


def test_win32_ui_is_refused_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uw, "os", _OsProxy("posix"))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.hwnd_owner_pid(5)
    assert refused.value.code == "unsupported_on_platform"


@pytest.mark.parametrize("hwnd", [0, -1, True, "5", None])
def test_hostile_hwnds_are_refused_before_any_win32_call(hwnd: Any) -> None:
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.require_allowed_hwnd(hwnd, ALLOWED)
    assert refused.value.code == "invalid_params"


def test_a_dead_hwnd_is_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.require_allowed_hwnd(12345, ALLOWED)
    assert refused.value.code == "not_found"


def test_a_foreign_hwnd_is_refused_with_its_owner_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.require_allowed_hwnd(9, ALLOWED)
    assert refused.value.code == "permission_denied"
    assert refused.value.details["pid"] == 999

    assert uw.require_allowed_hwnd(5, ALLOWED) == 100


def test_window_text_is_clamped_to_the_text_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table = _table()
    table[5]["title"] = "x" * 5000
    _pin(monkeypatch, _FakeUser32(table))
    assert uw.get_window_text(5, ALLOWED) == "x" * 4096


def test_describe_hwnd_reports_the_full_row(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    described = uw.describe_hwnd(6)
    assert described == {
        "hwnd": 6,
        "pid": 100,
        "class_name": "Button",
        "title": "OK",
        "visible": True,
        "control_id": 1,
        "enabled": True,
    }


# ---------------------------------------------------------------------------
# Child enumeration and the bounded window tree.
# ---------------------------------------------------------------------------


def test_child_listing_is_pid_bounded_and_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    children = uw.list_child_windows(5, ALLOWED)
    assert [child["hwnd"] for child in children] == [6, 7]
    assert all(child["pid"] == 100 for child in children)


def test_child_listing_stops_at_the_callback_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    children = uw.list_child_windows(5, ALLOWED, max_callbacks=1)
    assert [child["hwnd"] for child in children] == [6], "enumeration must stop, not skip"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_depth": -1},
        {"max_depth": 9},
        {"max_depth": True},
        {"max_nodes": 0},
        {"max_nodes": 257},
        {"max_nodes": True},
    ],
)
def test_tree_budget_shapes_are_refused(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, Any],
) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.build_window_tree([uw.describe_hwnd(5)], ALLOWED, **kwargs)
    assert refused.value.code == "invalid_params"


def test_tree_descends_and_respects_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    root = uw.describe_hwnd(5)

    deep = uw.build_window_tree([root], ALLOWED, max_depth=1)
    assert deep["count"] == 3 and deep["truncated"] is False
    assert [c["hwnd"] for c in deep["nodes"][0]["children"]] == [6, 7]

    shallow = uw.build_window_tree([root], ALLOWED, max_depth=0)
    assert shallow["count"] == 1
    assert shallow["nodes"][0]["children"] == [], "depth 0 must not enumerate children"


def test_tree_truncates_at_the_node_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    root = uw.describe_hwnd(5)

    tree = uw.build_window_tree([root, root], ALLOWED, max_depth=1, max_nodes=2)

    assert tree["truncated"] is True and tree["count"] == 2
    assert len(tree["nodes"]) == 1, "the second root must be dropped once the budget is spent"


def test_a_deep_subtree_exhausting_the_budget_stops_the_sibling_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table = _table()
    table[6]["children"] = [8]
    table[8] = {"pid": 100, "title": "Nested", "class_name": "Edit", "parent": 6}
    _pin(monkeypatch, _FakeUser32(table))

    tree = uw.build_window_tree([uw.describe_hwnd(5)], ALLOWED, max_depth=2, max_nodes=3)

    assert tree["truncated"] is True and tree["count"] == 3
    children = tree["nodes"][0]["children"]
    assert [c["hwnd"] for c in children] == [6], "the sibling after the exhausted subtree is cut"


# ---------------------------------------------------------------------------
# resolve / wait.
# ---------------------------------------------------------------------------


def test_resolve_by_hwnd_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    assert uw.resolve_hwnd(ALLOWED, hwnd=6)["title"] == "OK"


def test_resolve_without_any_selector_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.resolve_hwnd(ALLOWED)
    assert refused.value.code == "invalid_params"

    with pytest.raises(UiPidBoundaryError) as refused:
        uw.resolve_hwnd(ALLOWED, parent_hwnd=5)
    assert refused.value.code == "invalid_params"
    assert "child resolve" in refused.value.message


def test_resolve_filters_and_reports_ambiguity(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))

    match = uw.resolve_hwnd(ALLOWED, parent_hwnd=5, title="OK")
    assert match["hwnd"] == 6

    match = uw.resolve_hwnd(ALLOWED, parent_hwnd=5, title_contains="anc", control_id=2)
    assert match["hwnd"] == 7

    with pytest.raises(UiPidBoundaryError) as ambiguous:
        uw.resolve_hwnd(ALLOWED, parent_hwnd=5, class_name="Button")
    assert ambiguous.value.code == "ambiguous"
    assert ambiguous.value.details["count"] == 2

    with pytest.raises(UiPidBoundaryError) as missing:
        uw.resolve_hwnd(ALLOWED, parent_hwnd=5, title="No Such Button")
    assert missing.value.code == "not_found"

    with pytest.raises(UiPidBoundaryError) as wrong_class:
        uw.resolve_hwnd(ALLOWED, parent_hwnd=5, class_name="Edit")
    assert wrong_class.value.code == "not_found"

    with pytest.raises(UiPidBoundaryError) as wrong_id:
        uw.resolve_hwnd(ALLOWED, parent_hwnd=5, control_id=99)
    assert wrong_id.value.code == "not_found"


def test_resolve_over_top_level_windows_uses_the_pid_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    import headless_re_mcp.core.windows as windows_module

    monkeypatch.setattr(
        windows_module,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 5, "class_name": "Notepad", "title": "Debuggee"}],
    )

    assert uw.resolve_hwnd(ALLOWED, class_name="Notepad")["hwnd"] == 5


@pytest.mark.parametrize("timeout", [True, 0, -1, 31, "5"])
def test_wait_timeout_shapes_are_refused(timeout: Any) -> None:
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.wait_for_window(ALLOWED, timeout=timeout)
    assert refused.value.code == "invalid_params"


def _fake_clock(monkeypatch: pytest.MonkeyPatch, *, step: float) -> None:
    state = {"now": 0.0}

    def monotonic() -> float:
        state["now"] += step
        return state["now"]

    monkeypatch.setattr(
        uw, "time", SimpleNamespace(monotonic=monotonic, sleep=lambda seconds: None)
    )


def test_wait_returns_the_window_when_it_appears(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_clock(monkeypatch, step=0.1)
    answers = iter(
        [
            UiPidBoundaryError("not_found", "nothing yet"),
            {"hwnd": 6, "title": "OK"},
        ]
    )

    def resolve(allowed: Any, **kwargs: Any) -> Any:
        answer = next(answers)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(uw, "resolve_hwnd", resolve)

    result = uw.wait_for_window(ALLOWED, timeout=5.0, title="OK")

    assert result["matched"] is True and result["window"]["hwnd"] == 6
    assert result["waited_ms"] >= 0


def test_wait_times_out_with_the_last_resolve_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_clock(monkeypatch, step=0.6)

    def resolve(allowed: Any, **kwargs: Any) -> Any:
        raise UiPidBoundaryError("not_found", "still nothing")

    monkeypatch.setattr(uw, "resolve_hwnd", resolve)

    with pytest.raises(UiPidBoundaryError) as refused:
        uw.wait_for_window(ALLOWED, timeout=1.0, title="OK")

    assert refused.value.code == "timeout"
    assert refused.value.details["last_error"] == "still nothing"


def test_wait_propagates_non_retryable_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_clock(monkeypatch, step=0.1)

    def resolve(allowed: Any, **kwargs: Any) -> Any:
        raise UiPidBoundaryError("permission_denied", "boundary breach")

    monkeypatch.setattr(uw, "resolve_hwnd", resolve)

    with pytest.raises(UiPidBoundaryError) as refused:
        uw.wait_for_window(ALLOWED, timeout=1.0, title="OK")

    assert refused.value.code == "permission_denied", "only not_found/ambiguous may be retried"


# ---------------------------------------------------------------------------
# Message plumbing: send with timeout, post, click, keys, text.
# ---------------------------------------------------------------------------


def test_send_timeout_returns_the_marshaled_result(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(_table(), send_result=42)
    _pin(monkeypatch, user32)
    assert uw._send_timeout(5, uw.WM_CLOSE, 0, 0, 1000) == 42


def test_send_timeout_failure_is_a_timeout_with_winerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(_table(), send_ok=False))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw._send_timeout(5, uw.WM_CLOSE, 0, 0, 1000)
    assert refused.value.code == "timeout"
    assert refused.value.details["winerror"] == 5


def test_post_failure_is_a_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, _FakeUser32(_table(), post_ok=False))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw._post_message(5, uw.WM_CLOSE, 0, 0)
    assert refused.value.code == "backend_error"


def test_click_posts_bm_click_without_foreground(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)

    envelope = uw.click_hwnd(6, ALLOWED)

    assert user32.posted == [(6, uw.BM_CLICK, 0, 0)]
    assert envelope["backend"] == "win32_postmessage"
    assert envelope["foreground_required"] is False


@pytest.mark.parametrize(
    ("x", "y"), [(-1, 0), (0, -1), (65536, 0), (0, 65536), (True, 0), ("1", 0)]
)
def test_click_at_refuses_hostile_coordinates(
    monkeypatch: pytest.MonkeyPatch,
    x: Any,
    y: Any,
) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.click_hwnd_at(6, ALLOWED, x=x, y=y)
    assert refused.value.code == "invalid_params"
    assert user32.posted == []


def test_click_at_posts_the_full_mouse_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)

    envelope = uw.click_hwnd_at(6, ALLOWED, x=30, y=20)

    lp = (20 << 16) | 30
    assert user32.posted == [
        (6, uw.WM_MOUSEMOVE, 0, lp),
        (6, uw.WM_LBUTTONDOWN, uw.MK_LBUTTON, lp),
        (6, uw.WM_LBUTTONUP, 0, lp),
    ]
    assert envelope["backend"] == "win32_postmessage_client"


def test_text_set_and_key_paths_send_the_expected_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)

    text_set = uw.set_window_text(6, "hello", ALLOWED)
    assert text_set["backend"] == "win32_sendmessage"
    assert user32.sent[0][:2] == (6, uw.WM_SETTEXT)

    user32.sent.clear()
    typed = uw.send_key(6, allowed_pids=ALLOWED, text="ab")
    assert typed["backend"] == "win32_wm_char"
    assert user32.sent == [
        (6, uw.WM_CHAR, ord("a")),
        (6, uw.WM_CHAR, ord("b")),
    ]

    user32.sent.clear()
    pressed = uw.send_key(6, allowed_pids=ALLOWED, vk=13)
    assert pressed["backend"] == "win32_wm_key"
    assert user32.sent == [(6, uw.WM_KEYDOWN, 13), (6, uw.WM_KEYUP, 13)]


def test_hostile_text_and_key_shapes_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)

    calls: tuple[Callable[[], Any], ...] = (
        lambda: uw.set_window_text(6, 42, ALLOWED),  # type: ignore[arg-type]
        lambda: uw.set_window_text(6, "x" * 4097, ALLOWED),
        lambda: uw.send_key(6, allowed_pids=ALLOWED, text="a", vk=13),
        lambda: uw.send_key(6, allowed_pids=ALLOWED),
        lambda: uw.send_key(6, allowed_pids=ALLOWED, text=""),
        lambda: uw.send_key(6, allowed_pids=ALLOWED, text="x" * 33),
        lambda: uw.send_key(6, allowed_pids=ALLOWED, vk=0),
        lambda: uw.send_key(6, allowed_pids=ALLOWED, vk=255),
        lambda: uw.send_key(6, allowed_pids=ALLOWED, vk=True),
    )
    for call in calls:
        with pytest.raises(UiPidBoundaryError) as refused:
            call()
        assert refused.value.code == "invalid_params"
    assert user32.sent == [], "no refused payload may reach the message queue"


# ---------------------------------------------------------------------------
# close_hwnd and the invoke whitelist.
# ---------------------------------------------------------------------------


def test_close_methods_send_their_documented_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)

    closed = uw.close_hwnd(5, ALLOWED, method="nc_close")
    assert closed["backend"] == "win32_nc_close_sendmessage"
    assert closed["method"] == "nc_close" and closed["shown_noactivate"] is False
    assert [p[1] for p in user32.posted] == [uw.WM_NCLBUTTONDOWN, uw.WM_NCLBUTTONUP]
    assert [s[:2] for s in user32.sent] == [(5, uw.WM_SYSCOMMAND), (5, uw.WM_CLOSE)]

    user32.sent.clear()
    assert uw.close_hwnd(5, ALLOWED, method="syscommand")["backend"] == "win32_syscommand_close"
    assert [s[:2] for s in user32.sent] == [(5, uw.WM_SYSCOMMAND)]

    user32.sent.clear()
    assert uw.close_hwnd(5, ALLOWED, method="wm_close")["backend"] == "win32_wm_close"
    assert [s[:2] for s in user32.sent] == [(5, uw.WM_CLOSE)]


def test_close_refuses_unknown_methods_and_broken_rects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, _FakeUser32(_table()))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.close_hwnd(5, ALLOWED, method="alt_f4")
    assert refused.value.code == "invalid_params"

    _pin(monkeypatch, _FakeUser32(_table(), rect_ok=False))
    with pytest.raises(UiPidBoundaryError) as broken:
        uw.close_hwnd(5, ALLOWED)
    assert broken.value.code == "backend_error"


def test_a_cloaked_window_is_revealed_without_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table = _table()
    table[5]["rect"] = (-32000, -32000, -31900, -31900)
    user32 = _FakeUser32(table)
    _pin(monkeypatch, user32)

    closed = uw.close_hwnd(5, ALLOWED, method="wm_close")

    assert closed["shown_noactivate"] is True
    assert user32.shown == [(5, 4)], "SW_SHOWNOACTIVATE, never an activating show"


def test_invoke_dispatches_through_the_whitelist(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)

    with pytest.raises(UiPidBoundaryError) as refused:
        uw.invoke_hwnd(6, ALLOWED, action="sendmessage")
    assert refused.value.code == "invalid_params"
    assert refused.value.details["allowed"] == sorted(uw._INVOKE_WHITELIST)

    assert uw.invoke_hwnd(6, ALLOWED, action="click")["backend"] == "win32_postmessage"
    assert uw.invoke_hwnd(6, ALLOWED, action="wm_close")["backend"] == "win32_wm_close"

    with pytest.raises(UiPidBoundaryError) as textless:
        uw.invoke_hwnd(6, ALLOWED, action="set_text")
    assert textless.value.code == "invalid_params"
    assert uw.invoke_hwnd(6, ALLOWED, action="set_text", text="v")["action"] == "text.set"


def test_invoke_command_notifies_the_parent_with_bn_clicked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(_table())
    _pin(monkeypatch, user32)

    envelope = uw.invoke_hwnd(6, ALLOWED, action="command")

    assert envelope["parent_hwnd"] == 5 and envelope["control_id"] == 1
    assert user32.sent == [(5, uw.WM_COMMAND, (uw.BN_CLICKED << 16) | 1)]

    # A parentless control notifies itself instead.
    user32.sent.clear()
    envelope = uw.invoke_hwnd(5, ALLOWED, action="command", control_id=3)
    assert envelope["parent_hwnd"] == 5
    assert user32.sent == [(5, uw.WM_COMMAND, (uw.BN_CLICKED << 16) | 3)]


# ---------------------------------------------------------------------------
# Capture-size guards, BMP writer, and uniformity estimation.
# ---------------------------------------------------------------------------


def test_capture_size_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    table = _table()
    table[5]["rect"] = (0, 0, 0, 50)
    _pin(monkeypatch, _FakeUser32(table))
    with pytest.raises(UiPidBoundaryError) as empty:
        uw._window_capture_size(5, client_only=False)
    assert empty.value.code == "invalid_state"

    table[5]["rect"] = (0, 0, 9000, 10)
    _pin(monkeypatch, _FakeUser32(table))
    with pytest.raises(UiPidBoundaryError) as edge:
        uw._window_capture_size(5, client_only=False)
    assert edge.value.code == "invalid_params" and "max edge" in edge.value.message

    table[5]["rect"] = (0, 0, 8192, 4096)
    _pin(monkeypatch, _FakeUser32(table))
    with pytest.raises(UiPidBoundaryError) as pixels:
        uw._window_capture_size(5, client_only=False)
    assert pixels.value.code == "invalid_params" and "max pixels" in pixels.value.message

    _pin(monkeypatch, _FakeUser32(table, rect_ok=False, client_rect_ok=False))
    for client_only in (False, True):
        with pytest.raises(UiPidBoundaryError) as broken:
            uw._window_capture_size(5, client_only=client_only)
        assert broken.value.code == "capability_unavailable"

    table[5]["client_rect"] = (0, 0, 64, 32)
    _pin(monkeypatch, _FakeUser32(table))
    assert uw._window_capture_size(5, client_only=True) == (64, 32)


def test_bmp_writer_produces_a_readable_header(tmp_path: Path) -> None:
    width, height = 2, 2
    stride = 8
    pixels = bytes(range(stride * height))
    out = tmp_path / "shot.bmp"

    written = uw._write_bmp_bgr(out, width, height, pixels)

    raw = out.read_bytes()
    assert written == len(raw) == 14 + 40 + len(pixels)
    assert raw[:2] == b"BM"
    header_width, header_height = struct.unpack_from("<ii", raw, 18)
    assert (header_width, header_height) == (width, height)
    assert raw[54:] == pixels

    with pytest.raises(UiPidBoundaryError) as refused:
        uw._write_bmp_bgr(out, width, height, pixels[:-1])
    assert refused.value.code == "capability_unavailable"


def test_uniformity_estimation_names_each_degradation() -> None:
    stride = 8

    blank = uw._estimate_capture_uniformity(bytes(stride * 2), 2, 2, stride)
    assert blank["degraded"] is True and blank["degraded_reason"] == "blank_capture"

    uniform = uw._estimate_capture_uniformity(bytes([200, 200, 200] * 2 + [0, 0]) * 2, 2, 2, stride)
    assert uniform["degraded"] is True and uniform["degraded_reason"] == "uniform_capture"

    varied = uw._estimate_capture_uniformity(
        bytes([10, 20, 30, 200, 100, 50, 0, 0]) + bytes([90, 80, 70, 60, 50, 40, 0, 0]),
        2,
        2,
        stride,
    )
    assert varied["degraded"] is False and varied["degraded_reason"] is None

    empty = uw._estimate_capture_uniformity(b"", 2, 2, stride)
    assert empty["degraded_reason"] == "empty_capture" and empty["sampled_pixels"] == 0

    short = uw._estimate_capture_uniformity(b"\x01", 2, 2, stride)
    assert short["degraded_reason"] == "empty_capture", "unsampleable bytes are an empty capture"


def test_mostly_black_capture_is_distinguished_from_blank() -> None:
    width = 200
    stride = ((width * 3 + 3) // 4) * 4
    row = bytearray(stride)
    row[0:3] = (250, 250, 250)  # one bright pixel breaks uniformity
    result = uw._estimate_capture_uniformity(bytes(row), width, 1, stride)
    assert result["degraded"] is True
    assert result["degraded_reason"] == "mostly_black_capture"


def test_capture_preference_orders_by_degradation_then_darkness() -> None:
    assert uw._prefer_capture_uniformity({"degraded": True}, {"degraded": False}) is True
    assert uw._prefer_capture_uniformity({"degraded": False}, {"degraded": True}) is False
    assert (
        uw._prefer_capture_uniformity(
            {"degraded": True, "dark_ratio": 0.9},
            {"degraded": True, "dark_ratio": 0.2},
        )
        is True
    )


# ---------------------------------------------------------------------------
# The full screenshot path against scripted GDI.
# ---------------------------------------------------------------------------

_VARIED = bytes([10, 20, 30, 200, 100, 50, 0, 0]) + bytes([90, 80, 70, 60, 50, 40, 0, 0])
_BLANK = bytes(16)


class _FakeGdi:
    def __init__(
        self, *, frames: list[bytes], bitblt_ok: bool = True, alloc_ok: bool = True
    ) -> None:
        self.frames = list(frames)
        self.bitblt_ok = bitblt_ok
        self.alloc_ok = alloc_ok
        self.freed: list[str] = []

        def CreateCompatibleDC(dc: Any) -> int:
            return 11 if self.alloc_ok else 0

        def CreateCompatibleBitmap(dc: Any, w: int, h: int) -> int:
            return 12 if self.alloc_ok else 0

        def SelectObject(dc: Any, obj: Any) -> int:
            return 13

        def BitBlt(*args: Any) -> bool:
            return self.bitblt_ok

        def DeleteDC(dc: Any) -> bool:
            self.freed.append("dc")
            return True

        def DeleteObject(obj: Any) -> bool:
            self.freed.append("bitmap")
            return True

        def GetDIBits(mdc: Any, bmp: Any, start: Any, h: Any, buf: Any, bmi: Any, fl: Any) -> int:
            frame = self.frames.pop(0) if self.frames else _VARIED
            ctypes.memmove(buf._obj, frame, min(len(frame), len(buf._obj)))
            return _as_int(h)

        self.CreateCompatibleDC = CreateCompatibleDC
        self.CreateCompatibleBitmap = CreateCompatibleBitmap
        self.SelectObject = SelectObject
        self.BitBlt = BitBlt
        self.DeleteDC = DeleteDC
        self.DeleteObject = DeleteObject
        self.GetDIBits = GetDIBits


class _FakeCaptureUser32(_FakeUser32):
    def __init__(
        self, table: dict[int, dict[str, Any]], *, print_ok: bool = True, dc: int = 10
    ) -> None:
        super().__init__(table)
        self.print_flags: list[int] = []
        self.released = 0
        self._dc = dc

        def GetWindowDC(hwnd: Any) -> int:
            return self._dc

        def GetDC(hwnd: Any) -> int:
            return self._dc

        def ReleaseDC(hwnd: Any, dc: Any) -> int:
            self.released += 1
            return 1

        def PrintWindow(hwnd: Any, dc: Any, flags: Any) -> bool:
            self.print_flags.append(_as_int(flags))
            return print_ok

        self.GetWindowDC = GetWindowDC
        self.GetDC = GetDC
        self.ReleaseDC = ReleaseDC
        self.PrintWindow = PrintWindow


def _capture_table() -> dict[int, dict[str, Any]]:
    table = _table()
    table[5]["rect"] = (0, 0, 2, 2)
    table[5]["client_rect"] = (0, 0, 2, 2)
    return table


def _pin_capture(
    monkeypatch: pytest.MonkeyPatch,
    user32: _FakeCaptureUser32,
    gdi: _FakeGdi,
) -> None:
    _pin(monkeypatch, user32, dlls={"user32": user32, "gdi32": gdi})


def test_screenshot_requires_a_bmp_suffix(tmp_path: Path) -> None:
    with pytest.raises(UiPidBoundaryError) as refused:
        uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.png")
    assert refused.value.code == "invalid_params"


def test_screenshot_happy_path_writes_the_bmp(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user32 = _FakeCaptureUser32(_capture_table())
    gdi = _FakeGdi(frames=[_VARIED])
    _pin_capture(monkeypatch, user32, gdi)
    out = tmp_path / "shot.bmp"

    envelope = uw.capture_hwnd_screenshot(5, ALLOWED, out)

    assert envelope["backend"] == "win32_printwindow"
    assert envelope["degraded"] is False
    assert envelope["width"] == 2 and envelope["height"] == 2
    assert out.read_bytes()[:2] == b"BM"
    assert user32.print_flags == [uw.PW_RENDERFULLCONTENT]
    assert user32.released == 1 and gdi.freed == ["bitmap", "dc"]


def test_client_only_screenshot_asks_for_client_content(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user32 = _FakeCaptureUser32(_capture_table())
    gdi = _FakeGdi(frames=[_VARIED])
    _pin_capture(monkeypatch, user32, gdi)

    envelope = uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "c.bmp", client_only=True)

    assert envelope["client_only"] is True
    assert user32.print_flags == [uw.PW_RENDERFULLCONTENT | uw.PW_CLIENTONLY]


def test_a_blank_printwindow_frame_retries_with_bitblt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user32 = _FakeCaptureUser32(_capture_table())
    gdi = _FakeGdi(frames=[_BLANK, _VARIED])
    _pin_capture(monkeypatch, user32, gdi)

    envelope = uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.bmp")

    assert envelope["backend"] == "win32_bitblt", "the less-blank BitBlt frame must win"
    assert envelope["degraded"] is False


def test_printwindow_refusal_falls_back_to_bitblt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user32 = _FakeCaptureUser32(_capture_table(), print_ok=False)
    gdi = _FakeGdi(frames=[_VARIED])
    _pin_capture(monkeypatch, user32, gdi)

    envelope = uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.bmp")

    assert envelope["backend"] == "win32_bitblt"


def test_both_capture_backends_failing_is_a_named_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user32 = _FakeCaptureUser32(_capture_table(), print_ok=False)
    gdi = _FakeGdi(frames=[], bitblt_ok=False)
    _pin_capture(monkeypatch, user32, gdi)

    with pytest.raises(UiPidBoundaryError) as refused:
        uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.bmp")

    assert refused.value.code == "capability_unavailable"
    assert "BitBlt" in refused.value.message
    assert gdi.freed == ["bitmap", "dc"], "GDI objects must be freed on the failure path"


def test_gdi_allocation_failure_is_a_named_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user32 = _FakeCaptureUser32(_capture_table())
    gdi = _FakeGdi(frames=[], alloc_ok=False)
    _pin_capture(monkeypatch, user32, gdi)

    with pytest.raises(UiPidBoundaryError) as refused:
        uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.bmp")
    assert "capture bitmap" in refused.value.message

    user32 = _FakeCaptureUser32(_capture_table(), dc=0)
    _pin_capture(monkeypatch, user32, _FakeGdi(frames=[]))
    with pytest.raises(UiPidBoundaryError) as no_dc:
        uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.bmp")
    assert "window DC" in no_dc.value.message


def test_an_hwnd_that_changes_owner_mid_capture_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The post-capture ownership re-check closes the hwnd-reuse TOCTOU."""
    table = _capture_table()
    user32 = _FakeCaptureUser32(table)
    original_print = user32.PrintWindow

    def flip_owner_then_print(hwnd: Any, dc: Any, flags: Any) -> bool:
        table[5]["pid"] = 999
        return original_print(hwnd, dc, flags)

    user32.PrintWindow = flip_owner_then_print
    gdi = _FakeGdi(frames=[_VARIED])
    _pin_capture(monkeypatch, user32, gdi)
    out = tmp_path / "shot.bmp"

    with pytest.raises(UiPidBoundaryError) as refused:
        uw.capture_hwnd_screenshot(5, ALLOWED, out)

    assert refused.value.code == "permission_denied"
    assert not out.exists(), "no pixels may be persisted for a window that changed hands"
    assert gdi.freed == ["bitmap", "dc"]


def test_an_iconic_window_is_revealed_before_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    table = _capture_table()
    table[5]["iconic"] = True
    user32 = _FakeCaptureUser32(table)
    gdi = _FakeGdi(frames=[_VARIED])
    _pin_capture(monkeypatch, user32, gdi)

    uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.bmp")

    assert (5, uw._SW_SHOWNOACTIVATE) in user32.shown


def test_a_retry_frame_that_is_no_better_is_not_preferred(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user32 = _FakeCaptureUser32(_capture_table())
    gdi = _FakeGdi(frames=[_BLANK, _BLANK])
    _pin_capture(monkeypatch, user32, gdi)

    envelope = uw.capture_hwnd_screenshot(5, ALLOWED, tmp_path / "shot.bmp")

    assert envelope["backend"] == "win32_printwindow", "an equally blank retry must not win"
    assert envelope["degraded"] is True
    assert envelope["degraded_reason"] == "blank_capture"


def test_reveal_skips_a_window_whose_rect_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(_table(), rect_ok=False)
    _pin(monkeypatch, user32)

    uw._maybe_reveal_hwnd_for_capture(5)

    assert user32.shown == [], "an unreadable rect is not evidence the window needs revealing"


def test_dibits_shortfall_is_a_named_error(monkeypatch: pytest.MonkeyPatch) -> None:
    gdi = SimpleNamespace(
        GetDIBits=lambda mdc, bmp, start, h, buf, bmi, fl: 0,
    )
    _pin(monkeypatch, _FakeUser32(_table()))
    with pytest.raises(UiPidBoundaryError) as refused:
        uw._copy_dibits(gdi, 11, 12, 2, 2)
    assert refused.value.code == "capability_unavailable"
    assert refused.value.details["got"] == 0
