"""Coverage for the Win32 UI automation layer on a non-Windows host.

Everything routes through ``ctypes.windll.user32`` (and private WinDLL handles
for screen capture), so a registry-backed fake user32 drives the real message
and enumeration code, and fake user32/gdi32 capture handles feed pixel buffers
through the genuine BMP writer and uniformity estimator.
"""

from __future__ import annotations

import ctypes
import os
import time
from pathlib import Path, PosixPath
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_win32 as w32
import headless_re_mcp.core.windows as core_windows
from headless_re_mcp.core.ui_win32 import (
    _estimate_capture_uniformity,
    _prefer_capture_uniformity,
    _window_capture_size,
    _write_bmp_bgr,
    build_window_tree,
    capture_hwnd_screenshot,
    click_hwnd,
    click_hwnd_at,
    close_hwnd,
    describe_hwnd,
    get_window_text,
    hwnd_owner_pid,
    invoke_hwnd,
    list_child_windows,
    require_allowed_hwnd,
    resolve_hwnd,
    send_key,
    set_window_text,
    wait_for_window,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_ALLOWED = frozenset({7})


def _hv(value: Any) -> int:
    inner = getattr(value, "value", value)
    return int(inner or 0)


def _win(
    *,
    pid: int = 7,
    title: str = "Main",
    class_name: str = "Cls",
    control_id: int = 0,
    visible: bool = True,
    children: tuple[int, ...] = (),
    rect: tuple[int, int, int, int] | None = (0, 0, 100, 50),
    client: tuple[int, int, int, int] | None = (0, 0, 90, 40),
    iconic: bool = False,
    parent: int = 0,
) -> dict[str, Any]:
    return {
        "pid": pid,
        "title": title,
        "class_name": class_name,
        "control_id": control_id,
        "visible": visible,
        "children": list(children),
        "rect": rect,
        "client": client,
        "iconic": iconic,
        "parent": parent,
    }


class _FakeUser32:
    def __init__(
        self,
        windows: dict[int, dict[str, Any]],
        *,
        post_ok: bool = True,
        send_ok: bool = True,
    ) -> None:
        self.windows = windows
        self.posted: list[tuple[int, int, int, int]] = []
        self.sent: list[tuple[int, int, int]] = []
        self.shown: list[tuple[int, int]] = []

        def SendMessageTimeoutW(
            hwnd: Any, msg: Any, wp: Any, lp: Any, flags: Any, timeout: Any, out: Any
        ) -> int:
            if not send_ok:
                return 0
            self.sent.append((_hv(hwnd), _hv(msg), _hv(wp)))
            out._obj.value = 1
            return 1

        def PostMessageW(hwnd: Any, msg: Any, wp: Any, lp: Any) -> int:
            if not post_ok:
                return 0
            self.posted.append((_hv(hwnd), _hv(msg), _hv(wp), _hv(lp)))
            return 1

        self.SendMessageTimeoutW = SendMessageTimeoutW
        self.PostMessageW = PostMessageW

    def _w(self, hwnd: Any) -> dict[str, Any]:
        return self.windows.get(_hv(hwnd), _win(pid=0, title="", rect=None, client=None))

    def IsWindow(self, hwnd: Any) -> int:
        return 1 if _hv(hwnd) in self.windows else 0

    def GetWindowThreadProcessId(self, hwnd: Any, out: Any) -> int:
        out._obj.value = self._w(hwnd)["pid"]
        return 1

    def GetWindowTextLengthW(self, hwnd: Any) -> int:
        return len(self._w(hwnd)["title"])

    def GetWindowTextW(self, hwnd: Any, buffer: Any, count: int) -> int:
        buffer.value = self._w(hwnd)["title"][: max(0, count - 1)]
        return len(buffer.value)

    def GetClassNameW(self, hwnd: Any, buffer: Any, count: int) -> int:
        buffer.value = self._w(hwnd)["class_name"]
        return len(buffer.value)

    def GetDlgCtrlID(self, hwnd: Any) -> int:
        return int(self._w(hwnd)["control_id"])

    def IsWindowVisible(self, hwnd: Any) -> int:
        return 1 if self._w(hwnd)["visible"] else 0

    def IsWindowEnabled(self, hwnd: Any) -> int:
        return 1

    def EnumChildWindows(self, parent: Any, callback: Any, lparam: int) -> int:
        for child in self._w(parent)["children"]:
            if not callback(child, 0):
                break
        return 1

    def GetWindowRect(self, hwnd: Any, out: Any) -> int:
        rect = self._w(hwnd)["rect"]
        if rect is None:
            return 0
        target = out._obj
        target.left, target.top, target.right, target.bottom = rect
        return 1

    def GetClientRect(self, hwnd: Any, out: Any) -> int:
        client = self._w(hwnd)["client"]
        if client is None:
            return 0
        target = out._obj
        target.left, target.top, target.right, target.bottom = client
        return 1

    def ShowWindow(self, hwnd: Any, flag: int) -> int:
        self.shown.append((_hv(hwnd), flag))
        return 1

    def IsIconic(self, hwnd: Any) -> int:
        return 1 if self._w(hwnd)["iconic"] else 0

    def GetParent(self, hwnd: Any) -> int:
        return int(self._w(hwnd)["parent"])


def _env(
    monkeypatch: pytest.MonkeyPatch,
    windows: dict[int, dict[str, Any]] | None = None,
    **kwargs: Any,
) -> _FakeUser32:
    user32 = _FakeUser32(windows if windows is not None else {100: _win()}, **kwargs)
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(user32=user32), raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)
    # Path() dispatches on os.name at call time; keep PosixPath on this host.
    monkeypatch.setattr(w32, "Path", PosixPath)
    return user32


# --------------------------------------------------------------------------
# gate / ownership
# --------------------------------------------------------------------------


def test_user32_is_unavailable_off_windows() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        hwnd_owner_pid(100)
    assert info.value.code == "unsupported_on_platform"


def test_require_allowed_hwnd_validates_the_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="positive integer"):
        require_allowed_hwnd(0, _ALLOWED)
    with pytest.raises(UiPidBoundaryError) as info:
        require_allowed_hwnd(999, _ALLOWED)
    assert info.value.code == "not_found"


def test_require_allowed_hwnd_rejects_a_foreign_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch, {100: _win(pid=1234)})
    with pytest.raises(UiPidBoundaryError) as info:
        require_allowed_hwnd(100, _ALLOWED)
    assert info.value.code == "permission_denied"


def test_require_allowed_hwnd_returns_the_owner_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch)
    assert require_allowed_hwnd(100, _ALLOWED) == 7


def test_describe_hwnd_reads_the_full_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, {100: _win(title="Editor", class_name="Edit", control_id=12)})
    described = describe_hwnd(100)
    assert described == {
        "hwnd": 100,
        "pid": 7,
        "class_name": "Edit",
        "title": "Editor",
        "visible": True,
        "control_id": 12,
        "enabled": True,
    }


# --------------------------------------------------------------------------
# child enumeration / tree
# --------------------------------------------------------------------------


def test_list_child_windows_filters_and_sorts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(
        monkeypatch,
        {
            100: _win(children=(103, 101, 102)),
            101: _win(title="a"),
            102: _win(pid=999, title="foreign"),
            103: _win(title="b"),
        },
    )
    children = list_child_windows(100, _ALLOWED)
    assert [child["hwnd"] for child in children] == [101, 103]


def test_list_child_windows_stops_at_max_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(
        monkeypatch,
        {
            100: _win(children=(101, 102, 103)),
            101: _win(),
            102: _win(),
            103: _win(),
        },
    )
    children = list_child_windows(100, _ALLOWED, max_callbacks=2)
    assert [child["hwnd"] for child in children] == [101, 102]


def test_tree_rejects_bad_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="max_depth"):
        build_window_tree([], _ALLOWED, max_depth=9)
    with pytest.raises(UiPidBoundaryError, match="max_nodes"):
        build_window_tree([], _ALLOWED, max_nodes=0)


def test_tree_walks_within_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(
        monkeypatch,
        {
            100: _win(title="root", children=(101,)),
            101: _win(title="child"),
        },
    )
    tree = build_window_tree([describe_hwnd(100)], _ALLOWED, max_depth=2)
    assert tree["count"] == 2
    assert tree["truncated"] is False
    assert tree["nodes"][0]["children"][0]["title"] == "child"


def test_tree_respects_max_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(
        monkeypatch,
        {
            100: _win(children=(101,)),
            101: _win(children=(102,)),
            102: _win(),
        },
    )
    tree = build_window_tree([describe_hwnd(100)], _ALLOWED, max_depth=1)
    assert tree["count"] == 2
    assert tree["nodes"][0]["children"][0]["children"] == []


def test_tree_truncates_and_breaks_on_the_node_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(
        monkeypatch,
        {
            100: _win(children=(101, 102, 103)),
            101: _win(children=(110,)),
            102: _win(),
            103: _win(),
            110: _win(),
        },
    )
    tree = build_window_tree([describe_hwnd(100)], _ALLOWED, max_nodes=4)
    assert tree["count"] == 4
    assert tree["truncated"] is True


def test_tree_skips_roots_once_the_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch, {100: _win(), 200: _win()})
    tree = build_window_tree([describe_hwnd(100), describe_hwnd(200)], _ALLOWED, max_nodes=1)
    assert tree["count"] == 1
    assert len(tree["nodes"]) == 1
    assert tree["truncated"] is True


# --------------------------------------------------------------------------
# resolve_hwnd
# --------------------------------------------------------------------------


def test_resolve_by_hwnd_describes_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, {100: _win(title="Direct")})
    assert resolve_hwnd(_ALLOWED, hwnd=100)["title"] == "Direct"


def test_resolve_requires_a_selector(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    monkeypatch.setattr(core_windows, "list_windows_for_pids", lambda pids: [])
    with pytest.raises(UiPidBoundaryError, match="at least one of"):
        resolve_hwnd(_ALLOWED)


def test_resolve_child_requires_a_selector(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, {100: _win(children=())})
    with pytest.raises(UiPidBoundaryError, match="child resolve requires"):
        resolve_hwnd(_ALLOWED, parent_hwnd=100)


def test_resolve_filters_children_on_each_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(
        monkeypatch,
        {
            100: _win(children=(101, 102, 103)),
            101: _win(class_name="Button", title="OK", control_id=1),
            102: _win(class_name="Edit", title="Name box", control_id=2),
            103: _win(class_name="Button", title="Cancel", control_id=3),
        },
    )
    assert resolve_hwnd(_ALLOWED, parent_hwnd=100, title="OK")["hwnd"] == 101
    assert resolve_hwnd(_ALLOWED, parent_hwnd=100, class_name="Edit")["hwnd"] == 102
    assert resolve_hwnd(_ALLOWED, parent_hwnd=100, title_contains="ancel")["hwnd"] == 103
    assert resolve_hwnd(_ALLOWED, parent_hwnd=100, control_id=2)["hwnd"] == 102


def test_resolve_reports_no_match(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, {100: _win(children=())})
    with pytest.raises(UiPidBoundaryError) as info:
        resolve_hwnd(_ALLOWED, parent_hwnd=100, title="missing")
    assert info.value.code == "not_found"


def test_resolve_reports_ambiguity(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(
        monkeypatch,
        {
            100: _win(children=(101, 102)),
            101: _win(class_name="Button"),
            102: _win(class_name="Button"),
        },
    )
    with pytest.raises(UiPidBoundaryError) as info:
        resolve_hwnd(_ALLOWED, parent_hwnd=100, class_name="Button")
    assert info.value.code == "ambiguous"
    assert info.value.details["count"] == 2


def test_resolve_scans_top_level_windows_without_a_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch)
    monkeypatch.setattr(
        core_windows,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 300, "class_name": "App", "title": "Target", "control_id": 0}],
    )
    assert resolve_hwnd(_ALLOWED, title_contains="Targ")["hwnd"] == 300


# --------------------------------------------------------------------------
# messaging primitives and actions
# --------------------------------------------------------------------------


def test_send_timeout_maps_a_hung_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, send_ok=False)
    with pytest.raises(UiPidBoundaryError) as info:
        set_window_text(100, "hi", _ALLOWED)
    assert info.value.code == "timeout"


def test_post_message_maps_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, post_ok=False)
    with pytest.raises(UiPidBoundaryError) as info:
        click_hwnd(100, _ALLOWED)
    assert info.value.code == "backend_error"


def test_click_posts_bm_click(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _env(monkeypatch)
    result = click_hwnd(100, _ALLOWED)
    assert result["backend"] == "win32_postmessage"
    assert user32.posted == [(100, w32.BM_CLICK, 0, 0)]


def test_click_at_validates_coordinates(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    for x, y in ((-1, 5), (5, -1), (70000, 5), (1.5, 5)):
        with pytest.raises(UiPidBoundaryError, match="client coordinates"):
            click_hwnd_at(100, _ALLOWED, x=x, y=y)  # type: ignore[arg-type]


def test_click_at_posts_the_mouse_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _env(monkeypatch)
    result = click_hwnd_at(100, _ALLOWED, x=3, y=4)
    assert result["action"] == "click_at"
    messages = [message for (_, message, _, _) in user32.posted]
    assert messages == [w32.WM_MOUSEMOVE, w32.WM_LBUTTONDOWN, w32.WM_LBUTTONUP]


def test_close_rejects_an_unknown_method(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="close method"):
        close_hwnd(100, _ALLOWED, method="detonate")


def test_close_maps_a_rect_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, {100: _win(rect=None)})
    with pytest.raises(UiPidBoundaryError, match="GetWindowRect failed"):
        close_hwnd(100, _ALLOWED)


def test_close_nc_close_reveals_a_cloaked_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _env(monkeypatch, {100: _win(rect=(20000, 5, 20100, 55))})
    result = close_hwnd(100, _ALLOWED)
    assert result["shown_noactivate"] is True
    assert result["backend"] == "win32_nc_close_sendmessage"
    assert user32.shown == [(100, 4)]
    posted = [message for (_, message, _, _) in user32.posted]
    assert posted == [w32.WM_NCLBUTTONDOWN, w32.WM_NCLBUTTONUP]
    sent = [message for (_, message, _) in user32.sent]
    assert sent == [w32.WM_SYSCOMMAND, w32.WM_CLOSE]


def test_close_syscommand_sends_sc_close(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _env(monkeypatch)
    result = close_hwnd(100, _ALLOWED, method="syscommand")
    assert result["backend"] == "win32_syscommand_close"
    assert user32.sent == [(100, w32.WM_SYSCOMMAND, w32.SC_CLOSE)]
    assert user32.shown == []


def test_close_wm_close_sends_only_wm_close(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _env(monkeypatch)
    result = close_hwnd(100, _ALLOWED, method="wm_close")
    assert result["backend"] == "win32_wm_close"
    assert user32.sent == [(100, w32.WM_CLOSE, 0)]


def test_set_window_text_validates_and_sends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="must be a string"):
        set_window_text(100, 12, _ALLOWED)  # type: ignore[arg-type]
    with pytest.raises(UiPidBoundaryError, match="exceeds"):
        set_window_text(100, "x" * 4097, _ALLOWED)
    result = set_window_text(100, "hello", _ALLOWED)
    assert result["action"] == "text.set"
    assert user32.sent == [(100, w32.WM_SETTEXT, 0)]


def test_get_window_text_reads_the_title(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, {100: _win(title="Reader")})
    assert get_window_text(100, _ALLOWED) == "Reader"


def test_send_key_requires_exactly_one_of_text_or_vk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="not both"):
        send_key(100, allowed_pids=_ALLOWED, text="a", vk=65)
    with pytest.raises(UiPidBoundaryError, match="provide text or vk"):
        send_key(100, allowed_pids=_ALLOWED)


def test_send_key_types_characters(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _env(monkeypatch)
    result = send_key(100, allowed_pids=_ALLOWED, text="ab")
    assert result["backend"] == "win32_wm_char"
    assert user32.sent == [
        (100, w32.WM_CHAR, ord("a")),
        (100, w32.WM_CHAR, ord("b")),
    ]


def test_send_key_rejects_bad_text_and_vk(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="at most 32"):
        send_key(100, allowed_pids=_ALLOWED, text="")
    with pytest.raises(UiPidBoundaryError, match="1..254"):
        send_key(100, allowed_pids=_ALLOWED, vk=0)


def test_send_key_presses_a_virtual_key(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _env(monkeypatch)
    result = send_key(100, allowed_pids=_ALLOWED, vk=13)
    assert result["backend"] == "win32_wm_key"
    assert user32.sent == [(100, w32.WM_KEYDOWN, 13), (100, w32.WM_KEYUP, 13)]


# --------------------------------------------------------------------------
# invoke_hwnd
# --------------------------------------------------------------------------


def test_invoke_rejects_non_whitelisted_actions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="whitelist"):
        invoke_hwnd(100, _ALLOWED, action="sendmessage")


def test_invoke_close_delegates_to_close(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    assert invoke_hwnd(100, _ALLOWED, action="wm_close")["backend"] == "win32_wm_close"
    assert invoke_hwnd(100, _ALLOWED, action="close")["backend"] == "win32_nc_close_sendmessage"


def test_invoke_click_delegates_to_click(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    assert invoke_hwnd(100, _ALLOWED)["backend"] == "win32_postmessage"


def test_invoke_set_text_requires_text(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    with pytest.raises(UiPidBoundaryError, match="requires text"):
        invoke_hwnd(100, _ALLOWED, action="set_text")
    result = invoke_hwnd(100, _ALLOWED, action="set_text", text="typed")
    assert result["action"] == "text.set"


def test_invoke_command_notifies_the_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    user32 = _env(
        monkeypatch,
        {
            100: _win(parent=90, control_id=17),
            90: _win(),
        },
    )
    result = invoke_hwnd(100, _ALLOWED, action="command")
    assert result["parent_hwnd"] == 90
    assert result["control_id"] == 17
    assert user32.sent == [(90, w32.WM_COMMAND, (w32.BN_CLICKED << 16) | 17)]


def test_invoke_command_without_a_parent_targets_the_hwnd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _env(monkeypatch, {100: _win(parent=0)})
    result = invoke_hwnd(100, _ALLOWED, action="wm_command", control_id=3)
    assert result["parent_hwnd"] == 100
    assert user32.sent[0][0] == 100


# --------------------------------------------------------------------------
# capture helpers
# --------------------------------------------------------------------------


def test_prefer_capture_uniformity_ranks_alternatives() -> None:
    degraded = {"degraded": True, "dark_ratio": 1.0}
    clean = {"degraded": False, "dark_ratio": 0.1}
    assert _prefer_capture_uniformity(degraded, clean) is True
    assert _prefer_capture_uniformity(clean, degraded) is False
    assert (
        _prefer_capture_uniformity(
            {"degraded": True, "dark_ratio": 0.9}, {"degraded": True, "dark_ratio": 0.5}
        )
        is True
    )


def test_window_capture_size_reads_both_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch, {100: _win(rect=(0, 0, 100, 50), client=(0, 0, 90, 40))})
    assert _window_capture_size(100, client_only=False) == (100, 50)
    assert _window_capture_size(100, client_only=True) == (90, 40)


def test_window_capture_size_maps_rect_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch, {100: _win(rect=None, client=None)})
    with pytest.raises(UiPidBoundaryError, match="GetWindowRect failed"):
        _window_capture_size(100, client_only=False)
    with pytest.raises(UiPidBoundaryError, match="GetClientRect failed"):
        _window_capture_size(100, client_only=True)


def test_window_capture_size_bounds_the_area(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch, {100: _win(rect=(0, 0, 0, 0))})
    with pytest.raises(UiPidBoundaryError, match="empty capture area"):
        _window_capture_size(100, client_only=False)
    _env(monkeypatch, {100: _win(rect=(0, 0, 9000, 10))})
    with pytest.raises(UiPidBoundaryError, match="max edge"):
        _window_capture_size(100, client_only=False)
    _env(monkeypatch, {100: _win(rect=(0, 0, 5000, 5000))})
    with pytest.raises(UiPidBoundaryError, match="max pixels"):
        _window_capture_size(100, client_only=False)


def test_write_bmp_rejects_a_size_mismatch(tmp_path: Path) -> None:
    with pytest.raises(UiPidBoundaryError, match="size mismatch"):
        _write_bmp_bgr(tmp_path / "x.bmp", 2, 2, b"\x00" * 3)


def test_write_bmp_produces_a_readable_file(tmp_path: Path) -> None:
    stride = ((2 * 3 + 3) // 4) * 4
    out = tmp_path / "shot.bmp"
    size = _write_bmp_bgr(out, 2, 2, b"\x10" * (stride * 2))
    data = out.read_bytes()
    assert data[:2] == b"BM"
    assert len(data) == size == 54 + stride * 2


def test_uniformity_flags_an_empty_capture() -> None:
    verdict = _estimate_capture_uniformity(b"", 0, 0, 0)
    assert verdict["degraded"] is True
    assert verdict["degraded_reason"] == "empty_capture"


def test_uniformity_flags_an_unreadable_buffer() -> None:
    verdict = _estimate_capture_uniformity(b"\x00", 100, 100, 400)
    assert verdict["sampled_pixels"] == 0
    assert verdict["degraded_reason"] == "empty_capture"


def _pixels(width: int, height: int, colors: list[tuple[int, int, int]]) -> bytes:
    stride = ((width * 3 + 3) // 4) * 4
    rows = bytearray(stride * height)
    for index in range(width * height):
        row, col = divmod(index, width)
        offset = row * stride + col * 3
        rows[offset : offset + 3] = bytes(colors[index % len(colors)])
    return bytes(rows)


def test_uniformity_passes_a_varied_capture() -> None:
    pixels = _pixels(4, 4, [(200, 10, 10), (10, 200, 10), (10, 10, 200)])
    verdict = _estimate_capture_uniformity(pixels, 4, 4, 12)
    assert verdict["degraded"] is False
    assert verdict["degraded_reason"] is None


def test_uniformity_flags_blank_and_uniform_and_mostly_black() -> None:
    blank = _estimate_capture_uniformity(_pixels(4, 4, [(0, 0, 0)]), 4, 4, 12)
    assert blank["degraded_reason"] == "blank_capture"
    uniform = _estimate_capture_uniformity(_pixels(4, 4, [(200, 200, 200)]), 4, 4, 12)
    assert uniform["degraded_reason"] == "uniform_capture"
    mostly = _estimate_capture_uniformity(
        _pixels(20, 20, [(250, 250, 250)] + [(0, 0, 0)] * 399), 20, 20, 60
    )
    assert mostly["degraded_reason"] == "mostly_black_capture"


# --------------------------------------------------------------------------
# capture_hwnd_screenshot
# --------------------------------------------------------------------------


class _CaptureDlls:
    """user32/gdi32 WinDLL stand-ins with plain-function attributes."""

    def __init__(
        self,
        *,
        window_dc: int = 111,
        mem_dc: int = 222,
        bitmap: int = 333,
        print_ok: bool = True,
        blit_results: list[bool] | None = None,
        frames: list[bytes] | None = None,
        dib_ok: bool = True,
    ) -> None:
        self.released: list[int] = []
        blits = list(blit_results or [])
        pending = list(frames or [])

        def release_dc(hwnd: Any, dc: Any) -> int:
            self.released.append(_hv(dc))
            return 1

        self.user32 = SimpleNamespace(
            GetWindowDC=lambda hwnd: window_dc,
            GetDC=lambda hwnd: window_dc,
            ReleaseDC=release_dc,
            PrintWindow=lambda hwnd, dc, flags: print_ok,
        )

        def get_dibits(
            dc: Any, bmp: Any, start: int, height: Any, buf: Any, bmi: Any, flag: int
        ) -> int:
            if not dib_ok:
                return 0
            frame = pending.pop(0)
            ctypes.memmove(buf._obj, frame, len(frame))
            return _hv(height)

        self.gdi32 = SimpleNamespace(
            CreateCompatibleDC=lambda dc: mem_dc,
            CreateCompatibleBitmap=lambda dc, w, h: bitmap,
            SelectObject=lambda dc, obj: 444,
            BitBlt=lambda *args: blits.pop(0) if blits else True,
            DeleteDC=lambda dc: True,
            DeleteObject=lambda obj: True,
            GetDIBits=get_dibits,
        )

    def windll_for(self, name: str, use_last_error: bool = False) -> Any:
        return self.user32 if name == "user32" else self.gdi32


def _capture_env(
    monkeypatch: pytest.MonkeyPatch, dlls: _CaptureDlls, *, rect: tuple[int, int, int, int]
) -> _FakeUser32:
    user32 = _env(monkeypatch, {100: _win(rect=rect, client=rect)})
    monkeypatch.setattr(ctypes, "WinDLL", dlls.windll_for, raising=False)
    return user32


_VARIED = _pixels(2, 2, [(200, 10, 10), (10, 200, 10)])
_BLANK = _pixels(2, 2, [(0, 0, 0)])


def test_capture_requires_a_bmp_suffix(tmp_path: Path) -> None:
    with pytest.raises(UiPidBoundaryError, match=".bmp"):
        capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.png")


def test_capture_via_printwindow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dlls = _CaptureDlls(frames=[_VARIED])
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    result = capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")
    assert result["backend"] == "win32_printwindow"
    assert result["degraded"] is False
    assert result["artifact"] == str(tmp_path / "shot.bmp")
    assert (tmp_path / "shot.bmp").is_file()
    assert dlls.released == [111]


def test_capture_client_only_uses_getdc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # rect=None also exercises the reveal helper's GetWindowRect-failure branch.
    dlls = _CaptureDlls(frames=[_VARIED])
    _env(monkeypatch, {100: _win(rect=None, client=(0, 0, 2, 2))})
    monkeypatch.setattr(ctypes, "WinDLL", dlls.windll_for, raising=False)
    result = capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp", client_only=True)
    assert result["client_only"] is True


def test_capture_reveals_an_iconic_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dlls = _CaptureDlls(frames=[_VARIED])
    user32 = _env(monkeypatch, {100: _win(rect=(0, 0, 2, 2), client=(0, 0, 2, 2), iconic=True)})
    monkeypatch.setattr(ctypes, "WinDLL", dlls.windll_for, raising=False)
    capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")
    assert user32.shown == [(100, w32._SW_SHOWNOACTIVATE)]


def test_capture_fails_without_a_window_dc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dlls = _CaptureDlls(window_dc=0)
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    with pytest.raises(UiPidBoundaryError, match="window DC"):
        capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")


@pytest.mark.parametrize(("mem_dc", "bitmap"), [(0, 333), (222, 0)])
def test_capture_fails_when_allocation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mem_dc: int, bitmap: int
) -> None:
    dlls = _CaptureDlls(mem_dc=mem_dc, bitmap=bitmap)
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    with pytest.raises(UiPidBoundaryError, match="capture bitmap"):
        capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")


def test_capture_falls_back_to_bitblt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dlls = _CaptureDlls(print_ok=False, blit_results=[True], frames=[_VARIED])
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    result = capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")
    assert result["backend"] == "win32_bitblt"


def test_capture_fails_when_both_strategies_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dlls = _CaptureDlls(print_ok=False, blit_results=[False])
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    with pytest.raises(UiPidBoundaryError, match="both failed"):
        capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")


def test_capture_retries_a_blank_printwindow_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dlls = _CaptureDlls(blit_results=[True], frames=[_BLANK, _VARIED])
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    result = capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")
    assert result["backend"] == "win32_bitblt"
    assert result["degraded"] is False


def test_capture_keeps_the_original_when_the_retry_is_no_better(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dlls = _CaptureDlls(blit_results=[True], frames=[_BLANK, _BLANK])
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    result = capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")
    assert result["backend"] == "win32_printwindow"
    assert result["degraded"] is True


def test_capture_keeps_the_original_when_the_retry_blit_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dlls = _CaptureDlls(blit_results=[False], frames=[_BLANK])
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    result = capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")
    assert result["backend"] == "win32_printwindow"
    assert result["degraded_reason"] == "blank_capture"


def test_capture_maps_a_getdibits_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dlls = _CaptureDlls(dib_ok=False)
    _capture_env(monkeypatch, dlls, rect=(0, 0, 2, 2))
    with pytest.raises(UiPidBoundaryError, match="GetDIBits failed"):
        capture_hwnd_screenshot(100, _ALLOWED, tmp_path / "shot.bmp")


# --------------------------------------------------------------------------
# wait_for_window
# --------------------------------------------------------------------------


def _clock(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> None:
    ticks = iter(values)
    last = [values[-1]]

    def monotonic() -> float:
        try:
            last[0] = next(ticks)
        except StopIteration:
            return last[0]
        return last[0]

    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(time, "sleep", lambda seconds: None)


@pytest.mark.parametrize("timeout", [True, "ten", 0, 31.0])
def test_wait_rejects_bad_timeouts(monkeypatch: pytest.MonkeyPatch, timeout: Any) -> None:
    with pytest.raises(UiPidBoundaryError, match="timeout must be"):
        wait_for_window(_ALLOWED, timeout=timeout)


def test_wait_returns_the_first_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(w32, "resolve_hwnd", lambda allowed, **kw: {"hwnd": 100, "title": "Found"})
    _clock(monkeypatch, [0.0, 0.0, 0.1])
    result = wait_for_window(_ALLOWED, title="Found")
    assert result["matched"] is True
    assert result["window"]["hwnd"] == 100


def test_wait_retries_after_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = iter(
        [
            UiPidBoundaryError("not_found", "nothing yet"),
            {"hwnd": 100, "title": "Late"},
        ]
    )

    def resolver(allowed: Any, **kw: Any) -> Any:
        outcome = next(attempts)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(w32, "resolve_hwnd", resolver)
    _clock(monkeypatch, [0.0, 0.0, 0.5, 0.6])
    result = wait_for_window(_ALLOWED, title="Late")
    assert result["matched"] is True


def test_wait_reraises_non_retryable_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolver(allowed: Any, **kw: Any) -> Any:
        raise UiPidBoundaryError("invalid_params", "bad selector")

    monkeypatch.setattr(w32, "resolve_hwnd", resolver)
    _clock(monkeypatch, [0.0, 0.0])
    with pytest.raises(UiPidBoundaryError, match="bad selector"):
        wait_for_window(_ALLOWED, title="x")


def test_wait_times_out_with_the_last_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolver(allowed: Any, **kw: Any) -> Any:
        raise UiPidBoundaryError("ambiguous", "two matched")

    monkeypatch.setattr(w32, "resolve_hwnd", resolver)
    _clock(monkeypatch, [0.0, 0.0, 20.0])
    with pytest.raises(UiPidBoundaryError) as info:
        wait_for_window(_ALLOWED, title="x", timeout=10.0)
    assert info.value.code == "timeout"
    assert info.value.details["last_error"] == "two matched"
