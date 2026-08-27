"""Deterministic coverage for ``core.windows`` on non-Windows hosts.

The module guards the M10.1 UI PID boundary and wraps Win32 window
enumeration plus the native open-file dialog. Everything Windows-only is
exercised here through proxies: ``os.name`` is pinned to ``"nt"`` and
``ctypes.windll`` is replaced with cooperative fakes, while real ctypes
buffers and callback types keep the pointer plumbing honest.
"""

from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.windows as wm
from headless_re_mcp.core.windows import (
    UiPidBoundaryError,
    blocked_ui_pids,
    describe_process_windows,
    is_pid_alive,
    list_input_desktop_windows,
    list_process_windows,
    list_windows_for_pids,
    pick_open_file,
    pick_open_file_status,
    resolve_allowed_ui_pids,
    snapshot_input_desktop,
    window_capture_rank,
    window_is_capturable,
    wnd_enum_callback_type,
)


class _OsProxy:
    """``os`` with ``name`` pinned, everything else forwarded."""

    name = "nt"

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


class _CtypesProxy:
    """``ctypes`` with a fake ``windll``, everything else forwarded."""

    def __init__(self, windll: SimpleNamespace) -> None:
        self.windll = windll

    def __getattr__(self, attribute: str) -> Any:
        return getattr(ctypes, attribute)


def _pin_windows(monkeypatch: pytest.MonkeyPatch, windll: SimpleNamespace) -> None:
    monkeypatch.setattr(wm, "os", _OsProxy())
    monkeypatch.setattr(wm, "ctypes", _CtypesProxy(windll))


class _FakeUser32:
    """Answers the Win32 window queries from a table of fake windows."""

    def __init__(self, windows: dict[int, dict[str, Any]]) -> None:
        self.windows = windows

    def EnumWindows(self, callback: Any, lparam: int) -> int:
        for hwnd in sorted(self.windows):
            if not callback(hwnd, lparam):
                break
        return 1

    def GetWindowThreadProcessId(self, hwnd: int, owner_ref: Any) -> int:
        owner_ref._obj.value = int(self.windows[hwnd]["pid"])
        return 1

    def GetWindowTextLengthW(self, hwnd: int) -> int:
        return len(str(self.windows[hwnd].get("title", "")))

    def GetWindowTextW(self, hwnd: int, buffer: Any, size: int) -> int:
        buffer.value = str(self.windows[hwnd].get("title", ""))[: max(0, size - 1)]
        return len(buffer.value)

    def GetClassNameW(self, hwnd: int, buffer: Any, size: int) -> int:
        buffer.value = str(self.windows[hwnd].get("class_name", ""))[: max(0, size - 1)]
        return len(buffer.value)

    def IsWindowVisible(self, hwnd: int) -> int:
        return int(bool(self.windows[hwnd].get("visible", False)))

    def IsWindowEnabled(self, hwnd: int) -> int:
        return int(bool(self.windows[hwnd].get("enabled", True)))

    def IsIconic(self, hwnd: int) -> int:
        return int(bool(self.windows[hwnd].get("minimized", False)))

    def GetWindowRect(self, hwnd: int, rect_ref: Any) -> int:
        rect = rect_ref._obj
        rect.left, rect.top, rect.right, rect.bottom = self.windows[hwnd].get("rect", (0, 0, 0, 0))
        return 1

    def GetForegroundWindow(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# Pure helpers: capture ranking and the PID boundary.
# ---------------------------------------------------------------------------


def test_capturable_needs_positive_unminimized_rectangle() -> None:
    good = {"rect": {"width": 100, "height": 50}, "visible": True}
    assert window_is_capturable(good)
    assert not window_is_capturable({**good, "minimized": True})
    assert not window_is_capturable({"rect": "corrupted"})
    assert not window_is_capturable({"rect": {"width": 0, "height": 50}})
    assert not window_is_capturable({"area": 500, "rect": {"width": 0, "height": 0}})


def test_larger_hidden_window_outranks_visible_empty_one() -> None:
    visible_empty = {"visible": True, "rect": {"width": 0, "height": 0}, "title": "x"}
    hidden_large = {"visible": False, "rect": {"width": 800, "height": 600}, "title": "y"}
    assert window_capture_rank(hidden_large) > window_capture_rank(visible_empty)


def test_enum_callback_type_falls_back_to_cfunctype_off_windows() -> None:
    callback_type = wnd_enum_callback_type()
    wrapped = callback_type(lambda hwnd, lparam: True)
    assert wrapped(1, 0) == 1, "the BOOL restype must survive a round trip"


def test_blocked_pids_skip_non_positive_host_and_debugger() -> None:
    assert blocked_ui_pids(debugger_pid=None, self_pid=0) == set()
    assert blocked_ui_pids(debugger_pid=-5, self_pid=7) == {7}
    assert blocked_ui_pids(debugger_pid=9, self_pid=7) == {7, 9}


def test_debuggee_colliding_with_host_pid_is_refused() -> None:
    with pytest.raises(UiPidBoundaryError) as refused:
        resolve_allowed_ui_pids(debuggee_pid=7, debugger_pid=None, self_pid=7)
    assert refused.value.code == "permission_denied"


@pytest.mark.parametrize("hostile", [True, -1, 0, "12"])
def test_child_pid_entries_must_be_positive_integers(hostile: Any) -> None:
    with pytest.raises(UiPidBoundaryError) as refused:
        resolve_allowed_ui_pids(
            debuggee_pid=100,
            debugger_pid=200,
            allow_child_pids=[hostile],
            self_pid=300,
        )
    assert refused.value.code == "invalid_params"


def test_child_pid_that_is_the_debugger_is_refused() -> None:
    with pytest.raises(UiPidBoundaryError) as refused:
        resolve_allowed_ui_pids(
            debuggee_pid=100,
            debugger_pid=200,
            allow_child_pids=[200],
            self_pid=300,
        )
    assert refused.value.code == "permission_denied"
    assert refused.value.details["child_pid"] == 200


def test_same_image_children_are_admitted_via_process_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import headless_re_mcp.core.process_tree as process_tree

    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid: [101, 102])
    monkeypatch.setattr(
        process_tree,
        "filter_same_image_pids",
        lambda pid, children: [child for child in children if child == 101],
    )

    allowed, blocked = resolve_allowed_ui_pids(
        debuggee_pid=100,
        debugger_pid=200,
        include_same_image_children=True,
        self_pid=300,
    )

    assert allowed == frozenset({100, 101}), "only the same-image child joins the allow-set"
    assert blocked == frozenset({200, 300})


# ---------------------------------------------------------------------------
# Window enumeration through the faked user32.
# ---------------------------------------------------------------------------


_WINDOW_TABLE: dict[int, dict[str, Any]] = {
    2: {
        "pid": 100,
        "title": "Debuggee - main",
        "class_name": "Notepad",
        "visible": True,
        "rect": (10, 10, 810, 610),
    },
    3: {
        "pid": 999,
        "title": "Analyzer console",
        "class_name": "ConsoleWindowClass",
        "visible": True,
        "rect": (0, 0, 100, 100),
    },
    4: {
        "pid": 100,
        "title": "",
        "class_name": "MSCTFIME UI",
        "visible": False,
        "minimized": True,
        # A hostile rectangle: right/bottom before left/top must clamp to 0.
        "rect": (50, 50, 10, 10),
    },
}


def test_process_window_listing_is_pid_bounded_and_sorted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_windows(monkeypatch, SimpleNamespace(user32=_FakeUser32(_WINDOW_TABLE)))

    rows = list_process_windows(100)

    assert [row["hwnd"] for row in rows] == [2, 4]
    assert all(row["pid"] == 100 for row in rows), "windows of other processes must not leak"
    assert rows[0]["title"] == "Debuggee - main"
    assert rows[0]["class_name"] == "Notepad"
    assert rows[0]["visible"] is True and rows[1]["visible"] is False


def test_process_window_listing_refuses_bad_pids_and_posix() -> None:
    assert list_process_windows(100) == [], "no Win32 access on a POSIX host"
    assert list_process_windows(0) == []
    assert list_process_windows("100") == []  # type: ignore[arg-type]


def test_multi_pid_listing_dedupes_and_drops_hostile_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[int] = []

    def record(pid: int) -> list[dict[str, Any]]:
        seen.append(pid)
        return [{"hwnd": pid, "pid": pid}]

    monkeypatch.setattr(wm, "list_process_windows", record)

    rows = list_windows_for_pids([300, 100, 100, True, -7, "9", 200])  # type: ignore[list-item]

    assert seen == [100, 200, 300], "deduped, sorted, bools and non-ints dropped"
    assert [row["pid"] for row in rows] == [100, 200, 300]


def test_desktop_snapshot_rows_are_bounded_ranked_and_clamped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_windows(monkeypatch, SimpleNamespace(user32=_FakeUser32(_WINDOW_TABLE)))

    unbounded = list_input_desktop_windows(allowed_pids=None)
    assert [row["hwnd"] for row in unbounded] == [2, 3, 4], "capturable first, then by area"
    assert unbounded[0]["rect"] == {
        "left": 10,
        "top": 10,
        "right": 810,
        "bottom": 610,
        "width": 800,
        "height": 600,
    }
    assert unbounded[0]["area"] == 800 * 600

    inverted = next(row for row in unbounded if row["hwnd"] == 4)
    assert inverted["rect"]["width"] == 0 and inverted["rect"]["height"] == 0, (
        "an inverted rectangle must clamp instead of going negative"
    )
    assert inverted["minimized"] is True

    bounded = list_input_desktop_windows(allowed_pids=frozenset({100}))
    assert {row["pid"] for row in bounded} == {100}, "the PID boundary holds during enumeration"


def test_desktop_windows_are_empty_on_posix() -> None:
    assert list_input_desktop_windows(allowed_pids=None) == []


def test_desktop_snapshot_reports_both_bounded_and_total_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wm, "os", _OsProxy())
    all_rows = [{"pid": 100, "hwnd": 2}, {"pid": 999, "hwnd": 3}]
    monkeypatch.setattr(wm, "list_input_desktop_windows", lambda *, allowed_pids: list(all_rows))

    snapshot = snapshot_input_desktop(allowed_pids=frozenset({100}))

    assert snapshot["available"] is True and snapshot["input_desktop"] is True
    assert snapshot["window_count"] == 1, "only the allowed PID's window is returned"
    assert snapshot["desktop_window_count"] == 2, "the total is still disclosed"
    assert snapshot["windows"] == [{"pid": 100, "hwnd": 2}]


def test_legacy_window_strings_carry_hwnd_class_and_title(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        wm,
        "list_process_windows",
        lambda pid: [{"hwnd": 255, "class_name": "Notepad", "title": "hello"}],
    )
    assert describe_process_windows(100) == {"0xff:Notepad:hello"}


# ---------------------------------------------------------------------------
# is_pid_alive on both hosts.
# ---------------------------------------------------------------------------


class _FakeKernel32:
    def __init__(self, *, handle: int, exit_query_ok: int, exit_code: int) -> None:
        self.handle = handle
        self.exit_query_ok = exit_query_ok
        self.exit_code = exit_code
        self.closed: list[int] = []

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
        return self.handle

    def GetExitCodeProcess(self, handle: int, code_ref: Any) -> int:
        code_ref._obj.value = self.exit_code
        return self.exit_query_ok

    def CloseHandle(self, handle: int) -> int:
        self.closed.append(handle)
        return 1


def test_pid_liveness_on_posix_uses_signal_zero() -> None:
    assert is_pid_alive(os.getpid()) is True
    finished = subprocess.Popen([sys.executable, "-c", ""])
    finished.wait(timeout=30)
    assert is_pid_alive(finished.pid) is False, "a reaped child is not alive"
    assert is_pid_alive(0) is False
    assert is_pid_alive(True) is False, "bools are not PIDs even though they are ints"


@pytest.mark.parametrize(
    ("handle", "exit_query_ok", "exit_code", "alive"),
    [
        (0, 1, 259, False),  # OpenProcess refused: treat as gone
        (5, 0, 259, False),  # exit-code query failed: fail closed
        (5, 1, 259, True),  # STILL_ACTIVE
        (5, 1, 0, False),  # exited cleanly
    ],
)
def test_pid_liveness_on_windows_reads_still_active(
    monkeypatch: pytest.MonkeyPatch,
    handle: int,
    exit_query_ok: int,
    exit_code: int,
    alive: bool,
) -> None:
    kernel32 = _FakeKernel32(handle=handle, exit_query_ok=exit_query_ok, exit_code=exit_code)
    _pin_windows(monkeypatch, SimpleNamespace(kernel32=kernel32))

    assert is_pid_alive(4242) is alive
    if handle:
        assert kernel32.closed == [handle], "the process handle must not leak"


# ---------------------------------------------------------------------------
# The native open-file dialog: envelopes for every outcome.
# ---------------------------------------------------------------------------


def test_dialog_is_unavailable_off_windows() -> None:
    status = pick_open_file_status()
    assert status == {
        "path": None,
        "cancelled": False,
        "available": False,
        "busy": False,
        "error": None,
    }
    assert pick_open_file() is None


def test_concurrent_pick_reports_busy_not_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wm, "os", _OsProxy())
    assert wm._PICK_LOCK.acquire(blocking=False)
    try:
        status = pick_open_file_status()
    finally:
        wm._PICK_LOCK.release()
    assert status["busy"] is True
    assert status["cancelled"] is False, "lock contention must not look like a cancel"
    assert status["path"] is None


def test_a_dialog_thread_that_never_starts_is_an_error_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wm, "os", _OsProxy())
    monkeypatch.setattr(wm, "_STA_THREAD", None)
    monkeypatch.setattr(wm, "_sta_dialog_loop", lambda: None)
    monkeypatch.setattr(
        wm,
        "_STA_READY",
        SimpleNamespace(clear=lambda: None, wait=lambda timeout: False, set=lambda: None),
    )

    status = pick_open_file_status()

    assert status["error"] == "file dialog thread failed to start"
    assert status["path"] is None and status["cancelled"] is False
    assert not wm._PICK_LOCK.locked(), "the pick lock must be released on failure"


def _live_dummy_thread() -> threading.Thread:
    thread = threading.Thread(target=threading.Event().wait, daemon=True)
    thread.start()
    return thread


def test_a_wedged_dialog_thread_times_out_instead_of_hanging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wm, "os", _OsProxy())
    monkeypatch.setattr(wm, "_STA_THREAD", _live_dummy_thread())
    # A private job queue: nothing may leak into the real dialog thread later.
    monkeypatch.setattr(wm, "_STA_JOBS", queue.Queue())

    class _EmptyReply:
        def get(self, timeout: float) -> Any:
            raise queue.Empty

        def put(self, item: Any) -> None:
            return None

    monkeypatch.setattr(
        wm,
        "queue",
        SimpleNamespace(Queue=_EmptyReply, Empty=queue.Empty),
    )

    status = pick_open_file_status()

    assert status["error"] == "dialog_timeout"
    assert status["path"] is None


def test_a_reply_that_is_not_a_dict_is_named_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wm, "os", _OsProxy())
    monkeypatch.setattr(wm, "_STA_THREAD", _live_dummy_thread())
    monkeypatch.setattr(wm, "_STA_JOBS", queue.Queue())

    class _GarbageReply:
        def get(self, timeout: float) -> Any:
            return "garbage"

        def put(self, item: Any) -> None:
            return None

    monkeypatch.setattr(
        wm,
        "queue",
        SimpleNamespace(Queue=_GarbageReply, Empty=queue.Empty),
    )

    status = pick_open_file_status()

    assert status["error"] == "dialog_invalid_result"


def _ole32() -> SimpleNamespace:
    return SimpleNamespace(ole32=SimpleNamespace(CoInitializeEx=lambda apartment, mode: 0))


def test_the_sta_loop_delivers_the_dialog_result(monkeypatch: pytest.MonkeyPatch) -> None:
    picked = {
        "path": "C:\\samples\\a.exe",
        "cancelled": False,
        "available": True,
        "busy": False,
        "error": None,
    }
    _pin_windows(monkeypatch, _ole32())
    monkeypatch.setattr(wm, "_show_open_file_dialog", lambda title: dict(picked))

    status = pick_open_file_status(title="pick a sample")

    assert status == picked
    assert pick_open_file(title="pick a sample") == "C:\\samples\\a.exe"


def test_a_crashing_dialog_becomes_an_error_envelope_not_a_dead_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(title: str | None) -> dict[str, Any]:
        raise ValueError("dialog exploded")

    _pin_windows(monkeypatch, _ole32())
    monkeypatch.setattr(wm, "_show_open_file_dialog", explode)

    status = pick_open_file_status()

    assert status["error"] == "dialog exploded"
    assert status["path"] is None and status["cancelled"] is False

    # The loop survived the crash: the next pick still gets an answer.
    monkeypatch.setattr(wm, "_show_open_file_dialog", lambda title: wm._pick_unavailable())
    assert pick_open_file_status()["available"] is False


# ---------------------------------------------------------------------------
# _show_open_file_dialog itself, against a fake comdlg32.
# ---------------------------------------------------------------------------


def _comdlg(get_open: Any, extended_error: int = 0) -> SimpleNamespace:
    def comm_dlg_extended_error() -> int:
        return extended_error

    return SimpleNamespace(
        user32=_FakeUser32({}),
        comdlg32=SimpleNamespace(
            GetOpenFileNameW=get_open,
            CommDlgExtendedError=comm_dlg_extended_error,
        ),
    )


def test_dialog_success_reads_the_picked_path_from_the_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def write_path_and_accept(ofn_ref: Any) -> int:
        ofn = ofn_ref._obj
        buffer_address = ctypes.c_void_p.from_address(
            ctypes.addressof(ofn) + type(ofn).lpstrFile.offset
        ).value
        assert buffer_address, "the dialog must hand comdlg32 a real buffer"
        payload = ctypes.create_unicode_buffer("C:\\picked\\sample.exe")
        ctypes.memmove(buffer_address, payload, ctypes.sizeof(payload))
        return 1

    _pin_windows(monkeypatch, _comdlg(write_path_and_accept))

    result = wm._show_open_file_dialog("choose")

    assert result["path"] == "C:\\picked\\sample.exe"
    assert result["cancelled"] is False and result["error"] is None


def test_dialog_accept_with_an_empty_buffer_counts_as_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_windows(monkeypatch, _comdlg(lambda ofn_ref: 1))

    result = wm._show_open_file_dialog(None)

    assert result["cancelled"] is True and result["path"] is None


def test_dialog_dismissal_without_extended_error_is_a_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_windows(monkeypatch, _comdlg(lambda ofn_ref: 0, extended_error=0))

    result = wm._show_open_file_dialog(None)

    assert result["cancelled"] is True and result["error"] is None


def test_dialog_failure_names_the_commdlg_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_windows(monkeypatch, _comdlg(lambda ofn_ref: 0, extended_error=0x3002))

    result = wm._show_open_file_dialog(None)

    assert result["cancelled"] is False
    assert result["error"] == f"commdlg_{0x3002}"
