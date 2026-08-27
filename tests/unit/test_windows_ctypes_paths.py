"""Coverage for the Win32 window/PID/file-dialog helpers on a non-Windows host.

``ctypes.windll`` only exists on Windows, so every enumeration and dialog test
below fakes ``os.name`` as ``"nt"`` and installs a fake ``ctypes.windll`` whose
methods drive the real callbacks. The pure-Python boundary logic and sort keys
are exercised directly.
"""

from __future__ import annotations

import ctypes
import os
import queue
import threading
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.windows as win
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
)

# --------------------------------------------------------------------------
# pure logic
# --------------------------------------------------------------------------


def test_window_is_capturable_needs_positive_area() -> None:
    assert window_is_capturable({"rect": {"width": 10, "height": 5}}) is True
    assert window_is_capturable({"rect": {"width": 0, "height": 5}}) is False
    assert window_is_capturable({"area": 20, "minimized": True}) is False
    assert window_is_capturable({"rect": "bogus"}) is False


def test_window_capture_rank_orders_by_capturability_then_area() -> None:
    small = {"rect": {"width": 2, "height": 2}, "visible": True, "title": "a"}
    big = {"rect": {"width": 20, "height": 20}, "visible": True, "title": "b"}
    assert window_capture_rank(big) > window_capture_rank(small)
    hidden_zero = {"rect": {"width": 0, "height": 0}, "visible": True}
    assert window_capture_rank(small) > window_capture_rank(hidden_zero)


def test_blocked_ui_pids_skips_nonpositive_hosts() -> None:
    assert blocked_ui_pids(debugger_pid=None, self_pid=0) == set()
    assert blocked_ui_pids(debugger_pid=0, self_pid=0) == set()
    assert blocked_ui_pids(debugger_pid=900, self_pid=100) == {900, 100}


def test_resolve_allowed_rejects_debuggee_colliding_with_a_blocked_pid() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        resolve_allowed_ui_pids(debuggee_pid=900, debugger_pid=900, self_pid=100)
    assert info.value.code == "permission_denied"


def test_resolve_allowed_rejects_a_non_positive_child() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        resolve_allowed_ui_pids(
            debuggee_pid=7100,
            debugger_pid=7000,
            allow_child_pids=[0],
            self_pid=42,
        )
    assert info.value.code == "invalid_params"


# --------------------------------------------------------------------------
# faked Win32 enumeration
# --------------------------------------------------------------------------


class _FakeUser32:
    """A user32 whose EnumWindows drives the real ctypes callback."""

    def __init__(self, pid_for_hwnd: dict[int, int]) -> None:
        self._pid_for_hwnd = pid_for_hwnd

    def GetWindowThreadProcessId(self, hwnd: int, lp: Any) -> int:
        lp._obj.value = self._pid_for_hwnd.get(int(hwnd), 0)
        return 1

    def GetWindowTextLengthW(self, hwnd: int) -> int:
        return 32

    def GetWindowTextW(self, hwnd: int, buf: Any, n: int) -> int:
        buf.value = f"Title{int(hwnd)}"
        return 5

    def GetClassNameW(self, hwnd: int, buf: Any, n: int) -> int:
        buf.value = "ClassName"
        return 9

    def IsWindowVisible(self, hwnd: int) -> int:
        return 1

    def IsWindowEnabled(self, hwnd: int) -> int:
        return 1

    def IsIconic(self, hwnd: int) -> int:
        return 0

    def GetWindowRect(self, hwnd: int, rect_ptr: Any) -> int:
        rect = rect_ptr._obj
        rect.left, rect.top, rect.right, rect.bottom = 0, 0, 100, 50
        return 1

    def GetForegroundWindow(self) -> int:
        return 0

    def EnumWindows(self, cb: Any, lparam: int) -> int:
        for hwnd in self._pid_for_hwnd:
            cb(hwnd, 0)
        return 1


def _install_windll(monkeypatch: pytest.MonkeyPatch, **modules: Any) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(**modules), raising=False)


def test_list_process_windows_filters_to_the_owner_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32({100: 7, 200: 999})
    _install_windll(monkeypatch, user32=user32)

    rows = list_process_windows(7)

    assert [row["hwnd"] for row in rows] == [100]
    assert rows[0]["pid"] == 7
    assert rows[0]["title"] == "Title100"
    assert rows[0]["class_name"] == "ClassName"


def test_list_process_windows_is_empty_off_windows() -> None:
    assert list_process_windows(7) == []


def test_list_process_windows_rejects_a_bad_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_windll(monkeypatch, user32=_FakeUser32({}))
    assert list_process_windows(0) == []


def test_list_windows_for_pids_dedupes_and_sorts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32({100: 7, 200: 8})
    _install_windll(monkeypatch, user32=user32)

    rows = list_windows_for_pids([8, 7, 7, 0, -1, "x"])  # type: ignore[list-item]

    assert sorted(row["hwnd"] for row in rows) == [100, 200]


def test_list_input_desktop_windows_bounds_by_allowed_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32({100: 7, 200: 999})
    _install_windll(monkeypatch, user32=user32)

    rows = list_input_desktop_windows(allowed_pids=frozenset({7}))

    assert [row["hwnd"] for row in rows] == [100]
    assert rows[0]["rect"]["width"] == 100
    assert rows[0]["area"] == 5000


def test_list_input_desktop_windows_is_empty_off_windows() -> None:
    assert list_input_desktop_windows() == []


def test_snapshot_input_desktop_unavailable_off_windows() -> None:
    snap = snapshot_input_desktop()
    assert snap["available"] is False
    assert snap["mode"] == "unavailable"


def test_snapshot_input_desktop_counts_all_then_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32({100: 7, 200: 999})
    _install_windll(monkeypatch, user32=user32)

    snap = snapshot_input_desktop(allowed_pids=frozenset({7}))

    assert snap["available"] is True
    assert snap["desktop_window_count"] == 2
    assert snap["window_count"] == 1
    assert snap["input_desktop"] is True


def test_snapshot_input_desktop_without_a_pid_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32({100: 7, 200: 999})
    _install_windll(monkeypatch, user32=user32)

    snap = snapshot_input_desktop()

    assert snap["window_count"] == 2
    assert snap["desktop_window_count"] == 2


def test_describe_process_windows_uses_the_legacy_string_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_windll(monkeypatch, user32=_FakeUser32({100: 7}))
    described = describe_process_windows(7)
    assert described == {"0x64:ClassName:Title100"}


# --------------------------------------------------------------------------
# is_pid_alive
# --------------------------------------------------------------------------


def test_is_pid_alive_rejects_a_bad_pid() -> None:
    assert is_pid_alive(0) is False
    assert is_pid_alive(-1) is False


def test_is_pid_alive_on_posix_uses_os_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "kill", lambda pid, sig: None)
    assert is_pid_alive(12345) is True

    def raise_oserror(pid: int, sig: int) -> None:
        raise OSError("no such process")

    monkeypatch.setattr(os, "kill", raise_oserror)
    assert is_pid_alive(12345) is False


class _FakeKernel32:
    def __init__(self, *, handle: int, exit_code: int, get_exit_ok: int = 1) -> None:
        self._handle = handle
        self._exit_code = exit_code
        self._get_exit_ok = get_exit_ok
        self.closed: list[int] = []

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
        return self._handle

    def GetExitCodeProcess(self, handle: int, out: Any) -> int:
        out._obj.value = self._exit_code
        return self._get_exit_ok

    def CloseHandle(self, handle: int) -> int:
        self.closed.append(handle)
        return 1


def test_is_pid_alive_windows_no_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_windll(monkeypatch, kernel32=_FakeKernel32(handle=0, exit_code=259))
    assert is_pid_alive(4242) is False


def test_is_pid_alive_windows_still_active(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = _FakeKernel32(handle=55, exit_code=259)
    _install_windll(monkeypatch, kernel32=kernel32)
    assert is_pid_alive(4242) is True
    assert kernel32.closed == [55]


def test_is_pid_alive_windows_exited(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_windll(monkeypatch, kernel32=_FakeKernel32(handle=55, exit_code=0))
    assert is_pid_alive(4242) is False


def test_is_pid_alive_windows_query_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_windll(monkeypatch, kernel32=_FakeKernel32(handle=55, exit_code=259, get_exit_ok=0))
    assert is_pid_alive(4242) is False


# --------------------------------------------------------------------------
# _show_open_file_dialog
# --------------------------------------------------------------------------


def _install_dialog(
    monkeypatch: pytest.MonkeyPatch,
    *,
    get_open_ok: bool,
    comm_err: int = 0,
    write_path: str | None = None,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    created: list[tuple[Any, Any]] = []
    orig_buffer = ctypes.create_unicode_buffer

    def record_buffer(arg: Any, *rest: Any) -> Any:
        buf = orig_buffer(arg, *rest)
        created.append((arg, buf))
        return buf

    monkeypatch.setattr(ctypes, "create_unicode_buffer", record_buffer)

    def get_open(ptr: Any) -> int:
        if write_path is not None:
            for arg, buf in created:
                if isinstance(arg, int) and arg == 32768:
                    buf.value = write_path
        return 1 if get_open_ok else 0

    def comm_error() -> int:
        return comm_err

    monkeypatch.setattr(
        ctypes,
        "windll",
        SimpleNamespace(
            user32=SimpleNamespace(GetForegroundWindow=lambda: 0),
            comdlg32=SimpleNamespace(GetOpenFileNameW=get_open, CommDlgExtendedError=comm_error),
            ole32=SimpleNamespace(CoInitializeEx=lambda a, b: 0),
        ),
        raising=False,
    )


def test_show_open_file_dialog_returns_a_selected_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_dialog(monkeypatch, get_open_ok=True, write_path="C:/samples/a.exe")
    result = win._show_open_file_dialog("Pick")
    assert result["path"] == "C:/samples/a.exe"
    assert result["cancelled"] is False
    assert result["available"] is True


def test_show_open_file_dialog_treats_empty_selection_as_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_dialog(monkeypatch, get_open_ok=True, write_path="")
    result = win._show_open_file_dialog(None)
    assert result["path"] is None
    assert result["cancelled"] is True


def test_show_open_file_dialog_reports_a_plain_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_dialog(monkeypatch, get_open_ok=False, comm_err=0)
    result = win._show_open_file_dialog(None)
    assert result["cancelled"] is True
    assert result["error"] is None


def test_show_open_file_dialog_reports_a_commdlg_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_dialog(monkeypatch, get_open_ok=False, comm_err=5)
    result = win._show_open_file_dialog(None)
    assert result["cancelled"] is False
    assert result["error"] == "commdlg_5"


# --------------------------------------------------------------------------
# STA dialog thread lifecycle
# --------------------------------------------------------------------------


def test_sta_dialog_loop_serves_jobs_and_survives_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ctypes,
        "windll",
        SimpleNamespace(ole32=SimpleNamespace(CoInitializeEx=lambda a, b: 0)),
        raising=False,
    )
    monkeypatch.setattr(win, "_STA_THREAD", None)

    # The loop only rescues OSError/ValueError/TypeError/AttributeError, so the
    # failure case must raise one of those to exercise its handler.
    outcomes: Any = iter([{"path": "C:/x.exe"}, OSError("dialog blew up")])

    def fake_dialog(title: str | None) -> dict[str, Any]:
        value = next(outcomes)
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, dict)
        return value

    monkeypatch.setattr(win, "_show_open_file_dialog", fake_dialog)

    win._ensure_sta_dialog_thread()
    win._ensure_sta_dialog_thread()  # second call sees a live thread and returns

    reply_ok: queue.Queue[dict[str, Any]] = queue.Queue()
    win._STA_JOBS.put(("Pick", reply_ok))
    assert reply_ok.get(timeout=5)["path"] == "C:/x.exe"

    reply_err: queue.Queue[dict[str, Any]] = queue.Queue()
    win._STA_JOBS.put(("Pick", reply_err))
    failed = reply_err.get(timeout=5)
    assert "dialog blew up" in str(failed["error"])


def test_ensure_sta_dialog_thread_raises_when_it_never_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(win, "_STA_THREAD", None)

    class _DeadThread:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def start(self) -> None:
            return None

        def is_alive(self) -> bool:
            return False

    class _NeverReady:
        def clear(self) -> None:
            return None

        def wait(self, timeout: float) -> bool:
            return False

    monkeypatch.setattr(threading, "Thread", _DeadThread)
    monkeypatch.setattr(win, "_STA_READY", _NeverReady())

    with pytest.raises(RuntimeError, match="failed to start"):
        win._ensure_sta_dialog_thread()


# --------------------------------------------------------------------------
# pick_open_file_status / pick_open_file
# --------------------------------------------------------------------------


class _ReplyQueue:
    """Stand-in reply queue whose get() yields a scripted outcome."""

    def __init__(self, outcome: Any) -> None:
        self._outcome = outcome

    def put(self, item: Any) -> None:
        return None

    def get(self, timeout: float | None = None) -> Any:
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return self._outcome


def _stub_status_backend(monkeypatch: pytest.MonkeyPatch, outcome: Any) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(win, "_ensure_sta_dialog_thread", lambda: None)
    monkeypatch.setattr(win, "_STA_JOBS", queue.Queue())
    monkeypatch.setattr(queue, "Queue", lambda: _ReplyQueue(outcome))


def test_pick_status_is_unavailable_off_windows() -> None:
    status = pick_open_file_status()
    assert status["available"] is False


def test_pick_status_reports_a_busy_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    win._PICK_LOCK.acquire()
    try:
        status = pick_open_file_status()
    finally:
        win._PICK_LOCK.release()
    assert status["busy"] is True


def test_pick_status_returns_the_dialog_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_status_backend(monkeypatch, {"path": "C:/x.exe", "cancelled": False})
    status = pick_open_file_status(title="Pick")
    assert status["path"] == "C:/x.exe"


def test_pick_status_reports_a_dialog_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_status_backend(monkeypatch, queue.Empty())
    status = pick_open_file_status()
    assert status["error"] == "dialog_timeout"


def test_pick_status_rejects_a_non_dict_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_status_backend(monkeypatch, "not a dict")
    status = pick_open_file_status()
    assert status["error"] == "dialog_invalid_result"


def test_pick_status_maps_a_thread_startup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")

    def boom() -> None:
        raise RuntimeError("file dialog thread failed to start")

    monkeypatch.setattr(win, "_ensure_sta_dialog_thread", boom)
    monkeypatch.setattr(win, "_STA_JOBS", queue.Queue())
    status = pick_open_file_status()
    assert "failed to start" in str(status["error"])


def test_pick_open_file_returns_only_a_usable_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(win, "pick_open_file_status", lambda *, title=None: {"path": "C:/x.exe"})
    assert pick_open_file() == "C:/x.exe"

    monkeypatch.setattr(win, "pick_open_file_status", lambda *, title=None: {"path": "   "})
    assert pick_open_file() is None

    monkeypatch.setattr(win, "pick_open_file_status", lambda *, title=None: {"path": None})
    assert pick_open_file() is None
