"""Win32 window/enumeration/file-dialog surface of ``core.windows``.

Everything past the PID-boundary math in ``core.windows`` speaks straight to
``ctypes.windll`` (EnumWindows, OpenProcess/GetExitCodeProcess, and the
GetOpenFileNameW dialog that runs on its own STA thread), so on a hosted Linux
runner the whole enumeration/dialog half of the module was dark. These fakes
stand in for user32/kernel32/comdlg32 -- driving the enumeration callbacks
through a real ``ctypes.byref`` so the pointer writes are exercised, and running
the STA dialog loop inline -- to pin the window rows, the liveness probe, and
the cancelled/busy/timeout/error distinctions the operator UI depends on.
"""

from __future__ import annotations

import ctypes
import os
import queue
import threading
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.windows as winmod
from headless_re_mcp.core.windows import UiPidBoundaryError

# ---------------------------------------------------------------------------
# ctypes.windll fakes


class _FakeUser32:
    """user32 stand-in: enumeration writes owner PID / rect via ``byref._obj``."""

    def __init__(self, windows: list[dict[str, Any]]) -> None:
        self._by_hwnd = {int(w["hwnd"]): w for w in windows}
        self._order = [int(w["hwnd"]) for w in windows]

    def EnumWindows(self, callback: Any, _lparam: int) -> int:
        for hwnd in self._order:
            callback(hwnd, 0)
        return 1

    def GetWindowThreadProcessId(self, hwnd: int, lp: Any) -> int:
        lp._obj.value = int(self._by_hwnd[int(hwnd)]["pid"])
        return 4

    def GetWindowTextLengthW(self, hwnd: int) -> int:
        return len(str(self._by_hwnd[int(hwnd)].get("title", "")))

    def GetWindowTextW(self, hwnd: int, buf: Any, _n: int) -> int:
        buf.value = str(self._by_hwnd[int(hwnd)].get("title", ""))
        return len(buf.value)

    def GetClassNameW(self, hwnd: int, buf: Any, _n: int) -> int:
        buf.value = str(self._by_hwnd[int(hwnd)].get("class_name", ""))
        return len(buf.value)

    def IsWindowVisible(self, hwnd: int) -> int:
        return 1 if self._by_hwnd[int(hwnd)].get("visible") else 0

    def IsWindowEnabled(self, hwnd: int) -> int:
        return 1 if self._by_hwnd[int(hwnd)].get("enabled", True) else 0

    def IsIconic(self, hwnd: int) -> int:
        return 1 if self._by_hwnd[int(hwnd)].get("minimized") else 0

    def GetWindowRect(self, hwnd: int, lp: Any) -> int:
        left, top, right, bottom = self._by_hwnd[int(hwnd)].get("rect", (0, 0, 0, 0))
        rect = lp._obj
        rect.left, rect.top, rect.right, rect.bottom = left, top, right, bottom
        return 1

    def GetForegroundWindow(self) -> int:
        return 0


class _FakeKernel32:
    def __init__(self, *, open_handle: int = 123, exit_ok: int = 1, exit_code: int = 259) -> None:
        self.open_handle = open_handle
        self.exit_ok = exit_ok
        self.exit_code = exit_code
        self.closed: list[int] = []

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return self.open_handle

    def GetExitCodeProcess(self, _handle: int, lp: Any) -> int:
        lp._obj.value = self.exit_code
        return self.exit_ok

    def CloseHandle(self, handle: int) -> int:
        self.closed.append(int(handle))
        return 1


class _FakeCommDlg:
    """A callable tolerant of the argtypes/restype assignment the code performs."""

    def __init__(self, fn: Any) -> None:
        self._fn = fn
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._fn(*args, **kwargs)


def _install_windll(
    monkeypatch: pytest.MonkeyPatch,
    *,
    user32: Any = None,
    kernel32: Any = None,
    ole32: Any = None,
    comdlg32: Any = None,
) -> None:
    namespace = SimpleNamespace(
        user32=user32 if user32 is not None else _FakeUser32([]),
        kernel32=kernel32 if kernel32 is not None else _FakeKernel32(),
        ole32=ole32 if ole32 is not None else SimpleNamespace(CoInitializeEx=lambda *_a: 0),
        comdlg32=comdlg32 if comdlg32 is not None else SimpleNamespace(),
    )
    monkeypatch.setattr(ctypes, "windll", namespace, raising=False)


def _identity_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the WINFUNCTYPE wrapper for identity so callbacks stay pure Python."""
    monkeypatch.setattr(winmod, "wnd_enum_callback_type", lambda: lambda cb: cb)


# ---------------------------------------------------------------------------
# blocked_ui_pids / resolve_allowed_ui_pids guards


def test_blocked_ui_pids_skips_a_nonpositive_host() -> None:
    assert winmod.blocked_ui_pids(debugger_pid=7000, self_pid=0) == {7000}


def test_blocked_ui_pids_omits_a_missing_debugger() -> None:
    assert winmod.blocked_ui_pids(debugger_pid=None, self_pid=42) == {42}


def test_resolve_allowed_ui_pids_refuses_debuggee_that_is_blocked() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        winmod.resolve_allowed_ui_pids(debuggee_pid=42, debugger_pid=7000, self_pid=42)
    assert exc.value.code == "permission_denied"


def test_resolve_allowed_ui_pids_refuses_a_nonpositive_child() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        winmod.resolve_allowed_ui_pids(
            debuggee_pid=7100,
            debugger_pid=7000,
            allow_child_pids=[0],
            self_pid=42,
        )
    assert exc.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# list_process_windows / list_windows_for_pids


def test_list_process_windows_empty_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert winmod.list_process_windows(7) == []


def test_list_windows_for_pids_keeps_only_matching_owners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _identity_callback(monkeypatch)
    user32 = _FakeUser32(
        [
            {"hwnd": 0x30, "pid": 7, "title": "main", "class_name": "Win", "visible": True},
            {"hwnd": 0x40, "pid": 99, "title": "other", "class_name": "Other", "visible": False},
            {"hwnd": 0x50, "pid": 7, "title": "dlg", "class_name": "Dlg", "visible": True},
        ]
    )
    _install_windll(monkeypatch, user32=user32)
    # Non-int / non-positive PIDs are dropped before enumeration.
    rows = winmod.list_windows_for_pids([7, 0, -3])
    assert [row["hwnd"] for row in rows] == [0x30, 0x50]
    assert all(row["pid"] == 7 for row in rows)
    assert rows[0]["title"] == "main"
    assert rows[0]["class_name"] == "Win"
    assert rows[0]["visible"] is True


# ---------------------------------------------------------------------------
# list_input_desktop_windows / snapshot_input_desktop


def test_list_input_desktop_windows_empty_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert winmod.list_input_desktop_windows() == []


def test_list_input_desktop_windows_filters_by_allowed_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _identity_callback(monkeypatch)
    user32 = _FakeUser32(
        [
            {
                "hwnd": 0x1,
                "pid": 7,
                "title": "keep",
                "class_name": "K",
                "visible": True,
                "enabled": True,
                "minimized": False,
                "rect": (0, 0, 10, 10),
            },
            {
                "hwnd": 0x2,
                "pid": 8,
                "title": "drop",
                "class_name": "D",
                "visible": True,
                "enabled": True,
                "minimized": False,
                "rect": (0, 0, 10, 10),
            },
        ]
    )
    _install_windll(monkeypatch, user32=user32)
    rows = winmod.list_input_desktop_windows(allowed_pids=frozenset({7}))
    assert [row["hwnd"] for row in rows] == [0x1]


def test_snapshot_input_desktop_reports_all_and_bounded_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _identity_callback(monkeypatch)
    user32 = _FakeUser32(
        [
            {
                "hwnd": 0x10,
                "pid": 7,
                "title": "A",
                "class_name": "C",
                "visible": True,
                "enabled": True,
                "minimized": False,
                "rect": (0, 0, 100, 50),
            },
            {
                "hwnd": 0x20,
                "pid": 9,
                "title": "B",
                "class_name": "D",
                "visible": True,
                "enabled": True,
                "minimized": False,
                "rect": (0, 0, 200, 100),
            },
        ]
    )
    _install_windll(monkeypatch, user32=user32)

    bounded = winmod.snapshot_input_desktop(allowed_pids=frozenset({7}))
    assert bounded["available"] is True
    assert bounded["input_desktop"] is True
    assert bounded["desktop_window_count"] == 2
    assert bounded["window_count"] == 1
    assert bounded["windows"][0]["pid"] == 7

    unbounded = winmod.snapshot_input_desktop(allowed_pids=None)
    assert unbounded["window_count"] == 2
    assert unbounded["desktop_window_count"] == 2


# ---------------------------------------------------------------------------
# is_pid_alive


def test_is_pid_alive_rejects_bad_pids() -> None:
    assert winmod.is_pid_alive(0) is False
    assert winmod.is_pid_alive(-1) is False
    assert winmod.is_pid_alive("x") is False  # type: ignore[arg-type]


def test_is_pid_alive_uses_signal_zero_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "kill", lambda _pid, _sig: None)
    assert winmod.is_pid_alive(4321) is True


def test_is_pid_alive_false_when_signal_zero_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")

    def boom(_pid: int, _sig: int) -> None:
        raise OSError("no such process")

    monkeypatch.setattr(os, "kill", boom)
    assert winmod.is_pid_alive(4321) is False


def test_is_pid_alive_false_when_open_process_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _install_windll(monkeypatch, kernel32=_FakeKernel32(open_handle=0))
    assert winmod.is_pid_alive(4321) is False


def test_is_pid_alive_false_when_exit_code_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    kernel32 = _FakeKernel32(exit_ok=0)
    _install_windll(monkeypatch, kernel32=kernel32)
    assert winmod.is_pid_alive(4321) is False
    assert kernel32.closed == [123]  # handle is still closed in the finally


def test_is_pid_alive_true_when_still_active(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    kernel32 = _FakeKernel32(exit_ok=1, exit_code=259)
    _install_windll(monkeypatch, kernel32=kernel32)
    assert winmod.is_pid_alive(4321) is True
    assert kernel32.closed == [123]


def test_is_pid_alive_false_when_process_has_exited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _install_windll(monkeypatch, kernel32=_FakeKernel32(exit_ok=1, exit_code=0))
    assert winmod.is_pid_alive(4321) is False


# ---------------------------------------------------------------------------
# _show_open_file_dialog


def _dialog_windll(
    monkeypatch: pytest.MonkeyPatch,
    *,
    get_open: Any,
    extended: Any,
) -> None:
    comdlg32 = SimpleNamespace(
        GetOpenFileNameW=_FakeCommDlg(get_open),
        CommDlgExtendedError=_FakeCommDlg(extended),
    )
    _install_windll(monkeypatch, comdlg32=comdlg32)


def test_show_dialog_returns_the_selected_path(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[tuple[tuple[Any, ...], Any]] = []
    original = ctypes.create_unicode_buffer

    def recording(*args: Any, **kwargs: Any) -> Any:
        buf = original(*args, **kwargs)
        created.append((args, buf))
        return buf

    monkeypatch.setattr(ctypes, "create_unicode_buffer", recording)

    def get_open(_ref: Any) -> int:
        # The large integer-sized buffer is lpstrFile; fill it as the OS would.
        for args, buf in created:
            if args and isinstance(args[0], int) and args[0] >= 1024:
                buf.value = "C:\\sample.exe"
        return 1

    _dialog_windll(monkeypatch, get_open=get_open, extended=lambda: 0)
    result = winmod._show_open_file_dialog("Pick a file")
    assert result["path"] == "C:\\sample.exe"
    assert result["available"] is True
    assert result["cancelled"] is False


def test_show_dialog_reports_cancel_when_ok_but_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _dialog_windll(monkeypatch, get_open=lambda _ref: 1, extended=lambda: 0)
    result = winmod._show_open_file_dialog(None)
    assert result["cancelled"] is True
    assert result["path"] is None


def test_show_dialog_reports_cancel_when_closed_without_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dialog_windll(monkeypatch, get_open=lambda _ref: 0, extended=lambda: 0)
    result = winmod._show_open_file_dialog(None)
    assert result["cancelled"] is True
    assert result["error"] is None


def test_show_dialog_reports_a_commdlg_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _dialog_windll(monkeypatch, get_open=lambda _ref: 0, extended=lambda: 5)
    result = winmod._show_open_file_dialog(None)
    assert result["cancelled"] is False
    assert result["error"] == "commdlg_5"


# ---------------------------------------------------------------------------
# _sta_dialog_loop


class _Stop(Exception):
    """Sentinel to break the otherwise-infinite dialog loop after one job."""


class _OneShotJobs:
    def __init__(self, jobs: list[tuple[str | None, queue.Queue[Any]]]) -> None:
        self._jobs = list(jobs)

    def get(self) -> tuple[str | None, queue.Queue[Any]]:
        if self._jobs:
            return self._jobs.pop(0)
        raise _Stop()


def test_sta_dialog_loop_answers_one_job(monkeypatch: pytest.MonkeyPatch) -> None:
    reply: queue.Queue[Any] = queue.Queue()
    monkeypatch.setattr(winmod, "_STA_JOBS", _OneShotJobs([("Title", reply)]))
    monkeypatch.setattr(winmod, "_STA_READY", threading.Event())
    monkeypatch.setattr(winmod, "_show_open_file_dialog", lambda title: {"path": title})
    _install_windll(monkeypatch, ole32=SimpleNamespace(CoInitializeEx=lambda *_a: 0))
    with pytest.raises(_Stop):
        winmod._sta_dialog_loop()
    assert winmod._STA_READY.is_set()
    assert reply.get_nowait() == {"path": "Title"}


def test_sta_dialog_loop_reports_a_dialog_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    reply: queue.Queue[Any] = queue.Queue()
    monkeypatch.setattr(winmod, "_STA_JOBS", _OneShotJobs([("Title", reply)]))
    monkeypatch.setattr(winmod, "_STA_READY", threading.Event())

    def boom(_title: str | None) -> dict[str, Any]:
        raise OSError("dialog exploded")

    monkeypatch.setattr(winmod, "_show_open_file_dialog", boom)
    _install_windll(monkeypatch, ole32=SimpleNamespace(CoInitializeEx=lambda *_a: 0))
    with pytest.raises(_Stop):
        winmod._sta_dialog_loop()
    result = reply.get_nowait()
    assert result["error"] == "dialog exploded"
    assert result["available"] is True


# ---------------------------------------------------------------------------
# _ensure_sta_dialog_thread


class _FakeThread:
    def __init__(self, *, target: Any, name: str, daemon: bool) -> None:
        self.target = target
        self.name = name
        self.daemon = daemon
        self._alive = False

    def start(self) -> None:
        self._alive = True
        winmod._STA_READY.set()

    def is_alive(self) -> bool:
        return self._alive


class _FakeEvent:
    def __init__(self, wait_result: bool) -> None:
        self._wait_result = wait_result
        self._set = False

    def clear(self) -> None:
        self._set = False

    def set(self) -> None:
        self._set = True

    def wait(self, timeout: float | None = None) -> bool:
        return self._wait_result

    def is_set(self) -> bool:
        return self._set


def test_ensure_sta_thread_reuses_a_live_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    live = _FakeThread(target=lambda: None, name="x", daemon=True)
    live._alive = True
    monkeypatch.setattr(winmod, "_STA_THREAD", live)

    def forbidden(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("a live worker must not be replaced")

    monkeypatch.setattr(threading, "Thread", forbidden)
    winmod._ensure_sta_dialog_thread()


def test_ensure_sta_thread_starts_a_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(winmod, "_STA_THREAD", None)
    monkeypatch.setattr(winmod, "_STA_READY", _FakeEvent(True))
    monkeypatch.setattr(threading, "Thread", _FakeThread)
    winmod._ensure_sta_dialog_thread()
    assert winmod._STA_THREAD is not None
    assert winmod._STA_THREAD.is_alive()


def test_ensure_sta_thread_raises_when_worker_never_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(winmod, "_STA_THREAD", None)
    monkeypatch.setattr(winmod, "_STA_READY", _FakeEvent(False))

    class _SilentThread(_FakeThread):
        def start(self) -> None:  # never signals ready
            self._alive = True

    monkeypatch.setattr(threading, "Thread", _SilentThread)
    with pytest.raises(RuntimeError, match="file dialog thread failed to start"):
        winmod._ensure_sta_dialog_thread()


# ---------------------------------------------------------------------------
# pick_open_file_status / pick_open_file


class _ImmediateJobs:
    """A jobs queue whose ``put`` answers the reply synchronously (no worker)."""

    def __init__(self, result: Any) -> None:
        self._result = result
        self.titles: list[str | None] = []

    def put(self, item: tuple[str | None, queue.Queue[Any]]) -> None:
        title, reply = item
        self.titles.append(title)
        reply.put(self._result)


def test_pick_open_file_status_returns_the_worker_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(winmod, "_PICK_LOCK", threading.Lock())
    monkeypatch.setattr(winmod, "_ensure_sta_dialog_thread", lambda: None)
    jobs = _ImmediateJobs(
        {
            "path": "C:\\a.exe",
            "available": True,
            "cancelled": False,
            "busy": False,
            "error": None,
        }
    )
    monkeypatch.setattr(winmod, "_STA_JOBS", jobs)
    result = winmod.pick_open_file_status(title="Choose")
    assert result["path"] == "C:\\a.exe"
    assert jobs.titles == ["Choose"]


def test_pick_open_file_status_reports_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(winmod, "_PICK_LOCK", threading.Lock())
    monkeypatch.setattr(winmod, "_ensure_sta_dialog_thread", lambda: None)
    monkeypatch.setattr(winmod, "_STA_JOBS", SimpleNamespace(put=lambda _item: None))

    class _EmptyReply:
        def get(self, timeout: float | None = None) -> Any:
            raise queue.Empty

    monkeypatch.setattr(
        winmod,
        "queue",
        SimpleNamespace(Queue=lambda: _EmptyReply(), Empty=queue.Empty),
    )
    result = winmod.pick_open_file_status()
    assert result["error"] == "dialog_timeout"


def test_pick_open_file_status_rejects_a_non_dict_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(winmod, "_PICK_LOCK", threading.Lock())
    monkeypatch.setattr(winmod, "_ensure_sta_dialog_thread", lambda: None)
    monkeypatch.setattr(winmod, "_STA_JOBS", _ImmediateJobs("not-a-dict"))
    result = winmod.pick_open_file_status()
    assert result["error"] == "dialog_invalid_result"


def test_pick_open_file_status_reports_a_thread_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(winmod, "_PICK_LOCK", threading.Lock())

    def boom() -> None:
        raise RuntimeError("file dialog thread failed to start")

    monkeypatch.setattr(winmod, "_ensure_sta_dialog_thread", boom)
    result = winmod.pick_open_file_status()
    assert "failed to start" in result["error"]
    assert result["available"] is True


def test_pick_open_file_returns_a_real_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        winmod, "pick_open_file_status", lambda *, title=None: {"path": "C:\\x.exe"}
    )
    assert winmod.pick_open_file(title="t") == "C:\\x.exe"


def test_pick_open_file_none_for_blank_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(winmod, "pick_open_file_status", lambda *, title=None: {"path": "   "})
    assert winmod.pick_open_file() is None
