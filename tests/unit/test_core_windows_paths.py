"""Coverage for the Win32 window enumeration, liveness probe, and file dialog.

The enumeration callbacks and the OPENFILENAMEW plumbing are decision logic
around a handful of user32/comdlg32 calls. Faking those tables lets the
callback bodies, the PID filters, and every dialog outcome (picked, cancelled,
failed, busy, timed out) run anywhere, the same pattern as the process-tree
and desktop-isolation tests.
"""

from __future__ import annotations

import os
import queue
import types
from typing import Any

import pytest

import headless_re_mcp.core.windows as win

JsonObject = dict[str, Any]


class _NtOsProxy:
    """Report ``name == "nt"`` while forwarding everything else to the real os."""

    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


def _pretend_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(win, "os", _NtOsProxy())


def _install_windll(monkeypatch: pytest.MonkeyPatch, **tables: Any) -> None:
    monkeypatch.setattr(
        win.ctypes,
        "windll",
        types.SimpleNamespace(**tables),
        raising=False,
    )


class _FakeUser32:
    """user32 stand-in enumerating a fixed window table through the real callback."""

    def __init__(self, rows: dict[int, JsonObject]) -> None:
        self._rows = rows

    def EnumWindows(self, callback: Any, lparam: int) -> int:  # noqa: N802
        for hwnd in self._rows:
            callback(hwnd, lparam)
        return 1

    def GetWindowThreadProcessId(self, hwnd: int, pid_ref: Any) -> int:  # noqa: N802
        pid_ref._obj.value = int(self._rows[hwnd]["pid"])
        return 1

    def GetWindowTextLengthW(self, hwnd: int) -> int:  # noqa: N802
        return len(str(self._rows[hwnd].get("title") or ""))

    def GetWindowTextW(self, hwnd: int, buffer: Any, size: int) -> int:  # noqa: N802
        buffer.value = str(self._rows[hwnd].get("title") or "")
        return len(buffer.value)

    def GetClassNameW(self, hwnd: int, buffer: Any, size: int) -> int:  # noqa: N802
        buffer.value = str(self._rows[hwnd].get("class_name") or "Window")
        return len(buffer.value)

    def IsWindowVisible(self, hwnd: int) -> int:  # noqa: N802
        return 1 if self._rows[hwnd].get("visible") else 0

    def IsWindowEnabled(self, hwnd: int) -> int:  # noqa: N802
        return 1 if self._rows[hwnd].get("enabled", True) else 0

    def IsIconic(self, hwnd: int) -> int:  # noqa: N802
        return 1 if self._rows[hwnd].get("minimized") else 0

    def GetWindowRect(self, hwnd: int, rect_ref: Any) -> int:  # noqa: N802
        rect = rect_ref._obj
        left, top, right, bottom = self._rows[hwnd].get("rect", (0, 0, 0, 0))
        rect.left, rect.top, rect.right, rect.bottom = left, top, right, bottom
        return 1


# --------------------------------------------------------------------------- #
# blocked / allowed UI pids
# --------------------------------------------------------------------------- #


def test_blocked_pids_ignore_a_nonpositive_host_and_debugger() -> None:
    assert win.blocked_ui_pids(debugger_pid=None, self_pid=0) == set()
    assert win.blocked_ui_pids(debugger_pid=-4, self_pid=0) == set()
    assert win.blocked_ui_pids(debugger_pid=9, self_pid=7) == {7, 9}


def test_resolve_allowed_rejects_a_debuggee_that_is_the_host() -> None:
    with pytest.raises(win.UiPidBoundaryError) as exc:
        win.resolve_allowed_ui_pids(debuggee_pid=7, debugger_pid=None, self_pid=7)
    assert exc.value.code == "permission_denied"


def test_resolve_allowed_rejects_a_malformed_child_pid() -> None:
    with pytest.raises(win.UiPidBoundaryError) as exc:
        win.resolve_allowed_ui_pids(
            debuggee_pid=100,
            debugger_pid=None,
            allow_child_pids=[0],
            self_pid=7,
        )
    assert exc.value.code == "invalid_params"


# --------------------------------------------------------------------------- #
# window enumeration
# --------------------------------------------------------------------------- #


def test_list_process_windows_collects_only_the_target_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(
        {
            11: {"pid": 42, "title": "Main", "class_name": "AppWnd", "visible": True},
            22: {"pid": 99, "title": "Other", "class_name": "X", "visible": True},
            33: {"pid": 42, "title": "", "class_name": "Dlg", "visible": False},
        }
    )
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, user32=user32)

    rows = win.list_process_windows(42)

    assert [row["hwnd"] for row in rows] == [11, 33]
    assert rows[0]["title"] == "Main"
    assert rows[0]["class_name"] == "AppWnd"
    assert rows[0]["visible"] is True
    assert rows[1]["visible"] is False

    described = win.describe_process_windows(42)
    assert "0xb:AppWnd:Main" in described


def test_list_windows_for_pids_skips_invalid_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[int] = []
    monkeypatch.setattr(win, "list_process_windows", lambda pid: seen.append(pid) or [])
    win.list_windows_for_pids([0, -1, 42, 42, "x", 7])  # type: ignore[list-item]
    assert seen == [7, 42]


def test_list_input_desktop_windows_filters_and_ranks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(
        {
            11: {
                "pid": 42,
                "title": "Big",
                "class_name": "AppWnd",
                "visible": True,
                "rect": (0, 0, 100, 50),
            },
            22: {
                "pid": 42,
                "title": "Zero",
                "class_name": "Ghost",
                "visible": True,
                "rect": (0, 0, 0, 0),
            },
            33: {
                "pid": 9,
                "title": "Blocked",
                "class_name": "X",
                "visible": True,
                "rect": (0, 0, 10, 10),
            },
        }
    )
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, user32=user32)

    rows = win.list_input_desktop_windows(allowed_pids=frozenset({42}))

    assert [row["hwnd"] for row in rows] == [11, 22], "capturable area must outrank a 0x0 window"
    assert rows[0]["rect"]["width"] == 100
    assert rows[0]["area"] == 5000
    assert rows[1]["area"] == 0


def test_snapshot_input_desktop_reports_bounded_and_total_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pretend_windows(monkeypatch)
    all_rows = [{"pid": 42, "hwnd": 11}, {"pid": 9, "hwnd": 22}]
    monkeypatch.setattr(win, "list_input_desktop_windows", lambda *, allowed_pids: all_rows)

    snapshot = win.snapshot_input_desktop(allowed_pids=frozenset({42}))

    assert snapshot["available"] is True
    assert snapshot["window_count"] == 1
    assert snapshot["desktop_window_count"] == 2
    assert snapshot["windows"] == [{"pid": 42, "hwnd": 11}]

    unbounded = win.snapshot_input_desktop(allowed_pids=None)
    assert unbounded["window_count"] == 2


# --------------------------------------------------------------------------- #
# is_pid_alive
# --------------------------------------------------------------------------- #


def test_is_pid_alive_rejects_bad_input_and_probes_posix() -> None:
    assert win.is_pid_alive(0) is False
    assert win.is_pid_alive("7") is False  # type: ignore[arg-type]
    if os.name != "nt":
        assert win.is_pid_alive(os.getpid()) is True


def test_is_pid_alive_reads_still_active_through_the_win32_arm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exit_code(value: int) -> Any:
        def get(handle: Any, code_ref: Any) -> int:
            code_ref._obj.value = value
            return 1

        return get

    _pretend_windows(monkeypatch)
    kernel32 = types.SimpleNamespace(
        OpenProcess=lambda access, inherit, pid: 555,
        GetExitCodeProcess=exit_code(259),
        CloseHandle=lambda handle: 1,
    )
    _install_windll(monkeypatch, kernel32=kernel32)
    assert win.is_pid_alive(4242) is True

    kernel32.GetExitCodeProcess = exit_code(0)
    assert win.is_pid_alive(4242) is False

    kernel32.GetExitCodeProcess = lambda handle, code_ref: 0
    assert win.is_pid_alive(4242) is False

    kernel32.OpenProcess = lambda access, inherit, pid: 0
    assert win.is_pid_alive(4242) is False


# --------------------------------------------------------------------------- #
# the open-file dialog
# --------------------------------------------------------------------------- #


def _dialog_windll(
    monkeypatch: pytest.MonkeyPatch,
    *,
    accepted: bool,
    extended_error: int = 0,
    picked: str = "",
) -> None:
    class _GetOpen:
        argtypes: Any = None
        restype: Any = None

        def __call__(self, ofn_ref: Any) -> int:
            return 1 if accepted else 0

    class _CommErr:
        restype: Any = None

        def __call__(self) -> int:
            return extended_error

    _install_windll(
        monkeypatch,
        user32=types.SimpleNamespace(GetForegroundWindow=lambda: 0),
        comdlg32=types.SimpleNamespace(
            GetOpenFileNameW=_GetOpen(),
            CommDlgExtendedError=_CommErr(),
        ),
    )
    if picked:
        real_buffer = win.ctypes.create_unicode_buffer

        def prefilled(init: Any, size: int | None = None) -> Any:
            buffer = real_buffer(init) if size is None else real_buffer(init, size)
            # The 32768-char buffer is the file-name slot the dialog writes to;
            # prefilling it models the operator picking a path.
            if init == 32768:
                buffer.value = picked
            return buffer

        monkeypatch.setattr(win.ctypes, "create_unicode_buffer", prefilled)


def test_dialog_returns_the_picked_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _dialog_windll(monkeypatch, accepted=True, picked="C:\\samples\\target.exe")
    result = win._show_open_file_dialog("pick")
    assert result["path"] == "C:\\samples\\target.exe"
    assert result["cancelled"] is False


def test_dialog_treats_an_accepted_empty_path_as_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dialog_windll(monkeypatch, accepted=True)
    result = win._show_open_file_dialog(None)
    assert result["path"] is None
    assert result["cancelled"] is True


def test_dialog_maps_a_plain_close_to_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    _dialog_windll(monkeypatch, accepted=False, extended_error=0)
    result = win._show_open_file_dialog(None)
    assert result["cancelled"] is True
    assert result["error"] is None


def test_dialog_reports_an_extended_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _dialog_windll(monkeypatch, accepted=False, extended_error=123)
    result = win._show_open_file_dialog(None)
    assert result["cancelled"] is False
    assert result["error"] == "commdlg_123"


# --------------------------------------------------------------------------- #
# the STA dialog thread and pick_open_file_status
# --------------------------------------------------------------------------- #


class _InstantJobs:
    """A job queue whose consumer answers immediately, standing in for the STA thread."""

    def __init__(self, result: Any) -> None:
        self._result = result

    def put(self, item: tuple[str | None, Any]) -> None:
        _title, reply = item
        reply.put(self._result)


def test_pick_status_is_unavailable_off_windows() -> None:
    result = win.pick_open_file_status()
    assert result["available"] is False
    assert win.pick_open_file() is None


def test_pick_status_reports_busy_under_contention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pretend_windows(monkeypatch)
    assert win._PICK_LOCK.acquire(blocking=False)
    try:
        result = win.pick_open_file_status()
    finally:
        win._PICK_LOCK.release()
    assert result["busy"] is True


def test_pick_status_returns_the_dialog_result(monkeypatch: pytest.MonkeyPatch) -> None:
    _pretend_windows(monkeypatch)
    monkeypatch.setattr(win, "_ensure_sta_dialog_thread", lambda: None)
    picked = {"path": "C:\\x.exe", "cancelled": False, "available": True, "busy": False}
    monkeypatch.setattr(win, "_STA_JOBS", _InstantJobs(picked))
    assert win.pick_open_file_status() == picked


def test_pick_status_flags_a_non_dict_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    _pretend_windows(monkeypatch)
    monkeypatch.setattr(win, "_ensure_sta_dialog_thread", lambda: None)
    monkeypatch.setattr(win, "_STA_JOBS", _InstantJobs("garbage"))
    assert win.pick_open_file_status()["error"] == "dialog_invalid_result"


def test_pick_status_times_out_when_the_thread_never_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pretend_windows(monkeypatch)
    monkeypatch.setattr(win, "_ensure_sta_dialog_thread", lambda: None)

    class _SilentReply:
        def get(self, timeout: float | None = None) -> Any:
            raise queue.Empty

    class _DropJobs:
        def put(self, item: Any) -> None:
            pass

    monkeypatch.setattr(win, "_STA_JOBS", _DropJobs())
    monkeypatch.setattr(win, "queue", types.SimpleNamespace(Queue=_SilentReply, Empty=queue.Empty))
    assert win.pick_open_file_status()["error"] == "dialog_timeout"


def test_pick_status_reports_a_thread_that_cannot_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pretend_windows(monkeypatch)

    def refuse() -> None:
        raise RuntimeError("file dialog thread failed to start")

    monkeypatch.setattr(win, "_ensure_sta_dialog_thread", refuse)
    result = win.pick_open_file_status()
    assert result["error"] == "file dialog thread failed to start"


def test_ensure_sta_thread_reuses_a_live_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[bool] = []
    monkeypatch.setattr(win, "_STA_THREAD", types.SimpleNamespace(is_alive=lambda: True))
    monkeypatch.setattr(win, "_sta_dialog_loop", lambda: started.append(True))
    win._ensure_sta_dialog_thread()
    assert started == []


def test_ensure_sta_thread_starts_and_awaits_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(win, "_STA_THREAD", None)
    monkeypatch.setattr(win, "_sta_dialog_loop", lambda: win._STA_READY.set())
    win._ensure_sta_dialog_thread()
    assert win._STA_READY.is_set()


def test_ensure_sta_thread_raises_when_readiness_never_comes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(win, "_STA_THREAD", None)
    monkeypatch.setattr(win, "_sta_dialog_loop", lambda: None)
    monkeypatch.setattr(
        win,
        "_STA_READY",
        types.SimpleNamespace(clear=lambda: None, wait=lambda timeout: False),
    )
    with pytest.raises(RuntimeError, match="failed to start"):
        win._ensure_sta_dialog_thread()


def test_sta_dialog_loop_answers_jobs_and_wraps_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One loop pass per job: a result is forwarded, an exception becomes an error dict."""
    _install_windll(
        monkeypatch,
        ole32=types.SimpleNamespace(CoInitializeEx=lambda reserved, flags: 0),
    )
    outcomes = iter(
        [
            {"path": "C:\\x.exe", "cancelled": False, "available": True, "busy": False},
            ValueError("dialog exploded"),
            KeyboardInterrupt(),  # ends the otherwise-infinite loop
        ]
    )

    def scripted(title: str | None) -> JsonObject:
        outcome = next(outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(win, "_show_open_file_dialog", scripted)
    first: queue.Queue[JsonObject] = queue.Queue()
    second: queue.Queue[JsonObject] = queue.Queue()
    third: queue.Queue[JsonObject] = queue.Queue()
    win._STA_JOBS.put(("pick", first))
    win._STA_JOBS.put(("pick", second))
    win._STA_JOBS.put(("pick", third))

    with pytest.raises(KeyboardInterrupt):
        win._sta_dialog_loop()

    assert first.get(timeout=1)["path"] == "C:\\x.exe"
    assert second.get(timeout=1)["error"] == "dialog exploded"
