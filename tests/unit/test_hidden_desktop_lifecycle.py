"""Hermetic cover for the hidden-desktop isolation lifecycle.

``hidden_desktop`` is the isolation boundary a debuggee's anti-debug UI is
supposed to stay behind: the desktop is created inside the operator's window
station but never switched to, and ``capture`` refuses any HWND that does not
belong to an authorized pid on that exact desktop. All of it is Win32 ctypes,
so the CI (Linux) only ever ran the module's import -- measured 18% coverage,
with every class body untouched. These tests patch the thin ``_api`` /
``_enumerate_windows`` / ``_exit_code`` / ``_desktop_name`` seams so the actual
logic runs on Linux and pins what a refactor must not break: the capture
fail-closed check, the process handle closed exactly once across poll/wait, the
desktop-identity round-trip that reclaims a mis-created handle, and the
non-Windows guards that keep every entry point from touching Win32 by mistake.
"""

from __future__ import annotations

import ctypes
import io
import subprocess
from typing import Any, cast

import pytest

import headless_re_mcp.core.hidden_desktop as hd
from headless_re_mcp.core.hidden_desktop import (
    DesktopProcess,
    HiddenDesktop,
    HiddenDesktopError,
    _environment_block,
    _require_windows,
    create_process_on_desktop,
)

_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF


def _fake_winerror(monkeypatch: pytest.MonkeyPatch) -> None:
    """WinError/get_last_error only exist on Windows; give the error paths a
    concrete OSError to raise so they can be exercised on Linux CI."""
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        ctypes, "WinError", lambda code=0: OSError(code or 5, "winerror"), raising=False
    )


class _FakeKernel32:
    def __init__(self, *, wait_result: int = _WAIT_TIMEOUT, terminate_ok: bool = True) -> None:
        self.wait_result = wait_result
        self.terminate_ok = terminate_ok
        self.closed_handles: list[int] = []
        self.terminated: list[int] = []
        self.wait_calls: list[int] = []

    def WaitForSingleObject(self, handle: Any, ms: Any) -> int:
        self.wait_calls.append(int(ms))
        return self.wait_result

    def CloseHandle(self, handle: Any) -> bool:
        self.closed_handles.append(int(handle.value) if handle.value is not None else 0)
        return True

    def TerminateProcess(self, handle: Any, code: Any) -> bool:
        self.terminated.append(int(code))
        return self.terminate_ok


class _FakeUser32:
    def __init__(self, *, create_handle: int = 0xABCD, close_ok: bool = True) -> None:
        self.create_handle = create_handle
        self.close_ok = close_ok
        self.closed_desktops: list[int] = []

    def CreateDesktopW(self, *_args: Any) -> int:
        return self.create_handle

    def CloseDesktop(self, handle: Any) -> bool:
        value = handle.value if isinstance(handle, ctypes.c_void_p) else handle
        self.closed_desktops.append(int(value) if value is not None else 0)
        return self.close_ok


def _proc(handle: int = 0x1000) -> DesktopProcess:
    return DesktopProcess(
        args=["worker.exe", "--go"],
        process_handle=handle,
        pid=4321,
        stdin=io.StringIO(),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


# ---- non-Windows fail-safes ----------------------------------------------------


def test_require_windows_refuses_off_windows() -> None:
    # The suite runs on Linux, so os.name is already not "nt".
    with pytest.raises(HiddenDesktopError, match="require Windows"):
        _require_windows()


def test_every_win32_entry_point_refuses_off_windows() -> None:
    with pytest.raises(HiddenDesktopError):
        HiddenDesktop.create()
    with pytest.raises(HiddenDesktopError):
        create_process_on_desktop(["worker.exe"], r"WinSta0\Hidden")


def test_spawn_on_a_closed_desktop_refuses_before_touching_win32() -> None:
    desktop = HiddenDesktop("HeadlessRE-x", 0x10)
    desktop._closed = True
    with pytest.raises(HiddenDesktopError, match="desktop is closed"):
        desktop.spawn(["worker.exe"])


# ---- environment block ---------------------------------------------------------


def test_environment_block_is_sorted_and_double_null_terminated() -> None:
    # A c_wchar array slices to a str at runtime; mypy only sees list[Any].
    block = cast(str, _environment_block({"PATH": "/x", "beta": "2", "Alpha": "1"})[:])
    fields = block.split("\0")
    # Case-insensitive sort, "key=value" per entry, empty trailing entries mark
    # the block's terminating double-NUL that CreateProcessW requires.
    assert [f for f in fields if f] == ["Alpha=1", "beta=2", "PATH=/x"]
    assert block.endswith("\0\0")


def test_environment_block_of_empty_mapping_is_just_the_terminator() -> None:
    assert set(_environment_block({})[:]) == {"\0"}


# ---- DesktopProcess lifecycle --------------------------------------------------


def test_poll_returns_none_while_the_child_is_running(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = _FakeKernel32(wait_result=_WAIT_TIMEOUT)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    proc = _proc()
    assert proc.poll() is None
    assert proc.returncode is None
    assert kernel.closed_handles == []  # a running child's handle stays open


def test_poll_records_exit_and_closes_handle_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _FakeKernel32(wait_result=_WAIT_OBJECT_0)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    proc = _proc(handle=0x2222)
    monkeypatch.setattr(proc, "_exit_code", lambda: 7)

    assert proc.poll() == 7
    assert proc.poll() == 7  # cached; must not re-wait or re-close
    assert proc.returncode == 7
    assert kernel.closed_handles == [0x2222]


def test_poll_raises_on_wait_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_winerror(monkeypatch)
    kernel = _FakeKernel32(wait_result=_WAIT_FAILED)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    with pytest.raises(OSError):
        _proc().poll()


def test_wait_times_out_as_subprocess_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = _FakeKernel32(wait_result=_WAIT_TIMEOUT)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    proc = _proc()
    with pytest.raises(subprocess.TimeoutExpired):
        proc.wait(timeout=0.5)
    # Timeout is clamped to a millisecond count, never INFINITE.
    assert kernel.wait_calls == [500]


def test_wait_none_timeout_blocks_infinite(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = _FakeKernel32(wait_result=_WAIT_OBJECT_0)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    proc = _proc()
    monkeypatch.setattr(proc, "_exit_code", lambda: 0)
    assert proc.wait() == 0
    assert kernel.wait_calls == [hd._INFINITE]


def test_terminate_kills_a_running_child_then_is_a_noop_once_exited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _FakeKernel32(wait_result=_WAIT_TIMEOUT)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    proc = _proc()

    proc.kill()  # kill() delegates to terminate()
    assert kernel.terminated == [1]

    proc.returncode = 3  # now "already exited"
    proc.terminate()
    assert kernel.terminated == [1]  # no second TerminateProcess


def test_terminate_raises_when_the_kill_call_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_winerror(monkeypatch)
    kernel = _FakeKernel32(wait_result=_WAIT_TIMEOUT, terminate_ok=False)
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    with pytest.raises(OSError):
        _proc().terminate()


def test_close_handle_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = _FakeKernel32()
    monkeypatch.setattr(hd, "_api", lambda: (None, kernel))
    proc = _proc(handle=0x9)
    proc._close_handle()
    proc._close_handle()
    assert kernel.closed_handles == [0x9]


# ---- HiddenDesktop.create identity round-trip ----------------------------------


def test_create_returns_a_named_desktop_when_identity_round_trips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(create_handle=0x77)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    monkeypatch.setattr(hd, "_desktop_name", lambda _u, _h: "HeadlessRE-abc")
    # Force the generated name so _desktop_name can echo it back.
    monkeypatch.setattr(hd, "uuid4", lambda: type("U", (), {"hex": "abc"})())

    desktop = HiddenDesktop.create(prefix="HeadlessRE")
    assert desktop.name == "HeadlessRE-abc"
    assert desktop.qualified_name == r"WinSta0\HeadlessRE-abc"
    assert user32.closed_desktops == []  # a good handle is kept


def test_create_reclaims_the_handle_when_identity_does_not_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32(create_handle=0x88)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    monkeypatch.setattr(hd, "uuid4", lambda: type("U", (), {"hex": "abc"})())
    # The OS handed back a different desktop than we asked for.
    monkeypatch.setattr(hd, "_desktop_name", lambda _u, _h: "SomethingElse")

    with pytest.raises(HiddenDesktopError, match="did not round-trip"):
        HiddenDesktop.create(prefix="HeadlessRE")
    assert user32.closed_desktops == [0x88]  # the impostor handle is closed


def test_create_raises_when_the_desktop_cannot_be_made(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_winerror(monkeypatch)
    user32 = _FakeUser32(create_handle=0)  # NULL: CreateDesktopW failed
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    with pytest.raises(OSError):
        HiddenDesktop.create()


# ---- window enumeration, snapshot, capture authorization -----------------------


def _rows() -> list[dict[str, Any]]:
    def row(hwnd: int, pid: int, title: str, area: int, visible: bool) -> dict[str, Any]:
        w = 40 if area else 0
        h = area // 40 if area else 0
        return {
            "hwnd": hwnd,
            "pid": pid,
            "title": title,
            "class_name": "Window",
            "visible": visible,
            "enabled": True,
            "minimized": False,
            "rect": {"left": 0, "top": 0, "right": w, "bottom": h, "width": w, "height": h},
            "area": area,
        }

    return [
        row(0x1, 4321, "small", 0, True),
        row(0x2, 4321, "debuggee-main", 40 * 300, True),
        row(0x3, 999, "other-process", 40 * 100, True),
    ]


def _desktop_with_rows(monkeypatch: pytest.MonkeyPatch) -> HiddenDesktop:
    desktop = HiddenDesktop("HeadlessRE-abc", 0x55)
    monkeypatch.setattr(desktop, "_enumerate_windows", lambda: _rows())
    return desktop


def test_windows_filters_to_the_authorized_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    desktop = _desktop_with_rows(monkeypatch)
    assert {row["hwnd"] for row in desktop.windows()} == {0x1, 0x2, 0x3}
    mine = desktop.windows(allowed_pids=frozenset({4321}))
    assert {row["hwnd"] for row in mine} == {0x1, 0x2}


def test_snapshot_reports_isolation_and_ranks_the_capturable_window_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop = _desktop_with_rows(monkeypatch)
    snap = desktop.snapshot(allowed_pids=frozenset({4321}))
    assert snap["available"] is True
    assert snap["mode"] == "hidden_win32"
    assert snap["input_desktop"] is False
    assert snap["name"] == "HeadlessRE-abc"
    assert snap["qualified_name"] == r"WinSta0\HeadlessRE-abc"
    assert snap["window_count"] == 2
    assert snap["desktop_window_count"] == 3
    # The larger visible window outranks the 0x0 ghost.
    assert snap["windows"][0]["hwnd"] == 0x2


def test_process_window_descriptions_are_formatted_per_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop = _desktop_with_rows(monkeypatch)
    described = desktop.process_window_descriptions(4321)
    assert "Window:debuggee-main (hwnd=2)" in described
    assert all("other-process" not in text for text in described)


def test_capture_refuses_a_window_that_is_not_authorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop = _desktop_with_rows(monkeypatch)
    calls: list[Any] = []
    monkeypatch.setattr(
        "headless_re_mcp.core.ui_win32.capture_hwnd_screenshot",
        lambda *args: calls.append(args),
    )
    # 0x3 belongs to pid 999, not in the authorized set.
    with pytest.raises(HiddenDesktopError, match="not on the authorized"):
        desktop.capture(0x3, allowed_pids=frozenset({4321}), output_path="/tmp/out.png")
    assert calls == [], "an unauthorized HWND must never reach the screenshot path"


def test_capture_delegates_for_an_authorized_window(monkeypatch: pytest.MonkeyPatch) -> None:
    desktop = _desktop_with_rows(monkeypatch)
    recorded: dict[str, Any] = {}

    def fake_capture(hwnd: int, allowed: frozenset[int], output: Any) -> dict[str, Any]:
        recorded.update(hwnd=hwnd, allowed=allowed, output=output)
        return {"ok": True, "path": str(output)}

    monkeypatch.setattr("headless_re_mcp.core.ui_win32.capture_hwnd_screenshot", fake_capture)
    result = desktop.capture(0x2, allowed_pids=frozenset({4321}), output_path="/tmp/shot.png")
    assert result == {"ok": True, "path": "/tmp/shot.png"}
    assert recorded["hwnd"] == 0x2
    assert recorded["allowed"] == frozenset({4321})


# ---- close / context manager ---------------------------------------------------


def test_close_is_idempotent_and_context_manager_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _FakeUser32()
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    with HiddenDesktop("HeadlessRE-abc", 0x66) as desktop:
        assert desktop._closed is False
    assert desktop._closed is True
    desktop.close()  # second close is a no-op
    assert user32.closed_desktops == [0x66]


def test_close_raises_when_the_desktop_handle_cannot_be_freed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_winerror(monkeypatch)
    user32 = _FakeUser32(close_ok=False)
    monkeypatch.setattr(hd, "_api", lambda: (user32, None))
    with pytest.raises(OSError):
        HiddenDesktop("HeadlessRE-abc", 0x66).close()
