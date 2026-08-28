"""Coverage for the Win32 hidden-desktop lifecycle without a real desktop.

hidden_desktop.py is decision logic wrapped around a dozen user32/kernel32
entry points: desktop create/close with an identity round-trip, bounded window
enumeration through a real WNDENUMPROC, the CreateProcessW wrapper with
explicit lpDesktop, and a Popen-compatible process handle. Faking the two DLL
tables (the same pattern as the process-tree and desktop-isolation tests) lets
every arm run on any platform: happy paths, each WinError raise, the closed
and mismatch guards, and the wait/poll/terminate state machine.
"""

from __future__ import annotations

import ctypes
import io
import os
import subprocess
import sys
import types
from typing import Any

import pytest

import headless_re_mcp.core.hidden_desktop as hd

JsonObject = dict[str, Any]

_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF
_INFINITE = 0xFFFFFFFF


class _NtOsProxy:
    """Report ``name == "nt"`` while forwarding everything else to the real os."""

    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


class _Win32World:
    """A configurable user32/kernel32 pair driving the hidden-desktop arms."""

    def __init__(
        self,
        *,
        windows: dict[int, JsonObject] | None = None,
        reported_name: str | None = None,
        create_desktop_handle: int = 777,
        enum_ok: bool = True,
        enum_error: int = 0,
        name_readback_fails: bool = False,
        wait_results: list[int] | None = None,
        exit_code: int = 0,
        exit_code_ok: bool = True,
        create_process_ok: bool = True,
        terminate_ok: bool = True,
        close_desktop_ok: bool = True,
        pid: int = 4242,
        process_handle: int = 1234,
    ) -> None:
        self.windows = dict(windows or {})
        self.reported_name = reported_name
        self.create_desktop_handle = create_desktop_handle
        self.enum_ok = enum_ok
        self.enum_error = enum_error
        self.name_readback_fails = name_readback_fails
        self.wait_results = list(wait_results or [_WAIT_OBJECT_0])
        self.exit_code = exit_code
        self.exit_code_ok = exit_code_ok
        self.create_process_ok = create_process_ok
        self.terminate_ok = terminate_ok
        self.close_desktop_ok = close_desktop_ok
        self.pid = pid
        self.process_handle = process_handle

        self.last_error = 0
        self.created_desktop_names: list[str] = []
        self.closed_desktops: list[Any] = []
        self.closed_handles: list[Any] = []
        self.terminated: list[Any] = []
        self.wait_calls: list[int] = []
        self.create_process_calls: list[JsonObject] = []

        self.user32 = self._build_user32()
        self.kernel32 = self._build_kernel32()

    def _reported(self) -> str:
        if self.reported_name is not None:
            return self.reported_name
        return self.created_desktop_names[-1] if self.created_desktop_names else ""

    def _build_user32(self) -> types.SimpleNamespace:
        world = self

        def create_desktop(
            name: str, device: Any, sec: Any, flags: int, access: int, sd: Any
        ) -> int:
            world.created_desktop_names.append(name)
            if not world.create_desktop_handle:
                world.last_error = 8
            return world.create_desktop_handle

        def close_desktop(handle: Any) -> int:
            world.closed_desktops.append(getattr(handle, "value", handle))
            if not world.close_desktop_ok:
                world.last_error = 6
                return 0
            return 1

        def user_object_information(
            handle: Any, index: int, buffer: Any, size: int, required_ref: Any
        ) -> int:
            name = world._reported()
            if buffer is None:
                required_ref._obj.value = (
                    (len(name) + 1) * ctypes.sizeof(ctypes.c_wchar) if name else 0
                )
                return 1
            if world.name_readback_fails:
                world.last_error = 31
                return 0
            buffer.value = name
            return 1

        def enum_desktop_windows(handle: Any, callback: Any, param: Any) -> int:
            if not world.enum_ok:
                world.last_error = world.enum_error
                return 0
            for hwnd in world.windows:
                callback(hwnd, 0)
            return 1

        def window_pid(hwnd: int, pid_ref: Any) -> int:
            pid_ref._obj.value = int(world.windows[hwnd]["pid"])
            return 1

        def text_length(hwnd: int) -> int:
            return len(str(world.windows[hwnd].get("title") or ""))

        def window_text(hwnd: int, buffer: Any, size: int) -> int:
            buffer.value = str(world.windows[hwnd].get("title") or "")
            return len(buffer.value)

        def class_name(hwnd: int, buffer: Any, size: int) -> int:
            buffer.value = str(world.windows[hwnd].get("class_name") or "Window")
            return len(buffer.value)

        def window_rect(hwnd: int, rect_ref: Any) -> int:
            rect = rect_ref._obj
            left, top, right, bottom = world.windows[hwnd].get("rect", (0, 0, 0, 0))
            rect.left, rect.top, rect.right, rect.bottom = left, top, right, bottom
            return 1

        def is_visible(hwnd: int) -> int:
            return 1 if world.windows[hwnd].get("visible") else 0

        def is_enabled(hwnd: int) -> int:
            return 1 if world.windows[hwnd].get("enabled", True) else 0

        def is_iconic(hwnd: int) -> int:
            return 1 if world.windows[hwnd].get("minimized") else 0

        return types.SimpleNamespace(
            CreateDesktopW=create_desktop,
            CloseDesktop=close_desktop,
            GetUserObjectInformationW=user_object_information,
            EnumDesktopWindows=enum_desktop_windows,
            GetWindowThreadProcessId=window_pid,
            GetWindowTextLengthW=text_length,
            GetWindowTextW=window_text,
            GetClassNameW=class_name,
            GetWindowRect=window_rect,
            IsWindowVisible=is_visible,
            IsWindowEnabled=is_enabled,
            IsIconic=is_iconic,
        )

    def _build_kernel32(self) -> types.SimpleNamespace:
        world = self

        def create_process(
            app: Any,
            cmdline: Any,
            process_attrs: Any,
            thread_attrs: Any,
            inherit: Any,
            flags: int,
            environment: Any,
            cwd: Any,
            startup_ref: Any,
            process_ref: Any,
        ) -> int:
            world.create_process_calls.append(
                {
                    "cmdline": cmdline.value,
                    "cwd": cwd,
                    "flags": flags,
                    "desktop": startup_ref._obj.lpDesktop,
                }
            )
            if not world.create_process_ok:
                world.last_error = 5
                return 0
            info = process_ref._obj
            info.hProcess = world.process_handle
            info.hThread = None
            info.dwProcessId = world.pid
            return 1

        def close_handle(handle: Any) -> int:
            world.closed_handles.append(getattr(handle, "value", handle))
            return 1

        def wait_for(handle: Any, milliseconds: int) -> int:
            world.wait_calls.append(int(milliseconds))
            if world.wait_results:
                return world.wait_results.pop(0)
            return _WAIT_OBJECT_0

        def exit_code(handle: Any, value_ref: Any) -> int:
            if not world.exit_code_ok:
                world.last_error = 6
                return 0
            value_ref._obj.value = world.exit_code
            return 1

        def terminate(handle: Any, code: int) -> int:
            world.terminated.append(getattr(handle, "value", handle))
            if not world.terminate_ok:
                world.last_error = 5
                return 0
            return 1

        return types.SimpleNamespace(
            CreateProcessW=create_process,
            CloseHandle=close_handle,
            WaitForSingleObject=wait_for,
            GetExitCodeProcess=exit_code,
            TerminateProcess=terminate,
        )


def _install(monkeypatch: pytest.MonkeyPatch, world: _Win32World) -> None:
    monkeypatch.setattr(hd, "os", _NtOsProxy())
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, use_last_error=False: {
            "user32": world.user32,
            "kernel32": world.kernel32,
        }[name],
        raising=False,
    )
    monkeypatch.setattr(
        ctypes,
        "WinError",
        lambda code=0: OSError(f"win32 error {code}"),
        raising=False,
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: world.last_error, raising=False)
    monkeypatch.setattr(
        ctypes,
        "set_last_error",
        lambda value: setattr(world, "last_error", value),
        raising=False,
    )


def _streams() -> dict[str, Any]:
    return {"stdin": io.StringIO(), "stdout": io.StringIO(), "stderr": io.StringIO()}


def _process(world: _Win32World, monkeypatch: pytest.MonkeyPatch) -> hd.DesktopProcess:
    _install(monkeypatch, world)
    return hd.DesktopProcess(
        args=["worker.exe"],
        process_handle=world.process_handle,
        pid=world.pid,
        **_streams(),
    )


# --------------------------------------------------------------------------- #
# platform guard and pure helpers
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_the_platform_guard_refuses_off_windows() -> None:
    with pytest.raises(hd.HiddenDesktopError, match="require Windows"):
        hd.HiddenDesktop.create()
    with pytest.raises(hd.HiddenDesktopError, match="require Windows"):
        hd.create_process_on_desktop(["x.exe"], "WinSta0\\D")


def test_environment_block_sorts_entries_case_insensitively() -> None:
    block = hd._environment_block({"b": "2", "A": "1", "Z": "3"})
    text = block[:]
    assert "A=1\x00b=2\x00Z=3\x00\x00" in text


# --------------------------------------------------------------------------- #
# HiddenDesktop.create and the name round-trip
# --------------------------------------------------------------------------- #


def test_create_round_trips_the_desktop_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World()
    _install(monkeypatch, world)

    desktop = hd.HiddenDesktop.create(prefix="Probe")

    assert desktop.name.startswith("Probe-")
    assert desktop.qualified_name == rf"WinSta0\{desktop.name}"
    assert world.created_desktop_names == [desktop.name]
    assert world.closed_desktops == []


def test_create_raises_when_the_desktop_cannot_be_made(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(create_desktop_handle=0)
    _install(monkeypatch, world)
    with pytest.raises(OSError, match="win32 error"):
        hd.HiddenDesktop.create()


def test_create_closes_the_handle_when_the_identity_does_not_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(reported_name="SomebodyElse")
    _install(monkeypatch, world)
    with pytest.raises(hd.HiddenDesktopError, match="did not round-trip"):
        hd.HiddenDesktop.create()
    assert world.closed_desktops == [777]


def test_desktop_name_reports_empty_when_no_size_comes_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(reported_name="")
    _install(monkeypatch, world)
    assert hd._desktop_name(world.user32, 777) == ""


def test_desktop_name_raises_when_the_readback_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(reported_name="Probe", name_readback_fails=True)
    _install(monkeypatch, world)
    with pytest.raises(OSError, match="win32 error"):
        hd._desktop_name(world.user32, 777)


# --------------------------------------------------------------------------- #
# window enumeration, filtering, snapshot
# --------------------------------------------------------------------------- #

_TWO_WINDOWS: dict[int, JsonObject] = {
    11: {
        "pid": 42,
        "title": "Analyzer",
        "class_name": "MainWnd",
        "visible": True,
        "rect": (0, 0, 800, 600),
    },
    22: {
        "pid": 99,
        "title": "",
        "class_name": "Ghost",
        "visible": False,
        "minimized": True,
        "rect": (0, 0, 0, 0),
    },
}


def test_windows_reports_every_row_with_geometry(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(windows=_TWO_WINDOWS)
    _install(monkeypatch, world)
    desktop = hd.HiddenDesktop("D", 777)

    rows = desktop.windows()

    assert [row["hwnd"] for row in rows] == [11, 22]
    first = rows[0]
    assert first["pid"] == 42
    assert first["title"] == "Analyzer"
    assert first["class_name"] == "MainWnd"
    assert first["visible"] is True
    assert first["rect"]["width"] == 800
    assert first["area"] == 800 * 600
    assert rows[1]["minimized"] is True


def test_windows_filters_to_the_allowed_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(windows=_TWO_WINDOWS)
    _install(monkeypatch, world)
    desktop = hd.HiddenDesktop("D", 777)

    rows = desktop.windows(allowed_pids=frozenset({42}))
    assert [row["pid"] for row in rows] == [42]

    descriptions = desktop.process_window_descriptions(42)
    assert descriptions == ["MainWnd:Analyzer (hwnd=11)"]


def test_enumeration_raises_only_when_a_real_error_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failing = _Win32World(enum_ok=False, enum_error=5)
    _install(monkeypatch, failing)
    with pytest.raises(OSError, match="win32 error"):
        hd.HiddenDesktop("D", 777).windows()

    benign = _Win32World(enum_ok=False, enum_error=0)
    _install(monkeypatch, benign)
    assert hd.HiddenDesktop("D", 777).windows() == []


def test_a_closed_desktop_enumerates_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(windows=_TWO_WINDOWS)
    _install(monkeypatch, world)
    desktop = hd.HiddenDesktop("D", 777)
    desktop.close()
    assert desktop.windows() == []


def test_snapshot_ranks_capturable_windows_first(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(windows=_TWO_WINDOWS)
    _install(monkeypatch, world)
    desktop = hd.HiddenDesktop("D", 777)

    snapshot = desktop.snapshot(allowed_pids=frozenset({42, 99}))

    assert snapshot["available"] is True
    assert snapshot["mode"] == "hidden_win32"
    assert snapshot["input_desktop"] is False
    assert snapshot["window_count"] == 2
    assert snapshot["desktop_window_count"] == 2
    assert snapshot["windows"][0]["hwnd"] == 11, "the visible sized window ranks first"


# --------------------------------------------------------------------------- #
# capture authorization
# --------------------------------------------------------------------------- #


def test_capture_refuses_a_window_off_the_authorized_desktop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(windows=_TWO_WINDOWS)
    _install(monkeypatch, world)
    desktop = hd.HiddenDesktop("D", 777)
    with pytest.raises(hd.HiddenDesktopError, match="not on the authorized"):
        desktop.capture(22, allowed_pids=frozenset({42}), output_path="out.png")


def test_capture_forwards_an_authorized_window(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(windows=_TWO_WINDOWS)
    _install(monkeypatch, world)
    forwarded: list[tuple[int, frozenset[int], Any]] = []

    def fake_capture(hwnd: int, pids: frozenset[int], path: Any) -> JsonObject:
        forwarded.append((hwnd, pids, path))
        return {"ok": True}

    monkeypatch.setattr(
        "headless_re_mcp.core.ui_win32.capture_hwnd_screenshot", fake_capture
    )
    desktop = hd.HiddenDesktop("D", 777)

    result = desktop.capture(11, allowed_pids=frozenset({42}), output_path="out.png")

    assert result == {"ok": True}
    assert forwarded == [(11, frozenset({42}), "out.png")]


# --------------------------------------------------------------------------- #
# close and the context manager
# --------------------------------------------------------------------------- #


def test_close_releases_the_handle_once(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World()
    _install(monkeypatch, world)
    with hd.HiddenDesktop("D", 777) as desktop:
        pass
    desktop.close()
    assert world.closed_desktops == [777], "a second close must not touch the handle again"


def test_close_raises_when_the_handle_cannot_be_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(close_desktop_ok=False)
    _install(monkeypatch, world)
    desktop = hd.HiddenDesktop("D", 777)
    with pytest.raises(OSError, match="win32 error"):
        desktop.close()


# --------------------------------------------------------------------------- #
# spawn
# --------------------------------------------------------------------------- #


def test_spawn_refuses_a_closed_desktop(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World()
    _install(monkeypatch, world)
    desktop = hd.HiddenDesktop("D", 777)
    desktop.close()
    with pytest.raises(hd.HiddenDesktopError, match="closed"):
        desktop.spawn(["x.exe"])


def test_spawn_forwards_to_the_qualified_desktop(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World()
    _install(monkeypatch, world)
    calls: list[tuple[Any, str]] = []
    sentinel = object()

    def fake_create(args: Any, desktop: str, **kw: Any) -> Any:
        calls.append((args, desktop))
        return sentinel

    monkeypatch.setattr(hd, "create_process_on_desktop", fake_create)
    desktop = hd.HiddenDesktop("Probe", 777)

    assert desktop.spawn(["x.exe", "--flag"]) is sentinel
    assert calls == [(["x.exe", "--flag"], r"WinSta0\Probe")]


# --------------------------------------------------------------------------- #
# create_process_on_desktop
# --------------------------------------------------------------------------- #


def _fake_msvcrt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(get_osfhandle=lambda fd: fd))


def test_create_process_rejects_empty_args(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World()
    _install(monkeypatch, world)
    _fake_msvcrt(monkeypatch)
    with pytest.raises(ValueError, match="must not be empty"):
        hd.create_process_on_desktop([], "WinSta0\\D")


def test_create_process_launches_on_the_named_desktop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(pid=515, process_handle=808)
    _install(monkeypatch, world)
    _fake_msvcrt(monkeypatch)

    process = hd.create_process_on_desktop(
        ["worker.exe", "--attach"], "WinSta0\\Probe", cwd="C:\\work"
    )
    try:
        assert process.pid == 515
        assert process.args == ["worker.exe", "--attach"]
        call = world.create_process_calls[0]
        assert call["desktop"] == "WinSta0\\Probe"
        assert call["cwd"] == "C:\\work"
        assert "worker.exe --attach" in call["cmdline"]
        assert process.stdout.read() == "", "the child write end is closed, so EOF"
    finally:
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
        process._close_handle()


def test_create_process_raises_and_cleans_up_when_the_launch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(create_process_ok=False)
    _install(monkeypatch, world)
    _fake_msvcrt(monkeypatch)
    with pytest.raises(OSError, match="win32 error"):
        hd.create_process_on_desktop(["worker.exe"], "WinSta0\\D")


# --------------------------------------------------------------------------- #
# DesktopProcess poll / wait / terminate
# --------------------------------------------------------------------------- #


def test_poll_reports_none_while_the_process_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _process(_Win32World(wait_results=[_WAIT_TIMEOUT]), monkeypatch)
    assert process.poll() is None


def test_poll_collects_the_exit_code_and_closes_the_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(wait_results=[_WAIT_OBJECT_0], exit_code=7)
    process = _process(world, monkeypatch)

    assert process.poll() == 7
    assert world.closed_handles == [1234]
    # The second poll answers from the cached returncode.
    assert process.poll() == 7
    assert world.closed_handles == [1234]


def test_poll_raises_when_the_wait_itself_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _process(_Win32World(wait_results=[_WAIT_FAILED]), monkeypatch)
    with pytest.raises(OSError, match="win32 error"):
        process.poll()


def test_poll_raises_when_the_exit_code_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(wait_results=[_WAIT_OBJECT_0], exit_code_ok=False)
    process = _process(world, monkeypatch)
    with pytest.raises(OSError, match="win32 error"):
        process.poll()


def test_wait_times_out_like_popen(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(wait_results=[_WAIT_TIMEOUT])
    process = _process(world, monkeypatch)
    with pytest.raises(subprocess.TimeoutExpired):
        process.wait(timeout=1.5)
    assert world.wait_calls == [1500]


def test_wait_without_a_deadline_blocks_forever(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(wait_results=[_WAIT_OBJECT_0], exit_code=3)
    process = _process(world, monkeypatch)

    assert process.wait() == 3
    assert world.wait_calls == [_INFINITE]
    # A second wait answers from the cached returncode without another API call.
    assert process.wait() == 3
    assert world.wait_calls == [_INFINITE]


def test_wait_raises_on_an_unexpected_wait_result(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _process(_Win32World(wait_results=[_WAIT_FAILED]), monkeypatch)
    with pytest.raises(OSError, match="win32 error"):
        process.wait(timeout=1.0)


def test_terminate_skips_a_process_that_already_exited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(wait_results=[_WAIT_OBJECT_0], exit_code=0)
    process = _process(world, monkeypatch)
    process.terminate()
    assert world.terminated == []


def test_kill_terminates_a_running_process(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World(wait_results=[_WAIT_TIMEOUT])
    process = _process(world, monkeypatch)
    process.kill()
    assert world.terminated == [1234]


def test_terminate_raises_when_the_kill_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _Win32World(wait_results=[_WAIT_TIMEOUT], terminate_ok=False)
    process = _process(world, monkeypatch)
    with pytest.raises(OSError, match="win32 error"):
        process.terminate()


def test_close_handle_releases_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _Win32World()
    process = _process(world, monkeypatch)
    process._close_handle()
    process._close_handle()
    assert world.closed_handles == [1234]
