"""Coverage for the shared subprocess lifecycle helpers off Windows.

The mixin's ``pid``/``analyzer_windows``/``terminate_process`` and the Windows
arm of ``no_window_popen_kwargs`` were only reachable through Win32-only tests
that skip here, leaving ``subprocess_rpc.py`` at 58%. None of the behaviour is
truly Windows specific: the mixin just delegates, and the Windows kwargs arm is
exercised by pinning ``os.name`` and standing in for the Win32 console
constants the same way the process-group tests do.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

import pytest

import headless_re_mcp.backends.common.subprocess_rpc as rpc
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)


class _FakeProcess:
    def __init__(self, pid: int = 4321) -> None:
        self.pid = pid


class _Managed(ManagedSubprocessMixin):
    def __init__(self, process: Any, lock: Any = None) -> None:
        self._process = process
        self._observed_windows: set[str] = set()
        if lock is not None:
            self._lock = lock


# --------------------------------------------------------------------------- #
# no_window_popen_kwargs                                                      #
# --------------------------------------------------------------------------- #
def test_no_window_kwargs_are_inert_off_windows() -> None:
    kwargs = no_window_popen_kwargs()
    assert kwargs == {"creationflags": 0, "startupinfo": None}


def test_no_window_kwargs_hide_the_console_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Windows arm must request a hidden console, not just a flag.

    Pins the logic that off-Windows CI never runs: the CREATE_NO_WINDOW
    creation flag, the STARTF_USESHOWWINDOW bit set on the startupinfo, and
    wShowWindow forced to SW_HIDE (0).
    """

    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 5

    # os / subprocess are the same module objects the helper imported, so
    # patching them here changes what no_window_popen_kwargs sees.
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001, raising=False)
    monkeypatch.setattr(subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)

    kwargs = no_window_popen_kwargs()

    assert kwargs["creationflags"] == 0x08000000
    startupinfo = kwargs["startupinfo"]
    assert startupinfo is not None
    assert startupinfo.dwFlags & 0x00000001
    assert startupinfo.wShowWindow == 0


# --------------------------------------------------------------------------- #
# ManagedSubprocessMixin                                                      #
# --------------------------------------------------------------------------- #
def test_pid_is_the_processes_pid_as_an_int() -> None:
    managed = _Managed(_FakeProcess(pid=1234))
    assert managed.pid == 1234
    assert isinstance(managed.pid, int)


def test_analyzer_windows_are_sorted_and_accumulated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each read returns the current windows sorted and remembers every title.

    ``_observed_windows`` is the audit set the gate consults to fail a run that
    ever popped a window, so a title seen once must stick even after it closes.
    """
    windows = {"zeta", "alpha"}
    monkeypatch.setattr(rpc, "describe_process_windows", lambda _pid: set(windows))
    managed = _Managed(_FakeProcess())

    assert list(managed.analyzer_windows) == ["alpha", "zeta"]
    assert managed._observed_windows == {"alpha", "zeta"}

    windows = {"beta"}
    assert list(managed.analyzer_windows) == ["beta"]
    # The earlier titles are retained even though they are gone now.
    assert managed._observed_windows == {"alpha", "beta", "zeta"}


class _RecordingLock:
    def __init__(self) -> None:
        self.depth = 0
        self.entered = False

    def __enter__(self) -> _RecordingLock:
        self.entered = True
        self.depth += 1
        return self

    def __exit__(self, *_exc: object) -> None:
        self.depth -= 1


def test_terminate_process_kills_the_tree_under_the_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Termination must delegate to the tree kill while holding the lock.

    A bare process.kill() leaves the tools the launcher started running; the
    mixin calls terminate_process_tree instead, and it must do so under the
    instance lock so a concurrent RPC cannot race the teardown.
    """
    lock = _RecordingLock()
    process = _FakeProcess()
    seen: dict[str, Any] = {}

    def fake_tree_kill(proc: Any, *, wait_s: float = 3.0) -> list[int]:
        seen["proc"] = proc
        seen["wait_s"] = wait_s
        seen["locked"] = lock.depth
        return [proc.pid]

    monkeypatch.setattr(rpc, "terminate_process_tree", fake_tree_kill)

    _Managed(process, lock=lock).terminate_process(wait_timeout=1.5)

    assert lock.entered is True
    assert lock.depth == 0
    assert seen["proc"] is process
    assert seen["wait_s"] == 1.5
    assert seen["locked"] == 1


def test_terminate_process_without_a_lock_uses_a_null_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An instance that never set ``_lock`` still terminates cleanly."""
    process = _FakeProcess()
    called: dict[str, Any] = {}

    def fake_tree_kill(proc: Any, *, wait_s: float = 3.0) -> list[int]:
        called["wait_s"] = wait_s
        return []

    monkeypatch.setattr(rpc, "terminate_process_tree", fake_tree_kill)

    managed = _Managed(process)
    assert not hasattr(managed, "_lock")
    managed.terminate_process()

    assert called["wait_s"] == 3.0


def test_managed_subprocess_mixin_import_is_stable() -> None:
    # Guards against the helper module losing its public surface.
    assert issubclass(_Managed, ManagedSubprocessMixin)
    assert callable(no_window_popen_kwargs)
    assert os.name in {"nt", "posix"}
