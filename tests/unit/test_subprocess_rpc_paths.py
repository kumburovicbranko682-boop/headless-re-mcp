"""Shared subprocess lifecycle helpers for the IDA / x64dbg clients.

Everything here is portable: the Windows console-hiding branch is reached by
faking ``os.name``, and the window/termination helpers are replaced so no real
process is ever launched.
"""

from __future__ import annotations

from threading import RLock
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.common.subprocess_rpc as subprocess_rpc
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)


def test_no_window_kwargs_are_inert_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess_rpc.os, "name", "posix")

    kwargs = no_window_popen_kwargs()

    assert kwargs["creationflags"] == 0
    assert kwargs["startupinfo"] is None


def test_no_window_kwargs_hide_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 99

    monkeypatch.setattr(subprocess_rpc.os, "name", "nt")
    monkeypatch.setattr(subprocess_rpc.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess_rpc.subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)
    monkeypatch.setattr(subprocess_rpc.subprocess, "STARTF_USESHOWWINDOW", 1, raising=False)

    kwargs = no_window_popen_kwargs()

    assert kwargs["creationflags"] == 0x08000000
    startupinfo = kwargs["startupinfo"]
    assert startupinfo.wShowWindow == 0
    assert startupinfo.dwFlags & 1


class _Managed(ManagedSubprocessMixin):
    def __init__(self, pid: int, *, lock: Any = None) -> None:
        self._process = SimpleNamespace(pid=pid)
        self._observed_windows: set[str] = set()
        if lock is not None:
            self._lock = lock


def test_pid_reads_the_underlying_process() -> None:
    assert _Managed(4321).pid == 4321


def test_analyzer_windows_are_sorted_and_remembered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess_rpc, "describe_process_windows", lambda _pid: {"Beta", "Alpha"}
    )
    managed = _Managed(10)

    titles = managed.analyzer_windows

    assert titles == ("Alpha", "Beta")
    assert managed._observed_windows == {"Alpha", "Beta"}


def test_analyzer_windows_with_no_windows_stays_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess_rpc, "describe_process_windows", lambda _pid: set())
    managed = _Managed(10)

    assert managed.analyzer_windows == ()
    assert managed._observed_windows == set()


def test_terminate_process_uses_a_null_lock_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[Any, float]] = []
    monkeypatch.setattr(
        subprocess_rpc,
        "terminate_process_tree",
        lambda process, *, wait_s=5.0: seen.append((process, wait_s)),
    )
    managed = _Managed(10)

    managed.terminate_process(wait_timeout=1.5)

    assert seen == [(managed._process, 1.5)]


def test_terminate_process_holds_the_lock_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[float] = []
    monkeypatch.setattr(
        subprocess_rpc,
        "terminate_process_tree",
        lambda process, *, wait_s=5.0: calls.append(wait_s),
    )
    managed = _Managed(10, lock=RLock())

    managed.terminate_process()

    assert calls == [3.0]
