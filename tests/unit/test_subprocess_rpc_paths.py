"""Unit coverage for the shared subprocess lifecycle helpers."""

from __future__ import annotations

import os
import subprocess
import threading
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.common.subprocess_rpc as rpc
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)


class _Managed(ManagedSubprocessMixin):
    def __init__(self, process: Any) -> None:
        self._process = process
        self._observed_windows: set[str] = set()


def test_no_window_kwargs_are_inert_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert no_window_popen_kwargs() == {"creationflags": 0, "startupinfo": None}


def test_no_window_kwargs_hide_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 99

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 1, raising=False)
    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)

    kwargs = no_window_popen_kwargs()

    assert kwargs["creationflags"] == 0x08000000
    info = kwargs["startupinfo"]
    assert info.dwFlags & 1
    assert info.wShowWindow == 0


def test_pid_reads_the_managed_process() -> None:
    assert _Managed(SimpleNamespace(pid=4321)).pid == 4321


def test_analyzer_windows_sorts_and_accumulates_titles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rpc, "describe_process_windows", lambda pid: ["zeta", "alpha"])
    managed = _Managed(SimpleNamespace(pid=7))

    first = managed.analyzer_windows
    assert first == ("alpha", "zeta")

    monkeypatch.setattr(rpc, "describe_process_windows", lambda pid: ["beta"])
    second = managed.analyzer_windows
    assert second == ("beta",)
    assert managed._observed_windows == {"alpha", "beta", "zeta"}


def test_terminate_process_tears_down_the_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, float]] = []
    monkeypatch.setattr(
        rpc,
        "terminate_process_tree",
        lambda process, *, wait_s: calls.append((process, wait_s)),
    )
    process = SimpleNamespace(pid=7)

    _Managed(process).terminate_process(wait_timeout=1.5)

    assert calls == [(process, 1.5)]


def test_terminate_process_honours_an_instance_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = threading.Lock()
    held_during_call: list[bool] = []
    monkeypatch.setattr(
        rpc,
        "terminate_process_tree",
        lambda process, *, wait_s: held_during_call.append(lock.locked()),
    )
    managed = _Managed(SimpleNamespace(pid=7))
    managed._lock = lock  # type: ignore[attr-defined]

    managed.terminate_process()

    assert held_during_call == [True]
    assert not lock.locked()
