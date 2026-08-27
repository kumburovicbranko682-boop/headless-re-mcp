"""Shared subprocess lifecycle helpers used by the IDA / x64dbg clients."""

from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common import subprocess_rpc
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)


def test_no_window_popen_kwargs_shape() -> None:
    kwargs = no_window_popen_kwargs()
    assert set(kwargs) == {"creationflags", "startupinfo"}
    # On this POSIX runner there is no console window to suppress.
    assert kwargs["creationflags"] == 0
    assert kwargs["startupinfo"] is None


class _Managed(ManagedSubprocessMixin):
    def __init__(self, process: Any, lock: Any = None) -> None:
        self._process = process
        self._observed_windows = set()
        if lock is not None:
            self._lock = lock


def test_pid_reads_the_process(monkeypatch: pytest.MonkeyPatch) -> None:
    managed = _Managed(SimpleNamespace(pid=4321))
    assert managed.pid == 4321


def test_analyzer_windows_sorts_and_remembers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess_rpc, "describe_process_windows", lambda pid: {"Zeta", "Alpha"}
    )
    managed = _Managed(SimpleNamespace(pid=1))
    titles = managed.analyzer_windows
    assert titles == ("Alpha", "Zeta")
    assert managed._observed_windows == {"Alpha", "Zeta"}


def test_terminate_process_uses_a_lock_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Any, float]] = []
    monkeypatch.setattr(
        subprocess_rpc,
        "terminate_process_tree",
        lambda process, *, wait_s: seen.append((process, wait_s)),
    )
    process = SimpleNamespace(pid=7)
    managed = _Managed(process, lock=threading.Lock())
    managed.terminate_process(wait_timeout=1.5)
    assert seen == [(process, 1.5)]


def test_terminate_process_falls_back_to_nullcontext(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Any, float]] = []
    monkeypatch.setattr(
        subprocess_rpc,
        "terminate_process_tree",
        lambda process, *, wait_s: seen.append((process, wait_s)),
    )
    process = SimpleNamespace(pid=9)
    managed = _Managed(process)  # no _lock attribute
    managed.terminate_process()
    assert seen == [(process, 3.0)]
