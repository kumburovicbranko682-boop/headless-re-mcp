"""Managed subprocess terminate must kill the process the child started."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

import pytest

from headless_re_mcp.backends.common import subprocess_rpc
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)

_LAUNCHER = (
    "import os, subprocess, sys, time\n"
    "flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0\n"
    "child = subprocess.Popen([sys.executable, '-c', "
    "'import time\\nwhile True: time.sleep(0.2)'], creationflags=flags)\n"
    "print('CHILD', child.pid, flush=True)\n"
    "while True: time.sleep(0.2)\n"
)


def _pid_is_alive(pid: int) -> bool:
    import ctypes

    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


class _Dummy(ManagedSubprocessMixin):
    def __init__(self, process: subprocess.Popen[Any]) -> None:
        self._process = process
        self._observed_windows: set[str] = set()


def _dead_process() -> subprocess.Popen[Any]:
    """A real (already-exited) Popen: gives a genuine pid without a live child.

    The window-probe and tree-killer are monkeypatched in these tests, so the
    process only needs a valid ``pid``; reaping it here keeps the suite clean.
    """
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc


def test_pid_reflects_the_underlying_process() -> None:
    proc = _dead_process()
    assert _Dummy(proc).pid == proc.pid


def test_analyzer_windows_returns_sorted_titles_and_accumulates_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # analyzer_windows is what the service layer polls to notice a debugger
    # popping a modal window; it must return a stable, sorted view and never
    # forget a title once seen, even if a later probe reports fewer.
    proc = _dead_process()
    dummy = _Dummy(proc)
    monkeypatch.setattr(subprocess_rpc, "describe_process_windows", lambda pid: {"Zed", "Alpha"})
    assert list(dummy.analyzer_windows) == ["Alpha", "Zed"]
    assert dummy._observed_windows == {"Alpha", "Zed"}

    monkeypatch.setattr(subprocess_rpc, "describe_process_windows", lambda pid: {"Beta"})
    assert list(dummy.analyzer_windows) == ["Beta"]
    assert dummy._observed_windows == {"Alpha", "Zed", "Beta"}


def test_terminate_process_delegates_to_the_tree_killer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc = _dead_process()
    calls: list[tuple[int, float]] = []

    def fake_kill(process: subprocess.Popen[Any], *, wait_s: float) -> None:
        calls.append((process.pid, wait_s))

    monkeypatch.setattr(subprocess_rpc, "terminate_process_tree", fake_kill)
    _Dummy(proc).terminate_process(wait_timeout=1.5)
    assert calls == [(proc.pid, 1.5)]


def test_managed_terminate_kills_the_process_the_child_started() -> None:
    """terminate()/kill() on the spawned process left its child running.

    Measured: launcher dead after terminate_process(), sleeper still alive.
    """
    if os.name != "nt":
        pytest.skip("descendant enumeration here is Win32 (skip != pass)")

    process = subprocess.Popen(
        [sys.executable, "-c", _LAUNCHER],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **no_window_popen_kwargs(),
    )
    assert process.stdout is not None
    child = int(process.stdout.readline().split()[1])
    started = time.monotonic()
    _Dummy(process).terminate_process(wait_timeout=1.0)
    elapsed = time.monotonic() - started

    assert elapsed < 10.0, f"mixin terminate hung for {elapsed:.1f}s"
    assert _pid_is_alive(process.pid) is False
    assert _pid_is_alive(child) is False
