"""Cover the managed-subprocess mixin accessors and teardown on POSIX."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

import pytest

import headless_re_mcp.backends.common.subprocess_rpc as sr
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)


@pytest.mark.skipif(
    os.name == "nt", reason="on Windows the kwargs are the real CREATE_NO_WINDOW"
)
def test_no_window_kwargs_are_inert_off_windows() -> None:
    kwargs = no_window_popen_kwargs()
    assert kwargs == {"creationflags": 0, "startupinfo": None}


class _Dummy(ManagedSubprocessMixin):
    def __init__(self, process: Any) -> None:
        self._process = process
        self._observed_windows: set[str] = set()


class _FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid


def test_pid_reads_the_underlying_process() -> None:
    dummy = _Dummy(_FakeProcess(4321))
    assert dummy.pid == 4321


def test_analyzer_windows_sorts_and_remembers_titles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sr, "describe_process_windows", lambda _pid: {"win-b", "win-a"}
    )
    dummy = _Dummy(_FakeProcess(11))
    assert dummy.analyzer_windows == ("win-a", "win-b")
    assert dummy._observed_windows == {"win-a", "win-b"}


def test_terminate_process_kills_a_real_child() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    started = time.monotonic()
    _Dummy(process).terminate_process(wait_timeout=2.0)
    elapsed = time.monotonic() - started

    assert elapsed < 10.0
    assert process.poll() is not None
