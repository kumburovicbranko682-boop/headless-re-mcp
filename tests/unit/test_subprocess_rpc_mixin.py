"""Cross-platform contract for the shared managed-subprocess mixin.

The existing terminate test proves descendant killing, but it is Win32-only and
skips on Linux, leaving the mixin's shape, properties, and lock seam unexercised
on the Linux CI job. These tests pin the parts that hold on every platform: the
no-console launch kwargs, the ``pid`` / ``analyzer_windows`` properties, and that
``terminate_process`` honours an optional ``_lock`` and actually reaps the
process it was given.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from threading import RLock

import pytest

from headless_re_mcp.backends.common import subprocess_rpc
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)


class _Dummy(ManagedSubprocessMixin):
    def __init__(self, process: subprocess.Popen[bytes], *, lock: RLock | None = None) -> None:
        self._process = process
        self._observed_windows: set[str] = set()
        if lock is not None:
            self._lock = lock


def _spawn_sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen([sys.executable, "-c", "import time\nwhile True: time.sleep(0.2)"])


def test_no_window_kwargs_shape_matches_the_platform() -> None:
    kwargs = no_window_popen_kwargs()
    assert set(kwargs) == {"creationflags", "startupinfo"}
    if os.name == "nt":
        # Suppress both the console window and the initial ShowWindow.
        assert kwargs["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
        assert kwargs["startupinfo"] is not None
        assert kwargs["startupinfo"].wShowWindow == 0
    else:
        assert kwargs["creationflags"] == 0
        assert kwargs["startupinfo"] is None


def test_pid_property_reports_the_process_pid() -> None:
    process = _spawn_sleeper()
    try:
        assert _Dummy(process).pid == process.pid
    finally:
        process.kill()
        process.wait(timeout=5.0)


def test_analyzer_windows_is_sorted_and_accumulates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _spawn_sleeper()
    dummy = _Dummy(process)
    try:
        monkeypatch.setattr(
            subprocess_rpc,
            "describe_process_windows",
            lambda pid: {"0x2:C:later", "0x1:C:earlier"},
        )
        assert dummy.analyzer_windows == ("0x1:C:earlier", "0x2:C:later")
        assert dummy._observed_windows == {"0x1:C:earlier", "0x2:C:later"}

        # A window that closes drops out of the live tuple but the cumulative
        # sighting set still remembers it.
        monkeypatch.setattr(subprocess_rpc, "describe_process_windows", lambda pid: set())
        assert dummy.analyzer_windows == tuple()
        assert dummy._observed_windows == {"0x1:C:earlier", "0x2:C:later"}
    finally:
        process.kill()
        process.wait(timeout=5.0)


def test_terminate_process_reaps_the_process_without_a_lock() -> None:
    process = _spawn_sleeper()
    started = time.monotonic()
    _Dummy(process).terminate_process(wait_timeout=2.0)
    assert time.monotonic() - started < 10.0
    assert process.poll() is not None


def test_terminate_process_holds_the_optional_lock() -> None:
    process = _spawn_sleeper()
    lock = RLock()
    _Dummy(process, lock=lock).terminate_process(wait_timeout=2.0)
    assert process.poll() is not None
    # The lock was released, not left held, so a subsequent acquire succeeds.
    assert lock.acquire(blocking=False) is True
    lock.release()
