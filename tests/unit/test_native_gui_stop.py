"""GUI stop must wait until the owned child has actually exited."""

from __future__ import annotations

import subprocess
import sys
import time

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.native_app.bootstrap import stop_owned_process


def test_stop_owned_process_waits_until_the_child_exits() -> None:
    """Measured: terminate() left poll() None immediately (pid still running).

    The GUI then dropped the handle, so the next start spawned a second
    serve. Overnight two MCP processes fight over IDA. Wait until the
    child is gone before forgetting it.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **no_window_popen_kwargs(),
    )
    time.sleep(0.3)
    assert proc.poll() is None
    t0 = time.perf_counter()
    stop_owned_process(proc, wait_s=5.0)
    elapsed = time.perf_counter() - t0
    assert elapsed < 8.0
    assert proc.poll() is not None

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
    import os

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


def test_stop_owned_process_kills_the_process_the_serve_started() -> None:
    """terminate()/kill() on the serve left IDA running.

    Measured: launcher dead after stop_owned_process, sleeper still alive.
    The next start then fought over the same backend.
    """
    import os

    import pytest

    if os.name != "nt":
        pytest.skip("descendant enumeration here is Win32 (skip != pass)")

    proc = subprocess.Popen(
        [sys.executable, "-c", _LAUNCHER],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **no_window_popen_kwargs(),
    )
    assert proc.stdout is not None
    child = int(proc.stdout.readline().split()[1])
    t0 = time.perf_counter()
    stop_owned_process(proc, wait_s=5.0)
    elapsed = time.perf_counter() - t0
    assert elapsed < 8.0
    assert proc.poll() is not None
    assert _pid_is_alive(child) is False
