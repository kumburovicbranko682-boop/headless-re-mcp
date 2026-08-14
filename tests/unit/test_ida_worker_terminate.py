"""IDA worker terminate must kill the process the worker started."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.backends.ida.client import IdaWorkerClient

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


def test_ida_worker_terminate_kills_the_process_the_worker_started() -> None:
    """terminate()/kill() on the worker left its child running.

    Measured: launcher dead after terminate(), sleeper still alive. An
    overnight session.close then held a core and the database for the rest
    of the process life.
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
    line = process.stdout.readline()
    child = int(line.split()[1])
    client = IdaWorkerClient.__new__(IdaWorkerClient)
    client._process = process
    client._closed = False

    started = time.monotonic()
    client.terminate()
    elapsed = time.monotonic() - started

    assert elapsed < 10.0, f"ida terminate hung for {elapsed:.1f}s"
    assert _pid_is_alive(process.pid) is False
    assert _pid_is_alive(child) is False
