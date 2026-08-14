"""idalib gate timeout must kill the process the worker started."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ida import gate as gate_mod
from headless_re_mcp.backends.ida.gate import run_idalib_gate
from headless_re_mcp.config import Settings

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


def test_idalib_gate_timeout_kills_the_process_the_worker_started(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """process.kill() stopped the worker and left the child running.

    Measured: timeout 0.8s returned in 0.81s with ok False, while the
    sleeper the launcher started was still alive. An overnight idalib
    probe that overran then held a core and a lock on the sample for the
    rest of the process life.
    """
    if os.name != "nt":
        pytest.skip("descendant enumeration here is Win32 (skip != pass)")

    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    fake_ida = tmp_path / "IDA"
    fake_ida.mkdir()
    settings = replace(Settings.load(), ida_home=fake_ida)

    real_popen = subprocess.Popen
    seen = {"first": True}

    def fake_popen(cmd: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        if seen["first"]:
            seen["first"] = False
            return real_popen([sys.executable, "-c", _LAUNCHER], **kwargs)
        return real_popen(cmd, **kwargs)

    monkeypatch.setattr(gate_mod.subprocess, "Popen", fake_popen)

    started = time.monotonic()
    result = run_idalib_gate(binary, settings, timeout=0.8)
    elapsed = time.monotonic() - started

    assert elapsed < 10.0, f"idalib gate timeout hung for {elapsed:.1f}s"
    assert result.ok is False
    killed = result.payload["killed_pids"]
    assert len(killed) >= 2
    for pid in killed:
        assert _pid_is_alive(int(pid)) is False
