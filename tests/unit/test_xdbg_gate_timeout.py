"""x64dbg headless gate timeout must kill the process the executable started."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg import gate as gate_mod
from headless_re_mcp.backends.x64dbg.gate import run_command_loop_gate
from headless_re_mcp.core.models import Architecture

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


def test_xdbg_gate_timeout_kills_the_process_the_executable_started(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """process.kill() stopped the headless exe and left the child running.

    Measured: timeout 0.8s returned in 0.81s with ok False, while the
    sleeper the launcher started was still alive. An overnight doctor
    probe that overran then held a core for the rest of the process life.
    """
    if os.name != "nt":
        pytest.skip("descendant enumeration here is Win32 (skip != pass)")

    exe = tmp_path / "headless.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(gate_mod, "detect_pe_architecture", lambda path: Architecture.X64)

    real_popen = subprocess.Popen
    seen = {"first": True}

    def fake_popen(cmd: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        if seen["first"]:
            seen["first"] = False
            return real_popen([sys.executable, "-c", _LAUNCHER], **kwargs)
        return real_popen(cmd, **kwargs)

    monkeypatch.setattr(gate_mod.subprocess, "Popen", fake_popen)

    started = time.monotonic()
    result = run_command_loop_gate(exe, Architecture.X64, timeout=0.8)
    elapsed = time.monotonic() - started

    assert elapsed < 10.0, f"xdbg gate timeout hung for {elapsed:.1f}s"
    assert result.ok is False
    child = None
    for line in (result.stdout or "").splitlines():
        if line.startswith("CHILD"):
            child = int(line.split()[1])
    assert child is not None
    assert _pid_is_alive(child) is False
