"""idalib gate timeout must kill what the worker started and still return."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.backends.ida.gate as gate
from headless_re_mcp.config import Settings


def test_idalib_gate_timeout_kills_what_the_launcher_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """process.kill left the child holding the pipes.

    Measured: timeout 0.4s, then communicate(10) raised TimeoutExpired
    after 10.4s total; the sleeper the launcher started was still alive.
    The gate never returned a result.
    """
    pid_path = tmp_path / "child.pid"
    launcher = tmp_path / "launcher.py"
    launcher.write_text(
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.25)'])\n"
        f"open({str(pid_path)!r}, 'w').write(str(child.pid))\n"
        "while True: time.sleep(0.25)\n",
        encoding="utf-8",
    )
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    real_popen = subprocess.Popen

    def fake_popen(argv: object, **kwargs: object) -> subprocess.Popen[str]:
        command = list(argv) if isinstance(argv, (list, tuple)) else argv
        if any("gate_worker" in str(part) for part in command):
            command = [sys.executable, str(launcher)]
        return real_popen(command, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(gate.subprocess, "Popen", fake_popen)
    settings = replace(Settings.load(), ida_home=tmp_path)
    started = time.monotonic()
    result = gate.run_idalib_gate(binary, settings, timeout=0.4)
    elapsed = time.monotonic() - started

    assert result.ok is False
    assert "timed out" in str(result.payload.get("error") or "")
    assert elapsed < 5.0
    assert pid_path.is_file()
    child = int(pid_path.read_text())
    deadline = time.monotonic() + 2.0
    alive = True
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except OSError:
            alive = False
            break
        time.sleep(0.05)
    assert alive is False, "the process the gate worker started outlived the timeout"
