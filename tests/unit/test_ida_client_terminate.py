"""IDA worker terminate must kill what the worker started."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.backends.ida.client as ida_client
from headless_re_mcp.config import Settings


def test_ida_client_terminate_kills_what_the_worker_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """process.kill left the child running after the client returned.

    Measured: terminate() returned in 0.13s with the parent gone and the
    sleeper the worker started still alive. An unattended close then
    leaked the idalib process and its database lock.
    """
    pid_path = tmp_path / "child.pid"
    launcher = tmp_path / "worker.py"
    launcher.write_text(
        "import json, subprocess, sys, time\n"
        "print(json.dumps({'event':'ready','data':{'capabilities':[]}}), flush=True)\n"
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
        if any("ida.worker" in str(part) for part in command):
            command = [sys.executable, str(launcher)]
        return real_popen(command, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ida_client.subprocess, "Popen", fake_popen)
    settings = replace(Settings.load(), ida_home=tmp_path)
    client = ida_client.IdaWorkerClient(binary, settings, startup_timeout=5)
    deadline = time.monotonic() + 2.0
    while not pid_path.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    child = int(pid_path.read_text())
    try:
        client.terminate()
        alive = True
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                os.kill(child, 0)
            except OSError:
                alive = False
                break
            time.sleep(0.05)
        assert alive is False, "the process the IDA worker started outlived terminate"
    finally:
        with suppress(OSError):
            os.kill(child, 9)
