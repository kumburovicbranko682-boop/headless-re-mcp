from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.backends.ida.gate as gate_module
from headless_re_mcp.config import Settings


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            return fh.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


def test_idalib_gate_timeout_kills_the_whole_process_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeout used to kill only the launcher, then hang draining inherited pipes."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ")
    child_file = tmp_path / "child.pid"
    script = tmp_path / "sleeper.py"
    script.write_text(
        "import subprocess, sys\n"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(child_file)!r}, 'w').write(str(c.pid))\n"
        "import time; time.sleep(60)\n"
    )
    real_popen = subprocess.Popen
    launched: dict[str, int] = {}

    def fake_popen(cmd: object, **kwargs: object) -> subprocess.Popen[str]:
        proc = real_popen(
            [sys.executable, str(script)],
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
            text=True,
        )
        launched["pid"] = proc.pid
        return proc

    monkeypatch.setattr(gate_module.subprocess, "Popen", fake_popen)
    settings = replace(Settings.load(), ida_home=tmp_path)

    started = time.monotonic()
    result = gate_module.run_idalib_gate(binary, settings, timeout=0.4)
    elapsed = time.monotonic() - started
    time.sleep(0.15)

    child_pid = int(child_file.read_text()) if child_file.exists() else -1
    try:
        assert result.ok is False
        assert elapsed < 3.0, f"drain hung for {elapsed:.3f}s after a 0.4s timeout"
        assert not _alive(launched["pid"])
        assert child_pid > 0
        assert not _alive(child_pid), f"child {child_pid} still alive after gate timeout"
    finally:
        with suppress(OSError):
            os.kill(child_pid, 9)
        with suppress(OSError):
            os.kill(launched["pid"], 9)
