from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.gate as gate_module
from headless_re_mcp.core.models import Architecture


def _write_minimal_pe(path: Path, machine: int) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


class _FakeProcess:
    pid = 4242

    def __init__(self, *, delay: float = 0.0) -> None:
        self.returncode: int | None = 0
        self.delay = delay
        self.input: str | None = None
        self.killed = False

    def communicate(
        self,
        input: str | None = None,
        timeout: float | None = None,
    ) -> tuple[str, str]:
        assert timeout is not None
        self.input = input
        if self.delay:
            time.sleep(self.delay)
        return "[headless] entering command loop...\n", ""

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_command_loop_gate_uses_isolated_user_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x8664)
    process = _FakeProcess()
    launch: dict[str, Any] = {}

    def fake_popen(args: list[str], **kwargs: object) -> _FakeProcess:
        launch["args"] = args
        launch["kwargs"] = kwargs
        return process

    monkeypatch.setattr(gate_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(gate_module, "describe_process_windows", lambda _pid: ())

    result = gate_module.run_command_loop_gate(
        executable,
        Architecture.X64,
        timeout=1.0,
    )

    args = launch["args"]
    assert result.ok
    assert process.input == "state\nexit\n"
    assert args[:2] == [str(executable), "-userdir"]
    assert not Path(args[2]).exists()
    assert launch["kwargs"]["encoding"] == "utf-8"


def test_command_loop_gate_rejects_analyzer_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x014C)
    process = _FakeProcess(delay=0.08)

    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        gate_module,
        "describe_process_windows",
        lambda _pid: ("x32dbg analyzer window",),
    )

    result = gate_module.run_command_loop_gate(
        executable,
        Architecture.X86,
        timeout=1.0,
    )

    assert not result.ok
    assert result.command_loop_seen
    assert result.analyzer_windows == ("x32dbg analyzer window",)


def test_command_loop_gate_rejects_wrong_architecture(tmp_path: Path) -> None:
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x014C)

    with pytest.raises(ValueError, match="expected x64.*got x86"):
        gate_module.run_command_loop_gate(executable, Architecture.X64)


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            return fh.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


def test_command_loop_gate_timeout_kills_the_whole_process_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeout used to kill only the launcher, then hang draining inherited pipes."""
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x8664)
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

    def fake_popen(args: object, **kwargs: object) -> subprocess.Popen[str]:
        proc = real_popen(
            [sys.executable, str(script)],
            stdin=kwargs.get("stdin"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
            text=True,
        )
        launched["pid"] = proc.pid
        return proc

    monkeypatch.setattr(gate_module.subprocess, "Popen", fake_popen)

    started = time.monotonic()
    result = gate_module.run_command_loop_gate(
        executable,
        Architecture.X64,
        timeout=0.4,
    )
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