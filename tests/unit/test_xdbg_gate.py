from __future__ import annotations

import subprocess
import threading
import time
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


def test_gate_result_round_trips_to_dict() -> None:
    result = gate_module.XdbgHeadlessGateResult(
        ok=True,
        architecture=Architecture.X64,
        executable="headless.exe",
        exit_code=0,
        stdout="out",
        stderr="err",
        analyzer_windows=("w",),
        command_loop_seen=True,
    )
    assert result.to_dict() == {
        "ok": True,
        "architecture": "x64",
        "executable": "headless.exe",
        "exit_code": 0,
        "stdout": "out",
        "stderr": "err",
        "analyzer_windows": ["w"],
        "command_loop_seen": True,
    }


def test_command_loop_gate_monitor_polls_while_the_worker_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x8664)
    polled = threading.Event()

    class _SlowProcess(_FakeProcess):
        def communicate(
            self,
            input: str | None = None,
            timeout: float | None = None,
        ) -> tuple[str, str]:
            assert polled.wait(5)
            return super().communicate(input=input, timeout=timeout)

    def describe(_pid: int) -> tuple[str, ...]:
        polled.set()
        return ("poll window",)

    monkeypatch.setattr(gate_module, "_WINDOW_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *_a, **_k: _SlowProcess())
    monkeypatch.setattr(gate_module, "describe_process_windows", describe)

    result = gate_module.run_command_loop_gate(executable, Architecture.X64, timeout=5.0)

    assert result.ok is False
    assert result.analyzer_windows == ("poll window",)


class _HungProcess(_FakeProcess):
    def __init__(self) -> None:
        super().__init__()
        self.returncode = None
        self.calls = 0

    def communicate(
        self,
        input: str | None = None,
        timeout: float | None = None,
    ) -> tuple[str, str]:
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired(cmd="headless.exe", timeout=timeout or 0)
        return "drained tail", "late stderr"


def test_command_loop_gate_timeout_terminates_the_tree_and_drains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x8664)
    process = _HungProcess()
    killed: list[Any] = []

    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(gate_module, "describe_process_windows", lambda _pid: ())
    monkeypatch.setattr(gate_module, "terminate_process_tree", killed.append)

    result = gate_module.run_command_loop_gate(executable, Architecture.X64, timeout=0.1)

    assert killed == [process]
    assert result.ok is False
    assert result.exit_code == -1
    assert result.stdout == "drained tail"
    assert result.stderr == "late stderr"
