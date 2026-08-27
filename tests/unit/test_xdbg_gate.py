from __future__ import annotations

import subprocess
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


def test_result_to_dict_is_a_plain_serializable_mapping() -> None:
    result = gate_module.XdbgHeadlessGateResult(
        ok=True,
        architecture=Architecture.X64,
        executable="/tmp/headless.exe",
        exit_code=0,
        stdout="[headless] entering command loop",
        stderr="",
        analyzer_windows=("0x1:Cls:Title",),
        command_loop_seen=True,
    )
    assert result.to_dict() == {
        "ok": True,
        "architecture": "x64",
        "executable": "/tmp/headless.exe",
        "exit_code": 0,
        "stdout": "[headless] entering command loop",
        "stderr": "",
        "analyzer_windows": ["0x1:Cls:Title"],
        "command_loop_seen": True,
    }


class _TimeoutProcess:
    """A launch that never finishes the command loop within the deadline."""

    pid = 4243

    def __init__(self) -> None:
        self.returncode: int | None = None
        self._communicate_calls = 0
        self.killed = False

    def communicate(
        self,
        input: str | None = None,
        timeout: float | None = None,
    ) -> tuple[str, str]:
        self._communicate_calls += 1
        if self._communicate_calls == 1:
            raise subprocess.TimeoutExpired(cmd="headless.exe", timeout=timeout or 0.0)
        return "", ""

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int | None:
        return self.returncode


def test_command_loop_gate_kills_a_process_that_overruns_the_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """communicate() timing out must kill the tree, not hang or crash.

    process.kill() alone stops the headless executable and leaves whatever it
    started running; the gate calls terminate_process_tree instead. Here the
    launch is faked so the timeout arm runs off Windows: the result is not ok,
    the command loop was never seen, and the killed exit code is carried
    through rather than an exception escaping.
    """
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x8664)
    process = _TimeoutProcess()

    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(gate_module, "describe_process_windows", lambda _pid: ())

    result = gate_module.run_command_loop_gate(
        executable,
        Architecture.X64,
        timeout=0.2,
    )

    assert process.killed is True
    assert result.ok is False
    assert result.command_loop_seen is False
    assert result.exit_code == -9
    assert result.stdout == ""


def test_command_loop_gate_enumerates_windows_while_the_process_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The background monitor must actually poll, not just sample on exit.

    With the poll interval shrunk and the launch made to linger, the monitor
    thread's enumeration loop runs while the process is alive -- the arc that
    catches an analyzer window popping up mid-run rather than only at teardown.
    """
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable, 0x8664)
    monkeypatch.setattr(gate_module, "_WINDOW_POLL_INTERVAL", 0.01)
    process = _FakeProcess(delay=0.15)

    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(gate_module, "describe_process_windows", lambda _pid: {"popup-window"})

    result = gate_module.run_command_loop_gate(
        executable,
        Architecture.X64,
        timeout=1.0,
    )

    assert result.analyzer_windows == ("popup-window",)
    assert result.ok is False
