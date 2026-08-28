"""The x64dbg gate's window-poll loop and timeout arm, runnable on Linux.

test_xdbg_gate.py drives the verdict logic with a fake process that answers in
80 ms -- faster than the 250 ms window-poll interval -- so the monitor thread's
loop body never executes there. And the only test of the timeout arm,
test_xdbg_gate_timeout.py, is skipped off Windows because it checks the real
descendant kill. That leaves the poll body, the timeout's tree-kill-then-drain
sequence, and the drain-also-failed fallback unexecuted on the platform CI
runs on. This file covers them with fakes: the tree kill itself stays pinned
by the Windows test; here the contract under test is what the gate does with
its result -- drained output is reported, a failed drain reports empty streams
and exit code -1 rather than inventing data, and a window seen mid-run fails
the gate even if the process exits cleanly afterwards.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.gate as gate_module
from headless_re_mcp.core.models import Architecture


def _write_minimal_pe(path: Path, machine: int = 0x8664) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


class _SlowProcess:
    """Answers cleanly, but only after the window monitor has polled."""

    pid = 4242

    def __init__(self, delay: float) -> None:
        self.returncode: int | None = 0
        self._delay = delay

    def communicate(
        self, input: str | None = None, timeout: float | None = None
    ) -> tuple[str, str]:
        time.sleep(self._delay)
        return "[headless] entering command loop...\n", ""


class _TimingOutProcess:
    """First communicate overruns; the drain after the kill is configurable."""

    pid = 4242

    def __init__(self, drain: tuple[str, str] | Exception) -> None:
        self.returncode: int | None = None
        self.communicate_calls = 0
        self._drain = drain

    def communicate(
        self, input: str | None = None, timeout: float | None = None
    ) -> tuple[str, str]:
        self.communicate_calls += 1
        if self.communicate_calls == 1:
            raise subprocess.TimeoutExpired(cmd="headless.exe", timeout=timeout or 0.0)
        if isinstance(self._drain, Exception):
            raise self._drain
        return self._drain


def _gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process: Any,
    *,
    windows: tuple[str, ...] = (),
) -> gate_module.XdbgHeadlessGateResult:
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable)
    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(gate_module, "describe_process_windows", lambda _pid: windows)
    return gate_module.run_command_loop_gate(executable, Architecture.X64, timeout=1.0)


# --------------------------------------------------------------------------- #
# the monitor thread polls while the gate waits                               #
# --------------------------------------------------------------------------- #
def test_the_window_monitor_polls_while_the_gate_is_still_waiting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A window that is only visible mid-run must still fail the gate.

    The final enumeration after the process exits cannot see it; only the
    polling thread can, so the poll body itself is what this pins.
    """
    executable = tmp_path / "headless.exe"
    _write_minimal_pe(executable)
    calls: list[float] = []

    def windows_seen_mid_run(_pid: int) -> tuple[str, ...]:
        calls.append(time.monotonic())
        # Visible only while the process is alive: the final post-exit
        # enumeration (always executed) reports nothing.
        return ("x64dbg analyzer",) if len(calls) == 1 else ()

    process = _SlowProcess(delay=0.4)  # longer than the 0.25s poll interval
    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(gate_module, "describe_process_windows", windows_seen_mid_run)

    result = gate_module.run_command_loop_gate(executable, Architecture.X64, timeout=5.0)

    assert len(calls) >= 2, "the monitor must have polled before the final enumeration"
    assert result.command_loop_seen is True
    assert result.exit_code == 0
    assert result.analyzer_windows == ("x64dbg analyzer",)
    assert result.ok is False, "a mid-run window fails the gate despite the clean exit"


# --------------------------------------------------------------------------- #
# the timeout arm: kill the tree, then report what could be drained           #
# --------------------------------------------------------------------------- #
def test_a_timed_out_gate_kills_the_tree_and_reports_the_drained_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _TimingOutProcess(drain=("partial stdout\n", "partial stderr\n"))
    killed: list[Any] = []

    def fake_tree_kill(target: Any, **kwargs: Any) -> list[int]:
        killed.append(target)
        target.returncode = -9
        return [target.pid]

    monkeypatch.setattr(gate_module, "terminate_process_tree", fake_tree_kill)

    result = _gate(tmp_path, monkeypatch, process)

    assert killed == [process], "the whole tree is killed, not just the launcher"
    assert process.communicate_calls == 2, "after the kill the streams are drained"
    assert result.ok is False
    assert result.exit_code == -9
    assert result.stdout == "partial stdout\n"
    assert result.stderr == "partial stderr\n"
    assert result.command_loop_seen is False


def test_a_timed_out_gate_whose_drain_also_fails_reports_empty_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When even the post-kill drain fails, the gate must say 'nothing' --
    empty streams and exit code -1 -- rather than raise or invent output."""
    process = _TimingOutProcess(drain=ValueError("I/O operation on closed file"))
    monkeypatch.setattr(gate_module, "terminate_process_tree", lambda t, **k: [])

    result = _gate(tmp_path, monkeypatch, process)

    assert result.ok is False
    assert result.stdout == ""
    assert result.stderr == ""
    assert result.exit_code == -1, "no exit code was observed, so none is invented"
    assert result.command_loop_seen is False
