"""The x64dbg command-loop gate's monitor loop and timeout kill path.

test_xdbg_gate.py / test_xdbg_gate_timeout.py drive the architecture guard and
the top-level result; the window-monitor loop body and the TimeoutExpired kill
+ drain arm need a fake Popen whose ``communicate`` blocks (so the monitor
iterates) or times out (so the terminate/drain path runs). Nothing real is
launched: subprocess, the PE probe, the userdir seed, window enumeration and
the tree-kill are all patched.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.gate as gate_mod
from headless_re_mcp.backends.x64dbg.gate import run_command_loop_gate
from headless_re_mcp.core.models import Architecture


class _FakeProcess:
    def __init__(self, behaviors: list[Any], *, returncode: int = 0) -> None:
        self.pid = 4321
        self.returncode = returncode
        self._behaviors = behaviors
        self._call = 0

    def communicate(
        self, input: str | None = None, timeout: float | None = None
    ) -> tuple[str, str]:
        behavior = self._behaviors[min(self._call, len(self._behaviors) - 1)]
        self._call += 1
        if isinstance(behavior, BaseException):
            raise behavior
        if callable(behavior):
            return behavior()
        return behavior

    def kill(self) -> None:
        self.returncode = -9

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode


def _install_common(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeProcess,
    *,
    windows: set[str] | None = None,
) -> dict[str, Any]:
    recorded: dict[str, Any] = {"terminated": [], "seeded": []}

    fake_subprocess = SimpleNamespace(
        Popen=lambda *args, **kwargs: process,
        PIPE=subprocess.PIPE,
        TimeoutExpired=subprocess.TimeoutExpired,
    )
    monkeypatch.setattr(gate_mod, "subprocess", fake_subprocess)
    monkeypatch.setattr(
        gate_mod, "detect_pe_architecture", lambda path: Architecture.X64
    )
    monkeypatch.setattr(
        gate_mod, "seed_headless_event_settings", recorded["seeded"].append
    )
    monkeypatch.setattr(
        gate_mod, "describe_process_windows", lambda pid: set(windows or set())
    )
    monkeypatch.setattr(
        gate_mod, "no_window_popen_kwargs", lambda: {}
    )
    monkeypatch.setattr(
        gate_mod,
        "terminate_process_tree",
        lambda proc, **kwargs: recorded["terminated"].append(proc),
    )
    return recorded


def _executable(tmp_path: Path) -> Path:
    path = tmp_path / "x64_headless.exe"
    path.write_bytes(b"MZ fake headless")
    return path


def test_a_clean_run_reports_the_command_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeProcess(
        [("[headless] entering command loop\nstate ok\n", "")], returncode=0
    )
    recorded = _install_common(monkeypatch, process)

    result = run_command_loop_gate(_executable(tmp_path), Architecture.X64)

    assert result.ok is True
    assert result.command_loop_seen is True
    assert result.exit_code == 0
    assert result.analyzer_windows == ()
    assert len(recorded["seeded"]) == 1
    assert recorded["terminated"] == []
    payload = result.to_dict()
    assert payload["ok"] is True
    assert payload["architecture"] == "x64"
    assert payload["analyzer_windows"] == []


def test_observed_windows_make_the_gate_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeProcess(
        [("[headless] entering command loop\n", "")], returncode=0
    )
    _install_common(monkeypatch, process, windows={"x64dbg", "About"})

    result = run_command_loop_gate(_executable(tmp_path), Architecture.X64)

    assert result.ok is False  # a visible analyzer window fails the gate
    assert result.analyzer_windows == ("About", "x64dbg")


def test_the_monitor_loop_enumerates_windows_while_the_run_is_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen_pids: list[int] = []

    def slow_communicate() -> tuple[str, str]:
        time.sleep(0.06)  # let the monitor thread iterate its poll loop
        return ("[headless] entering command loop\n", "")

    process = _FakeProcess([slow_communicate], returncode=0)
    _install_common(monkeypatch, process)
    monkeypatch.setattr(gate_mod, "_WINDOW_POLL_INTERVAL", 0.001)
    monkeypatch.setattr(
        gate_mod,
        "describe_process_windows",
        lambda pid: (seen_pids.append(pid), set())[1],
    )

    result = run_command_loop_gate(_executable(tmp_path), Architecture.X64)

    assert result.ok is True
    # The monitor loop body (and the finally sweep) both queried the live pid.
    assert seen_pids and all(pid == process.pid for pid in seen_pids)


def test_a_timeout_kills_the_tree_and_drains_the_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    timeout = subprocess.TimeoutExpired(cmd="x64_headless.exe", timeout=60.0)
    process = _FakeProcess(
        [timeout, ("drained stdout", "drained stderr")], returncode=1
    )
    recorded = _install_common(monkeypatch, process)

    result = run_command_loop_gate(_executable(tmp_path), Architecture.X64, timeout=0.5)

    assert recorded["terminated"] == [process]
    assert result.stdout == "drained stdout"
    assert result.stderr == "drained stderr"
    assert result.command_loop_seen is False
    assert result.ok is False


def test_a_timeout_whose_drain_also_fails_reports_empty_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    timeout = subprocess.TimeoutExpired(cmd="x64_headless.exe", timeout=60.0)
    drain_failure = subprocess.TimeoutExpired(cmd="x64_headless.exe", timeout=5.0)
    process = _FakeProcess([timeout, drain_failure], returncode=1)
    _install_common(monkeypatch, process)

    result = run_command_loop_gate(_executable(tmp_path), Architecture.X64, timeout=0.5)

    assert result.stdout == ""  # drain raised and was suppressed
    assert result.stderr == ""


def test_an_architecture_mismatch_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeProcess([("", "")])
    _install_common(monkeypatch, process)
    monkeypatch.setattr(
        gate_mod, "detect_pe_architecture", lambda path: Architecture.X86
    )

    with pytest.raises(ValueError, match="expected x64"):
        run_command_loop_gate(_executable(tmp_path), Architecture.X64)
