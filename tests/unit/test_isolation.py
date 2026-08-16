from __future__ import annotations

import subprocess
from typing import Any

import pytest

from headless_re_mcp.core.isolation import (
    IsolationError,
    IsolationPolicy,
    IsolationRunner,
)


def _completed(code: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["snapshot"], returncode=code, stdout="", stderr=stderr)


def test_no_configured_command_is_reported_rather_than_pretended() -> None:
    """Plenty of deployments analyse trusted binaries and need no rotation.

    That has to be distinguishable from a rotation that happened, or a report
    cannot say whether the sample ran on a clean machine.
    """
    outcome = IsolationRunner().rotate()

    assert outcome["ok"] is True
    assert outcome["performed"] is False


def test_a_successful_command_is_recorded_as_performed() -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return _completed(0)

    policy = IsolationPolicy(command=("revert.ps1", "--snapshot", "clean"))
    outcome = IsolationRunner(policy, run=run).rotate(reason="mission:abc")

    assert outcome["ok"] is True and outcome["performed"] is True
    assert calls == [["revert.ps1", "--snapshot", "clean"]]
    assert outcome["reason"] == "mission:abc"


def test_a_failing_required_step_refuses_to_continue() -> None:
    """Carrying on is the one outcome that silently cross-contaminates results."""

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return _completed(3, stderr="snapshot not found")

    runner = IsolationRunner(IsolationPolicy(command=("revert.ps1",)), run=run)

    with pytest.raises(IsolationError) as caught:
        runner.rotate()
    assert "exited with 3" in str(caught.value)
    assert "snapshot not found" in str(caught.value.detail["stderr"])


def test_a_failing_optional_step_reports_without_raising() -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return _completed(1)

    runner = IsolationRunner(IsolationPolicy(command=("revert.ps1",), required=False), run=run)
    outcome = runner.rotate()

    assert outcome["ok"] is False
    assert outcome["performed"] is True


def test_a_command_that_cannot_start_is_a_failure_not_a_crash() -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("revert.ps1")

    runner = IsolationRunner(IsolationPolicy(command=("revert.ps1",), required=False), run=run)
    outcome = runner.rotate()

    assert outcome["ok"] is False
    assert "FileNotFoundError" in str(outcome["detail"])


def test_a_timeout_kills_what_the_isolation_command_started(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A snapshot script is often a launcher.

    Measured: a 0.5s isolation timeout returned while the child it started
    was still alive -- so the next sample would rotate on a machine the
    previous revert was still touching.
    """
    import os
    import sys
    import time

    marker = tmp_path / "child.pid"
    body = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        f"child = subprocess.Popen([sys.executable, '-c', "
        f"'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"Path({str(marker)!r}).write_text(str(child.pid))\n"
        "while True:\n"
        "    time.sleep(0.2)\n"
    )
    policy = IsolationPolicy(command=(sys.executable, "-c", body), timeout_s=0.5, required=False)
    child = 0
    try:
        outcome = IsolationRunner(policy).rotate()
        assert outcome["ok"] is False
        deadline = time.monotonic() + 3.0
        while not marker.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.is_file(), "the isolation command never reported its child"
        child = int(marker.read_text().strip())
        while _pid_alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _pid_alive(child) is False, "the isolation child outlived the timeout"
    finally:
        if child and _pid_alive(child):
            os.kill(child, 9)


def _pid_alive(pid: int) -> bool:
    import os

    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def test_a_timeout_is_a_failure() -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="revert.ps1", timeout=1.0)

    runner = IsolationRunner(IsolationPolicy(command=("revert.ps1",), required=False), run=run)
    outcome = runner.rotate()

    assert outcome["ok"] is False
    assert "Timeout" in str(outcome["detail"])


def test_the_timeout_is_passed_to_the_command() -> None:
    seen: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        return _completed(0)

    IsolationRunner(IsolationPolicy(command=("x",), timeout_s=42.0), run=run).rotate()

    assert seen["timeout"] == 42.0
    assert seen["check"] is False


def test_policy_reads_a_string_command_as_a_shell_style_argv(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    from headless_re_mcp.config import Settings

    base = replace(Settings.load(), artifact_root=tmp_path)
    policy = IsolationPolicy.from_settings(
        replace(base, isolation_command='pwsh -File "C:/vm/revert.ps1"')
    )

    assert policy.command == ("pwsh", "-File", "C:/vm/revert.ps1")
    assert policy.configured is True


def test_policy_defaults_to_not_configured_and_fail_closed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    from headless_re_mcp.config import Settings

    policy = IsolationPolicy.from_settings(replace(Settings.load(), artifact_root=tmp_path))

    assert policy.configured is False
    assert policy.required is True