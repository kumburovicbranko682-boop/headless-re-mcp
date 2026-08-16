from __future__ import annotations

import subprocess
from pathlib import Path
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


def test_a_timeout_kills_the_process_the_command_started(tmp_path: Path) -> None:
    """subprocess.run left the isolation child running after the deadline.

    Measured: a script that launched sleep 60 and then slept still left
    the child alive after a 0.4s timeout, so an overnight rollback that
    starts a hypervisor CLI would keep that process for the rest of the
    service life.
    """
    import os
    import time

    child_pid_file = tmp_path / "child.pid"
    script = tmp_path / "spawn_and_sleep.sh"
    script.write_text(
        "#!/bin/sh\n"
        f"sleep 60 &\n"
        f"echo $! > {child_pid_file}\n"
        "sleep 60\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    runner = IsolationRunner(
        IsolationPolicy(command=(str(script),), timeout_s=0.4, required=False)
    )
    started = time.monotonic()
    outcome = runner.rotate(reason="measure")
    elapsed = time.monotonic() - started
    assert outcome["ok"] is False
    assert "Timeout" in str(outcome["detail"])
    # run_bounded drains pipes for up to 5s after the kill.
    assert elapsed < 7.0
    child_pid = int(child_pid_file.read_text(encoding="utf-8").strip())
    still = os.path.exists(f"/proc/{child_pid}")
    if still:
        os.kill(child_pid, 9)
    assert still is False


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