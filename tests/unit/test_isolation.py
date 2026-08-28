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


def test_a_required_timeout_refuses_to_continue() -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del command, kwargs
        raise subprocess.TimeoutExpired(cmd="revert.ps1", timeout=1.0)

    runner = IsolationRunner(IsolationPolicy(command=("revert.ps1",)), run=run)

    with pytest.raises(IsolationError) as caught:
        runner.rotate()
    assert "Timeout" in str(caught.value)


def test_policy_reads_a_string_command_as_a_shell_style_argv(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    from headless_re_mcp.config import Settings

    base = replace(Settings.load(), artifact_root=tmp_path)
    policy = IsolationPolicy.from_settings(
        replace(base, isolation_command='pwsh -File "C:/vm/revert.ps1"')
    )

    assert policy.command == ("pwsh", "-File", "C:/vm/revert.ps1")
    assert policy.configured is True


def test_policy_keeps_windows_paths_intact(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """POSIX shlex eats backslashes: C:\\vm\\revert.ps1 becomes C:vmrevert.ps1."""
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core import isolation as isolation_mod

    base = replace(Settings.load(), artifact_root=tmp_path)
    monkeypatch.setattr(isolation_mod, "is_windows_host", lambda: True)
    policy = IsolationPolicy.from_settings(
        replace(base, isolation_command=r'pwsh -File "C:\Program Files\vm\revert.ps1"')
    )

    assert policy.command == ("pwsh", "-File", r"C:\Program Files\vm\revert.ps1")


def test_policy_refuses_a_windows_command_carrying_a_nul(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The Windows split smuggles backslashes through a NUL sentinel.

    A raw command that already contains a NUL would round-trip back into a
    backslash and silently rewrite the operator's argv -- turning, say, a
    argument boundary into a path separator. Rather than corrupt the one
    command whose whole job is to give the next sample a clean machine, the
    splitter refuses it. (POSIX hosts never reach this arm; pin it under a
    forced Windows host.)
    """
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core import isolation as isolation_mod

    base = replace(Settings.load(), artifact_root=tmp_path)
    monkeypatch.setattr(isolation_mod, "is_windows_host", lambda: True)
    with pytest.raises(ValueError, match="must not contain NUL"):
        IsolationPolicy.from_settings(
            replace(base, isolation_command="revert.ps1\x00--snapshot clean")
        )


def test_settings_load_splits_an_env_command_as_argv(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The env var is a command line, not a comma-separated set."""
    from headless_re_mcp.config import Settings

    monkeypatch.setenv(
        "HEADLESS_RE_ISOLATION_COMMAND",
        r'pwsh -File "C:\Program Files\vm\revert.ps1" --snapshot clean',
    )
    monkeypatch.delenv("HEADLESS_RE_ISOLATION_REQUIRED", raising=False)
    settings = Settings.load()
    assert settings.isolation_command == (
        "pwsh",
        "-File",
        r"C:\Program Files\vm\revert.ps1",
        "--snapshot",
        "clean",
    )


def test_policy_defaults_to_not_configured_and_fail_closed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    from headless_re_mcp.config import Settings

    policy = IsolationPolicy.from_settings(replace(Settings.load(), artifact_root=tmp_path))

    assert policy.configured is False
    assert policy.required is True


def test_the_default_runner_is_the_one_that_binds_children() -> None:
    """The injectable run is for tests. The default has to be the bounded one."""
    import inspect

    from headless_re_mcp.core import isolation

    assert IsolationRunner().run is None
    assert IsolationRunner().run is not subprocess.run
    assert "run_bounded" in inspect.getsource(isolation.IsolationRunner._invoke)


def test_a_command_that_finishes_is_still_reported_as_performed() -> None:
    import sys

    policy = IsolationPolicy(command=(sys.executable, "-c", "import sys; sys.exit(0)"))
    outcome = IsolationRunner(policy).rotate(reason="quant")

    assert outcome["ok"] is True
    assert outcome["performed"] is True


def test_a_real_timeout_returns_instead_of_waiting_out_the_child(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The operator's command is a launcher. Killing only it leaves the tool.

    Measured against a Python launcher that starts a sleeper: a 1s deadline
    returned in 1.0s and the child was still running. On Windows the post-kill
    drain has no timeout, so the same shape can also park the scheduler for
    good -- isolation runs off the loop, but a supervisor polling /readyz will
    restart the process in the middle of a rollback that never finished.
    """
    import os
    import sys
    import time
    from contextlib import suppress

    marker = tmp_path / "child.pid"
    launcher = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"Path({str(marker)!r}).write_text(str(child.pid))\n"
        "while True: time.sleep(0.2)\n"
    )
    policy = IsolationPolicy(
        command=(sys.executable, "-c", launcher),
        timeout_s=0.8,
        required=False,
    )
    started = time.monotonic()
    try:
        outcome = IsolationRunner(policy).rotate(reason="quant")
        elapsed = time.monotonic() - started

        assert outcome["ok"] is False
        assert "timed out" in str(outcome["detail"]).lower()
        assert elapsed < 10.0
    finally:
        if marker.is_file():
            with suppress(OSError, ValueError):
                os.kill(int(marker.read_text()), 9)
