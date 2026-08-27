"""Supervisor gate: ``supervise`` restarts a real crashed child and stops honestly.

The Supervisor class is unit-tested end to end with injected fakes; nothing so
far has run the actual ``python -m headless_re_mcp supervise`` CLI over real
child processes. This gate does, and pins the two behaviours an unattended
deployment stands on:

* a child that dies is restarted: kill the real serve-web child and a new one
  comes up answering ``/healthz`` on the same port, and the bounded-restart
  contract holds -- after ``--max-restarts`` is spent the supervisor stops on
  its own, reporting ``restart_limit`` with honest counters, instead of
  restarting forever;
* refusal is not a crash: when another console already holds the artifact
  root, the child looks at its environment and exits with the sysexits
  refusal code 78; the supervisor reports ``child_refused_to_start`` after
  exactly one start and never restarts it, because a restart cannot change a
  configuration that refuses to run.

All observations come from the supervisor's own structured JSON log lines on
stdout -- the interface an operator reads -- plus real HTTP probes against the
child. Pure Python end to end; no analysis backend is opened.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BOOT_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _isolated_env(tmp_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_root / "artifacts")
    env["XDG_CONFIG_HOME"] = str(tmp_root / "config")
    env["APPDATA"] = str(tmp_root / "config")
    env["LOCALAPPDATA"] = str(tmp_root / "config")
    return env


def _hard_kill(pid: int) -> None:
    """End the process without giving it a graceful-shutdown exit code 0."""
    if sys.platform == "win32":
        os.kill(pid, signal.SIGTERM)
    else:
        os.kill(pid, signal.SIGKILL)


class _SupervisorLog:
    """Collect the supervisor's stdout JSON lines as they arrive."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self.process = process
        self.records: list[dict[str, Any]] = []
        self.raw: list[str] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            with self._lock:
                self.raw.append(line.rstrip())
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    self.records.append(parsed)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.records)

    def wait_for(self, predicate: Any, *, timeout: float, what: str) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for record in self.snapshot():
                if predicate(record):
                    return record
            time.sleep(0.1)
        raise AssertionError(f"never observed {what}; log so far: {self.raw}")


def _wait_healthy(port: int, *, timeout: float = _BOOT_TIMEOUT_S) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2.0).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    raise AssertionError(f"child never answered /healthz on port {port}")


def _spawn_supervisor(env: dict[str, str], port: int, *extra: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "headless_re_mcp",
            "supervise",
            "--target",
            "serve-web",
            "--port",
            str(port),
            "--check-interval",
            "1",
            "--no-readiness",
            *extra,
        ],
        cwd=str(_PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@pytest.mark.integration
@pytest.mark.headless
def test_supervisor_restarts_a_crashed_child_and_stops_at_the_limit(tmp_path: Path) -> None:
    env = _isolated_env(tmp_path)
    port = _free_port()
    supervisor = _spawn_supervisor(env, port, "--max-restarts", "2")
    log = _SupervisorLog(supervisor)
    try:
        first = log.wait_for(
            lambda r: r.get("event") == "child.started" and r.get("attempt") == 1,
            timeout=_BOOT_TIMEOUT_S,
            what="the first child start",
        )
        first_pid = int(first["pid"])
        _wait_healthy(port)

        # Kill the real child; the supervisor must notice and bring up another.
        _hard_kill(first_pid)
        restarting = log.wait_for(
            lambda r: r.get("event") == "child.restarting",
            timeout=30.0,
            what="the restart decision",
        )
        assert restarting["reason"] == "crashed"

        second = log.wait_for(
            lambda r: r.get("event") == "child.started" and r.get("attempt") == 2,
            timeout=30.0,
            what="the replacement child",
        )
        second_pid = int(second["pid"])
        assert second_pid != first_pid
        _wait_healthy(port)

        # A second crash spends the restart budget: the supervisor stops on
        # its own with honest counters instead of restarting forever.
        _hard_kill(second_pid)
        log.wait_for(
            lambda r: r.get("event") == "supervisor.restart_limit",
            timeout=30.0,
            what="the restart limit",
        )
        assert supervisor.wait(timeout=30.0) == 1
        report = log.wait_for(
            lambda r: "stopped_reason" in r,
            timeout=10.0,
            what="the final report",
        )
        assert report["ok"] is False
        assert report["stopped_reason"] == "restart_limit"
        assert report["starts"] == 2
        assert report["crash_restarts"] == 2
        assert report["unhealthy_restarts"] == 0
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=15.0)


@pytest.mark.integration
@pytest.mark.headless
def test_supervisor_reports_a_refusing_child_instead_of_restarting_it(tmp_path: Path) -> None:
    env = _isolated_env(tmp_path)

    # A real console already holds the artifact root, so the supervised child
    # will refuse with sysexits code 78 rather than fight over the database.
    holder_port = _free_port()
    holder = subprocess.Popen(
        [sys.executable, "-m", "headless_re_mcp", "serve-web", "--port", str(holder_port)],
        cwd=str(_PROJECT_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        text=True,
    )
    supervisor: subprocess.Popen[str] | None = None
    try:
        _wait_healthy(holder_port)

        supervisor = _spawn_supervisor(env, _free_port())
        log = _SupervisorLog(supervisor)
        refused = log.wait_for(
            lambda r: r.get("event") == "supervisor.child_refused",
            timeout=_BOOT_TIMEOUT_S,
            what="the refusal verdict",
        )
        assert refused["exit_code"] == 78

        assert supervisor.wait(timeout=30.0) == 1
        report = log.wait_for(
            lambda r: "stopped_reason" in r,
            timeout=10.0,
            what="the final report",
        )
        assert report["stopped_reason"] == "child_refused_to_start"
        assert report["starts"] == 1
        assert report["crash_restarts"] == 0
        started = [r for r in log.snapshot() if r.get("event") == "child.started"]
        assert len(started) == 1, "a refusing child must not be restarted"
    finally:
        if supervisor is not None and supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=15.0)
        holder.terminate()
        try:
            holder.wait(timeout=15.0)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.wait(timeout=15.0)
