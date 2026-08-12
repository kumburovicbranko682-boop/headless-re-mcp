"""Keep the service running when nobody is watching it.

serve-web is a single foreground uvicorn process: close it and it is gone, crash
it and nothing brings it back. That is fine interactively and disqualifying for
24/7 operation, where the failure nobody sees is the one that matters.

The supervisor restarts the child when it exits and when it stops answering
/readyz, which are different failures: a process can be alive and wedged. Both
are bounded -- restarts back off, and a child that keeps dying quickly is
reported as unrecoverable rather than restarted forever, because a crash loop
that looks like uptime is worse than an honest stop.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

JsonObject = dict[str, Any]

# Restarts that happen faster than this are treated as a crash loop rather than
# as independent failures, so a child that dies on startup cannot spin forever.
HEALTHY_UPTIME_S = 60.0
MAX_RAPID_RESTARTS = 5
BACKOFF_START_S = 1.0
BACKOFF_CAP_S = 30.0


def probe_ready(url: str, *, timeout: float) -> tuple[bool, str]:
    """Ask the child whether it can accept work.

    A non-200 is a definite answer and is reported as such; anything that stops
    the request from completing is reported as unreachable. The distinction
    matters because only one of them means the process is still serving.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed loopback URL
            code = int(response.status)
            return (200 <= code < 300, f"http {code}")
    except urllib.error.HTTPError as exc:
        return (False, f"http {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return (False, f"unreachable: {type(exc).__name__}")


@dataclass(slots=True)
class SupervisorReport:
    """What the supervisor did, for a caller or an operator reading logs."""

    starts: int = 0
    crash_restarts: int = 0
    unhealthy_restarts: int = 0
    stopped_reason: str = "not_started"
    last_exit_code: int | None = None

    def as_json(self) -> JsonObject:
        return {
            "starts": self.starts,
            "crash_restarts": self.crash_restarts,
            "unhealthy_restarts": self.unhealthy_restarts,
            "stopped_reason": self.stopped_reason,
            "last_exit_code": self.last_exit_code,
        }


@dataclass(slots=True)
class Supervisor:
    """Run one child process and keep it running."""

    argv: Sequence[str]
    ready_url: str | None = None
    check_interval_s: float = 10.0
    probe_timeout_s: float = 5.0
    # Give the child room to bind its port and open its stores before the first
    # readiness verdict, or the supervisor restarts a service that was merely
    # still starting.
    grace_period_s: float = 30.0
    unhealthy_strikes: int = 3
    max_restarts: int | None = None
    spawn: Callable[[Sequence[str]], Any] = field(
        default=lambda argv: subprocess.Popen(list(argv))
    )
    probe: Callable[[str, float], tuple[bool, str]] = field(
        default=lambda url, timeout: probe_ready(url, timeout=timeout)
    )
    sleep: Callable[[float], None] = field(default=time.sleep)
    clock: Callable[[], float] = field(default=time.monotonic)
    log: Callable[[JsonObject], None] = field(
        default=lambda record: print(json.dumps(record, ensure_ascii=False), flush=True)
    )
    report: SupervisorReport = field(default_factory=SupervisorReport)

    def run_forever(self) -> SupervisorReport:
        backoff = BACKOFF_START_S
        rapid = 0
        while True:
            started_at = self.clock()
            child = self.spawn(self.argv)
            self.report.starts += 1
            self._log("child.started", pid=getattr(child, "pid", None), attempt=self.report.starts)

            reason = self._watch(child, started_at)
            uptime = self.clock() - started_at
            self.report.last_exit_code = child.poll()

            if reason == "stopped":
                self.report.stopped_reason = "child_exited_cleanly"
                self._log(
                    "child.exited",
                    code=self.report.last_exit_code,
                    uptime_s=round(uptime, 1),
                )
                return self.report

            if reason == "unhealthy":
                self.report.unhealthy_restarts += 1
                self._terminate(child)
            else:
                self.report.crash_restarts += 1

            # An immediate re-crash is one failure repeating, not many separate
            # ones, so only short-lived children count toward the loop limit.
            short_lived = uptime < HEALTHY_UPTIME_S
            rapid = rapid + 1 if short_lived else 0
            backoff = min(backoff * 2, BACKOFF_CAP_S) if short_lived else BACKOFF_START_S
            if rapid >= MAX_RAPID_RESTARTS:
                self.report.stopped_reason = "crash_loop"
                self._log("supervisor.giving_up", rapid_restarts=rapid, reason=reason)
                return self.report
            total = self.report.crash_restarts + self.report.unhealthy_restarts
            if self.max_restarts is not None and total >= self.max_restarts:
                self.report.stopped_reason = "restart_limit"
                self._log("supervisor.restart_limit", restarts=total)
                return self.report

            self._log(
                "child.restarting",
                reason=reason,
                backoff_s=backoff,
                uptime_s=round(uptime, 1),
            )
            self.sleep(backoff)

    def _watch(self, child: Any, started_at: float) -> str:
        """Block until the child exits or fails readiness. Returns why."""
        strikes = 0
        while True:
            self.sleep(self.check_interval_s)
            code = child.poll()
            if code is not None:
                return "stopped" if code == 0 else "crashed"
            if not self.ready_url:
                continue
            if self.clock() - started_at < self.grace_period_s:
                continue
            ready, detail = self.probe(self.ready_url, self.probe_timeout_s)
            if ready:
                strikes = 0
                continue
            strikes += 1
            self._log("child.unhealthy", detail=detail, strikes=strikes)
            if strikes >= self.unhealthy_strikes:
                return "unhealthy"

    def _terminate(self, child: Any) -> None:
        with_terminate = getattr(child, "terminate", None)
        if callable(with_terminate):
            with_terminate()
        wait = getattr(child, "wait", None)
        if callable(wait):
            try:
                wait(timeout=15)
            except (subprocess.TimeoutExpired, TypeError):
                kill = getattr(child, "kill", None)
                if callable(kill):
                    kill()

    def _log(self, event: str, **fields: Any) -> None:
        self.log({"event": event, "component": "supervisor", **fields})


def build_child_argv(
    target: str,
    *,
    host: str | None = None,
    port: int | None = None,
    config: str | None = None,
) -> list[str]:
    """Re-invoke this interpreter, so the child inherits the same environment."""
    argv = [sys.executable, "-m", "headless_re_mcp"]
    if config:
        argv += ["--config", config]
    argv.append(target)
    if target == "serve-web":
        if host:
            argv += ["--host", host]
        if port is not None:
            argv += ["--port", str(port)]
    return argv