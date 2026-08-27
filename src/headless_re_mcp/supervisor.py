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

import http.client
import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.platform_support import is_windows_host
from headless_re_mcp.process_group import assign_to_process_group

JsonObject = dict[str, Any]

# Restarts that happen faster than this are treated as a crash loop rather than
# as independent failures, so a child that dies on startup cannot spin forever.
HEALTHY_UPTIME_S = 60.0
MAX_RAPID_RESTARTS = 5
BACKOFF_START_S = 1.0
BACKOFF_CAP_S = 30.0
# urlopen's socket timeout is not an overall deadline. The caller can stop
# waiting on the join, but Python cannot kill the thread still blocked inside
# urlopen, so a permanently trickling child would add one blocked daemon on
# every health interval. Admit no replacement probe until that one unwinds.
_ready_probe_slots = threading.BoundedSemaphore(1)


def probe_ready(url: str, *, timeout: float) -> tuple[bool, str]:
    """Ask the child whether it can accept work.

    A non-200 is a definite answer and is reported as such; anything that stops
    the request from completing is reported as unreachable. The distinction
    matters because only one of them means the process is still serving.

    ``urlopen(..., timeout=)`` is the socket timeout. A child that accepts the
    connection and delivers one header byte inside that window resets it, so
    the probe never returns and the supervisor cannot count a strike. Measured:
    timeout 0.5s, one ``H`` every 250ms, returned after 4.016s when the
    listener finally hung up (BadStatusLine) -- the full hold, not the bound.
    The join is the overall deadline; a late answer is still used if it
    arrived before we gave up.
    """
    bound = max(0.05, float(timeout))
    box: list[tuple[bool, str] | BaseException] = []
    slots = _ready_probe_slots
    if not slots.acquire(blocking=False):
        # A prior probe is still blocked inside urlopen. Count this interval as
        # a failed check now rather than stacking another daemon behind it.
        return (False, "unreachable: ProbeAlreadyRunning")

    def work() -> None:
        try:
            with urllib.request.urlopen(url, timeout=bound) as response:  # noqa: S310 - fixed loopback URL
                code = int(response.status)
                box.append((200 <= code < 300, f"http {code}"))
        except urllib.error.HTTPError as exc:
            box.append((False, f"http {exc.code}"))
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            # A child wedged badly enough to answer with a malformed response
            # raises this, and it is not an OSError. That is the case a
            # readiness check exists to catch, so it must read as unreachable
            # rather than escape.
            http.client.HTTPException,
        ) as exc:
            box.append((False, f"unreachable: {type(exc).__name__}"))
        except BaseException as exc:  # noqa: BLE001 - handed to the join
            box.append(exc)
        finally:
            slots.release()

    thread = threading.Thread(target=work, name="ready-probe", daemon=True)
    try:
        thread.start()
    except BaseException as exc:  # noqa: BLE001 - a probe cannot end supervision
        slots.release()
        return (False, f"unreachable: {type(exc).__name__}")
    thread.join(bound)
    if box:
        result = box[0]
        if isinstance(result, BaseException):
            return (False, f"unreachable: {type(result).__name__}")
        return result
    return (False, "unreachable: TimeoutError")


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
    # An exit meaning the target declined to run rather than failed to. 78 is
    # the sysexits convention for a correct invocation against a configuration
    # that cannot work, and it is far enough from the small numbers an ordinary
    # crash produces not to catch one by accident. Measured before this: a
    # second supervisor restarted a child that was refusing on a 2, 4, 8, 16
    # second backoff, logging only "crashed", while the reason the child gave
    # went to its own console rather than the supervisor's log.
    refusal_exit_codes: frozenset[int] = frozenset({78})
    # Spawned without a console: the supervisor exists to restart the child, so
    # a visible window here means one new window per restart on a machine that
    # is meant to be running unattended.
    spawn: Callable[[Sequence[str]], Any] = field(
        default=lambda argv: subprocess.Popen(list(argv), **no_window_popen_kwargs())
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
    # The child currently being watched, so an interrupt can take it down too.
    _running: Any | None = field(default=None, init=False, repr=False)

    def run_forever(self) -> SupervisorReport:
        try:
            return self._supervise()
        finally:
            # Nothing else will. A child outlives its parent on Windows, so an
            # interrupt here left a web server running -- with the debuggers
            # and the debuggees it owns -- and nothing supervising it, while
            # the next start crash-looped against the port it still held.
            running = self._running
            self._running = None
            if running is not None and running.poll() is None:
                self._terminate(running)

    def _supervise(self) -> SupervisorReport:
        backoff = BACKOFF_START_S
        rapid = 0
        while True:
            started_at = self.clock()
            child = self._spawn_child()
            self._running = child
            if child is None:
                # Nothing started, so nothing ran. Counted and backed off as a
                # child that died at once, which is what it amounts to.
                self.report.crash_restarts += 1
                reason = "spawn_failed"
                uptime = 0.0
            else:
                self.report.starts += 1
                self._log(
                    "child.started",
                    pid=getattr(child, "pid", None),
                    attempt=self.report.starts,
                )

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

                if self.report.last_exit_code in self.refusal_exit_codes:
                    # Not a crash. The target looked at its environment, decided
                    # it must not run, and said so. Restarting cannot change
                    # that, and the reason it printed went to its own console
                    # rather than here, so an operator reading this log would
                    # otherwise see nothing but "crashed" on a loop.
                    self.report.stopped_reason = "child_refused_to_start"
                    self._log(
                        "supervisor.child_refused",
                        exit_code=self.report.last_exit_code,
                        detail="the target refused to start; a restart cannot change that",
                    )
                    return self.report

                if reason == "unhealthy":
                    self.report.unhealthy_restarts += 1
                    self._terminate(child)
                else:
                    self.report.crash_restarts += 1

            # An immediate re-crash is one failure repeating, not many separate
            # ones, so only short-lived children count toward the loop limit.
            short_lived = reason != "unhealthy" and uptime < HEALTHY_UPTIME_S
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

    def _spawn_child(self) -> Any | None:
        """Start the child, or report why it could not start.

        Popen fails for reasons that pass: a box out of memory or handles
        refuses to start a process. Raising here ended the supervisor, which
        left nothing running and nothing to restart it -- a worse outcome than
        the crash loop the backoff exists to bound.
        """
        try:
            child = self.spawn(self.argv)
        except Exception as exc:  # noqa: BLE001 - a failed start is a restart, not an exit
            self._log(
                "child.spawn_failed",
                error=f"{type(exc).__name__}: {exc}",
                attempt=self.report.starts + 1,
            )
            return None
        # Only a real process, so an injected fake cannot name a pid that
        # belongs to something else and have it killed when this exits.
        if (
            isinstance(child, subprocess.Popen)
            and is_windows_host()
            and not assign_to_process_group(child.pid)
        ):
            self._log("child.not_grouped", pid=child.pid)
        return child

    def _probe_once(self) -> tuple[bool, str]:
        """A probe that raises means not ready, not that the supervisor is over.

        probe_ready catches what urlopen documents, but http.client.HTTPException
        is not an OSError, and a wedged child answering with a malformed response
        raises exactly that -- the case readiness checking exists to catch.
        """
        try:
            return self.probe(self.ready_url or "", self.probe_timeout_s)
        except Exception as exc:  # noqa: BLE001 - an unanswerable probe is a failed probe
            return (False, f"probe raised: {type(exc).__name__}")

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
            ready, detail = self._probe_once()
            if ready:
                strikes = 0
                continue
            strikes += 1
            self._log("child.unhealthy", detail=detail, strikes=strikes)
            if strikes >= self.unhealthy_strikes:
                return "unhealthy"

    def _terminate(self, child: Any) -> None:
        if isinstance(child, subprocess.Popen):
            # terminate()/kill() stops the serve process and nothing else.
            # Measured: launcher dead after 0.002s, sleeper still alive, so an
            # overnight unhealthy restart fought over IDA and the debuggee the
            # old child started.
            terminate_process_tree(child, wait_s=15.0)
            return
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
        # Started detached, the default sink prints to a stdout nobody is
        # holding open. Losing a log line must not end the process whose whole
        # job is keeping the service alive.
        with suppress(Exception):
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