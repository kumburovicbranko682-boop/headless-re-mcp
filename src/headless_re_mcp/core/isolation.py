"""Run the operator's isolation step between samples.

The debugger really executes the sample, so the README requires rolling the VM
back between unknown binaries. Nothing automated that, which under 24/7 intake
means every sample after the first runs on a machine the previous one touched.

This does not manage virtual machines, and deliberately so: the hypervisor, the
snapshot names and the credentials belong to the deployment, and a service that
grew its own VM driver would be guessing at all three. It runs a command the
operator supplies at the point where isolation matters, verifies it succeeded,
and refuses to continue when it did not -- because silently carrying on is the
one outcome that produces cross-contaminated results nobody can spot later.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.telemetry import record_alert

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT_S = 600.0
_NUL = "\x00"


def _split_command(raw: str) -> tuple[str, ...]:
    """Split an operator-written command without eating Windows path slashes.

    POSIX ``shlex`` treats ``\\`` as an escape, so ``C:\\vm\\revert.ps1``
    becomes ``C:vmrevert.ps1``. Windows ``shlex`` (posix=False) keeps the
    quote characters. Protect backslashes, split the POSIX way so quotes
    still group arguments, then put the slashes back.
    """
    if os.name != "nt":
        return tuple(shlex.split(raw))
    if _NUL in raw:
        raise ValueError("isolation command must not contain NUL")
    return tuple(part.replace(_NUL, "\\") for part in shlex.split(raw.replace("\\", _NUL)))


def _run_isolation_command(
    command: list[str],
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Run the operator's command with a deadline that binds what it started.

    Isolation is a script the operator supplies -- typically a .ps1 that starts
    the hypervisor's snapshot tool. ``subprocess.run(timeout=...)`` kills that
    script and nothing else, then on Windows drains the pipes with no timeout.
    Measured: a 1s deadline returned in 1.0s and left the child running. The
    CLI tools already go through ``run_bounded`` for that reason; this is the
    same shape, on the path that runs between every unattended sample.
    """
    timeout = float(kwargs.get("timeout") or DEFAULT_TIMEOUT_S)
    creationflags = int(kwargs.get("creationflags") or 0)
    try:
        completed = run_bounded(
            list(command),
            timeout=timeout,
            creationflags=creationflags,
        )
    except TimedOut as exc:
        raise subprocess.TimeoutExpired(cmd=list(command), timeout=timeout) from exc
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=completed.returncode,
        stdout=completed.stdout.decode("utf-8", errors="replace"),
        stderr=completed.stderr.decode("utf-8", errors="replace"),
    )


@dataclass(frozen=True, slots=True)
class IsolationPolicy:
    """The command to run between samples, if the deployment has one."""

    command: tuple[str, ...] = ()
    timeout_s: float = DEFAULT_TIMEOUT_S
    # Fail closed: if the deployment declared an isolation step and it did not
    # work, the next sample must not run. An operator who prefers best-effort
    # can say so, but it cannot be the default.
    required: bool = True

    @classmethod
    def from_settings(cls, settings: object) -> IsolationPolicy:
        raw = getattr(settings, "isolation_command", ()) or ()
        # A single string is read the way an operator would write it in a config
        # file; a sequence is taken as an argv that is already split.
        command = (
            _split_command(raw)
            if isinstance(raw, str)
            else tuple(str(part) for part in raw)
        )
        timeout = getattr(settings, "isolation_timeout_s", DEFAULT_TIMEOUT_S)
        return cls(
            command=command,
            timeout_s=float(timeout or DEFAULT_TIMEOUT_S),
            required=bool(getattr(settings, "isolation_required", True)),
        )

    @property
    def configured(self) -> bool:
        return bool(self.command)


class IsolationError(RuntimeError):
    """The isolation step was required and did not succeed."""

    def __init__(self, message: str, *, detail: JsonObject | None = None) -> None:
        super().__init__(message)
        self.detail = detail or {}


@dataclass(slots=True)
class IsolationRunner:
    """Invoke the configured isolation command and report honestly."""

    policy: IsolationPolicy = field(default_factory=IsolationPolicy)
    # None means the production path: run_bounded, so a snapshot script that
    # starts a hypervisor tool is killed with its children. Tests inject a
    # fake here and keep the subprocess.run calling convention.
    run: Callable[..., subprocess.CompletedProcess[str]] | None = None
    clock: Callable[[], float] = time.monotonic

    def rotate(self, *, reason: str = "next_sample") -> JsonObject:
        """Run the isolation step. Raises only when it was required and failed."""
        if not self.policy.configured:
            # Not an error: plenty of deployments analyse only trusted binaries.
            # Reported so an operator can tell "no rotation" from "rotated".
            return {
                "ok": True,
                "performed": False,
                "reason": "no isolation command configured",
            }

        started = self.clock()
        command: Sequence[str] = self.policy.command
        try:
            completed = self._invoke(list(command))
        except TimedOut as exc:
            return self._failed(
                f"TimedOut: timed out after {exc.timeout:g}s; killed {list(exc.killed)}",
                command=command,
                elapsed=self.clock() - started,
                reason=reason,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return self._failed(
                f"{type(exc).__name__}: {exc}",
                command=command,
                elapsed=self.clock() - started,
                reason=reason,
            )

        elapsed = self.clock() - started
        code = int(completed.returncode)
        if code != 0:
            return self._failed(
                f"isolation command exited with {code}",
                command=command,
                elapsed=elapsed,
                reason=reason,
                stderr=(completed.stderr or "")[-2000:],
            )
        return {
            "ok": True,
            "performed": True,
            "command": list(command),
            "elapsed_s": round(elapsed, 3),
            "reason": reason,
        }

    def _invoke(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        if self.run is not None:
            return self.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.policy.timeout_s,
                check=False,
                # Runs once per sample on an unattended box; a console window
                # per rotation would pile up on the desktop.
                **no_window_popen_kwargs(),
            )
        flags = int(no_window_popen_kwargs().get("creationflags") or 0)
        bounded = run_bounded(
            command,
            timeout=self.policy.timeout_s,
            creationflags=flags,
        )
        return subprocess.CompletedProcess(
            args=command,
            returncode=bounded.returncode,
            stdout=bounded.stdout.decode("utf-8", errors="replace"),
            stderr=bounded.stderr.decode("utf-8", errors="replace"),
        )

    def _failed(
        self,
        detail: str,
        *,
        command: Sequence[str],
        elapsed: float,
        reason: str,
        stderr: str = "",
    ) -> JsonObject:
        payload: JsonObject = {
            "ok": False,
            "performed": True,
            "command": list(command),
            "elapsed_s": round(elapsed, 3),
            "reason": reason,
            "detail": detail,
        }
        if stderr:
            payload["stderr"] = stderr
        record_alert("isolation_failed", fields={"detail": detail, "reason": reason})
        if self.policy.required:
            raise IsolationError(
                f"isolation step failed and is required: {detail}",
                detail=payload,
            )
        return payload