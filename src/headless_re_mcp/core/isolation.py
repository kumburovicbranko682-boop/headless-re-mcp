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

import shlex
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.platform_support import is_windows_host
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
    if not is_windows_host():
        return tuple(shlex.split(raw))
    if _NUL in raw:
        raise ValueError("isolation command must not contain NUL")
    return tuple(part.replace(_NUL, "\\") for part in shlex.split(raw.replace("\\", _NUL)))


_warned_unsplittable = False


def _warn_unsplittable(exc: ValueError) -> None:
    # Once per process: the answer is a property of the configuration, not of
    # any one Settings.load(), and gate checks reload settings constantly.
    # The command text itself stays out of the alert -- the operator's
    # rotation command routinely embeds hypervisor credentials.
    global _warned_unsplittable  # noqa: PLW0603 - deliberate say-it-once latch
    if _warned_unsplittable:
        return
    _warned_unsplittable = True
    record_alert(
        "isolation_command_unsplittable",
        fields={
            "detail": str(exc),
            "consequence": (
                "the whole string is kept as one argv entry, so rotation "
                "fails closed instead of running samples without isolation"
            ),
        },
    )


def command_argv(value: object) -> tuple[str, ...]:
    """Read an operator-supplied isolation command as argv, without raising.

    A sequence is already argv; a string is split the way an operator would
    write it. A string that cannot be split (an unclosed quote around a
    Windows path is the usual typo) used to raise out of Settings.load(),
    which is called well beyond startup -- the settings reload route and the
    IDA gate both call it, so one bad quote turned into runtime 500s. Falling
    back to no command would be worse: it silently disables a step that
    exists to stop samples cross-contaminating each other. Keeping the whole
    string as a single argv entry does neither -- the server runs, and the
    rotation fails visibly when it is attempted.
    """
    if isinstance(value, (list, tuple)):
        return tuple(str(part) for part in value if str(part).strip())
    if not isinstance(value, str) or not value.strip():
        return ()
    try:
        return _split_command(value)
    except ValueError as exc:
        _warn_unsplittable(exc)
        return (value,)


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
        command = command_argv(raw)
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