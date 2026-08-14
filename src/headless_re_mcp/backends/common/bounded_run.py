"""Run a CLI tool with a deadline that also binds what the tool started.

``subprocess.run(timeout=...)`` kills the process it spawned and nothing else.
Several backends here spawn a launcher rather than the tool itself -- jadx,
apktool and Ghidra start a JVM, webcrack starts node -- and measured on this
machine, killing a launcher leaves the process it started running. After a
timeout the caller has its answer while an orphaned JVM keeps a core busy and a
lock on the sample, for the rest of the service's life.
"""

from __future__ import annotations

import subprocess
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.process_group import assign_to_process_group


class TimedOut(RuntimeError):
    """The tool outran its deadline; ``killed`` is what had to be stopped."""

    def __init__(self, timeout: float, killed: list[int]) -> None:
        super().__init__(f"timed out after {timeout:g}s")
        self.timeout = timeout
        self.killed = killed


@dataclass(frozen=True, slots=True)
class Completed:
    """The subset of CompletedProcess these callers use."""

    returncode: int
    stdout: bytes
    stderr: bytes


def run_bounded(
    cmd: list[str],
    *,
    timeout: float,
    creationflags: int = 0,
    cwd: Any = None,
    env: Any = None,
    drain_s: float = 5.0,
) -> Completed:
    """Capture output within the deadline, or kill the whole tree and raise."""
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
        cwd=cwd,
        env=env,
    ) as process:
        # Same net the debugger workers use: a force-kill of this process runs
        # no cleanup, and a JVM analysing a sample is not something to leave
        # behind because the service was stopped rather than closed.
        assign_to_process_group(process.pid)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            killed = terminate_process_tree(process)
            # Drained so the pipes close and the reader threads finish; the
            # output is discarded because the run did not produce an answer.
            with suppress(subprocess.TimeoutExpired, ValueError, OSError):
                process.communicate(timeout=drain_s)
            raise TimedOut(timeout, killed) from None
        return Completed(int(process.returncode or 0), stdout or b"", stderr or b"")
