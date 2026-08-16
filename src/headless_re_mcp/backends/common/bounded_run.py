"""Run a CLI tool with a deadline that also binds what the tool started.

``subprocess.run(timeout=...)`` kills the process it spawned and nothing else.
Several backends here spawn a launcher rather than the tool itself -- jadx,
apktool and Ghidra start a JVM, webcrack starts node -- and measured on this
machine, killing a launcher leaves the process it started running. After a
timeout the caller has its answer while an orphaned JVM keeps a core busy and a
lock on the sample, for the rest of the service's life.

``communicate()`` also keeps every byte of stdout and stderr. A chatty
analyzeHeadless run can be hundreds of megabytes of progress text nobody
reads; the callers already slice a few kilobytes. The readers below keep a
hard cap and discard the rest so the child does not block on a full pipe.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from threading import Thread
from time import monotonic
from typing import Any

from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.process_group import assign_to_process_group

# Per stream. Callers slice to a few KB; this is the peak we will hold.
DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024


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
    stdout_truncated: bool = False
    stderr_truncated: bool = False


def _read_capped(
    stream: Any, cap: int, chunks: list[bytes], truncated: list[bool]
) -> None:
    kept = 0
    try:
        while True:
            piece = stream.read(65536)
            if not piece:
                break
            if kept < cap:
                room = cap - kept
                if len(piece) > room:
                    chunks.append(piece[:room])
                    kept = cap
                    truncated[0] = True
                else:
                    chunks.append(piece)
                    kept += len(piece)
            else:
                truncated[0] = True
    except (ValueError, OSError):
        pass


def _join_readers(threads: tuple[Thread, Thread], timeout: float) -> bool:
    deadline = monotonic() + max(0.05, timeout)
    alive = False
    for thread in threads:
        remaining = deadline - monotonic()
        thread.join(timeout=max(0.0, remaining))
        if thread.is_alive():
            alive = True
    return alive


def run_bounded(
    cmd: list[str],
    *,
    timeout: float,
    creationflags: int = 0,
    cwd: Any = None,
    env: Any = None,
    drain_s: float = 5.0,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> Completed:
    """Capture output within the deadline, or kill the whole tree and raise."""
    cap = max(1, int(max_output))
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_trunc = [False]
    stderr_trunc = [False]
    with subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
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
        stdout_thread = Thread(
            target=_read_capped,
            args=(process.stdout, cap, stdout_chunks, stdout_trunc),
            name="bounded-stdout",
            daemon=True,
        )
        stderr_thread = Thread(
            target=_read_capped,
            args=(process.stderr, cap, stderr_chunks, stderr_trunc),
            name="bounded-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        readers = (stdout_thread, stderr_thread)
        started = monotonic()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            killed = terminate_process_tree(process)
            _join_readers(readers, drain_s)
            raise TimedOut(timeout, killed) from None
        returncode = int(process.returncode or 0)
        remaining = timeout - (monotonic() - started)
        if returncode == 0:
            # Isolation scripts and doctor probes often start a long-lived
            # helper and exit 0. Waiting out the rest of the deadline then
            # killing that helper is a successful run reported as a timeout.
            _join_readers(readers, min(drain_s, max(0.1, remaining)))
            return Completed(
                returncode,
                b"".join(stdout_chunks),
                b"".join(stderr_chunks),
                stdout_truncated=stdout_trunc[0],
                stderr_truncated=stderr_trunc[0],
            )
        if _join_readers(readers, max(0.1, remaining)):
            # Launcher gone with a failure, pipes still open: a child inherited them.
            killed = terminate_process_tree(process)
            _join_readers(readers, drain_s)
            raise TimedOut(timeout, killed)
        return Completed(
            returncode,
            b"".join(stdout_chunks),
            b"".join(stderr_chunks),
            stdout_truncated=stdout_trunc[0],
            stderr_truncated=stderr_trunc[0],
        )
