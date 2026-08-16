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
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import IO, Any

from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.process_group import assign_to_process_group

# Callers slice after the fact (r2 1 MiB, windbg 500 KiB, Ghidra 200k chars).
# Measured: 20 MiB stdout, run_bounded held 20 MiB (RSS +38 MiB) before any
# of those caps ran -- a verbose JVM log became a process-lifetime leak.
_DEFAULT_MAX_OUTPUT = 1_000_000


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
    # None means "same as len(stdout)": mocks that build a Completed with the
    # three positional fields keep working.
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    truncated: bool = False


class _BoundPipes:
    """Keep the first ``limit`` bytes of each stream and count the rest."""

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.stdout_n = 0
        self.stderr_n = 0
        self._lock = threading.Lock()

    def feed(self, which: str, chunk: bytes) -> None:
        with self._lock:
            if which == "out":
                self.stdout_n += len(chunk)
                room = self.limit - len(self.stdout)
                if room > 0:
                    self.stdout.extend(chunk[:room])
            else:
                self.stderr_n += len(chunk)
                room = self.limit - len(self.stderr)
                if room > 0:
                    self.stderr.extend(chunk[:room])


def _read_into(pipe: IO[bytes], pipes: _BoundPipes, which: str) -> None:
    try:
        while True:
            chunk = pipe.read(65536)
            if not chunk:
                break
            pipes.feed(which, chunk)
    except (OSError, ValueError):
        return
    finally:
        with suppress(OSError, ValueError):
            pipe.close()


def _join_readers(
    t_out: threading.Thread, t_err: threading.Thread, timeout: float
) -> None:
    t_out.join(timeout=timeout)
    t_err.join(timeout=max(0.05, timeout))


def run_bounded(
    cmd: list[str],
    *,
    timeout: float,
    creationflags: int = 0,
    cwd: Any = None,
    env: Any = None,
    drain_s: float = 5.0,
    max_output: int = _DEFAULT_MAX_OUTPUT,
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
        pipes = _BoundPipes(max_output)
        assert process.stdout is not None and process.stderr is not None
        t_out = threading.Thread(
            target=_read_into, args=(process.stdout, pipes, "out"), daemon=True
        )
        t_err = threading.Thread(
            target=_read_into, args=(process.stderr, pipes, "err"), daemon=True
        )
        t_out.start()
        t_err.start()
        deadline = time.monotonic() + timeout
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            killed = terminate_process_tree(process)
            # Drained so the pipes close and the reader threads finish; the
            # output is discarded because the run did not produce an answer.
            _join_readers(t_out, t_err, drain_s)
            raise TimedOut(timeout, killed) from None
        remaining = max(0.05, deadline - time.monotonic())
        _join_readers(t_out, t_err, remaining)
        if t_out.is_alive() or t_err.is_alive():
            # A child inherited the pipes and outlived the launcher. That is
            # the same hang communicate() used to hit; kill the tree.
            killed = terminate_process_tree(process)
            _join_readers(t_out, t_err, drain_s)
            raise TimedOut(timeout, killed) from None
        return Completed(
            int(process.returncode or 0),
            bytes(pipes.stdout),
            bytes(pipes.stderr),
            stdout_bytes=pipes.stdout_n,
            stderr_bytes=pipes.stderr_n,
            truncated=pipes.stdout_n > pipes.limit or pipes.stderr_n > pipes.limit,
        )
