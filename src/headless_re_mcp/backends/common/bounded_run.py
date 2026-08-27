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

import os
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from threading import Event, Thread
from time import monotonic
from typing import Any

from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.process_group import assign_to_process_group

# Per stream. Callers slice to a few KB; this is the peak we will hold.
DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024


class InvalidTimeout(ValueError):
    """A caller deadline that is not a positive, finite number of seconds."""


def clamp_cli_timeout(timeout: float, *, maximum: float) -> float:
    """Bound a caller-supplied CLI deadline before spawning anything.

    The tool schemas declare ``0 < timeout <= maximum``, but the agent
    transport invokes handlers straight from model arguments with no schema
    enforcement (``CommandCatalog.invoke`` -> ``spec.handler(**arguments)``),
    the same gap ``frida._bound_timeout`` and ``web._bound_nav_timeout`` already
    guard. Left unchecked, a non-positive value makes ``run_bounded`` launch the
    JVM/node only to kill it on the first loop iteration and report a misleading
    timeout for what is really a bad parameter, and a huge one lets a tool that
    hangs on hostile input hold a worker for as long as the caller named. Reject
    the first (and NaN) and cap the second, so every CLI adapter agrees on the
    bound regardless of transport.
    """
    value = float(timeout)
    if value != value or value <= 0:
        raise InvalidTimeout("timeout must be positive")
    return min(value, float(maximum))


class TimedOut(RuntimeError):
    """The tool outran its deadline; ``killed`` is what had to be stopped."""

    def __init__(self, timeout: float, killed: list[int]) -> None:
        super().__init__(f"timed out after {timeout:g}s")
        self.timeout = timeout
        self.killed = killed


class BoundedCancelled(RuntimeError):
    """The caller asked to stop; ``killed`` is the process tree that was cut."""

    def __init__(self, killed: list[int] | None = None) -> None:
        super().__init__("cancelled by caller")
        self.killed = list(killed or [])


_active_cancel: ContextVar[Event | None] = ContextVar("bounded_run_cancel", default=None)


def active_bound_cancel() -> Event | None:
    """Cancel event bound to this thread, if a dumper or CLI is in flight."""
    return _active_cancel.get()


@contextmanager
def bound_cancel_scope(cancel: Event) -> Iterator[Event]:
    """Make ``run_bounded`` / capture loops honor this event on this thread."""
    token = _active_cancel.set(cancel)
    try:
        yield cancel
    finally:
        _active_cancel.reset(token)


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
    finally:
        # The reader owns the stream: it closes here, on its own thread, once
        # read() has returned. The spawning thread must never close a pipe a
        # reader might still be blocked on -- that deadlocks on the buffered
        # stream's lock -- so closing from here is the only safe place.
        with suppress(Exception):
            stream.close()


def _join_readers(threads: tuple[Thread, Thread], timeout: float) -> bool:
    deadline = monotonic() + max(0.05, timeout)
    alive = False
    for thread in threads:
        remaining = deadline - monotonic()
        thread.join(timeout=max(0.0, remaining))
        if thread.is_alive():
            alive = True
    return alive


def _terminate_bounded_process(process: subprocess.Popen[bytes]) -> list[int]:
    """Stop a bounded process, including orphaned POSIX group members.

    A launcher can exit before the deadline while one of its children keeps an
    inherited stdout/stderr pipe open. Once re-parented, that child no longer
    appears in the launcher's process tree. POSIX bounded runs therefore start
    in a dedicated session and kill that process group as a final sweep.
    """
    return terminate_process_tree(process, kill_group=os.name != "nt")


def run_bounded(
    cmd: list[str],
    *,
    timeout: float,
    creationflags: int = 0,
    cwd: Any = None,
    env: Any = None,
    drain_s: float = 5.0,
    max_output: int = DEFAULT_MAX_OUTPUT,
    cancel: Event | None = None,
) -> Completed:
    """Capture output within the deadline, or kill the whole tree and raise."""
    cap = max(1, int(max_output))
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_trunc = [False]
    stderr_trunc = [False]
    stop = cancel if cancel is not None else active_bound_cancel()
    # Not `with subprocess.Popen(...)`: its __exit__ closes stdout/stderr from
    # this thread, and closing a pipe while a reader is still blocked in read()
    # deadlocks on the buffered stream's lock. That is not hypothetical -- a
    # launcher whose grandchild inherited the pipe keeps the write end open long
    # after the launcher is killed, so the reader never sees EOF. The readers
    # own and close their own streams; this thread only reaps the process.
    #
    # start_new_session gives the tool its own POSIX process group so a timeout
    # kill can signal the whole group. The ppid walk alone cannot reach a
    # grandchild the kernel has reparented to init, which is exactly what leaks
    # a JVM or a sleeper after the deadline.
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
        cwd=cwd,
        env=env,
        start_new_session=os.name != "nt",
    )
    try:
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
        deadline = started + timeout
        while True:
            if stop is not None and stop.is_set():
                killed = _terminate_bounded_process(process)
                _join_readers(readers, drain_s)
                raise BoundedCancelled(killed)
            remaining = deadline - monotonic()
            if remaining <= 0:
                killed = _terminate_bounded_process(process)
                _join_readers(readers, drain_s)
                raise TimedOut(timeout, killed)
            try:
                process.wait(timeout=min(0.2, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
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
            killed = _terminate_bounded_process(process)
            _join_readers(readers, drain_s)
            raise TimedOut(timeout, killed)
        return Completed(
            returncode,
            b"".join(stdout_chunks),
            b"".join(stderr_chunks),
            stdout_truncated=stdout_trunc[0],
            stderr_truncated=stderr_trunc[0],
        )
    finally:
        # Reap the child if an unexpected error left it running; never touch the
        # pipes here, the readers close them. poll() is already set on every
        # normal return and raise above, so this only fires on a surprise.
        with suppress(Exception):
            if process.poll() is None:
                terminate_process_tree(process)
