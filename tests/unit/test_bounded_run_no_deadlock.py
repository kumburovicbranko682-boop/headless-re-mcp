"""A bounded CLI timeout must never wedge on a pipe an orphan still holds.

``run_bounded`` used to run the tool under ``with subprocess.Popen(...)``. Its
``__exit__`` closes stdout/stderr on the calling thread, and closing a pipe
while a reader thread is still blocked in ``read()`` deadlocks on the buffered
stream's lock. A grandchild that inherits the pipes and outlives the launcher
keeps the write end open, so the reader never sees EOF and the close hangs
forever -- a bounded timeout that never returns.

These tests reproduce that deterministically by forcing the parent/child walk
to miss the grandchild, exactly as it does for an orphan the kernel has
reparented to init. They are POSIX-only: the inherited-pipe reproduction and
the process-group kill are both POSIX behaviour.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.core import process_tree

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="inherited-pipe orphan reproduction is POSIX"
)


def _pid_alive(pid: int) -> bool:
    """True only for a live process, never for a killed-but-unreaped zombie.

    ``os.kill(pid, 0)`` succeeds on a zombie, so it would call a grandchild the
    group kill already reaped "alive" during the window before its parent is
    waited on -- and in a container whose pid 1 does not reap orphans that window
    is unbounded. The point of these tests is that the orphan was *killed*; a
    zombie satisfies that. Read the state from ``/proc/<pid>/stat`` and treat
    'Z'/'X' as dead, the same probe the other process-kill suites use.
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return False
    close = stat.rfind(")")
    if close < 0:
        return False
    fields = stat[close + 2 :].split()
    if not fields:
        return False
    return fields[0] not in {"Z", "X", "x"}


def _launcher_code(pidfile: Path) -> str:
    # The grandchild inherits this process's stdout/stderr (it sets neither) and
    # sleeps forever, so it keeps the write end of run_bounded's pipes open after
    # the launcher is gone. It records its pid so the test can clean it up.
    return (
        "import subprocess, sys, os, time\n"
        "child = subprocess.Popen([sys.executable, '-c',"
        " 'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
        "while True: time.sleep(0.2)\n"
    )


def _read_pid(pidfile: Path, *, deadline_s: float = 3.0) -> int:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        with suppress(OSError, ValueError):
            text = pidfile.read_text().strip()
            if text:
                return int(text)
        time.sleep(0.02)
    raise AssertionError("launcher never recorded its child pid")


def test_bounded_timeout_does_not_deadlock_on_an_inherited_pipe(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """With the tree-kill unable to reach the orphan, the close must still not hang.

    The launcher is reaped normally; only the grandchild survives, holding the
    pipe. The reader owns and closes its own stream, so the spawning thread has
    no close to block on and the timeout returns within the deadline.
    """
    pidfile = tmp_path / "child.pid"

    # The walk finds nothing and the group kill is disabled, so the grandchild
    # lives on holding the pipe -- the exact state that used to deadlock close.
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [])
    monkeypatch.setattr(process_tree, "_kill_own_process_group", lambda pid: [])

    started = time.monotonic()
    try:
        with pytest.raises(TimedOut):
            run_bounded(
                [sys.executable, "-c", _launcher_code(pidfile)],
                timeout=0.8,
                drain_s=0.5,
            )
        assert time.monotonic() - started < 8.0
    finally:
        with suppress(Exception):
            os.kill(_read_pid(pidfile), signal.SIGKILL)


def test_bounded_timeout_kills_a_reparented_orphan_via_the_group(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The ppid walk cannot see a reparented orphan; the process group can.

    With ``collect_descendants`` blinded to the grandchild -- as it is for an
    orphan reparented to init -- the session kill is the only thing that reaches
    it, and the grandchild must be dead once the timeout returns.
    """
    pidfile = tmp_path / "child.pid"
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [])

    with pytest.raises(TimedOut):
        run_bounded(
            [sys.executable, "-c", _launcher_code(pidfile)],
            timeout=0.8,
            drain_s=0.5,
        )

    grandchild = _read_pid(pidfile)
    deadline = time.monotonic() + 5.0
    while _pid_alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.05)
    alive = _pid_alive(grandchild)
    with suppress(OSError):
        os.kill(grandchild, signal.SIGKILL)
    assert alive is False, "the reparented orphan outlived the group kill"


def _exiting_launcher_code(pidfile: Path, exit_code: int) -> str:
    # Unlike _launcher_code this launcher *exits* right after spawning the
    # sleeper, so run_bounded's post-wait branches run with the leader already
    # reaped while the grandchild still holds the write end of both pipes.
    return (
        "import subprocess, sys\n"
        "child = subprocess.Popen([sys.executable, '-c',"
        " 'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
        f"sys.exit({exit_code})\n"
    )


def test_a_clean_exit_with_an_inherited_pipe_is_success_not_a_timeout(
    tmp_path: Path,
) -> None:
    """Exit 0 while a child still holds the pipes must return, and return ok.

    Isolation scripts and doctor probes start a long-lived helper and exit 0.
    Two wrong outcomes are pinned here: blocking until the reader sees EOF
    (which never comes while the helper lives) would report the success as a
    timeout after the full deadline; and any post-exit kill would take down a
    helper the tool deliberately left running.
    """
    pidfile = tmp_path / "child.pid"
    started = time.monotonic()
    try:
        completed = run_bounded(
            [sys.executable, "-c", _exiting_launcher_code(pidfile, 0)],
            timeout=30.0,
            drain_s=0.5,
        )
        elapsed = time.monotonic() - started
        assert completed.returncode == 0
        # Returned on the short drain, nowhere near the 30s deadline.
        assert elapsed < 10.0
        # The deliberately-left helper survives a *successful* run.
        helper = _read_pid(pidfile)
        assert _pid_alive(helper) is True
    finally:
        with suppress(Exception):
            os.kill(_read_pid(pidfile), signal.SIGKILL)


def test_a_failed_exit_with_an_inherited_pipe_kills_the_orphan_and_raises(
    tmp_path: Path,
) -> None:
    """Exit nonzero with the pipes still held: kill what inherited them, raise.

    The launcher is already reaped when the kill runs, so the ppid walk sees
    nothing and ``getpgid`` on the leader fails; the group signal keyed on the
    recorded group id is the only path that still reaches the orphan. This
    pins that path end to end: the call raises TimedOut promptly instead of
    returning a result whose output a live writer could still be growing, and
    the orphan is dead once it returns.
    """
    pidfile = tmp_path / "child.pid"
    started = time.monotonic()
    try:
        with pytest.raises(TimedOut):
            run_bounded(
                [sys.executable, "-c", _exiting_launcher_code(pidfile, 1)],
                timeout=1.5,
                drain_s=0.5,
            )
        assert time.monotonic() - started < 10.0

        grandchild = _read_pid(pidfile)
        deadline = time.monotonic() + 5.0
        while _pid_alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.05)
        alive = _pid_alive(grandchild)
        assert alive is False, "the orphan holding the pipes outlived the failure kill"
    finally:
        with suppress(Exception):
            os.kill(_read_pid(pidfile), signal.SIGKILL)
