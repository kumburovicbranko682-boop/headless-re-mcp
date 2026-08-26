"""Direct coverage for the POSIX process-group helpers.

``collect_process_group`` / ``terminate_process_group`` /
``_kill_own_process_group`` were added so a bounded tool that orphans a worker
to init is still reaped: the kernel keeps the orphan in its original session
group even after the parent link is gone, so enumerating by group finds what the
ppid walk cannot. The bounded-run tests exercise this through ``run_bounded``
with the ppid walk monkeypatched away; these tests pin the helpers themselves,
including the guard that keeps ``_kill_own_process_group`` from ever signalling a
group the service does not lead (which would take down the service itself).

POSIX-only: process groups, ``setsid`` and ``killpg`` are POSIX behaviour.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

import pytest

from headless_re_mcp.core import process_tree

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="process groups / setsid / killpg are POSIX"
)

_SLEEP_FOREVER = "import time\nwhile True: time.sleep(0.2)\n"


def _pid_alive(pid: int) -> bool:
    """True only for a running/sleeping process, never for an unreaped zombie.

    ``os.kill(pid, 0)`` succeeds on a zombie, and in a container whose pid 1 does
    not reap orphans a killed child lingers as a zombie indefinitely -- so a kill
    check keyed on ``os.kill`` never observes death. The process state in
    ``/proc/<pid>/stat`` distinguishes a live process ('R'/'S'/'D'...) from one
    that has already been killed and is only waiting to be reaped ('Z'/'X').
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


def _wait_gone(pid: int, *, deadline_s: float = 5.0) -> bool:
    deadline = time.monotonic() + deadline_s
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    return not _pid_alive(pid)


def _kill(*pids: int) -> None:
    for pid in pids:
        with suppress(OSError):
            os.kill(pid, signal.SIGKILL)


def _leader_code(pidfile: Path) -> str:
    # Started with start_new_session=True, so this process leads its own group
    # (pgid == pid). The grandchild it spawns inherits that group, giving a
    # member whose group is the leader's pid but whose parent is the leader.
    return (
        "import subprocess, sys, pathlib, time\n"
        "child = subprocess.Popen([sys.executable, '-c',"
        f" {_SLEEP_FOREVER!r}])\n"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid))\n"
        "while True: time.sleep(0.2)\n"
    )


def _start_group_leader(pidfile: Path) -> tuple[int, int]:
    """Start a session-leader that records its grandchild's pid; return both."""
    leader = subprocess.Popen(
        [sys.executable, "-c", _leader_code(pidfile), str(pidfile)],
        start_new_session=True,
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        with suppress(OSError, ValueError):
            text = pidfile.read_text().strip()
            if text:
                grandchild = int(text)
                # The leader must actually lead its group for the premise to hold.
                assert os.getpgid(leader.pid) == leader.pid
                return leader.pid, grandchild
        time.sleep(0.02)
    _kill(leader.pid)
    raise AssertionError("group leader never recorded its grandchild pid")


def test_collect_process_group_finds_the_orphan_and_excludes_the_leader(
    tmp_path: Path,
) -> None:
    leader_pid, grandchild = _start_group_leader(tmp_path / "gc.pid")
    try:
        members = process_tree.collect_process_group(leader_pid)
        assert grandchild in members, "group member the ppid walk misses was not found"
        # The leader is the group id itself; the sweep returns members to kill,
        # not the leader whose Popen handle the caller still owns.
        assert leader_pid not in members
    finally:
        _kill(grandchild, leader_pid)


def test_terminate_process_group_kills_members_but_not_the_leader(
    tmp_path: Path,
) -> None:
    leader_pid, grandchild = _start_group_leader(tmp_path / "gc.pid")
    try:
        killed = process_tree.terminate_process_group(leader_pid)
        assert grandchild in killed
        assert _wait_gone(grandchild), "group member survived terminate_process_group"
        # collect_process_group excludes the leader, so it is left for the owner
        # of the Popen handle to reap -- it must still be alive here.
        assert _pid_alive(leader_pid)
    finally:
        _kill(grandchild, leader_pid)


def test_kill_own_process_group_refuses_a_group_it_does_not_lead(
    tmp_path: Path,
) -> None:
    """The guard is load-bearing: signalling a non-led group kills the service.

    A child started without a new session stays in this test's process group, so
    its pid is not its group id. The helper must notice that and return empty
    without sending any signal -- the child stays alive.
    """
    child = subprocess.Popen([sys.executable, "-c", _SLEEP_FOREVER])
    try:
        # Premise: the child is not its own group leader. If it somehow were,
        # signalling its group would hit this test's own group, so bail out
        # rather than risk it.
        if os.getpgid(child.pid) == child.pid:
            pytest.skip("child unexpectedly became its own group leader")
        result = process_tree._kill_own_process_group(child.pid)
        assert result == []
        time.sleep(0.2)
        assert child.poll() is None, "a group we do not lead was signalled"
    finally:
        _kill(child.pid)


def test_kill_own_process_group_kills_the_whole_group_it_leads(
    tmp_path: Path,
) -> None:
    leader_pid, grandchild = _start_group_leader(tmp_path / "gc.pid")
    try:
        result = process_tree._kill_own_process_group(leader_pid)
        assert result == [leader_pid]
        # killpg reaches the leader and every descendant that kept the group,
        # including the grandchild the ppid walk cannot see.
        assert _wait_gone(leader_pid), "the group leader survived its own group kill"
        assert _wait_gone(grandchild), "the reparented-style member survived the group kill"
    finally:
        _kill(grandchild, leader_pid)
