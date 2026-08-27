"""The reaping machinery itself is pinned here, not just its visible effect.

The sweep-level tests in test_unattended_resource_bounds assert a detached
helper is dead the moment a sweep returns. On a fast, idle machine those can
pass without deterministic reaping, because the kernel usually processes a
SIGKILL before the next /proc probe -- which is exactly how a merge dropped
the subreaper chain without a single test going red. These tests exercise the
mechanism directly so the pass can never again depend on scheduler timing.

Everything here is Linux-only: PR_SET_CHILD_SUBREAPER and waitpid-based
reaping have no Windows counterpart (TerminateProcess has no zombie state).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="child-subreaper reaping is a Linux mechanism (skip != pass)",
)

_SLEEP_FOREVER = "import time\nwhile True: time.sleep(0.2)"

# A launcher that starts a detached helper, reports its pid, and exits zero:
# the shape of the die/exeinfope/upx wrapper scripts whose helpers used to
# outlive the tool call.
_EXIT0_LAUNCHER = (
    "import subprocess, sys\n"
    "child = subprocess.Popen(\n"
    f"    [sys.executable, '-c', {_SLEEP_FOREVER!r}],\n"
    "    stdin=subprocess.DEVNULL,\n"
    "    stdout=subprocess.DEVNULL,\n"
    "    stderr=subprocess.DEVNULL,\n"
    "    close_fds=True,\n"
    ")\n"
    "print(child.pid, flush=True)\n"
    "raise SystemExit(0)\n"
)


def _proc_entry_exists(pid: int) -> bool:
    # A reaped pid has no /proc entry at all; a killed-but-unreaped one still
    # shows up there in state Z. Existence is therefore the reaped/not-reaped
    # distinction, stricter than the alive/dead probe the sweep tests use.
    return Path(f"/proc/{pid}").exists()


def test_the_process_is_a_child_subreaper() -> None:
    """Importing process_tree must have claimed orphaned grandchildren.

    Without PR_SET_CHILD_SUBREAPER a helper orphaned by its exiting launcher
    reparents to init, and this process has no way to wait on it -- every
    downstream reap becomes a hope that init gets there first.
    """
    from headless_re_mcp.core import process_tree

    assert process_tree._LINUX_CHILD_SUBREAPER is True


def test_a_killed_child_is_reaped_not_left_a_zombie() -> None:
    """_reap_terminated retires the pid instead of hoping someone else does.

    A direct child that is killed and never waited on stays a zombie in /proc
    for the parent's whole lifetime, so this fails deterministically -- not
    just under load -- if the waitpid loop is ever dropped again.
    """
    from headless_re_mcp.core.process_tree import _reap_terminated

    process = subprocess.Popen(
        [sys.executable, "-c", _SLEEP_FOREVER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    os.kill(process.pid, signal.SIGKILL)

    _reap_terminated([process.pid], 2.0)

    try:
        assert _proc_entry_exists(process.pid) is False
    finally:
        # The pid was reaped behind Popen's back; poll() absorbs the ECHILD so
        # the destructor does not warn about a still-running child.
        process.poll()


def test_the_leftover_sweep_leaves_no_zombie_behind() -> None:
    """terminate_leftover_process_tree must fully retire the orphan it kills.

    The launcher exits first, so its helper reparents to this process (the
    subreaper). Being the reaper is a debt: if the sweep killed the orphan but
    never waited on it, the zombie would sit under this process until exit.
    The /proc entry being gone right when the sweep returns proves both halves
    of the mechanism -- adoption and reaping -- are wired in.
    """
    from headless_re_mcp.core.process_tree import (
        terminate_leftover_process_tree,
        terminate_pid_tree,
    )

    # start_new_session mirrors the CLI adapters: the launcher leads its own
    # process group, which is how the sweep finds an orphan whose parent link
    # died with the launcher.
    process = subprocess.Popen(
        [sys.executable, "-c", _EXIT0_LAUNCHER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    helper = int(process.stdout.readline().strip())
    process.wait(timeout=5.0)
    process.stdout.close()

    try:
        killed = terminate_leftover_process_tree(process, wait_s=2.0)

        assert helper in killed
        # Gone entirely: dead is not enough, reaped is the contract.
        deadline = time.monotonic() + 2.0
        while _proc_entry_exists(helper) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _proc_entry_exists(helper) is False
    finally:
        terminate_pid_tree(helper)
