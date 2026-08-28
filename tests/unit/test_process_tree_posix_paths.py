"""POSIX coverage for ``core.process_tree``.

These exercise the Linux arms with real short-lived processes rather than
mocks: a launcher started with ``start_new_session`` leads its own group and
keeps a backgrounded child in it, which is exactly the shape the descendant
walk, the group scan and the timeout kills are written for. Windows arms
(``ctypes.windll``) are unreachable here and are left to the Toolhelp path.

Every spawned process leads its own session group and is torn down group-first
so nothing leaks; the current interpreter runs as a child subreaper, so any
reparented grandchild is reaped rather than left as a zombie.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from collections.abc import Iterator

import pytest

from headless_re_mcp.core import process_tree as pt

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX process-tree arms")


def _reap(pids: list[int]) -> None:
    for pid in pids:
        with contextlib.suppress(OSError):
            os.waitpid(pid, os.WNOHANG)


@contextlib.contextmanager
def _launcher_with_child() -> Iterator[subprocess.Popen[bytes]]:
    """A session-leading bash that backgrounds one ``sleep`` and waits on it."""
    proc = subprocess.Popen(
        ["bash", "-c", "sleep 30 & wait"],
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if pt.collect_descendants(proc.pid):
                break
            time.sleep(0.02)
        yield proc
    finally:
        members = pt.collect_process_group(proc.pid)
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)
        _reap(members)


@contextlib.contextmanager
def _lone_process() -> Iterator[subprocess.Popen[bytes]]:
    proc = subprocess.Popen(["sleep", "30"], start_new_session=True)
    try:
        time.sleep(0.1)
        yield proc
    finally:
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)


# ---------------------------------------------------------------------------
# enumeration
# ---------------------------------------------------------------------------


def test_enumerate_direct_children_rejects_non_positive_pids() -> None:
    assert pt.enumerate_direct_children(0) == []
    assert pt.enumerate_direct_children(-1) == []


def test_enumerate_direct_children_lists_a_live_child() -> None:
    with _lone_process() as proc:
        children = pt.enumerate_direct_children(os.getpid())
        assert proc.pid in children


def test_scan_proc_ppid_finds_a_child_and_honours_its_limit() -> None:
    with _lone_process() as first, _lone_process() as second:
        found = pt._scan_proc_ppid(os.getpid(), 16)
        assert first.pid in found and second.pid in found
        assert len(pt._scan_proc_ppid(os.getpid(), 1)) == 1


def test_enumerate_direct_children_proc_falls_back_to_the_stat_scan() -> None:
    # No such parent: the children file read fails, the ppid scan returns empty.
    assert pt._enumerate_direct_children_proc(2**30, 16) == []


def test_enumerate_direct_children_honours_its_page_limit() -> None:
    with _lone_process(), _lone_process():
        assert len(pt.enumerate_direct_children(os.getpid(), max_pids=1)) == 1


# ---------------------------------------------------------------------------
# descendant / group collection
# ---------------------------------------------------------------------------


def test_collect_descendants_walks_a_launcher_tree() -> None:
    with _launcher_with_child() as proc:
        descendants = pt.collect_descendants(proc.pid)
        assert descendants
        assert all(pid != proc.pid for pid in descendants)


def test_collect_process_group_matches_members_by_pgrp() -> None:
    assert pt.collect_process_group(-1) == []
    with _launcher_with_child() as proc:
        members = pt.collect_process_group(proc.pid)
        assert members
        assert proc.pid not in members


def test_collect_process_tree_merges_walk_and_group() -> None:
    with _launcher_with_child() as proc:
        tree = pt.collect_process_tree(proc.pid)
        assert tree
        assert proc.pid not in tree


# ---------------------------------------------------------------------------
# group kills
# ---------------------------------------------------------------------------


def test_terminate_process_group_kills_live_members() -> None:
    with _launcher_with_child() as proc:
        members = pt.collect_process_group(proc.pid)
        killed = pt.terminate_process_group(proc.pid)
        assert sorted(killed) == sorted(members)
        _reap(killed)


def test_kill_own_process_group_signals_only_a_leader() -> None:
    # The interpreter is not its own group leader under the test runner.
    assert pt._kill_own_process_group(os.getpid()) == []

    with _launcher_with_child() as proc:
        killed = pt._kill_own_process_group(proc.pid)
        assert killed == [proc.pid]
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)
        assert proc.poll() is not None


# ---------------------------------------------------------------------------
# reaping
# ---------------------------------------------------------------------------


def test_reap_terminated_is_a_noop_without_the_subreaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pt, "_LINUX_CHILD_SUBREAPER", False)
    pt._reap_terminated([1, 2, 3], 1.0)  # returns immediately, touches nothing


def test_reap_terminated_reaps_an_exited_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pt, "_LINUX_CHILD_SUBREAPER", True)
    proc = subprocess.Popen(["true"])
    time.sleep(0.05)

    # The interpreter is the subreaper, so this waitpid retires the zombie.
    pt._reap_terminated([proc.pid, -1], 1.0)

    # subprocess maps the now-missing child (ECHILD) to a clean exit code.
    assert proc.poll() == 0


def test_reap_terminated_discards_a_pid_that_is_already_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pt, "_LINUX_CHILD_SUBREAPER", True)
    # Not our child and no /proc entry: the sweep drops it without spinning.
    pt._reap_terminated([2**30], 0.5)


# ---------------------------------------------------------------------------
# process-tree kills over a Popen handle
# ---------------------------------------------------------------------------


class _HandleWithoutPid:
    pid = None


def test_terminate_process_tree_tolerates_a_handle_without_a_pid() -> None:
    assert pt.terminate_process_tree(_HandleWithoutPid()) == []


def test_terminate_process_tree_skips_killing_an_already_dead_process() -> None:
    proc = subprocess.Popen(["true"])
    proc.wait()

    # Never raises even when the handle has already exited; the kill is skipped.
    killed = pt.terminate_process_tree(proc, wait_s=1.0)

    assert isinstance(killed, list)


def test_terminate_process_tree_kills_a_launcher_and_its_descendants() -> None:
    with _launcher_with_child() as proc:
        killed = pt.terminate_process_tree(proc, wait_s=2.0)
        assert proc.pid in killed
        assert proc.poll() is not None


def test_terminate_process_tree_can_signal_the_whole_group() -> None:
    with _launcher_with_child() as proc:
        killed = pt.terminate_process_tree(proc, wait_s=2.0, kill_group=True)
        assert proc.pid in killed
        assert proc.poll() is not None


def test_terminate_leftover_process_tree_ignores_a_handle_without_a_pid() -> None:
    assert pt.terminate_leftover_process_tree(_HandleWithoutPid()) == []


def test_terminate_leftover_process_tree_is_quiet_with_no_leftovers() -> None:
    with _lone_process() as proc:
        assert pt.terminate_leftover_process_tree(proc, wait_s=1.0) == []
        assert proc.poll() is None


def test_terminate_leftover_process_tree_sweeps_a_detached_child() -> None:
    with _launcher_with_child() as proc:
        killed = pt.terminate_leftover_process_tree(proc, wait_s=2.0)
        assert killed
        assert proc.poll() is not None


def test_terminate_pid_tree_rejects_bad_pids() -> None:
    assert pt.terminate_pid_tree(0) == []
    assert pt.terminate_pid_tree(-5) == []


def test_terminate_pid_tree_kills_a_pid_and_its_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Skip the subreaper reap so the Popen handle keeps ownership of its pid.
    monkeypatch.setattr(pt, "_reap_terminated", lambda *args, **kwargs: None)
    with _launcher_with_child() as proc:
        members = pt.collect_process_group(proc.pid)
        killed = pt.terminate_pid_tree(proc.pid)
        assert proc.pid in killed
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)
        assert proc.poll() is not None
        _reap(members)


def test_kill_pid_terminates_a_live_process() -> None:
    with _lone_process() as proc:
        pt._kill_pid(proc.pid)
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)
        assert proc.poll() is not None


# ---------------------------------------------------------------------------
# image-path helpers (Windows-only body; the guard and callers are POSIX-safe)
# ---------------------------------------------------------------------------


def test_process_image_path_returns_none_off_windows() -> None:
    assert pt.process_image_path(-1) is None
    assert pt.process_image_path(os.getpid()) is None


def test_filter_same_image_pids_without_an_image_returns_empty() -> None:
    assert pt.filter_same_image_pids(os.getpid(), [1, 2, 3]) == []


def test_filter_same_image_pids_keeps_matching_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = {10: "/opt/app.exe", 20: "/opt/app.exe", 30: "/opt/other.exe"}
    monkeypatch.setattr(pt, "process_image_path", lambda pid: images.get(pid))

    assert pt.filter_same_image_pids(10, [20, 30]) == [20]


def test_probe_child_window_candidates_reports_children_with_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pt, "enumerate_direct_children", lambda pid, *, max_pids=16: [111, 222])
    monkeypatch.setattr(pt, "process_image_path", lambda pid: "/opt/app.exe")

    def lister(pid: int) -> list[dict[str, object]]:
        if pid == 111:
            return [{"visible": True, "title": "Main"}, {"visible": False, "title": "Hidden"}]
        return []

    out = pt.probe_child_window_candidates(os.getpid(), list_windows_fn=lister)

    assert len(out) == 1
    entry = out[0]
    assert entry["pid"] == 111
    assert entry["window_count"] == 2
    assert entry["visible_count"] == 1
    assert entry["titles"] == ["Main"]
    assert entry["same_image"] is True
