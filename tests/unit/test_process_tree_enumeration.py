"""Coverage for the process-tree enumeration and PID-kill helpers.

``test_process_group_kill`` and ``test_deterministic_reaping`` pin the POSIX
group sweep and the subreaper reap. This file covers the parts they do not: the
``/proc`` child enumeration, the bounded ``collect_descendants`` walk, the
``collect_process_tree`` merge, the image-path filter and window-candidate
probe (both driven with injected seams so they run on every platform), and
``terminate_pid_tree``. The real-process tests are POSIX-only because they lean
on ``/proc`` and ``os.kill``; the seam-driven ones are not.
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

_SLEEP_FOREVER = "import time\nwhile True: time.sleep(0.2)\n"
_LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="/proc enumeration is Linux"
)
_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="os.kill semantics are POSIX")


def _pid_alive(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return False
    close = stat.rfind(")")
    if close < 0:
        return False
    fields = stat[close + 2 :].split()
    return bool(fields) and fields[0] not in {"Z", "X", "x"}


def _wait_gone(pid: int, *, deadline_s: float = 5.0) -> bool:
    deadline = time.monotonic() + deadline_s
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    return not _pid_alive(pid)


def _spawn_sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen([sys.executable, "-c", _SLEEP_FOREVER])


def _kill(*pids: int) -> None:
    for pid in pids:
        with suppress(OSError):
            os.kill(pid, signal.SIGKILL)


# ---------------------------------------------------------------------------
# enumerate_direct_children / _proc scans
# ---------------------------------------------------------------------------


def test_enumerate_direct_children_rejects_invalid_parents() -> None:
    assert process_tree.enumerate_direct_children(0) == []
    assert process_tree.enumerate_direct_children(-5) == []


@_LINUX_ONLY
def test_enumerate_direct_children_finds_a_live_child() -> None:
    child = _spawn_sleeper()
    try:
        deadline = time.monotonic() + 5.0
        found: list[int] = []
        while time.monotonic() < deadline:
            found = process_tree.enumerate_direct_children(os.getpid())
            if child.pid in found:
                break
            time.sleep(0.02)
        assert child.pid in found
    finally:
        _kill(child.pid)
        child.wait(timeout=5.0)


@_LINUX_ONLY
def test_scan_proc_ppid_finds_a_child_directly() -> None:
    child = _spawn_sleeper()
    try:
        deadline = time.monotonic() + 5.0
        found: list[int] = []
        while time.monotonic() < deadline:
            found = process_tree._scan_proc_ppid(os.getpid(), 64)
            if child.pid in found:
                break
            time.sleep(0.02)
        assert child.pid in found
    finally:
        _kill(child.pid)
        child.wait(timeout=5.0)


@_LINUX_ONLY
def test_enumerate_children_proc_falls_back_when_the_children_file_is_absent() -> None:
    # A pid with no /proc entry makes the children-file read raise, which the
    # helper must swallow and fall through to the /proc ppid scan (here: empty).
    assert process_tree._enumerate_direct_children_proc(999_999_999, 64) == []


# ---------------------------------------------------------------------------
# collect_descendants bounds / collect_process_tree merge
# ---------------------------------------------------------------------------


def test_collect_descendants_is_bounded_in_breadth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # One parent with far more direct children than the cap: the walk must stop
    # at _MAX_KILL_DESCENDANTS rather than return the whole fork bomb.
    wide = list(range(1000, 1000 + process_tree._MAX_KILL_DESCENDANTS + 50))

    def children(pid: int, *, max_pids: int = 0) -> list[int]:
        del max_pids
        return wide if pid == 1 else []

    monkeypatch.setattr(process_tree, "enumerate_direct_children", children)
    found = process_tree.collect_descendants(1)
    assert len(found) == process_tree._MAX_KILL_DESCENDANTS


def test_collect_descendants_is_bounded_in_depth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A single chain deeper than the depth cap: each pid parents the next.
    def children(pid: int, *, max_pids: int = 0) -> list[int]:
        del max_pids
        return [pid + 1]

    monkeypatch.setattr(process_tree, "enumerate_direct_children", children)
    found = process_tree.collect_descendants(1)
    assert found == [2, 3, 4, 5]  # _MAX_KILL_DEPTH levels, one child each


def test_collect_descendants_ignores_cycles(monkeypatch: pytest.MonkeyPatch) -> None:
    # A child that points back at an ancestor must not be visited twice.
    def children(pid: int, *, max_pids: int = 0) -> list[int]:
        del max_pids
        return {1: [2], 2: [1, 3], 3: []}.get(pid, [])

    monkeypatch.setattr(process_tree, "enumerate_direct_children", children)
    found = process_tree.collect_descendants(1)
    assert sorted(found) == [2, 3]


def test_collect_process_tree_merges_walk_and_group_without_the_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [pid, 20, 30])
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pid: [30, 40])
    merged = process_tree.collect_process_tree(10)
    # The parent is dropped, group survivors are added, and the overlap (30) is
    # deduplicated while insertion order is preserved.
    assert merged == [20, 30, 40]


# ---------------------------------------------------------------------------
# filter_same_image_pids / probe_child_window_candidates (injected seams)
# ---------------------------------------------------------------------------


def test_filter_same_image_pids_needs_a_known_base_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: None)
    assert process_tree.filter_same_image_pids(100, [101, 102]) == []


def test_filter_same_image_pids_matches_case_insensitively(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = {
        100: r"C:\Tools\x64dbg.exe",
        101: r"c:\tools\X64DBG.EXE",  # same image, different case
        102: r"C:\Tools\other.exe",
        103: None,  # unreadable, must be skipped
    }
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: images.get(pid))
    assert process_tree.filter_same_image_pids(100, [101, 102, 103]) == [101]


def test_probe_child_window_candidates_reports_only_children_with_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process_tree, "enumerate_direct_children", lambda pid, *, max_pids=16: [201, 202]
    )
    images = {200: "/opt/app", 201: "/opt/app", 202: "/opt/helper"}
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: images.get(pid))

    windows = {
        201: [{"visible": True, "title": f"w{i}"} for i in range(10)],
        202: [],  # no windows at all -> skipped entirely
    }

    def lister(pid: int) -> list[dict[str, object]]:
        return windows.get(pid, [])

    out = process_tree.probe_child_window_candidates(200, list_windows_fn=lister)

    assert len(out) == 1
    row = out[0]
    assert row["pid"] == 201
    assert row["window_count"] == 10
    assert row["visible_count"] == 10
    assert len(row["titles"]) == 8  # titles are capped at eight
    assert row["same_image"] is True


def test_probe_child_window_candidates_marks_a_different_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process_tree, "enumerate_direct_children", lambda pid, *, max_pids=16: [301]
    )
    images = {300: "/opt/app", 301: "/opt/helper"}
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: images.get(pid))

    out = process_tree.probe_child_window_candidates(
        300,
        list_windows_fn=lambda pid: [{"visible": False, "title": "hidden"}],
    )
    assert out[0]["same_image"] is False
    assert out[0]["visible_count"] == 0
    assert out[0]["titles"] == []


# ---------------------------------------------------------------------------
# terminate_pid_tree / process_image_path
# ---------------------------------------------------------------------------


def test_terminate_pid_tree_rejects_invalid_pids() -> None:
    assert process_tree.terminate_pid_tree(0) == []
    assert process_tree.terminate_pid_tree(-1) == []


@_POSIX_ONLY
def test_terminate_pid_tree_kills_a_live_process() -> None:
    child = _spawn_sleeper()
    try:
        killed = process_tree.terminate_pid_tree(child.pid)
        assert child.pid in killed
        assert _wait_gone(child.pid), "terminate_pid_tree left the process alive"
    finally:
        _kill(child.pid)
        with suppress(Exception):
            child.wait(timeout=2.0)


@_LINUX_ONLY
def test_process_image_path_is_none_on_posix_and_for_bad_pids() -> None:
    # The Win32 image query is guarded off on POSIX, so this always answers None
    # there; a non-positive pid answers None on every platform.
    assert process_tree.process_image_path(os.getpid()) is None
    assert process_tree.process_image_path(0) is None
    assert process_tree.process_image_path(-1) is None


def test_collect_process_group_rejects_a_non_positive_group() -> None:
    assert process_tree.collect_process_group(0) == []
    assert process_tree.collect_process_group(-3) == []


def test_reap_terminated_is_a_noop_without_the_subreaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Off the Linux subreaper the orphans are init's to reap, so the sweep must
    # return at once rather than block on pids it can never wait on.
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", False)
    started = time.monotonic()
    process_tree._reap_terminated([999_999_999], 5.0)
    assert time.monotonic() - started < 1.0


def test_terminate_leftover_process_tree_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert process_tree.terminate_leftover_process_tree(object()) == []

    class _Proc:
        pid = 4321

    # Nothing was left behind, so the common clean exit stays a single scan and
    # returns without a kill.
    monkeypatch.setattr(process_tree, "collect_process_tree", lambda pid: [])
    assert process_tree.terminate_leftover_process_tree(_Proc()) == []


def test_terminate_pid_tree_kills_enumerated_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed_pids: list[int] = []
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [50, 60])
    monkeypatch.setattr(process_tree, "_kill_own_process_group", lambda pid: [])
    monkeypatch.setattr(process_tree, "_kill_pid", killed_pids.append)
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda pids, wait_s: None)

    killed = process_tree.terminate_pid_tree(40)

    # The parent dies first, then descendants deepest-last are killed in reverse.
    assert killed == [40, 60, 50]
    assert killed_pids == [40, 60, 50]
