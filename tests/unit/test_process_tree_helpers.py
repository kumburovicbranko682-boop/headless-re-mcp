"""Deterministic coverage for the process-tree kill/enumeration helpers.

The group helpers have real-process happy-path tests, but the parts that decide
what a timeout kill actually reaches -- the /proc parsers that read untrusted
``stat`` lines, the breadth/depth bounds on the descendant walk, and the several
terminate entry points -- are exercised here without spawning anything. The
/proc readers run against a faked filesystem so every malformed-line branch is
covered, and the terminate functions run against a fake process with their own
helpers stubbed, so the kill order and the group/descendant fan-out are pinned.
"""

from __future__ import annotations

import os

import pytest

from headless_re_mcp.core import process_tree

_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX /proc + process groups")


# --- a fake /proc for the stat parsers --------------------------------------


class _FakeProcEntry:
    def __init__(self, path: str, fs: dict[str, object]) -> None:
        self.path = path
        self.fs = fs

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    def __truediv__(self, other: str) -> _FakeProcEntry:
        return _FakeProcEntry(f"{self.path}/{other}", self.fs)

    def read_text(self, encoding: str = "ascii", errors: str = "replace") -> str:
        node = self.fs.get(self.path)
        if not isinstance(node, str):
            raise OSError(f"no such file: {self.path}")
        return node

    def iterdir(self) -> list[_FakeProcEntry]:
        node = self.fs.get(self.path)
        if not isinstance(node, list):
            raise OSError(f"not a directory: {self.path}")
        return [_FakeProcEntry(f"{self.path}/{name}", self.fs) for name in node]

    def exists(self) -> bool:
        return self.path in self.fs


def _install_procfs(monkeypatch: pytest.MonkeyPatch, fs: dict[str, object]) -> None:
    monkeypatch.setattr(process_tree, "Path", lambda p: _FakeProcEntry(str(p), fs))


def _stat(pid: int, state: str, ppid: int, pgrp: int) -> str:
    # Mirrors "pid (comm) state ppid pgrp ..." so state/ppid/pgrp land at the
    # same field indexes the parsers read.
    return f"{pid} (some (nested) comm) {state} {ppid} {pgrp} 0 0 0"


# --- collect_process_group --------------------------------------------------


@_POSIX_ONLY
def test_collect_process_group_rejects_bad_group_ids() -> None:
    assert process_tree.collect_process_group(0) == []
    assert process_tree.collect_process_group(-1) == []


@_POSIX_ONLY
def test_collect_process_group_returns_empty_when_proc_cannot_be_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_procfs(monkeypatch, {})  # no "/proc" dir node -> iterdir raises
    assert process_tree.collect_process_group(200) == []


@_POSIX_ONLY
def test_collect_process_group_filters_every_malformed_or_foreign_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs: dict[str, object] = {
        "/proc": ["100", "200", "300", "400", "500", "600", "700", "notdigit"],
        "/proc/100/stat": _stat(100, "S", 1, 200),  # member of group 200
        "/proc/200/stat": _stat(200, "S", 1, 200),  # the leader itself: skipped
        "/proc/300/stat": _stat(300, "Z", 1, 200),  # zombie member of group 200
        # 400 has no stat file -> read raises, skipped
        "/proc/500/stat": "garbage with no close paren",  # rfind(")") < 0
        "/proc/600/stat": "600 (c) S 1",  # too few fields -> IndexError on pgrp
        "/proc/700/stat": _stat(700, "S", 1, 999),  # different group
    }
    _install_procfs(monkeypatch, fs)

    everyone = process_tree.collect_process_group(200)
    assert everyone == [100, 300]

    live = process_tree.collect_process_group(200, live_only=True)
    assert live == [100]  # the zombie is dropped


@_POSIX_ONLY
def test_collect_process_group_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    pids = list(range(1000, 1000 + process_tree._MAX_KILL_DESCENDANTS + 10))
    fs: dict[str, object] = {"/proc": [str(pid) for pid in pids]}
    for pid in pids:
        fs[f"/proc/{pid}/stat"] = _stat(pid, "S", 1, 200)
    _install_procfs(monkeypatch, fs)
    members = process_tree.collect_process_group(200)
    assert len(members) == process_tree._MAX_KILL_DESCENDANTS


# --- _scan_proc_ppid --------------------------------------------------------


@_POSIX_ONLY
def test_scan_proc_ppid_returns_empty_when_proc_cannot_be_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_procfs(monkeypatch, {})
    assert process_tree._scan_proc_ppid(100, 16) == []


@_POSIX_ONLY
def test_scan_proc_ppid_matches_children_and_skips_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs: dict[str, object] = {
        "/proc": ["100", "200", "300", "400", "500", "notdigit"],
        "/proc/100/stat": _stat(100, "S", 100, 100),  # pid == parent, skipped
        "/proc/200/stat": _stat(200, "S", 100, 200),  # child of 100
        # 300 has no stat -> skipped
        "/proc/400/stat": "no paren",  # rfind(")") < 0
        "/proc/500/stat": _stat(500, "S", 999, 500),  # different parent
    }
    _install_procfs(monkeypatch, fs)
    assert process_tree._scan_proc_ppid(100, 16) == [200]


@_POSIX_ONLY
def test_scan_proc_ppid_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    pids = list(range(2000, 2050))
    fs: dict[str, object] = {"/proc": [str(pid) for pid in pids]}
    for pid in pids:
        fs[f"/proc/{pid}/stat"] = _stat(pid, "S", 100, pid)
    _install_procfs(monkeypatch, fs)
    assert len(process_tree._scan_proc_ppid(100, 5)) == 5


# --- _enumerate_direct_children_proc ----------------------------------------


@_POSIX_ONLY
def test_enumerate_direct_children_reads_the_children_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs: dict[str, object] = {"/proc/100/task/100/children": "200 xyz 201 202"}
    _install_procfs(monkeypatch, fs)
    assert process_tree._enumerate_direct_children_proc(100, 16) == [200, 201, 202]


@_POSIX_ONLY
def test_enumerate_direct_children_file_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    fs: dict[str, object] = {
        "/proc/100/task/100/children": " ".join(str(p) for p in range(300, 320))
    }
    _install_procfs(monkeypatch, fs)
    assert len(process_tree._enumerate_direct_children_proc(100, 4)) == 4


@_POSIX_ONLY
def test_enumerate_direct_children_file_skips_self_and_nonpositive_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs: dict[str, object] = {"/proc/100/task/100/children": "100 0 200"}
    _install_procfs(monkeypatch, fs)
    assert process_tree._enumerate_direct_children_proc(100, 16) == [200]


@_POSIX_ONLY
def test_scan_proc_ppid_skips_a_line_with_an_unparsable_ppid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs: dict[str, object] = {
        "/proc": ["500"],
        "/proc/500/stat": "500 (c) S notanint 500 0",  # ppid field is not an int
    }
    _install_procfs(monkeypatch, fs)
    assert process_tree._scan_proc_ppid(100, 16) == []


@_POSIX_ONLY
def test_enumerate_direct_children_falls_back_to_a_proc_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the children file is unreadable, the ppid scan takes over."""
    fs: dict[str, object] = {
        "/proc": ["200"],
        "/proc/200/stat": _stat(200, "S", 100, 200),
    }
    _install_procfs(monkeypatch, fs)
    assert process_tree._enumerate_direct_children_proc(100, 16) == [200]


# --- enumerate_direct_children guard ----------------------------------------


def test_enumerate_direct_children_rejects_bad_parent_pids() -> None:
    assert process_tree.enumerate_direct_children(-1) == []
    assert process_tree.enumerate_direct_children(0) == []


# --- collect_descendants bounds ---------------------------------------------


def test_collect_descendants_walks_a_tree_and_dedupes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = {1: [2, 3], 2: [4], 3: [4, 5], 4: [], 5: []}  # 4 is reachable two ways

    def fake_children(pid: int, *, max_pids: int) -> list[int]:
        return tree.get(pid, [])

    monkeypatch.setattr(process_tree, "enumerate_direct_children", fake_children)
    found = process_tree.collect_descendants(1)
    assert sorted(found) == [2, 3, 4, 5]
    assert found.count(4) == 1


def test_collect_descendants_is_bounded_in_breadth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single parent with thousands of children is capped at the kill bound."""
    wide = list(range(10, 10_000))

    def fake_children(pid: int, *, max_pids: int) -> list[int]:
        return wide if pid == 1 else []

    monkeypatch.setattr(process_tree, "enumerate_direct_children", fake_children)
    found = process_tree.collect_descendants(1)
    assert len(found) == process_tree._MAX_KILL_DESCENDANTS


def test_collect_descendants_is_bounded_in_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    """A chain deeper than the depth cap stops descending."""

    def fake_children(pid: int, *, max_pids: int) -> list[int]:
        return [pid + 1]  # an unbounded chain

    monkeypatch.setattr(process_tree, "enumerate_direct_children", fake_children)
    found = process_tree.collect_descendants(1)
    assert len(found) == process_tree._MAX_KILL_DEPTH


# --- collect_process_tree ---------------------------------------------------


def test_collect_process_tree_merges_walk_and_group(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [2, 3])
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pid: [3, 4, pid])
    tree = process_tree.collect_process_tree(1)
    assert tree == [2, 3, 4]  # deduped, and the parent itself excluded


# --- terminate_process_group ------------------------------------------------


def test_terminate_process_group_kills_each_member(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pid: [7, 8])
    killed_calls: list[int] = []
    monkeypatch.setattr(process_tree, "_kill_pid", lambda pid: killed_calls.append(pid))
    assert process_tree.terminate_process_group(200) == [7, 8]
    assert killed_calls == [7, 8]


# --- reap_orphaned_process_group (POSIX) ------------------------------------


@_POSIX_ONLY
def test_reap_orphaned_group_does_nothing_when_the_group_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pid, **k: [])
    acted = process_tree.reap_orphaned_process_group(object(), 200)
    assert acted is False


@_POSIX_ONLY
def test_reap_orphaned_group_sweeps_until_the_group_drains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remaining = [[9], [9], []]  # alive, alive, then gone

    def fake_group(pid: int, **kwargs: object) -> list[int]:
        return remaining.pop(0) if remaining else []

    swept: list[int] = []

    def fake_terminate(pid: int) -> list[int]:
        swept.append(pid)
        return []

    monkeypatch.setattr(process_tree, "collect_process_group", fake_group)
    monkeypatch.setattr(process_tree, "terminate_process_group", fake_terminate)
    acted = process_tree.reap_orphaned_process_group(object(), 200, confirm_s=1.0)
    assert acted is True
    assert swept  # it kept trying while members remained


@_POSIX_ONLY
def test_reap_orphaned_group_stops_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A group that never drains stops sweeping at the confirm deadline."""
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pid, **k: [9])
    monkeypatch.setattr(process_tree, "terminate_process_group", lambda pid: [])
    acted = process_tree.reap_orphaned_process_group(object(), 200, confirm_s=0.0)
    assert acted is True  # it acted, then broke out at the deadline


@_POSIX_ONLY
def test_reap_orphaned_group_forced_by_blocked_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pid, **k: [])
    monkeypatch.setattr(process_tree, "terminate_process_group", lambda pid: [])
    acted = process_tree.reap_orphaned_process_group(object(), 200, readers_blocked=True)
    assert acted is True


# --- terminate_process_tree -------------------------------------------------


class _FakeProc:
    def __init__(self, pid: object, poll_value: int | None = None) -> None:
        self.pid = pid
        self._poll = poll_value
        self.kill_called = False
        self.wait_called = False

    def poll(self) -> int | None:
        return self._poll

    def kill(self) -> None:
        self.kill_called = True

    def wait(self, timeout: float | None = None) -> None:
        self.wait_called = True


def _stub_terminate_helpers(
    monkeypatch: pytest.MonkeyPatch, *, descendants: list[int]
) -> list[int]:
    killed_pids: list[int] = []
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: list(descendants))
    monkeypatch.setattr(process_tree, "_kill_own_process_group", lambda pid: [])
    monkeypatch.setattr(process_tree, "_kill_pid", lambda pid: killed_pids.append(pid))
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda pids, wait_s: None)
    return killed_pids


def test_terminate_process_tree_kills_process_then_descendants_in_reverse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed_pids = _stub_terminate_helpers(monkeypatch, descendants=[600, 601])
    proc = _FakeProc(555, poll_value=None)
    killed = process_tree.terminate_process_tree(proc)
    assert proc.kill_called is True
    assert killed == [555, 601, 600]  # self, then descendants deepest-last reversed
    assert killed_pids == [601, 600]


def test_terminate_process_tree_skips_kill_when_already_exited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_terminate_helpers(monkeypatch, descendants=[600])
    proc = _FakeProc(555, poll_value=0)  # already dead
    killed = process_tree.terminate_process_tree(proc)
    assert proc.kill_called is False
    assert killed == [600]


def test_terminate_process_tree_without_a_pid_still_kills_the_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_terminate_helpers(monkeypatch, descendants=[])
    proc = _FakeProc(None, poll_value=None)  # no usable pid
    killed = process_tree.terminate_process_tree(proc)
    assert proc.kill_called is True
    assert killed == []  # nothing appended because the pid was not an int


@_POSIX_ONLY
def test_terminate_process_tree_signals_the_group_when_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_terminate_helpers(monkeypatch, descendants=[])
    group_kills: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: group_kills.append((pgid, sig)))
    proc = _FakeProc(555, poll_value=None)
    process_tree.terminate_process_tree(proc, kill_group=True)
    assert group_kills == [(555, 9)]


# --- terminate_leftover_process_tree ----------------------------------------


def test_terminate_leftover_rejects_a_bad_pid() -> None:
    assert process_tree.terminate_leftover_process_tree(_FakeProc(0)) == []


def test_terminate_leftover_noops_when_nothing_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "collect_process_tree", lambda pid: [])
    assert process_tree.terminate_leftover_process_tree(_FakeProc(555)) == []


def test_terminate_leftover_swallows_a_scan_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cleanup on the success path never raises, even if the scan itself throws."""

    def boom(pid: int) -> list[int]:
        raise OSError("proc scan failed")

    monkeypatch.setattr(process_tree, "collect_process_tree", boom)
    assert process_tree.terminate_leftover_process_tree(_FakeProc(555)) == []


def test_terminate_leftover_sweeps_walk_and_group(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_process_tree", lambda pid: [600])
    monkeypatch.setattr(process_tree, "terminate_process_tree", lambda proc, **k: [555, 600])
    monkeypatch.setattr(process_tree, "terminate_process_group", lambda pid: [601])
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda pids, wait_s: None)
    killed = process_tree.terminate_leftover_process_tree(_FakeProc(555))
    assert killed == [555, 600, 601]


# --- terminate_pid_tree -----------------------------------------------------


def test_terminate_pid_tree_rejects_a_bad_pid() -> None:
    assert process_tree.terminate_pid_tree(0) == []
    assert process_tree.terminate_pid_tree(-3) == []


def test_terminate_pid_tree_kills_pid_and_descendants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [600])
    monkeypatch.setattr(process_tree, "_kill_own_process_group", lambda pid: [])
    killed_pids: list[int] = []
    monkeypatch.setattr(process_tree, "_kill_pid", lambda pid: killed_pids.append(pid))
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda pids, wait_s: None)
    killed = process_tree.terminate_pid_tree(555)
    assert 555 in killed and 600 in killed
    assert killed_pids == [555, 600]


# --- _reap_terminated -------------------------------------------------------


def test_reap_terminated_returns_early_without_a_subreaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", False)
    # No exception even though these pids are not ours: it returns before waitpid.
    process_tree._reap_terminated([999_999_001], 0.05)


@_POSIX_ONLY
def test_reap_terminated_drops_pids_that_are_already_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pid that is neither our child nor present in /proc is dropped, not spun on."""
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
    process_tree._reap_terminated([999_999_002], 0.5)  # returns promptly


@_POSIX_ONLY
def test_reap_terminated_survives_a_waitpid_oserror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A waitpid failure other than ChildProcessError is swallowed until the deadline."""
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)

    def boom(pid: int, flags: int) -> tuple[int, int]:
        raise OSError("waitpid blew up")

    monkeypatch.setattr(os, "waitpid", boom)
    process_tree._reap_terminated([999_999_003], 0.05)  # returns at the deadline


@_POSIX_ONLY
def test_kill_own_process_group_without_killpg_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the POSIX group primitives are missing, the helper declines quietly."""
    monkeypatch.delattr(os, "killpg", raising=False)
    assert process_tree._kill_own_process_group(555) == []


# --- process_image_path / filter_same_image_pids ----------------------------


def test_process_image_path_is_none_off_windows() -> None:
    assert process_tree.process_image_path(1234) is None
    assert process_tree.process_image_path(-1) is None


def test_filter_same_image_pids_empty_without_a_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: None)
    assert process_tree.filter_same_image_pids(1, [2, 3]) == []


def test_filter_same_image_pids_matches_on_casefolded_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = {1: "C:/Tools/App.exe", 2: "c:/tools/app.EXE", 3: "C:/other.exe"}
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: images.get(pid))
    assert process_tree.filter_same_image_pids(1, [2, 3]) == [2]


# --- probe_child_window_candidates ------------------------------------------


def test_probe_child_window_candidates_reports_children_with_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid, **k: [600, 601])
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: f"/img/{pid}")

    def windows(pid: int) -> list[dict[str, object]]:
        if pid == 600:
            return [{"visible": True, "title": "Main"}, {"visible": False, "title": "hidden"}]
        return []  # 601 owns no windows and is skipped

    out = process_tree.probe_child_window_candidates(1, list_windows_fn=windows)
    assert len(out) == 1
    entry = out[0]
    assert entry["pid"] == 600
    assert entry["window_count"] == 2
    assert entry["visible_count"] == 1
    assert entry["titles"] == ["Main"]
    assert entry["same_image"] is False
