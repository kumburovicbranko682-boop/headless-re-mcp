"""Cross-platform coverage for the process-tree walkers and killers.

The Toolhelp/OpenProcess arms only run on Windows and the /proc parsers only
on Linux, but both sides are decision logic wrapped around a handful of
system calls. Faking the kernel32 table (as the x64dbg transport tests do)
and the /proc directory lets every branch run anywhere: the snapshot walk,
the image-path query, the ppid/pgrp parsers with their malformed-stat guards,
and the bounded descendant collection that keeps a fork bomb from pinning the
killer.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Any

import pytest

import headless_re_mcp.core.process_tree as ptree

JsonObject = dict[str, Any]


class _NtOsProxy:
    """Report ``name == "nt"`` while forwarding everything else to the real os.

    Patching the global ``os.name`` would poison ``pathlib.Path`` on Python
    3.11, where ``Path()`` picks WindowsPath (uninstantiable on POSIX) from
    ``os.name``; patching the module's reference confines the lie.
    """

    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


class _ApiFn:
    """A kernel32 entry point: callable, and accepts argtypes/restype assignment."""

    def __init__(self, behavior: Any = None) -> None:
        self._behavior = behavior
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *args: Any) -> Any:
        if self._behavior is None:
            return 1
        return self._behavior(*args)


def _fake_kernel32(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> Any:
    names = (
        "OpenProcess",
        "CloseHandle",
        "QueryFullProcessImageNameW",
        "CreateToolhelp32Snapshot",
        "Process32FirstW",
        "Process32NextW",
        "TerminateProcess",
    )
    kernel32 = types.SimpleNamespace(**{name: overrides.get(name, _ApiFn()) for name in names})
    monkeypatch.setattr(ptree, "os", _NtOsProxy())
    monkeypatch.setattr(
        ptree.ctypes,
        "windll",
        types.SimpleNamespace(kernel32=kernel32),
        raising=False,
    )
    return kernel32


# --------------------------------------------------------------------------- #
# fake /proc
# --------------------------------------------------------------------------- #


class _FakeStatFile:
    def __init__(self, text: str | None) -> None:
        self._text = text

    def read_text(self, **kwargs: Any) -> str:
        if self._text is None:
            raise OSError("process vanished")
        return self._text


class _FakeProcEntry:
    def __init__(self, name: str, stat_text: str | None) -> None:
        self.name = name
        self._stat = stat_text

    def __truediv__(self, part: str) -> _FakeStatFile:
        assert part == "stat"
        return _FakeStatFile(self._stat)


class _FakeProcRoot:
    def __init__(self, entries: list[_FakeProcEntry] | None) -> None:
        self._entries = entries

    def iterdir(self) -> Any:
        if self._entries is None:
            raise OSError("proc unavailable")
        return iter(self._entries)


def _fake_proc(monkeypatch: pytest.MonkeyPatch, entries: list[_FakeProcEntry] | None) -> None:
    real_path = ptree.Path
    root = _FakeProcRoot(entries)
    monkeypatch.setattr(
        ptree, "Path", lambda value: root if str(value) == "/proc" else real_path(value)
    )


def _stat_line(pid: int, ppid: int, pgrp: int, comm: str = "worker") -> str:
    return f"{pid} ({comm}) S {ppid} {pgrp} 77 0 -1"


# --------------------------------------------------------------------------- #
# subreaper probe
# --------------------------------------------------------------------------- #


def test_subreaper_probe_declines_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert ptree._enable_linux_child_subreaper() is False


def test_subreaper_probe_declines_when_prctl_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")

    def no_libc(*args: Any, **kwargs: Any) -> Any:
        raise OSError("no libc here")

    monkeypatch.setattr(ptree.ctypes, "CDLL", no_libc)
    assert ptree._enable_linux_child_subreaper() is False


# --------------------------------------------------------------------------- #
# process_image_path (Toolhelp arm)
# --------------------------------------------------------------------------- #


def test_image_path_returns_none_off_windows_and_for_bad_pids() -> None:
    assert ptree.process_image_path(0) is None
    assert ptree.process_image_path("7") is None  # type: ignore[arg-type]


def test_image_path_reads_the_full_image_name(monkeypatch: pytest.MonkeyPatch) -> None:
    def query(handle: Any, flags: int, buf: Any, size_ref: Any) -> int:
        buf.value = "C:\\tools\\sample.exe"
        return 1

    _fake_kernel32(
        monkeypatch,
        OpenProcess=_ApiFn(lambda *args: 1234),
        QueryFullProcessImageNameW=_ApiFn(query),
    )
    assert ptree.process_image_path(42) == "C:\\tools\\sample.exe"


def test_image_path_returns_none_when_the_process_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_kernel32(monkeypatch, OpenProcess=_ApiFn(lambda *args: 0))
    assert ptree.process_image_path(42) is None


def test_image_path_returns_none_when_the_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[Any] = []
    _fake_kernel32(
        monkeypatch,
        OpenProcess=_ApiFn(lambda *args: 1234),
        QueryFullProcessImageNameW=_ApiFn(lambda *args: 0),
        CloseHandle=_ApiFn(lambda handle: closed.append(handle) or 1),
    )
    assert ptree.process_image_path(42) is None
    assert closed == [1234], "the handle must be released on the failure path"


# --------------------------------------------------------------------------- #
# enumerate_direct_children (Toolhelp arm)
# --------------------------------------------------------------------------- #


def _snapshot_walk(rows: list[tuple[int, int]]) -> tuple[_ApiFn, _ApiFn]:
    """Process32First/Next fakes yielding (pid, ppid) rows into the entry."""
    remaining = list(rows)

    def fill(entry_ref: Any) -> int:
        if not remaining:
            return 0
        pid, ppid = remaining.pop(0)
        entry = entry_ref._obj
        entry.th32ProcessID = pid
        entry.th32ParentProcessID = ppid
        return 1

    return (
        _ApiFn(lambda snap, entry_ref: fill(entry_ref)),
        _ApiFn(lambda snap, entry_ref: fill(entry_ref)),
    )


def test_enumerate_children_rejects_a_bad_parent_pid() -> None:
    assert ptree.enumerate_direct_children(0) == []
    assert ptree.enumerate_direct_children("7") == []  # type: ignore[arg-type]


def test_enumerate_children_walks_the_toolhelp_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, nxt = _snapshot_walk([(300, 1), (101, 42), (42, 42), (100, 42)])
    _fake_kernel32(
        monkeypatch,
        CreateToolhelp32Snapshot=_ApiFn(lambda *args: 555),
        Process32FirstW=first,
        Process32NextW=nxt,
    )
    # The (42, 42) row is the parent listing itself and must be skipped.
    assert ptree.enumerate_direct_children(42) == [100, 101]


def test_enumerate_children_stops_at_the_requested_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, nxt = _snapshot_walk([(101, 42), (102, 42), (103, 42)])
    _fake_kernel32(
        monkeypatch,
        CreateToolhelp32Snapshot=_ApiFn(lambda *args: 555),
        Process32FirstW=first,
        Process32NextW=nxt,
    )
    assert ptree.enumerate_direct_children(42, max_pids=2) == [101, 102]


def test_enumerate_children_handles_an_invalid_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_kernel32(monkeypatch, CreateToolhelp32Snapshot=_ApiFn(lambda *args: 0xFFFFFFFF))
    assert ptree.enumerate_direct_children(42) == []


def test_enumerate_children_handles_an_empty_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_kernel32(
        monkeypatch,
        CreateToolhelp32Snapshot=_ApiFn(lambda *args: 555),
        Process32FirstW=_ApiFn(lambda *args: 0),
    )
    assert ptree.enumerate_direct_children(42) == []


# --------------------------------------------------------------------------- #
# /proc children-file and ppid-scan parsers
# --------------------------------------------------------------------------- #


def test_proc_children_file_parses_tokens_and_honors_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_path = ptree.Path

    class _ChildrenFile:
        def read_text(self, **kwargs: Any) -> str:
            return "junk 42 103 101 102 104"

    monkeypatch.setattr(
        ptree,
        "Path",
        lambda value: _ChildrenFile() if "children" in str(value) else real_path(value),
    )
    # "junk" is skipped, 42 is the parent itself, and the limit stops at two.
    assert ptree._enumerate_direct_children_proc(42, 2) == [101, 103]


def test_proc_children_file_returns_everything_under_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_path = ptree.Path

    class _ChildrenFile:
        def read_text(self, **kwargs: Any) -> str:
            return "102 101"

    monkeypatch.setattr(
        ptree,
        "Path",
        lambda value: _ChildrenFile() if "children" in str(value) else real_path(value),
    )
    assert ptree._enumerate_direct_children_proc(42, 16) == [101, 102]


def test_proc_ppid_scan_survives_every_malformed_stat_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        _FakeProcEntry("not-a-pid", None),
        _FakeProcEntry("42", _stat_line(42, 1, 42)),  # the parent itself
        _FakeProcEntry("200", None),  # stat read fails
        _FakeProcEntry("201", "201 (no-close-paren"),
        _FakeProcEntry("202", "202 (worker) S"),  # too few fields
        _FakeProcEntry("203", _stat_line(203, 42, 42)),
        _FakeProcEntry("204", _stat_line(204, 99, 99)),  # different parent
        _FakeProcEntry("205", _stat_line(205, 42, 42)),
        _FakeProcEntry("206", _stat_line(206, 42, 42)),  # beyond the limit
    ]
    _fake_proc(monkeypatch, entries)
    assert ptree._scan_proc_ppid(42, 2) == [203, 205]


def test_proc_ppid_scan_returns_empty_when_proc_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_proc(monkeypatch, None)
    assert ptree._scan_proc_ppid(42, 4) == []


# --------------------------------------------------------------------------- #
# collect_descendants / collect_process_group
# --------------------------------------------------------------------------- #


def test_collect_descendants_dedupes_cycles_and_stops_at_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = {42: [100, 101], 100: [102, 42], 101: [], 102: [100]}
    monkeypatch.setattr(
        ptree,
        "enumerate_direct_children",
        lambda pid, *, max_pids: tree.get(pid, []),
    )
    # 42 -> 100, 101; 100 -> 102 (42 already seen); 102 -> nothing new.
    assert ptree.collect_descendants(42) == [100, 101, 102]

    wide = {42: list(range(100, 100 + ptree._MAX_KILL_DESCENDANTS + 8))}
    monkeypatch.setattr(
        ptree,
        "enumerate_direct_children",
        lambda pid, *, max_pids: wide.get(pid, []),
    )
    assert len(ptree.collect_descendants(42)) == ptree._MAX_KILL_DESCENDANTS


def test_collect_descendants_stops_walking_at_the_depth_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chain deeper than the bound is cut, so a fork chain cannot pin the walk."""
    chain = {42: [100], 100: [101], 101: [102], 102: [103], 103: [104], 104: [105]}
    monkeypatch.setattr(
        ptree,
        "enumerate_direct_children",
        lambda pid, *, max_pids: chain.get(pid, []),
    )
    assert ptree.collect_descendants(42) == [100, 101, 102, 103]


def test_collect_process_group_rejects_bad_input_and_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert ptree.collect_process_group(0) == []
    assert ptree.collect_process_group("9") == []  # type: ignore[arg-type]
    monkeypatch.setattr(ptree, "os", _NtOsProxy())
    assert ptree.collect_process_group(42) == []


def test_collect_process_group_matches_members_on_their_own_pgrp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        _FakeProcEntry("self", None),  # not a pid
        _FakeProcEntry("42", _stat_line(42, 1, 42)),  # the leader itself
        _FakeProcEntry("300", None),  # stat read fails
        _FakeProcEntry("301", "301 (no-close"),
        _FakeProcEntry("302", "302 (worker) S 1"),  # too few fields
        _FakeProcEntry("303", _stat_line(303, 1, 42)),  # orphan kept the group
        _FakeProcEntry("304", _stat_line(304, 1, 9)),  # different group
    ]
    _fake_proc(monkeypatch, entries)
    assert ptree.collect_process_group(42) == [303]


def test_collect_process_group_stops_at_the_kill_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    count = ptree._MAX_KILL_DESCENDANTS + 5
    entries = [_FakeProcEntry(str(pid), _stat_line(pid, 1, 42)) for pid in range(100, 100 + count)]
    _fake_proc(monkeypatch, entries)
    assert len(ptree.collect_process_group(42)) == ptree._MAX_KILL_DESCENDANTS


def test_collect_process_group_returns_empty_when_proc_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_proc(monkeypatch, None)
    assert ptree.collect_process_group(42) == []


# --------------------------------------------------------------------------- #
# group kill guards, reaping, and the pid-tree killers
# --------------------------------------------------------------------------- #


def test_kill_own_process_group_declines_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ptree, "os", _NtOsProxy())
    assert ptree._kill_own_process_group(42) == []


def test_kill_own_process_group_declines_without_posix_primitives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoPgOs:
        name = "posix"

        def __getattr__(self, attr: str) -> Any:
            if attr in {"getpgid", "killpg"}:
                raise AttributeError(attr)
            return getattr(os, attr)

    monkeypatch.setattr(ptree, "os", _NoPgOs())
    assert ptree._kill_own_process_group(42) == []


def test_reap_terminated_is_a_noop_without_the_subreaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ptree, "_LINUX_CHILD_SUBREAPER", False)
    called: list[int] = []
    monkeypatch.setattr(ptree.os, "waitpid", lambda pid, flags: called.append(pid))
    ptree._reap_terminated([123], 1.0)
    assert called == []


def test_reap_terminated_skips_pids_whose_waitpid_keeps_failing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ptree, "_LINUX_CHILD_SUBREAPER", True)

    def refuse(pid: int, flags: int) -> tuple[int, int]:
        raise OSError("EINTR forever")

    monkeypatch.setattr(ptree.os, "waitpid", refuse)
    # wait_s=0 puts the deadline in the past, so one sweep runs and returns.
    ptree._reap_terminated([123], 0.0)


def test_reap_terminated_keeps_waiting_while_the_pid_is_not_yet_ours(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ChildProcessError with a live /proc entry means "not reparented yet"."""
    monkeypatch.setattr(ptree, "_LINUX_CHILD_SUBREAPER", True)

    def not_ours(pid: int, flags: int) -> tuple[int, int]:
        raise ChildProcessError("not our child yet")

    monkeypatch.setattr(ptree.os, "waitpid", not_ours)
    # os.getpid() is alive in /proc, so the pid stays pending; the zero
    # deadline ends the sweep after one pass instead of spinning.
    ptree._reap_terminated([os.getpid()], 0.0)


class _KillableProcess:
    def __init__(self, *, pid: Any = 4242, running: bool = True) -> None:
        self.pid = pid
        self._running = running
        self.events: list[str] = []

    def poll(self) -> int | None:
        return None if self._running else 0

    def kill(self) -> None:
        self.events.append("kill")
        self._running = False

    def wait(self, timeout: float | None = None) -> int:
        self.events.append("wait")
        return 0


def test_terminate_process_tree_kills_parent_then_descendants_deepest_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed_children: list[int] = []
    reaped: list[list[int]] = []
    monkeypatch.setattr(ptree, "collect_descendants", lambda pid: [100, 101])
    monkeypatch.setattr(ptree, "_kill_own_process_group", lambda pid: [])
    monkeypatch.setattr(ptree, "_kill_pid", lambda pid: killed_children.append(pid))
    monkeypatch.setattr(ptree, "_reap_terminated", lambda pids, wait: reaped.append(list(pids)))
    process = _KillableProcess()

    killed = ptree.terminate_process_tree(process, wait_s=1.0)

    assert process.events == ["kill", "wait"]
    assert killed_children == [101, 100], "deepest first, so a respawner dies last"
    assert killed == [4242, 101, 100]
    assert reaped == [[100, 101]]


def test_terminate_process_tree_signals_the_group_when_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group_kills: list[tuple[int, int]] = []
    monkeypatch.setattr(ptree, "collect_descendants", lambda pid: [])
    monkeypatch.setattr(ptree, "_kill_own_process_group", lambda pid: [])
    monkeypatch.setattr(ptree, "_reap_terminated", lambda pids, wait: None)
    monkeypatch.setattr(
        ptree.os,
        "killpg",
        lambda pgid, sig: group_kills.append((pgid, sig)),
        raising=False,
    )
    process = _KillableProcess(running=False)

    ptree.terminate_process_tree(process, wait_s=1.0, kill_group=True)

    assert group_kills == [(4242, 9)]


def test_terminate_process_tree_survives_a_handle_without_a_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Still killed, but never reported: an unknown pid must not enter the list."""
    monkeypatch.setattr(ptree, "_reap_terminated", lambda pids, wait: None)
    process = _KillableProcess(pid=None, running=True)
    assert ptree.terminate_process_tree(process, wait_s=1.0) == []
    assert process.events == ["kill", "wait"]


def test_terminate_leftover_tree_returns_empty_when_the_walk_itself_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(pid: int) -> list[int]:
        raise RuntimeError("proc scan corrupted")

    monkeypatch.setattr(ptree, "collect_process_tree", explode)
    process = types.SimpleNamespace(pid=4242)
    assert ptree.terminate_leftover_process_tree(process) == []


def test_terminate_leftover_tree_rejects_a_handle_without_a_pid() -> None:
    assert ptree.terminate_leftover_process_tree(types.SimpleNamespace(pid=None)) == []
    assert ptree.terminate_leftover_process_tree(types.SimpleNamespace(pid=-1)) == []


def test_terminate_leftover_tree_skips_the_kill_when_nothing_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ptree, "collect_process_tree", lambda pid: [])
    swept: list[int] = []
    monkeypatch.setattr(
        ptree, "terminate_process_tree", lambda process, wait_s: swept.append(process.pid)
    )
    assert ptree.terminate_leftover_process_tree(types.SimpleNamespace(pid=4242)) == []
    assert swept == [], "a clean exit must stay a single scan, not a kill sweep"


def test_terminate_pid_tree_rejects_bad_pids() -> None:
    assert ptree.terminate_pid_tree(0) == []
    assert ptree.terminate_pid_tree("9") == []  # type: ignore[arg-type]


def test_terminate_pid_tree_kills_the_pid_then_its_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed: list[int] = []
    monkeypatch.setattr(ptree, "collect_descendants", lambda pid: [100, 101])
    monkeypatch.setattr(ptree, "_kill_own_process_group", lambda pid: [])
    monkeypatch.setattr(ptree, "_kill_pid", lambda pid: killed.append(pid))
    monkeypatch.setattr(ptree, "_reap_terminated", lambda pids, wait: None)

    assert ptree.terminate_pid_tree(4242) == [4242, 101, 100]
    assert killed == [4242, 101, 100]


def test_kill_pid_terminates_through_the_win32_arm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, Any]] = []
    _fake_kernel32(
        monkeypatch,
        OpenProcess=_ApiFn(lambda *args: 777),
        TerminateProcess=_ApiFn(lambda handle, code: events.append(("terminate", handle)) or 1),
        CloseHandle=_ApiFn(lambda handle: events.append(("close", handle)) or 1),
    )
    ptree._kill_pid(4242)
    assert events == [("terminate", 777), ("close", 777)]


def test_kill_pid_gives_up_when_the_process_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[Any] = []
    _fake_kernel32(
        monkeypatch,
        OpenProcess=_ApiFn(lambda *args: 0),
        TerminateProcess=_ApiFn(lambda *args: terminated.append(args)),
    )
    ptree._kill_pid(4242)
    assert terminated == []


# --------------------------------------------------------------------------- #
# image filtering and child-window probing
# --------------------------------------------------------------------------- #


def test_filter_same_image_pids_requires_a_known_base_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ptree, "process_image_path", lambda pid: None)
    assert ptree.filter_same_image_pids(42, [100, 101]) == []


def test_filter_same_image_pids_matches_casefolded_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = {42: "C:\\Apps\\Sample.EXE", 100: "c:\\apps\\sample.exe", 101: "c:\\other.exe"}
    monkeypatch.setattr(ptree, "process_image_path", lambda pid: images.get(pid))
    assert ptree.filter_same_image_pids(42, [100, 101, 102]) == [100]


def test_probe_child_window_candidates_reports_only_window_owners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ptree, "enumerate_direct_children", lambda pid, *, max_pids: [100, 101])
    images = {42: "c:\\app.exe", 100: "c:\\app.exe", 101: "c:\\helper.exe"}
    monkeypatch.setattr(ptree, "process_image_path", lambda pid: images.get(pid))
    windows = {
        100: [
            {"visible": True, "title": "Main"},
            {"visible": False, "title": "Hidden"},
        ],
        101: [],
    }

    probed = ptree.probe_child_window_candidates(
        42, list_windows_fn=lambda pid: windows.get(pid, [])
    )

    assert len(probed) == 1, "a child with no windows must not be reported"
    row = probed[0]
    assert row["pid"] == 100
    assert row["window_count"] == 2
    assert row["visible_count"] == 1
    assert row["titles"] == ["Main"]
    assert row["same_image"] is True
