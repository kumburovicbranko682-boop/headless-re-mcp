"""Process-tree walking and killing paths, portable on any host.

The Windows Toolhelp / OpenProcess surfaces run against fake ``ctypes.windll``
objects (with ``os.name`` faked to ``"nt"``), and the /proc scans run against
a fake ``Path`` injected into the module namespace, so every branch executes
deterministically without spawning or killing anything real.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.process_tree as process_tree
from headless_re_mcp.core.process_tree import (
    _enable_linux_child_subreaper,
    _enumerate_direct_children_proc,
    _kill_pid,
    _reap_terminated,
    _scan_proc_ppid,
    collect_descendants,
    collect_process_group,
    enumerate_direct_children,
    filter_same_image_pids,
    probe_child_window_candidates,
    process_image_path,
    terminate_leftover_process_tree,
    terminate_pid_tree,
)

# --- subreaper -------------------------------------------------------------


def test_subreaper_is_linux_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")

    assert _enable_linux_child_subreaper() is False


def test_subreaper_failure_is_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_cdll(*args: Any, **kwargs: Any) -> Any:
        raise OSError("no libc")

    monkeypatch.setattr(process_tree.ctypes, "CDLL", broken_cdll)

    assert _enable_linux_child_subreaper() is False


# --- process_image_path (Windows API via fakes) ----------------------------


class _FakeQuery:
    """Stands in for QueryFullProcessImageNameW: callable + argtypes/restype."""

    def __init__(self, image: str | None, *, ok: bool = True) -> None:
        self.image = image
        self.ok = ok

    def __call__(self, handle: Any, flags: Any, buf: Any, size_ref: Any) -> int:
        if not self.ok:
            return 0
        buf.value = self.image or ""
        return 1


def _image_kernel32(
    *, handle: int = 7, image: str | None = "C:\\app.exe", query_ok: bool = True
) -> Any:
    closed: list[Any] = []
    kernel32 = SimpleNamespace(
        OpenProcess=lambda access, inherit, pid: handle,
        QueryFullProcessImageNameW=_FakeQuery(image, ok=query_ok),
        CloseHandle=closed.append,
    )
    kernel32.closed = closed
    return kernel32


def _fake_windows(monkeypatch: pytest.MonkeyPatch, kernel32: Any) -> None:
    monkeypatch.setattr(process_tree.os, "name", "nt")
    monkeypatch.setattr(
        process_tree.ctypes,
        "windll",
        SimpleNamespace(kernel32=kernel32),
        raising=False,
    )


def test_image_path_is_none_off_windows_or_for_bad_pids() -> None:
    assert process_image_path(12345) is None
    assert process_image_path(0) is None
    assert process_image_path(True) is None  # bool is not an accepted pid type


def test_image_path_is_none_when_the_process_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_windows(monkeypatch, _image_kernel32(handle=0))

    assert process_image_path(10) is None


def test_image_path_is_none_when_the_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _image_kernel32(query_ok=False)
    _fake_windows(monkeypatch, kernel32)

    assert process_image_path(10) is None
    assert kernel32.closed == [7]


def test_image_path_returns_the_queried_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _image_kernel32(image="C:\\tools\\x64dbg.exe")
    _fake_windows(monkeypatch, kernel32)

    assert process_image_path(10) == "C:\\tools\\x64dbg.exe"
    assert kernel32.closed == [7]


def test_an_empty_image_reads_as_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_windows(monkeypatch, _image_kernel32(image=""))

    assert process_image_path(10) is None


# --- enumerate_direct_children (Windows Toolhelp via fakes) -----------------


class _FakeToolhelp:
    """Scripted Toolhelp32 snapshot walk. Rows are (ppid, pid) pairs."""

    def __init__(self, rows: list[tuple[int, int]], *, snap: int = 42) -> None:
        self.rows = list(rows)
        self.snap = snap
        self.closed: list[Any] = []

    def CreateToolhelp32Snapshot(self, flags: int, pid: int) -> int:  # noqa: N802
        return self.snap

    def _fill(self, entry_ref: Any) -> int:
        if not self.rows:
            return 0
        ppid, pid = self.rows.pop(0)
        entry = entry_ref._obj
        entry.th32ParentProcessID = ppid
        entry.th32ProcessID = pid
        return 1

    def Process32FirstW(self, snap: int, entry_ref: Any) -> int:  # noqa: N802
        return self._fill(entry_ref)

    def Process32NextW(self, snap: int, entry_ref: Any) -> int:  # noqa: N802
        return self._fill(entry_ref)

    def CloseHandle(self, handle: Any) -> None:  # noqa: N802
        self.closed.append(handle)


def test_children_of_an_invalid_pid_are_empty() -> None:
    assert enumerate_direct_children(0) == []
    assert enumerate_direct_children("1234") == []  # type: ignore[arg-type]


def test_windows_children_need_a_valid_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_windows(monkeypatch, _FakeToolhelp([], snap=0))

    assert enumerate_direct_children(1234) == []


def test_windows_children_need_a_readable_first_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeToolhelp([])
    _fake_windows(monkeypatch, kernel32)

    assert enumerate_direct_children(1234) == []
    assert kernel32.closed == [42]


def test_windows_children_walk_matches_parents_and_sorts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [(999, 5), (1234, 0), (1234, 1234), (1234, 500), (777, 88), (1234, 400)]
    kernel32 = _FakeToolhelp(rows)
    _fake_windows(monkeypatch, kernel32)

    assert enumerate_direct_children(1234) == [400, 500]
    assert kernel32.closed == [42]


def test_windows_children_walk_stops_at_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeToolhelp([(1234, 500), (1234, 400)])
    _fake_windows(monkeypatch, kernel32)

    assert enumerate_direct_children(1234, max_pids=1) == [500]


# --- /proc children + ppid scan (fake Path) ---------------------------------


class _FakeFile:
    def __init__(self, text: str | None) -> None:
        self.text = text

    def read_text(self, **kwargs: Any) -> str:
        if self.text is None:
            raise OSError("unreadable")
        return self.text


class _FakeProcEntry:
    def __init__(self, name: str, stat_text: str | None) -> None:
        self.name = name
        self._stat = _FakeFile(stat_text)

    def __truediv__(self, other: str) -> _FakeFile:
        assert other == "stat"
        return self._stat


class _FakeProcDir:
    def __init__(self, entries: list[_FakeProcEntry] | None) -> None:
        self.entries = entries

    def iterdir(self) -> Any:
        if self.entries is None:
            raise OSError("no /proc")
        return iter(self.entries)


def _fake_paths(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, Any]) -> None:
    monkeypatch.setattr(process_tree, "Path", lambda arg: mapping[str(arg)])


def test_proc_children_file_tokens_are_filtered_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_paths(
        monkeypatch,
        {"/proc/1234/task/1234/children": _FakeFile("abc -5 1234 77 99")},
    )

    assert enumerate_direct_children(1234, max_pids=1) == [77]


def test_proc_children_file_reads_all_tokens_when_under_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_paths(
        monkeypatch,
        {"/proc/1234/task/1234/children": _FakeFile("99 77")},
    )

    assert _enumerate_direct_children_proc(1234, 16) == [77, 99]


def test_an_unreadable_children_file_falls_back_to_the_ppid_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_paths(
        monkeypatch,
        {
            "/proc/1234/task/1234/children": _FakeFile(None),
            "/proc": _FakeProcDir(
                [_FakeProcEntry("77", "77 (worker) S 1234 77 1 0")]
            ),
        },
    )

    assert enumerate_direct_children(1234) == [77]


def test_ppid_scan_returns_nothing_when_proc_is_unlistable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_paths(monkeypatch, {"/proc": _FakeProcDir(None)})

    assert _scan_proc_ppid(50, 16) == []


def test_ppid_scan_skips_malformed_entries_and_stops_at_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        _FakeProcEntry("self", None),
        _FakeProcEntry("50", "50 (parent) S 1 50"),
        _FakeProcEntry("60", None),
        _FakeProcEntry("61", "61 (no-close-paren"),
        _FakeProcEntry("62", "62 (short) R"),
        _FakeProcEntry("63", "63 (bad) R xx"),
        _FakeProcEntry("64", "64 (child) S 50 64"),
        _FakeProcEntry("65", "65 (other) S 1 65"),
        _FakeProcEntry("66", "66 (child) S 50 66"),
        _FakeProcEntry("67", "67 (never-reached) S 50 67"),
    ]
    _fake_paths(monkeypatch, {"/proc": _FakeProcDir(entries)})

    assert _scan_proc_ppid(50, 2) == [64, 66]


# --- collect_descendants ----------------------------------------------------


def test_descendants_deduplicate_shared_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = {1: [2, 3], 2: [4, 3], 3: [], 4: []}
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, max_pids=16: tree.get(pid, []),
    )

    assert collect_descendants(1) == [2, 3, 4]


def test_descendants_stop_at_the_kill_walk_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "_MAX_KILL_DESCENDANTS", 2)
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, max_pids=16: [pid * 10 + 1, pid * 10 + 2, pid * 10 + 3],
    )

    assert collect_descendants(1) == [11, 12]


def test_descendants_stop_at_the_depth_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, max_pids=16: [pid + 1],
    )

    assert collect_descendants(1) == [2, 3, 4, 5]


# --- collect_process_group ---------------------------------------------------


def test_process_group_is_posix_only_and_needs_a_valid_pgid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert collect_process_group(0) == []
    assert collect_process_group("50") == []  # type: ignore[arg-type]

    monkeypatch.setattr(process_tree.os, "name", "nt")
    assert collect_process_group(50) == []


def test_process_group_returns_nothing_when_proc_is_unlistable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_paths(monkeypatch, {"/proc": _FakeProcDir(None)})

    assert collect_process_group(50) == []


def test_process_group_matches_on_pgrp_and_stops_at_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        _FakeProcEntry("self", None),
        _FakeProcEntry("50", "50 (leader) S 1 50"),
        _FakeProcEntry("70", None),
        _FakeProcEntry("71", "71 (no-close-paren"),
        _FakeProcEntry("72", "72 (short) R 1"),
        _FakeProcEntry("73", "73 (member) S 1 50"),
        _FakeProcEntry("74", "74 (never-reached) S 1 50"),
    ]
    _fake_paths(monkeypatch, {"/proc": _FakeProcDir(entries)})
    monkeypatch.setattr(process_tree, "_MAX_KILL_DESCENDANTS", 1)

    assert collect_process_group(50) == [73]


# --- _kill_own_process_group -------------------------------------------------


def test_group_kill_is_a_noop_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree.os, "name", "nt")

    assert process_tree._kill_own_process_group(1234) == []


def test_group_kill_is_a_noop_without_posix_primitives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(process_tree.os, "getpgid")

    assert process_tree._kill_own_process_group(1234) == []


# --- _reap_terminated ---------------------------------------------------------


def test_reaping_is_skipped_without_the_subreaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any) -> Any:
        raise AssertionError("must not wait")

    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", False)
    monkeypatch.setattr(process_tree.os, "waitpid", forbidden)

    _reap_terminated([123], 0.5)


def test_reaping_tolerates_waitpid_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def flaky_waitpid(pid: int, options: int) -> Any:
        raise OSError("interrupted")

    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
    monkeypatch.setattr(process_tree.os, "waitpid", flaky_waitpid)

    _reap_terminated([123], 0.0)


# --- terminate helpers ---------------------------------------------------------


def test_leftover_sweep_swallows_a_failing_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_walk(pid: int) -> list[int]:
        raise RuntimeError("scan failed")

    monkeypatch.setattr(process_tree, "collect_process_tree", broken_walk)

    assert terminate_leftover_process_tree(SimpleNamespace(pid=1234)) == []


def test_leftover_sweep_ignores_a_handle_without_a_pid() -> None:
    assert terminate_leftover_process_tree(SimpleNamespace(pid=None)) == []


def test_leftover_sweep_is_a_noop_when_nothing_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_kill(process: Any, **kwargs: Any) -> list[int]:
        raise AssertionError("a clean exit must not be killed")

    monkeypatch.setattr(process_tree, "collect_process_tree", lambda pid: [])
    monkeypatch.setattr(process_tree, "terminate_process_tree", forbidden_kill)

    assert terminate_leftover_process_tree(SimpleNamespace(pid=1234)) == []


def test_tree_kill_of_a_pidless_handle_still_kills_the_process() -> None:
    calls: list[str] = []

    class _Handle:
        pid = None

        def poll(self) -> None:
            calls.append("poll")
            return None

        def kill(self) -> None:
            calls.append("kill")

        def wait(self, timeout: float) -> None:
            calls.append("wait")

    assert process_tree.terminate_process_tree(_Handle(), wait_s=0.1) == []
    assert calls == ["poll", "kill", "wait"]


def test_pid_tree_kill_rejects_invalid_pids() -> None:
    assert terminate_pid_tree(0) == []
    assert terminate_pid_tree("1234") == []  # type: ignore[arg-type]


class _FakeTerminator:
    def __init__(self, *, handle: int = 9) -> None:
        self.handle = handle
        self.terminated: list[tuple[Any, int]] = []
        self.closed: list[Any] = []

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:  # noqa: N802
        return self.handle

    def TerminateProcess(self, handle: Any, code: int) -> None:  # noqa: N802
        self.terminated.append((handle, code))

    def CloseHandle(self, handle: Any) -> None:  # noqa: N802
        self.closed.append(handle)


def test_windows_kill_gives_up_when_the_process_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeTerminator(handle=0)
    _fake_windows(monkeypatch, kernel32)

    _kill_pid(1234)

    assert kernel32.terminated == []
    assert kernel32.closed == []


def test_windows_kill_terminates_and_closes_the_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeTerminator()
    _fake_windows(monkeypatch, kernel32)

    _kill_pid(1234)

    assert kernel32.terminated == [(9, 1)]
    assert kernel32.closed == [9]


# --- image filtering and window probing ----------------------------------------


def test_image_filter_is_empty_when_the_debuggee_has_no_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: None)

    assert filter_same_image_pids(1, [2, 3]) == []


def test_image_filter_matches_casefolded_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = {1: "C:\\App\\a.exe", 2: "c:\\app\\A.EXE", 3: "C:\\other.exe", 4: None}
    monkeypatch.setattr(
        process_tree, "process_image_path", lambda pid: images.get(pid)
    )

    assert filter_same_image_pids(1, [2, 3, 4]) == [2]


def test_window_probe_reports_only_children_that_own_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process_tree, "enumerate_direct_children", lambda pid, max_pids=16: [10, 11]
    )
    images = {1: "C:\\a.exe", 11: "c:\\A.EXE"}
    monkeypatch.setattr(
        process_tree, "process_image_path", lambda pid: images.get(pid)
    )
    windows = {
        10: [],
        11: [
            {"visible": True, "title": "Main"},
            {"visible": False, "title": "hidden"},
            {"visible": True, "title": None},
        ],
    }

    probed = probe_child_window_candidates(1, list_windows_fn=windows.get)

    assert len(probed) == 1
    entry = probed[0]
    assert entry["pid"] == 11
    assert entry["window_count"] == 3
    assert entry["visible_count"] == 2
    assert entry["titles"] == ["Main", ""]
    assert entry["same_image"] is True
