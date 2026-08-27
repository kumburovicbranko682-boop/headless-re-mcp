"""Guard-path tests for the timeout-kill process-tree walker.

Every CLI-driven backend -- jadx, apktool, Ghidra, webcrack, de4dot -- relies
on this module to kill a timed-out launcher *and* the JVM or node worker it
started, and the Playwright track uses it to sweep a wedged browser by bare
PID.  These tests fake /proc and the os module so the parsing, bounding, and
reaping arms run deterministically without racing real processes.
"""

from __future__ import annotations

import os
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.core import process_tree as pt


class _FakeStat:
    def __init__(self, text: str | None, error: bool) -> None:
        self._text = text
        self._error = error

    def read_text(self, **_kwargs: Any) -> str:
        if self._error or self._text is None:
            raise OSError("unreadable stat")
        return self._text


class _FakeEntry:
    """One /proc directory entry with a controllable stat file."""

    def __init__(
        self, name: str, stat_text: str | None = None, *, stat_error: bool = False
    ) -> None:
        self.name = name
        self._stat = _FakeStat(stat_text, stat_error)

    def __truediv__(self, _other: str) -> _FakeStat:
        return self._stat


def _fake_proc(
    monkeypatch: pytest.MonkeyPatch,
    *,
    entries: list[_FakeEntry] | None = None,
    children_text: str | None = None,
    iterdir_error: bool = False,
) -> None:
    """Replace the module's Path so /proc reads come from the fixtures."""

    class _FakePath:
        def __init__(self, _raw: object) -> None:
            pass

        def read_text(self, **_kwargs: Any) -> str:
            if children_text is None:
                raise OSError("no children file")
            return children_text

        def iterdir(self) -> Any:
            if iterdir_error:
                raise OSError("no /proc")
            return iter(entries or [])

    monkeypatch.setattr(pt, "Path", _FakePath)


class _OsProxy:
    """Delegates to the real os module except for the named overrides."""

    def __init__(self, **overrides: Any) -> None:
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        if name in self._overrides:
            value = self._overrides[name]
            if value is AttributeError:
                raise AttributeError(name)
            return value
        return getattr(os, name)


def test_subreaper_probe_is_false_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert pt._enable_linux_child_subreaper() is False


def test_subreaper_probe_swallows_a_missing_libc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")

    def _no_libc(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("no libc")

    monkeypatch.setattr(pt, "ctypes", SimpleNamespace(CDLL=_no_libc))
    assert pt._enable_linux_child_subreaper() is False


@pytest.mark.parametrize(("prctl_result", "expected"), [(0, True), (1, False)])
def test_subreaper_probe_reads_the_prctl_result(
    monkeypatch: pytest.MonkeyPatch, prctl_result: int, expected: bool
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    libc = SimpleNamespace(prctl=lambda *_args: prctl_result)
    monkeypatch.setattr(pt, "ctypes", SimpleNamespace(CDLL=lambda *_a, **_k: libc))
    assert pt._enable_linux_child_subreaper() is expected


def test_process_image_path_is_none_off_windows() -> None:
    assert pt.process_image_path(1234) is None
    assert pt.process_image_path(-1) is None
    assert pt.process_image_path("1234") is None  # type: ignore[arg-type]


def test_enumerate_direct_children_rejects_bad_pids() -> None:
    assert pt.enumerate_direct_children(0) == []
    assert pt.enumerate_direct_children(-5) == []
    assert pt.enumerate_direct_children("7") == []  # type: ignore[arg-type]


def test_children_file_parse_skips_garbage_and_self(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_proc(monkeypatch, children_text="9 abc 42 7\n")
    assert pt.enumerate_direct_children(42) == [7, 9]


def test_children_file_parse_stops_at_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_proc(monkeypatch, children_text="1 2 3 4 5\n")
    assert pt.enumerate_direct_children(99, max_pids=2) == [1, 2]


def test_ppid_scan_covers_every_malformed_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the children file is unreadable the /proc scan takes over."""
    parent = 200
    entries = [
        _FakeEntry("self"),  # not a pid
        _FakeEntry("0"),  # pid <= 0
        _FakeEntry(str(parent)),  # the parent itself
        _FakeEntry("300", stat_error=True),  # unreadable stat
        _FakeEntry("301", "garbage without a comm field"),  # no closing paren
        _FakeEntry("302", "302 (x)"),  # too few fields after the comm
        _FakeEntry("303", "303 (x) S notanint 303"),  # unparseable ppid
        _FakeEntry("304", f"304 (x) S {parent} 304 1"),  # match
        _FakeEntry("305", "305 (x) S 1 305 1"),  # different parent
        _FakeEntry("306", f"306 (x) S {parent} 306 1"),  # match, hits the limit
        _FakeEntry("307", f"307 (x) S {parent} 307 1"),  # never reached
    ]
    _fake_proc(monkeypatch, entries=entries)
    assert pt.enumerate_direct_children(parent, max_pids=2) == [304, 306]


def test_ppid_scan_survives_a_missing_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_proc(monkeypatch, iterdir_error=True)
    assert pt._scan_proc_ppid(1, 5) == []


def test_collect_descendants_stops_at_the_depth_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = {1: [2], 2: [3], 3: [4], 4: [5], 5: [6]}

    def _children(pid: int, *, max_pids: int = 16) -> list[int]:
        return chain.get(pid, [])

    monkeypatch.setattr(pt, "enumerate_direct_children", _children)
    assert pt.collect_descendants(1) == [2, 3, 4, 5]


def test_collect_descendants_does_not_loop_on_a_pid_cycle(monkeypatch: pytest.MonkeyPatch) -> None:
    cycle = {1: [2], 2: [1, 3], 3: []}

    def _children(pid: int, *, max_pids: int = 16) -> list[int]:
        return cycle.get(pid, [])

    monkeypatch.setattr(pt, "enumerate_direct_children", _children)
    assert pt.collect_descendants(1) == [2, 3]


def test_collect_descendants_stops_at_the_breadth_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    wide = {1: list(range(10, 10 + 100))}

    def _children(pid: int, *, max_pids: int = 16) -> list[int]:
        return wide.get(pid, [])

    monkeypatch.setattr(pt, "enumerate_direct_children", _children)
    found = pt.collect_descendants(1)
    assert len(found) == pt._MAX_KILL_DESCENDANTS


def test_collect_process_group_rejects_bad_pgids() -> None:
    assert pt.collect_process_group(0) == []
    assert pt.collect_process_group(-1) == []
    assert pt.collect_process_group("9") == []  # type: ignore[arg-type]


def test_collect_process_group_survives_a_missing_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_proc(monkeypatch, iterdir_error=True)
    assert pt.collect_process_group(100) == []


def test_collect_process_group_skips_malformed_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    pgid = 500
    entries = [
        _FakeEntry("cmdline"),  # not a pid
        _FakeEntry(str(pgid)),  # the leader itself
        _FakeEntry("600", stat_error=True),  # unreadable stat
        _FakeEntry("601", "garbage without a comm field"),  # no closing paren
        _FakeEntry("602", "602 (x) S"),  # too few fields for pgrp
        _FakeEntry("603", f"603 (x) S 1 {pgid} 1"),  # member
        _FakeEntry("604", "604 (x) S 1 999 1"),  # different group
    ]
    _fake_proc(monkeypatch, entries=entries)
    assert pt.collect_process_group(pgid) == [603]


def test_collect_process_group_stops_at_the_kill_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    pgid = 500
    entries = [
        _FakeEntry(str(700 + index), f"{700 + index} (x) S 1 {pgid} 1")
        for index in range(pt._MAX_KILL_DESCENDANTS + 5)
    ]
    _fake_proc(monkeypatch, entries=entries)
    assert len(pt.collect_process_group(pgid)) == pt._MAX_KILL_DESCENDANTS


def test_kill_own_process_group_is_a_noop_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pt, "os", _OsProxy(name="nt"))
    assert pt._kill_own_process_group(123) == []


def test_kill_own_process_group_needs_the_posix_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pt, "os", _OsProxy(getpgid=AttributeError, killpg=AttributeError))
    assert pt._kill_own_process_group(123) == []


def test_kill_own_process_group_only_signals_a_leader(monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[tuple[int, int]] = []
    proxy = _OsProxy(
        getpgid=lambda pid: pid + 1,
        killpg=lambda pid, sig: killed.append((pid, sig)),
    )
    monkeypatch.setattr(pt, "os", proxy)
    assert pt._kill_own_process_group(123) == []
    assert killed == []


def test_kill_own_process_group_signals_the_led_group(monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[tuple[int, int]] = []
    proxy = _OsProxy(
        getpgid=lambda pid: pid,
        killpg=lambda pid, sig: killed.append((pid, sig)),
    )
    monkeypatch.setattr(pt, "os", proxy)
    assert pt._kill_own_process_group(123) == [123]
    assert killed == [(123, 9)]


def test_reap_is_a_noop_without_the_subreaper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pt, "_LINUX_CHILD_SUBREAPER", False)

    def _forbidden(*_args: Any) -> Any:
        raise AssertionError("waitpid must not run without the subreaper")

    monkeypatch.setattr(pt, "os", _OsProxy(waitpid=_forbidden))
    pt._reap_terminated([1234], 0.5)


def test_reap_retires_a_pid_that_is_already_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    """ChildProcessError plus a missing /proc entry means fully retired."""
    monkeypatch.setattr(pt, "_LINUX_CHILD_SUBREAPER", True)
    probe = subprocess.Popen([sys.executable, "-c", "pass"])
    pid = probe.pid
    probe.wait(timeout=10)
    pt._reap_terminated([pid], 0.5)


def test_reap_keeps_waiting_on_a_live_foreign_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    """ChildProcessError while /proc still lists the pid: not ours, keep looping."""
    monkeypatch.setattr(pt, "_LINUX_CHILD_SUBREAPER", True)
    pt._reap_terminated([1], 0.05)  # init: alive, never our child


def test_reap_swallows_a_generic_waitpid_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pt, "_LINUX_CHILD_SUBREAPER", True)

    def _broken(*_args: Any) -> Any:
        raise OSError("EINVAL")

    monkeypatch.setattr(pt, "os", _OsProxy(waitpid=_broken))
    pt._reap_terminated([os.getpid()], 0.05)


def test_leftover_sweep_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _broken(_pid: int) -> list[int]:
        raise RuntimeError("proc scan exploded")

    monkeypatch.setattr(pt, "collect_process_tree", _broken)
    assert pt.terminate_leftover_process_tree(SimpleNamespace(pid=4321)) == []


def test_terminate_pid_tree_rejects_bad_pids() -> None:
    assert pt.terminate_pid_tree(0) == []
    assert pt.terminate_pid_tree(-1) == []
    assert pt.terminate_pid_tree("7") == []  # type: ignore[arg-type]


def test_filter_same_image_pids_matches_casefolded_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = {
        10: "C:\\tools\\target.exe",
        11: "c:\\TOOLS\\TARGET.EXE",
        12: "c:\\other\\thing.exe",
        13: None,
    }
    monkeypatch.setattr(pt, "process_image_path", lambda pid: images.get(pid))
    assert pt.filter_same_image_pids(10, [11, 12, 13]) == [11]


def test_filter_same_image_pids_is_empty_without_a_base_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pt, "process_image_path", lambda _pid: None)
    assert pt.filter_same_image_pids(10, [11]) == []


def test_window_probe_reports_only_children_that_own_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pt, "enumerate_direct_children", lambda pid, *, max_pids=16: [10, 11, 12])
    images = {5: "c:\\a.exe", 10: "c:\\a.exe", 11: "c:\\b.exe", 12: None}
    monkeypatch.setattr(pt, "process_image_path", lambda pid: images.get(pid))
    windows = {
        10: [{"visible": True, "title": "Main"}, {"visible": False, "title": "Hidden"}],
        11: [{"visible": False, "title": "Tray"}],
        12: [],
    }
    out = pt.probe_child_window_candidates(5, list_windows_fn=lambda pid: windows[pid])
    assert [item["pid"] for item in out] == [10, 11]
    first = out[0]
    assert first["window_count"] == 2
    assert first["visible_count"] == 1
    assert first["titles"] == ["Main"]
    assert first["same_image"] is True
    assert out[1]["visible_count"] == 0
    assert out[1]["same_image"] is False
