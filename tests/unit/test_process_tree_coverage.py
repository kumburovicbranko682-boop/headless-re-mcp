"""Targeted coverage for :mod:`headless_re_mcp.core.process_tree`.

The ``/proc`` parsers run against a redirected fake ``/proc`` built in a
tmp directory so every malformed-entry branch is deterministic. The Win32
paths run with ``os.name`` forced to ``nt`` and a fake ``kernel32`` (with
``ctypes.byref`` shimmed to identity so the fakes can populate the real
``PROCESSENTRY32W`` structure the enumerator hands them).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.core import process_tree

# --------------------------------------------------------------------------- #
# Fake /proc redirect                                                          #
# --------------------------------------------------------------------------- #

_REAL_PATH = Path


def _redirect_proc(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    def factory(arg: Any) -> Path:
        text = str(arg)
        if text == "/proc":
            return _REAL_PATH(root)
        prefix = "/proc/"
        if text.startswith(prefix):
            return _REAL_PATH(root) / text[len(prefix) :]
        return _REAL_PATH(text)

    monkeypatch.setattr(process_tree, "Path", factory)


class _RaisingProcRoot:
    def iterdir(self) -> Any:
        raise OSError("/proc is unreadable")


def _redirect_proc_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    def factory(arg: Any) -> Any:
        if str(arg) == "/proc":
            return _RaisingProcRoot()
        return _REAL_PATH(str(arg))

    monkeypatch.setattr(process_tree, "Path", factory)


def _write_stat(proc: Path, pid: int, *, ppid: int, pgrp: int, comm: str = "proc") -> None:
    entry = proc / str(pid)
    entry.mkdir(parents=True, exist_ok=True)
    (entry / "stat").write_text(
        f"{pid} ({comm}) S {ppid} {pgrp} {pgrp} 0 -1 0\n",
        encoding="ascii",
    )


def _write_children(proc: Path, pid: int, tokens: str) -> None:
    task = proc / str(pid) / "task" / str(pid)
    task.mkdir(parents=True, exist_ok=True)
    (task / "children").write_text(tokens, encoding="ascii")


@pytest.fixture()
def fake_proc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    proc = tmp_path / "proc"
    proc.mkdir()
    # A non-numeric sibling that the scanners must ignore.
    (proc / "self").mkdir()
    # child pid 0 must be skipped by the pid<=0 guard.
    (proc / "0").mkdir()
    (proc / "0" / "stat").write_text("0 (zero) S 1 0 0\n", encoding="ascii")
    _write_stat(proc, 100, ppid=1, pgrp=100, comm="parent")
    _write_stat(proc, 200, ppid=100, pgrp=100, comm="child")
    _write_stat(proc, 201, ppid=100, pgrp=201, comm="kid")
    _write_stat(proc, 300, ppid=200, pgrp=100, comm="grand")
    _write_children(proc, 100, "200 xyz 201 0 100")
    _write_children(proc, 200, "300")
    _write_children(proc, 300, "200")  # cycle back to an already-seen pid
    # 777 has no stat file -> OSError on read.
    (proc / "777").mkdir()
    # 888 has a stat line with no closing paren.
    (proc / "888").mkdir()
    (proc / "888" / "stat").write_text("888 no_paren_here", encoding="ascii")
    # 999 has a stat whose ppid/pgrp fields are missing/garbage.
    (proc / "999").mkdir()
    (proc / "999" / "stat").write_text("999 (bad) X", encoding="ascii")
    _redirect_proc(monkeypatch, proc)
    return proc


# --------------------------------------------------------------------------- #
# _enable_linux_child_subreaper                                                #
# --------------------------------------------------------------------------- #


def test_subreaper_is_false_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree.sys, "platform", "darwin")
    assert process_tree._enable_linux_child_subreaper() is False


def test_subreaper_is_false_when_prctl_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree.sys, "platform", "linux")

    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("no prctl here")

    monkeypatch.setattr(process_tree.ctypes, "CDLL", boom)
    assert process_tree._enable_linux_child_subreaper() is False


# --------------------------------------------------------------------------- #
# enumerate_direct_children (validators + /proc)                               #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", [-1, 0, "nope"])
def test_enumerate_rejects_bad_pids(bad: Any) -> None:
    assert process_tree.enumerate_direct_children(bad) == []


def test_enumerate_reads_the_children_file(fake_proc: Path) -> None:
    assert process_tree.enumerate_direct_children(100, max_pids=8) == [200, 201]


def test_enumerate_children_file_honours_the_limit(fake_proc: Path) -> None:
    assert process_tree.enumerate_direct_children(100, max_pids=1) == [200]


def test_enumerate_falls_back_to_a_ppid_scan(fake_proc: Path) -> None:
    # pid 201 has no children file, so the reader falls back to the scan and
    # finds nothing parented to it.
    assert process_tree.enumerate_direct_children(201, max_pids=8) == []


# --------------------------------------------------------------------------- #
# _scan_proc_ppid                                                              #
# --------------------------------------------------------------------------- #


def test_scan_proc_ppid_matches_and_skips_malformed_entries(fake_proc: Path) -> None:
    assert process_tree._scan_proc_ppid(100, 8) == [200, 201]


def test_scan_proc_ppid_honours_the_limit(fake_proc: Path) -> None:
    assert len(process_tree._scan_proc_ppid(100, 1)) == 1


def test_scan_proc_ppid_returns_empty_when_proc_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _redirect_proc_unreadable(monkeypatch)
    assert process_tree._scan_proc_ppid(100, 8) == []


# --------------------------------------------------------------------------- #
# collect_descendants                                                          #
# --------------------------------------------------------------------------- #


def test_collect_descendants_walks_the_tree_and_ignores_cycles(fake_proc: Path) -> None:
    assert process_tree.collect_descendants(100) == [200, 201, 300]


def test_collect_descendants_stops_at_the_bound(
    fake_proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process_tree, "_MAX_KILL_DESCENDANTS", 2)
    found = process_tree.collect_descendants(100)
    assert len(found) == 2


def test_collect_descendants_stops_at_the_depth_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    # A chain longer than the depth bound leaves a non-empty frontier when the
    # loop runs out of iterations, so the walk stops without emptying it.
    chain = {100: [200], 200: [300], 300: [400], 400: [500], 500: [600]}
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, **_k: chain.get(pid, []),
    )
    assert process_tree.collect_descendants(100) == [200, 300, 400, 500]


# --------------------------------------------------------------------------- #
# collect_process_group / terminate_process_group                             #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", [-1, 0])
def test_collect_process_group_rejects_bad_gids(bad: int) -> None:
    assert process_tree.collect_process_group(bad) == []


def test_collect_process_group_is_empty_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree.os, "name", "nt")
    assert process_tree.collect_process_group(100) == []


def test_collect_process_group_matches_pgrp_and_skips_malformed(fake_proc: Path) -> None:
    assert process_tree.collect_process_group(100) == [200, 300]


def test_collect_process_group_honours_the_limit(
    fake_proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process_tree, "_MAX_KILL_DESCENDANTS", 1)
    assert len(process_tree.collect_process_group(100)) == 1


def test_collect_process_group_returns_empty_when_proc_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _redirect_proc_unreadable(monkeypatch)
    assert process_tree.collect_process_group(100) == []


def test_terminate_process_group_kills_each_member(
    fake_proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    killed_pids: list[int] = []
    monkeypatch.setattr(process_tree, "_kill_pid", killed_pids.append)

    result = process_tree.terminate_process_group(100)

    assert result == [200, 300]
    assert killed_pids == [200, 300]


# --------------------------------------------------------------------------- #
# _kill_own_process_group edges                                                #
# --------------------------------------------------------------------------- #


def test_kill_own_group_is_empty_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree.os, "name", "nt")
    assert process_tree._kill_own_process_group(123) == []


def test_kill_own_group_is_empty_without_posix_group_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree.os, "name", "posix")
    monkeypatch.setattr(process_tree.os, "getpgid", None, raising=False)
    assert process_tree._kill_own_process_group(123) == []


# --------------------------------------------------------------------------- #
# _reap_terminated                                                             #
# --------------------------------------------------------------------------- #


def test_reap_is_a_noop_without_the_subreaper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", False)
    called = False

    def boom(*_a: Any, **_k: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("waitpid must not be called")

    monkeypatch.setattr(process_tree.os, "waitpid", boom)
    process_tree._reap_terminated([111], 0.1)
    assert called is False


def test_reap_retires_children(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
    monkeypatch.setattr(process_tree.os, "waitpid", lambda pid, _flags: (pid, 0))
    process_tree._reap_terminated([111], 0.1)


def test_reap_discards_a_vanished_pid(
    fake_proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)

    def gone(_pid: int, _flags: int) -> Any:
        raise ChildProcessError("not our child")

    monkeypatch.setattr(process_tree.os, "waitpid", gone)
    # pid 555 has no /proc entry in the fake tree, so it is treated as retired.
    process_tree._reap_terminated([555], 0.1)


def test_reap_tolerates_transient_oserrors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)

    def flaky(_pid: int, _flags: int) -> Any:
        raise OSError("temporary")

    clock = {"t": 0.0}

    def mono() -> float:
        clock["t"] += 0.05
        return clock["t"]

    monkeypatch.setattr(process_tree.os, "waitpid", flaky)
    monkeypatch.setattr(process_tree.time, "monotonic", mono)
    monkeypatch.setattr(process_tree.time, "sleep", lambda _s: None)
    process_tree._reap_terminated([111], 0.1)


# --------------------------------------------------------------------------- #
# terminate_leftover_process_tree / terminate_pid_tree                         #
# --------------------------------------------------------------------------- #


def test_leftover_tree_swallows_enumeration_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_pid: int) -> Any:
        raise RuntimeError("snapshot failed")

    monkeypatch.setattr(process_tree, "collect_process_tree", boom)
    assert process_tree.terminate_leftover_process_tree(SimpleNamespace(pid=12345)) == []


@pytest.mark.parametrize("bad", [-1, 0, "nope"])
def test_terminate_pid_tree_rejects_bad_pids(bad: Any) -> None:
    assert process_tree.terminate_pid_tree(bad) == []


def test_terminate_pid_tree_kills_pid_and_descendants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_descendants", lambda _pid: [222])
    monkeypatch.setattr(process_tree, "_kill_own_process_group", lambda _pid: [])
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda *_a, **_k: None)
    killed_pids: list[int] = []
    monkeypatch.setattr(process_tree, "_kill_pid", killed_pids.append)

    result = process_tree.terminate_pid_tree(4242)

    assert result == [4242, 222]
    assert killed_pids == [4242, 222]


# --------------------------------------------------------------------------- #
# filter_same_image_pids / probe_child_window_candidates                       #
# --------------------------------------------------------------------------- #


def test_filter_same_image_pids_is_empty_without_a_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "process_image_path", lambda _pid: None)
    assert process_tree.filter_same_image_pids(1, [2, 3]) == []


def test_filter_same_image_pids_keeps_matching_images(monkeypatch: pytest.MonkeyPatch) -> None:
    images = {1: r"C:\App\App.EXE", 2: r"c:\app\app.exe", 3: r"C:\Other\other.exe"}
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: images.get(pid))
    assert process_tree.filter_same_image_pids(1, [2, 3]) == [2]


def test_probe_child_window_candidates_summarizes_windowed_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda _pid, **_k: [10, 11])
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: f"/img/{pid}")

    def lister(pid: int) -> list[dict[str, Any]]:
        if pid == 10:
            return [{"visible": True, "title": "Main"}, {"visible": False, "title": "Hidden"}]
        return []

    result = process_tree.probe_child_window_candidates(1, list_windows_fn=lister)

    assert len(result) == 1
    only = result[0]
    assert only["pid"] == 10
    assert only["window_count"] == 2
    assert only["visible_count"] == 1
    assert only["titles"] == ["Main"]
    assert only["same_image"] is False


# --------------------------------------------------------------------------- #
# Win32 paths                                                                  #
# --------------------------------------------------------------------------- #


def _use_windows(monkeypatch: pytest.MonkeyPatch, kernel32: Any) -> None:
    monkeypatch.setattr(process_tree.os, "name", "nt")
    monkeypatch.setattr(
        process_tree.ctypes, "windll", SimpleNamespace(kernel32=kernel32), raising=False
    )
    # The enumerator/image reader populate a real ctypes structure/buffer handed
    # to the fake calls, so make byref a passthrough for this test.
    monkeypatch.setattr(process_tree.ctypes, "byref", lambda obj: obj)


def test_process_image_path_reads_the_win32_image(monkeypatch: pytest.MonkeyPatch) -> None:
    def query(_handle: int, _flags: int, buf: Any, _size: Any) -> int:
        buf.value = r"C:\Program Files\App\app.exe"
        return 1

    kernel32 = SimpleNamespace(
        OpenProcess=lambda *_a: 0x2000,
        CloseHandle=lambda *_a: 1,
        QueryFullProcessImageNameW=query,
    )
    _use_windows(monkeypatch, kernel32)

    assert process_tree.process_image_path(4242) == r"C:\Program Files\App\app.exe"


def test_process_image_path_returns_none_off_windows() -> None:
    assert process_tree.process_image_path(999999) is None


def test_process_image_path_handles_a_closed_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = SimpleNamespace(
        OpenProcess=lambda *_a: 0,
        CloseHandle=lambda *_a: 1,
        QueryFullProcessImageNameW=lambda *_a: 1,
    )
    _use_windows(monkeypatch, kernel32)

    assert process_tree.process_image_path(4242) is None


def test_process_image_path_returns_none_when_the_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = SimpleNamespace(
        OpenProcess=lambda *_a: 0x2000,
        CloseHandle=lambda *_a: 1,
        QueryFullProcessImageNameW=lambda *_a: 0,
    )
    _use_windows(monkeypatch, kernel32)

    assert process_tree.process_image_path(4242) is None


class _FakeToolhelp:
    def __init__(self, processes: list[tuple[int, int]], *, snap: int = 0x1000) -> None:
        self._processes = processes
        self._snap = snap
        self._index = -1

    def CreateToolhelp32Snapshot(self, _flags: int, _pid: int) -> int:
        return self._snap

    def Process32FirstW(self, _snap: int, entry: Any) -> int:
        self._index = 0
        if not self._processes:
            return 0
        pid, ppid = self._processes[0]
        entry.th32ProcessID = pid
        entry.th32ParentProcessID = ppid
        return 1

    def Process32NextW(self, _snap: int, entry: Any) -> int:
        self._index += 1
        if self._index >= len(self._processes):
            return 0
        pid, ppid = self._processes[self._index]
        entry.th32ProcessID = pid
        entry.th32ParentProcessID = ppid
        return 1

    def CloseHandle(self, _handle: int) -> int:
        return 1


def test_enumerate_direct_children_win32_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    # (100, 100) is parented to the target but is the target itself, so the loop
    # must skip it instead of listing a process as its own child.
    kernel32 = _FakeToolhelp([(100, 1), (200, 100), (100, 100), (201, 100), (300, 200)])
    _use_windows(monkeypatch, kernel32)

    assert process_tree.enumerate_direct_children(100, max_pids=8) == [200, 201]


def test_enumerate_direct_children_win32_honours_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeToolhelp([(200, 100), (201, 100)])
    _use_windows(monkeypatch, kernel32)

    assert process_tree.enumerate_direct_children(100, max_pids=1) == [200]


def test_enumerate_direct_children_win32_empty_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = _FakeToolhelp([], snap=0)
    _use_windows(monkeypatch, kernel32)

    assert process_tree.enumerate_direct_children(100, max_pids=8) == []


def test_enumerate_direct_children_win32_first_entry_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeToolhelp([])
    _use_windows(monkeypatch, kernel32)

    assert process_tree.enumerate_direct_children(100, max_pids=8) == []


def test_kill_pid_uses_terminate_process_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"terminated": False, "closed": False}

    def terminate(_handle: int, _code: int) -> int:
        calls["terminated"] = True
        return 1

    def close(_handle: int) -> int:
        calls["closed"] = True
        return 1

    kernel32 = SimpleNamespace(
        OpenProcess=lambda *_a: 0x3000,
        TerminateProcess=terminate,
        CloseHandle=close,
    )
    _use_windows(monkeypatch, kernel32)

    process_tree._kill_pid(4242)

    assert calls == {"terminated": True, "closed": True}


def test_kill_pid_on_windows_tolerates_a_closed_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel32 = SimpleNamespace(
        OpenProcess=lambda *_a: 0,
        TerminateProcess=lambda *_a: 1,
        CloseHandle=lambda *_a: 1,
    )
    _use_windows(monkeypatch, kernel32)

    process_tree._kill_pid(4242)  # returns without raising
