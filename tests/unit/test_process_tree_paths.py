"""Full-surface coverage for ``core.process_tree``.

The module speaks two dialects that never both run on one host: a Windows half
(``ctypes.windll`` Toolhelp snapshots, ``QueryFullProcessImageNameW``,
``TerminateProcess``) and a POSIX half (``/proc`` ppid/pgrp scans, ``killpg``,
subreaper reaping). On a Linux runner the Windows half is otherwise dark and the
POSIX half only sees the paths a live process happens to produce. These fakes
stand in for ``ctypes.windll`` and for the ``/proc`` filesystem so both dialects
plus every guard, break-at-limit, and error fall-through are exercised.
"""

from __future__ import annotations

import ctypes
import os
import re
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.core import process_tree

# ---------------------------------------------------------------------------
# ctypes.windll fakes


class _Fn:
    """Callable that tolerates the argtypes/restype assignment the code does."""

    def __init__(self, fn: Any) -> None:
        self._fn = fn
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._fn(*args, **kwargs)


class _ImageKernel32:
    """kernel32 for ``process_image_path``: OpenProcess + QueryFullProcessImageNameW."""

    def __init__(self, *, handle: int = 55, image: str = "C:\\tool.exe", q_ok: bool = True) -> None:
        self.handle = handle
        self.image = image
        self.q_ok = q_ok
        self.closed: list[int] = []
        self.QueryFullProcessImageNameW = _Fn(self._query)

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return self.handle

    def _query(self, _handle: int, _flags: int, buf: Any, _size: Any) -> int:
        if not self.q_ok:
            return 0
        buf.value = self.image
        return 1

    def CloseHandle(self, handle: int) -> int:
        self.closed.append(int(handle))
        return 1


class _SnapKernel32:
    """kernel32 for the Toolhelp process walk: fills the entry struct per step."""

    def __init__(
        self, procs: list[tuple[int, int]], *, snap: int = 99, first_ok: bool = True
    ) -> None:
        self._procs = list(procs)
        self._snap = snap
        self._first_ok = first_ok
        self._idx = -1
        self.closed: list[int] = []

    def CreateToolhelp32Snapshot(self, _flags: int, _pid: int) -> int:
        return self._snap

    def Process32FirstW(self, _snap: int, ref: Any) -> int:
        if not self._first_ok:
            return 0
        self._idx = 0
        return self._fill(ref)

    def Process32NextW(self, _snap: int, ref: Any) -> int:
        self._idx += 1
        return self._fill(ref)

    def _fill(self, ref: Any) -> int:
        if self._idx >= len(self._procs):
            return 0
        ppid, pid = self._procs[self._idx]
        entry = ref._obj
        entry.th32ParentProcessID = ppid
        entry.th32ProcessID = pid
        return 1

    def CloseHandle(self, handle: int) -> int:
        self.closed.append(int(handle))
        return 1


class _KillKernel32:
    """kernel32 for ``_kill_pid`` on Windows."""

    def __init__(self, *, handle: int = 77) -> None:
        self.handle = handle
        self.terminated: list[int] = []
        self.closed: list[int] = []

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return self.handle

    def TerminateProcess(self, handle: int, _code: int) -> int:
        self.terminated.append(int(handle))
        return 1

    def CloseHandle(self, handle: int) -> int:
        self.closed.append(int(handle))
        return 1


def _install_windll(monkeypatch: pytest.MonkeyPatch, kernel32: Any) -> None:
    namespace = SimpleNamespace(kernel32=kernel32)
    monkeypatch.setattr(ctypes, "windll", namespace, raising=False)


def _force_nt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")


# ---------------------------------------------------------------------------
# fake /proc filesystem

_RAISE = object()


def _stat_line(ppid: int, pgrp: int, *, comm: str = "tool", state: str = "S", pid: int = 1) -> str:
    """A ``/proc/<pid>/stat`` line: after "(comm)" come state, ppid, pgrp, ..."""
    return f"{pid} ({comm}) {state} {ppid} {pgrp} 0 0 0 0 0"


class FakeProc:
    """Installable ``/proc`` stand-in for the ppid/pgrp scans and reap probes."""

    def __init__(self) -> None:
        self.iterdir_raises = False
        self.entries: list[str] = []
        self.children: dict[int, Any] = {}
        self.stats: dict[int, Any] = {}
        self.alive: set[int] = set()

    def install(self, mp: pytest.MonkeyPatch) -> None:
        orig_rt = Path.read_text
        orig_id = Path.iterdir
        orig_ex = Path.exists
        proc = self

        def read_text(self: Path, *a: Any, **k: Any) -> str:
            posix = self.as_posix()
            m = re.fullmatch(r"/proc/(\d+)/task/\d+/children", posix)
            if m:
                val = proc.children.get(int(m.group(1)), _RAISE)
                if val is _RAISE:
                    raise OSError("no children file")
                return str(val)
            m = re.fullmatch(r"/proc/(\d+)/stat", posix)
            if m:
                val = proc.stats.get(int(m.group(1)), _RAISE)
                if val is _RAISE:
                    raise OSError("no stat")
                return str(val)
            return orig_rt(self, *a, **k)

        def iterdir(self: Path) -> Any:
            if self.as_posix() == "/proc":
                if proc.iterdir_raises:
                    raise OSError("cannot list /proc")
                return iter([Path("/proc") / name for name in proc.entries])
            return orig_id(self)

        def exists(self: Path) -> bool:
            m = re.fullmatch(r"/proc/(\d+)", self.as_posix())
            if m:
                return int(m.group(1)) in proc.alive
            return orig_ex(self)

        mp.setattr(Path, "read_text", read_text)
        mp.setattr(Path, "iterdir", iterdir)
        mp.setattr(Path, "exists", exists)


# ---------------------------------------------------------------------------
# _enable_linux_child_subreaper


def test_subreaper_is_false_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert process_tree._enable_linux_child_subreaper() is False


def test_subreaper_true_when_prctl_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    libc = SimpleNamespace(prctl=lambda *a: 0)
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: libc)
    assert process_tree._enable_linux_child_subreaper() is True


def test_subreaper_false_when_prctl_returns_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    libc = SimpleNamespace(prctl=lambda *a: -1)
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: libc)
    assert process_tree._enable_linux_child_subreaper() is False


def test_subreaper_false_when_cdll_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")

    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("no libc")

    monkeypatch.setattr(ctypes, "CDLL", boom)
    assert process_tree._enable_linux_child_subreaper() is False


# ---------------------------------------------------------------------------
# _child_enum_limit


def test_child_enum_limit_clamps_to_kill_bound() -> None:
    assert process_tree._child_enum_limit(0) == 1
    assert process_tree._child_enum_limit(5) == 5
    assert process_tree._child_enum_limit(10_000) == process_tree._MAX_KILL_DESCENDANTS


# ---------------------------------------------------------------------------
# process_image_path


def test_process_image_path_rejects_bad_input() -> None:
    assert process_tree.process_image_path(0) is None
    assert process_tree.process_image_path(-4) is None
    assert process_tree.process_image_path(True) is None  # bool is not int by type()


def test_process_image_path_none_when_open_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    _install_windll(monkeypatch, _ImageKernel32(handle=0))
    assert process_tree.process_image_path(4321) is None


def test_process_image_path_none_when_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    kernel32 = _ImageKernel32(q_ok=False)
    _install_windll(monkeypatch, kernel32)
    assert process_tree.process_image_path(4321) is None
    assert kernel32.closed == [55]


def test_process_image_path_returns_image(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    kernel32 = _ImageKernel32(image="C:\\Windows\\notepad.exe")
    _install_windll(monkeypatch, kernel32)
    assert process_tree.process_image_path(4321) == "C:\\Windows\\notepad.exe"
    assert kernel32.closed == [55]


# ---------------------------------------------------------------------------
# enumerate_direct_children (Windows)


def test_enumerate_direct_children_rejects_bad_parent() -> None:
    assert process_tree.enumerate_direct_children(0) == []
    assert process_tree.enumerate_direct_children(-1) == []


def test_enumerate_windows_filters_by_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    procs = [(1, 50), (100, 202), (100, 201), (100, 100), (5, 60)]
    kernel32 = _SnapKernel32(procs)
    _install_windll(monkeypatch, kernel32)
    assert process_tree.enumerate_direct_children(100) == [201, 202]
    assert kernel32.closed == [99]


def test_enumerate_windows_stops_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    kernel32 = _SnapKernel32([(100, 201), (100, 202), (100, 203)])
    _install_windll(monkeypatch, kernel32)
    assert process_tree.enumerate_direct_children(100, max_pids=1) == [201]


def test_enumerate_windows_bad_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    _install_windll(monkeypatch, _SnapKernel32([], snap=0))
    assert process_tree.enumerate_direct_children(100) == []


def test_enumerate_windows_first_entry_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    kernel32 = _SnapKernel32([(100, 201)], first_ok=False)
    _install_windll(monkeypatch, kernel32)
    assert process_tree.enumerate_direct_children(100) == []
    assert kernel32.closed == [99]


# ---------------------------------------------------------------------------
# _enumerate_direct_children_proc (Linux)


def test_enumerate_proc_reads_children_file(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    proc.children[100] = "abc 100 0 -5 202 201"
    proc.install(monkeypatch)
    assert process_tree.enumerate_direct_children(100) == [201, 202]


def test_enumerate_proc_children_file_respects_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    proc.children[100] = "201 202 203"
    proc.install(monkeypatch)
    assert process_tree.enumerate_direct_children(100, max_pids=2) == [201, 202]


def test_enumerate_proc_falls_back_to_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    # No children file -> OSError -> _scan_proc_ppid over /proc.
    proc.entries = ["self", "201", "202", "303"]
    proc.stats = {
        201: _stat_line(ppid=100, pgrp=100),
        202: _stat_line(ppid=100, pgrp=100),
        303: _stat_line(ppid=7, pgrp=7),
    }
    proc.install(monkeypatch)
    assert process_tree.enumerate_direct_children(100) == [201, 202]


# ---------------------------------------------------------------------------
# _scan_proc_ppid edge branches


def test_scan_proc_ppid_iterdir_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    proc.iterdir_raises = True
    proc.install(monkeypatch)
    assert process_tree._scan_proc_ppid(100, 16) == []


def test_scan_proc_ppid_skips_malformed_and_foreign(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    proc.entries = ["self", "100", "200", "201", "202", "203", "204"]
    proc.stats = {
        # 100 == parent -> skipped before the stat read.
        200: _RAISE,  # stat OSError -> continue
        201: "201 no-close-paren 100",  # rfind(')') < 0 -> continue
        202: "202 (t)",  # fields empty -> IndexError -> continue
        203: _stat_line(ppid=999, pgrp=1),  # wrong parent
        204: _stat_line(ppid=100, pgrp=1),  # match
    }
    proc.install(monkeypatch)
    assert process_tree._scan_proc_ppid(100, 16) == [204]


def test_scan_proc_ppid_ppid_not_int(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    proc.entries = ["205"]
    proc.stats = {205: "205 (t) S notanint 1"}
    proc.install(monkeypatch)
    assert process_tree._scan_proc_ppid(100, 16) == []


def test_scan_proc_ppid_stops_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    kids = [str(pid) for pid in range(300, 305)]
    proc.entries = kids
    proc.stats = {int(name): _stat_line(ppid=100, pgrp=1) for name in kids}
    proc.install(monkeypatch)
    assert process_tree._scan_proc_ppid(100, 2) == [300, 301]


# ---------------------------------------------------------------------------
# collect_descendants


def test_collect_descendants_walks_depth_and_dedupes(monkeypatch: pytest.MonkeyPatch) -> None:
    tree = {100: [201, 202], 201: [301], 202: [], 301: [100]}
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, max_pids=0: tree.get(pid, []),
    )
    assert process_tree.collect_descendants(100) == [201, 202, 301]


def test_collect_descendants_stops_at_depth_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    # A chain deeper than the depth cap: the walk exhausts its rounds with a
    # non-empty frontier still queued, so the loop exits by running out of rounds
    # rather than emptying the frontier.
    chain = {100: [1], 1: [2], 2: [3], 3: [4], 4: [5], 5: [6]}
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, max_pids=0: chain.get(pid, []),
    )
    found = process_tree.collect_descendants(100)
    assert found == [1, 2, 3, 4]  # _MAX_KILL_DEPTH rounds, one child each


def test_collect_descendants_stops_at_breadth_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    wide = list(range(200, 300))  # 100 children, bound is 64
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, max_pids=0: wide if pid == 100 else [],
    )
    found = process_tree.collect_descendants(100)
    assert len(found) == process_tree._MAX_KILL_DESCENDANTS
    assert found == wide[: process_tree._MAX_KILL_DESCENDANTS]


# ---------------------------------------------------------------------------
# collect_process_group


def test_collect_process_group_empty_off_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    assert process_tree.collect_process_group(500) == []


def test_collect_process_group_rejects_bad_pgid() -> None:
    assert process_tree.collect_process_group(0) == []
    assert process_tree.collect_process_group(-3) == []


def test_collect_process_group_iterdir_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    proc.iterdir_raises = True
    proc.install(monkeypatch)
    assert process_tree.collect_process_group(500) == []


def test_collect_process_group_skips_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    proc.entries = ["self", "500", "600", "601", "602", "603", "604", "605"]
    proc.stats = {
        # 500 == pgid -> skipped before the stat read.
        600: _RAISE,  # stat OSError
        601: "601 no-close-paren",  # rfind(')') < 0
        602: "602 (t) S",  # fields[2] IndexError
        603: "603 (t) S 1 notint",  # fields[2] ValueError
        604: _stat_line(ppid=1, pgrp=999),  # parses but wrong group -> no append
        605: _stat_line(ppid=1, pgrp=500),  # match
    }
    proc.install(monkeypatch)
    assert process_tree.collect_process_group(500) == [605]


def test_collect_process_group_stops_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProc()
    members = [str(pid) for pid in range(1000, 1000 + process_tree._MAX_KILL_DESCENDANTS + 5)]
    proc.entries = members
    proc.stats = {int(name): _stat_line(ppid=1, pgrp=500) for name in members}
    proc.install(monkeypatch)
    out = process_tree.collect_process_group(500)
    assert len(out) == process_tree._MAX_KILL_DESCENDANTS


# ---------------------------------------------------------------------------
# collect_process_tree


def test_collect_process_tree_merges_and_excludes_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [201, 202])
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pid: [202, 303, 100])
    assert process_tree.collect_process_tree(100) == [201, 202, 303]


# ---------------------------------------------------------------------------
# terminate_process_group


def test_terminate_process_group_kills_each_member(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pgid: [201, 202])
    killed_calls: list[int] = []
    monkeypatch.setattr(process_tree, "_kill_pid", lambda pid: killed_calls.append(pid))
    assert process_tree.terminate_process_group(500) == [201, 202]
    assert killed_calls == [201, 202]


def test_terminate_process_group_survives_kill_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_process_group", lambda pgid: [201, 202])

    def flaky(pid: int) -> None:
        if pid == 201:
            raise OSError("gone")

    monkeypatch.setattr(process_tree, "_kill_pid", flaky)
    assert process_tree.terminate_process_group(500) == [202]


# ---------------------------------------------------------------------------
# _kill_own_process_group


def test_kill_own_group_empty_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    assert process_tree._kill_own_process_group(123) == []


def test_kill_own_group_empty_when_posix_calls_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "getpgid", raising=False)
    monkeypatch.delattr(os, "killpg", raising=False)
    assert process_tree._kill_own_process_group(123) == []


def test_kill_own_group_refuses_group_it_does_not_lead(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "getpgid", lambda pid: pid + 1)
    monkeypatch.setattr(os, "killpg", lambda *a: None, raising=False)
    assert process_tree._kill_own_process_group(123) == []


def test_kill_own_group_kills_led_group(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    seen: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "killpg", lambda pid, sig: seen.append((pid, sig)))
    assert process_tree._kill_own_process_group(123) == [123]
    assert seen == [(123, signal.SIGKILL)]


def test_kill_own_group_empty_when_killpg_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Leader check passes, but the group signal itself fails (already gone): the
    # helper swallows it and returns empty rather than claiming a kill.
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)

    def killpg(_pid: int, _sig: int) -> None:
        raise ProcessLookupError("group already reaped")

    monkeypatch.setattr(os, "killpg", killpg)
    assert process_tree._kill_own_process_group(123) == []


# ---------------------------------------------------------------------------
# _reap_terminated


def test_reap_noop_without_subreaper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", False)
    called = {"n": 0}

    def waitpid(*_a: Any) -> tuple[int, int]:
        called["n"] += 1
        return (0, 0)

    monkeypatch.setattr(os, "waitpid", waitpid)
    process_tree._reap_terminated([1, 2, 3], 1.0)
    assert called["n"] == 0


def test_reap_noop_when_nothing_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
    called = {"n": 0}

    def waitpid(*_a: Any) -> tuple[int, int]:
        called["n"] += 1
        return (0, 0)

    monkeypatch.setattr(os, "waitpid", waitpid)
    # All pids filtered out -> the while loop never runs.
    process_tree._reap_terminated([0, -1], 1.0)
    assert called["n"] == 0


def test_reap_retires_children(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)

    def waitpid(pid: int, _flags: int) -> tuple[int, int]:
        return (pid, 0)

    monkeypatch.setattr(os, "waitpid", waitpid)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    # Skips the pid<=0 entry, retires the rest in one pass.
    process_tree._reap_terminated([0, 201, 202], 1.0)


def test_reap_discards_fully_gone_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
    proc = FakeProc()
    proc.alive = set()  # /proc/<pid> does not exist -> fully retired
    proc.install(monkeypatch)

    def waitpid(_pid: int, _flags: int) -> tuple[int, int]:
        raise ChildProcessError("not our child")

    monkeypatch.setattr(os, "waitpid", waitpid)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    process_tree._reap_terminated([201], 1.0)


def test_reap_spins_then_gives_up_at_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
    proc = FakeProc()
    proc.alive = {201, 202}  # still present -> ChildProcessError keeps it pending
    proc.install(monkeypatch)

    def waitpid(pid: int, _flags: int) -> tuple[int, int]:
        if pid == 201:
            raise ChildProcessError("not reparented yet")
        raise OSError("transient")

    monkeypatch.setattr(os, "waitpid", waitpid)
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
    clock = iter([100.0, 100.0, 100.5, 101.5])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    process_tree._reap_terminated([201, 202], 1.0)
    assert sleeps  # spun at least once before the deadline elapsed


def test_reap_returns_once_pending_drains(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
    state = {"n": 0}

    def waitpid(pid: int, _flags: int) -> tuple[int, int]:
        state["n"] += 1
        if state["n"] == 1:
            return (0, 0)  # WNOHANG: not yet exited
        return (pid, 0)

    monkeypatch.setattr(os, "waitpid", waitpid)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    clock = iter([0.0, 0.0, 0.005, 0.005])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    process_tree._reap_terminated([201], 1.0)


# ---------------------------------------------------------------------------
# terminate_process_tree


class _FakeProcess:
    def __init__(self, *, pid: Any, poll_value: Any = None) -> None:
        self.pid = pid
        self._poll_value = poll_value
        self.killed = False
        self.waited = False

    def poll(self) -> Any:
        return self._poll_value

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        self.waited = True
        return 0


def _stub_tree_helpers(monkeypatch: pytest.MonkeyPatch, descendants: list[int]) -> list[int]:
    killed_pids: list[int] = []
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: list(descendants))
    monkeypatch.setattr(process_tree, "_kill_own_process_group", lambda pid: [])
    monkeypatch.setattr(process_tree, "_kill_pid", lambda pid: killed_pids.append(pid))
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda pids, wait: None)
    return killed_pids


def test_terminate_process_tree_no_pid_still_kills(monkeypatch: pytest.MonkeyPatch) -> None:
    killed_pids = _stub_tree_helpers(monkeypatch, [])
    process = _FakeProcess(pid=None, poll_value=None)
    result = process_tree.terminate_process_tree(process)
    assert result == []
    assert process.killed is True
    assert killed_pids == []


def test_terminate_process_tree_kills_parent_and_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed_pids = _stub_tree_helpers(monkeypatch, [301, 302])
    process = _FakeProcess(pid=100, poll_value=None)
    result = process_tree.terminate_process_tree(process)
    assert 100 in result
    assert killed_pids == [302, 301]  # deepest last in, killed in reverse
    assert process.killed is True


def test_terminate_process_tree_skips_kill_when_already_dead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_tree_helpers(monkeypatch, [])
    process = _FakeProcess(pid=100, poll_value=0)  # already exited
    result = process_tree.terminate_process_tree(process)
    assert result == []
    assert process.killed is False


def test_terminate_process_tree_group_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_tree_helpers(monkeypatch, [])
    killpg_calls: list[tuple[int, int]] = []
    monkeypatch.setattr(
        os, "killpg", lambda pid, sig: killpg_calls.append((pid, sig)), raising=False
    )
    process = _FakeProcess(pid=100, poll_value=0)
    process_tree.terminate_process_tree(process, kill_group=True)
    assert killpg_calls == [(100, 9)]


# ---------------------------------------------------------------------------
# terminate_leftover_process_tree


def test_terminate_leftover_rejects_bad_pid() -> None:
    assert process_tree.terminate_leftover_process_tree(_FakeProcess(pid=None)) == []
    assert process_tree.terminate_leftover_process_tree(_FakeProcess(pid=0)) == []


def test_terminate_leftover_noop_when_tree_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_process_tree", lambda pid: [])
    called = {"terminated": False}

    def fake_terminate(*_a: Any, **_k: Any) -> list[int]:
        called["terminated"] = True
        return []

    monkeypatch.setattr(process_tree, "terminate_process_tree", fake_terminate)
    assert process_tree.terminate_leftover_process_tree(_FakeProcess(pid=100)) == []
    assert called["terminated"] is False


def test_terminate_leftover_sweeps_when_dirty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_process_tree", lambda pid: [301])
    monkeypatch.setattr(process_tree, "terminate_process_tree", lambda *a, **k: [100, 301])
    monkeypatch.setattr(process_tree, "terminate_process_group", lambda pid: [301, 402])
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda pids, wait: None)
    result = process_tree.terminate_leftover_process_tree(_FakeProcess(pid=100))
    assert result == [100, 301, 402]


def test_terminate_leftover_swallows_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(pid: int) -> list[int]:
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(process_tree, "collect_process_tree", boom)
    assert process_tree.terminate_leftover_process_tree(_FakeProcess(pid=100)) == []


# ---------------------------------------------------------------------------
# terminate_pid_tree


def test_terminate_pid_tree_rejects_bad_pid() -> None:
    assert process_tree.terminate_pid_tree(0) == []
    assert process_tree.terminate_pid_tree(-9) == []


def test_terminate_pid_tree_kills_pid_and_descendants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [301, 302])
    monkeypatch.setattr(process_tree, "_kill_own_process_group", lambda pid: [])
    killed_pids: list[int] = []
    monkeypatch.setattr(process_tree, "_kill_pid", lambda pid: killed_pids.append(pid))
    monkeypatch.setattr(process_tree, "_reap_terminated", lambda pids, wait: None)
    result = process_tree.terminate_pid_tree(100)
    assert result == [100, 302, 301]
    assert killed_pids == [100, 302, 301]


# ---------------------------------------------------------------------------
# _kill_pid


def test_kill_pid_posix_uses_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: seen.append((pid, sig)))
    process_tree._kill_pid(4321)
    assert seen == [(4321, 9)]


def test_kill_pid_windows_open_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    kernel32 = _KillKernel32(handle=0)
    _install_windll(monkeypatch, kernel32)
    process_tree._kill_pid(4321)
    assert kernel32.terminated == []


def test_kill_pid_windows_terminates(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_nt(monkeypatch)
    kernel32 = _KillKernel32()
    _install_windll(monkeypatch, kernel32)
    process_tree._kill_pid(4321)
    assert kernel32.terminated == [77]
    assert kernel32.closed == [77]


# ---------------------------------------------------------------------------
# filter_same_image_pids


def test_filter_same_image_empty_when_base_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: None)
    assert process_tree.filter_same_image_pids(100, [201, 202]) == []


def test_filter_same_image_matches_casefold(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = {100: "C:\\Tool.exe", 201: "c:\\tool.EXE", 202: "C:\\other.exe", 203: None}

    def image(pid: int) -> Any:
        return paths.get(pid)

    monkeypatch.setattr(process_tree, "process_image_path", image)
    assert process_tree.filter_same_image_pids(100, [201, 202, 203]) == [201]


# ---------------------------------------------------------------------------
# probe_child_window_candidates


def test_probe_child_windows_builds_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        process_tree, "enumerate_direct_children", lambda pid, max_pids=0: [201, 202]
    )
    images = {100: "C:\\dbg.exe", 201: "C:\\dbg.exe", 202: "C:\\other.exe"}
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: images.get(pid))

    def lister(pid: int) -> list[dict[str, Any]]:
        if pid == 201:
            return [
                {"visible": True, "title": "Main"},
                {"visible": False, "title": "Hidden"},
            ]
        return []  # 202 has no windows -> skipped

    rows = process_tree.probe_child_window_candidates(100, list_windows_fn=lister)
    assert len(rows) == 1
    row = rows[0]
    assert row["pid"] == 201
    assert row["window_count"] == 2
    assert row["visible_count"] == 1
    assert row["titles"] == ["Main"]
    assert row["same_image"] is True


def test_probe_child_windows_defaults_to_core_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid, max_pids=0: [201])
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: "C:\\dbg.exe")
    import headless_re_mcp.core.windows as windows_mod

    monkeypatch.setattr(
        windows_mod,
        "list_process_windows",
        lambda pid: [{"visible": True, "title": "W"}],
    )
    rows = process_tree.probe_child_window_candidates(100)
    assert rows[0]["pid"] == 201
    assert rows[0]["titles"] == ["W"]
