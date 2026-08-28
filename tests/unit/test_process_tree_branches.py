"""POSIX-reachable guard branches in core/process_tree.py.

Every CLI backend (apktool, jadx, Ghidra, webcrack, r2) relies on these
helpers to find and kill a tool's descendants on timeout, so the /proc
parsing must tolerate hostile or racing content: non-numeric tokens, stat
lines without the ``(comm)`` close-paren, entries that vanish mid-scan, and
trees wider or deeper than the kill bounds.
"""

from __future__ import annotations

import os
import sys
from pathlib import PurePosixPath
from typing import Any

import pytest

from headless_re_mcp.core import process_tree


class _FakePath:
    """Stands in for pathlib.Path over a scripted /proc snapshot.

    ``mapping`` keys are absolute path strings; values are file text for
    read_text, a list of child names for iterdir, or an exception instance to
    raise from either.
    """

    def __init__(self, mapping: dict[str, Any], name: str) -> None:
        self._mapping = mapping
        self._path = name

    @property
    def name(self) -> str:
        return PurePosixPath(self._path).name

    def __truediv__(self, other: object) -> _FakePath:
        return _FakePath(self._mapping, f"{self._path}/{other}")

    def read_text(self, **_kwargs: Any) -> str:
        value = self._mapping.get(self._path)
        if isinstance(value, Exception):
            raise value
        if not isinstance(value, str):
            raise OSError(f"no such fake file: {self._path}")
        return value

    def iterdir(self) -> list[_FakePath]:
        value = self._mapping.get(self._path)
        if isinstance(value, Exception):
            raise value
        if not isinstance(value, list):
            raise OSError(f"not a fake dir: {self._path}")
        return [_FakePath(self._mapping, f"{self._path}/{child}") for child in value]

    def exists(self) -> bool:
        return self._path in self._mapping


def _install_proc(
    monkeypatch: pytest.MonkeyPatch, mapping: dict[str, Any]
) -> None:
    monkeypatch.setattr(
        process_tree, "Path", lambda raw="": _FakePath(mapping, str(raw))
    )


def _pid_alive_and_not_zombie(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as fh:
            stat = fh.read()
    except OSError:
        return False
    close = stat.rfind(")")
    fields = stat[close + 2 :].split()
    return bool(fields) and fields[0] != "Z"


class TestSubreaperProbe:
    def test_a_non_linux_platform_never_touches_prctl(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        assert process_tree._enable_linux_child_subreaper() is False

    def test_a_libc_without_prctl_reports_no_subreaper(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ctypes

        def broken(*args: Any, **kwargs: Any) -> Any:
            raise OSError("no libc here")

        monkeypatch.setattr(ctypes, "CDLL", broken)
        assert process_tree._enable_linux_child_subreaper() is False


class TestDirectChildEnumeration:
    def test_a_non_positive_or_non_int_pid_yields_nothing(self) -> None:
        assert process_tree.enumerate_direct_children(0) == []
        assert process_tree.enumerate_direct_children("7") == []  # type: ignore[arg-type]

    def test_the_children_file_parse_skips_junk_and_honors_the_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_proc(
            monkeypatch,
            {"/proc/50/task/50/children": "abc -3 50 200 100 300"},
        )
        got = process_tree.enumerate_direct_children(50, max_pids=2)
        assert got == [100, 200]

    def test_the_proc_scan_fallback_tolerates_every_hostile_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_proc(
            monkeypatch,
            {
                # children file gone -> fall back to the full /proc scan.
                "/proc/50/task/50/children": OSError("gone"),
                "/proc": ["self", "50", "60", "61", "62", "63", "70", "71"],
                # 60: stat unreadable (vanished mid-scan).
                "/proc/60/stat": OSError("vanished"),
                # 61: no close paren at all.
                "/proc/61/stat": "61 (broken",
                # 62: fields after the comm are junk.
                "/proc/62/stat": "62 (x) R notanint",
                # 63: another parent's child.
                "/proc/63/stat": "63 (x) S 9 9",
                # 70 and 71 both belong to 50; limit=1 keeps only the first.
                "/proc/70/stat": "70 (x) S 50 50",
                "/proc/71/stat": "71 (x) S 50 50",
            },
        )
        got = process_tree.enumerate_direct_children(50, max_pids=1)
        assert got == [70]
        # With room to spare the scan keeps walking past the first match.
        assert process_tree.enumerate_direct_children(50, max_pids=5) == [70, 71]

    def test_an_unreadable_proc_directory_yields_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_proc(
            monkeypatch,
            {
                "/proc/50/task/50/children": OSError("gone"),
                "/proc": OSError("proc unmounted"),
            },
        )
        assert process_tree.enumerate_direct_children(50) == []


class TestDescendantCollection:
    def test_a_cyclic_parent_child_graph_cannot_loop_the_walk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        graph = {10: [11], 11: [12], 12: [10, 11]}

        monkeypatch.setattr(
            process_tree,
            "enumerate_direct_children",
            lambda pid, max_pids=16: list(graph.get(pid, [])),
        )
        assert process_tree.collect_descendants(10) == [11, 12]

    def test_a_tree_wider_than_the_kill_bound_is_truncated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wide = list(range(100, 100 + 80))
        monkeypatch.setattr(
            process_tree,
            "enumerate_direct_children",
            lambda pid, max_pids=16: wide if pid == 10 else [],
        )
        got = process_tree.collect_descendants(10)
        assert len(got) == process_tree._MAX_KILL_DESCENDANTS

    def test_a_chain_deeper_than_the_depth_bound_is_cut_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain = {10: [11], 11: [12], 12: [13], 13: [14], 14: [15], 15: [16]}
        monkeypatch.setattr(
            process_tree,
            "enumerate_direct_children",
            lambda pid, max_pids=16: list(chain.get(pid, [])),
        )
        got = process_tree.collect_descendants(10)
        assert got == [11, 12, 13, 14]


class TestProcessGroupScan:
    def test_a_non_positive_pgid_yields_nothing(self) -> None:
        assert process_tree.collect_process_group(0) == []
        assert process_tree.collect_process_group("9") == []  # type: ignore[arg-type]

    def test_the_group_scan_tolerates_every_hostile_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_proc(
            monkeypatch,
            {
                "/proc": ["self", "50", "60", "61", "62", "63", "70"],
                "/proc/60/stat": OSError("vanished"),
                "/proc/61/stat": "61 (broken",
                "/proc/62/stat": "62 (x) R 1",  # pgrp field missing
                "/proc/63/stat": "63 (x) S 1 9",  # another group
                "/proc/70/stat": "70 (x) S 1 50",  # ours
            },
        )
        assert process_tree.collect_process_group(50) == [70]

    def test_an_unreadable_proc_directory_yields_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_proc(monkeypatch, {"/proc": OSError("proc unmounted")})
        assert process_tree.collect_process_group(50) == []

    def test_a_group_wider_than_the_kill_bound_is_truncated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        members = [str(pid) for pid in range(100, 100 + 70)]
        mapping: dict[str, Any] = {"/proc": members}
        for name in members:
            mapping[f"/proc/{name}/stat"] = f"{name} (x) S 1 50"
        _install_proc(monkeypatch, mapping)
        got = process_tree.collect_process_group(50)
        assert len(got) == process_tree._MAX_KILL_DESCENDANTS


class TestOwnGroupKill:
    def test_windows_has_no_process_groups(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(os, "name", "nt")
        assert process_tree._kill_own_process_group(1234) == []

    def test_a_host_without_killpg_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(os, "getpgid", None, raising=False)
        assert process_tree._kill_own_process_group(1234) == []

    @pytest.mark.skipif(os.name == "nt", reason="POSIX process groups")
    def test_a_process_that_does_not_lead_its_group_is_never_group_killed(self) -> None:
        import subprocess

        # No start_new_session, so the child shares our group and cannot lead it.
        child = subprocess.Popen(["sleep", "30"])
        try:
            assert process_tree._kill_own_process_group(child.pid) == []
            assert child.poll() is None, "the guard must not have signalled our group"
        finally:
            child.kill()
            child.wait(timeout=5)


class TestReap:
    def test_without_the_subreaper_the_reap_is_a_noop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", False)
        called: list[int] = []
        monkeypatch.setattr(os, "waitpid", lambda *a: called.append(1))
        process_tree._reap_terminated([999999], 0.05)
        assert called == []

    def test_an_unexpected_waitpid_error_does_not_spin_forever(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)

        def denied(pid: int, flags: int) -> tuple[int, int]:
            raise PermissionError("not yours")

        monkeypatch.setattr(os, "waitpid", denied)
        # Returns at the deadline instead of raising or spinning.
        process_tree._reap_terminated([999999], 0.05)

    @pytest.mark.skipif(os.name == "nt", reason="/proc is POSIX")
    def test_a_live_pid_that_is_not_our_child_stays_pending_until_deadline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # waitpid(1) raises ChildProcessError but /proc/1 exists, so the sweep
        # must keep it pending (someone else's child) rather than call it gone.
        monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)
        process_tree._reap_terminated([1], 0.05)


class TestLeftoverSweep:
    def test_an_exploding_tree_walk_reports_nothing_killed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Proc:
            pid = 4242

        def explode(pid: int) -> list[int]:
            raise RuntimeError("scan failed")

        monkeypatch.setattr(process_tree, "collect_process_tree", explode)
        assert process_tree.terminate_leftover_process_tree(_Proc()) == []

    def test_a_pid_tree_kill_refuses_a_bogus_pid(self) -> None:
        assert process_tree.terminate_pid_tree(0) == []
        assert process_tree.terminate_pid_tree("9") == []  # type: ignore[arg-type]

    def test_a_handle_without_a_pid_is_refused(self) -> None:
        class _NoPid:
            pid = None

        assert process_tree.terminate_leftover_process_tree(_NoPid()) == []

    def test_a_clean_tree_needs_no_sweep(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Proc:
            pid = 4242

        monkeypatch.setattr(process_tree, "collect_process_tree", lambda pid: [])
        assert process_tree.terminate_leftover_process_tree(_Proc()) == []

    def test_a_tree_kill_without_a_usable_pid_still_kills_the_handle(self) -> None:
        killed_handle: list[bool] = []

        class _Handle:
            pid = None

            def poll(self) -> None:
                return None

            def kill(self) -> None:
                killed_handle.append(True)

            def wait(self, timeout: float | None = None) -> int:
                return 0

        got = process_tree.terminate_process_tree(_Handle(), wait_s=0.1)
        assert killed_handle == [True]
        assert got == []

    @pytest.mark.skipif(os.name == "nt", reason="POSIX process spawn")
    def test_terminate_pid_tree_reaps_a_real_orphaned_helper(self) -> None:
        import subprocess
        import time

        # sh forks a sleeping helper; killing by pid alone would orphan it.
        launcher = subprocess.Popen(
            ["sh", "-c", "sleep 30 & sleep 30"], start_new_session=True
        )
        try:
            descendants: list[int] = []
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                descendants = process_tree.collect_descendants(launcher.pid)
                if descendants:
                    break
                time.sleep(0.05)
            killed = process_tree.terminate_pid_tree(launcher.pid)
            assert launcher.pid in killed
            # The sweep may have reaped the launcher itself, in which case
            # Popen.wait sees ECHILD and reports 0; "it returned" is the point.
            launcher.wait(timeout=5)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                lingering = [
                    pid
                    for pid in descendants
                    if _pid_alive_and_not_zombie(pid)
                ]
                if not lingering:
                    break
                time.sleep(0.05)
            assert not lingering, "the orphaned helper outlived the tree kill"
        finally:
            if launcher.poll() is None:
                launcher.kill()
                launcher.wait(timeout=5)


class TestSameImageFilter:
    def test_no_readable_base_image_matches_nothing(self) -> None:
        # On POSIX process_image_path is always None, so the filter fails closed.
        assert process_tree.filter_same_image_pids(os.getpid(), [1, 2]) == []

    def test_only_pids_sharing_the_debuggee_image_survive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        images = {10: r"C:\target\app.exe", 11: r"c:\TARGET\APP.EXE", 12: r"C:\other.exe", 13: None}
        monkeypatch.setattr(
            process_tree, "process_image_path", lambda pid: images.get(pid)
        )
        assert process_tree.filter_same_image_pids(10, [11, 12, 13]) == [11]


class TestChildWindowProbe:
    def test_windowless_children_are_skipped_and_owners_described(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            process_tree,
            "enumerate_direct_children",
            lambda pid, max_pids=16: [21, 22],
        )
        windows = {
            21: [],
            22: [
                {"visible": True, "title": "Install Wizard"},
                {"visible": False, "title": "hidden"},
            ],
        }
        out = process_tree.probe_child_window_candidates(
            20, list_windows_fn=lambda pid: windows[pid]
        )
        assert [row["pid"] for row in out] == [22]
        assert out[0]["window_count"] == 2
        assert out[0]["visible_count"] == 1
        assert out[0]["titles"] == ["Install Wizard"]
