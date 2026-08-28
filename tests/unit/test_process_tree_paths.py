"""POSIX branch coverage for core/process_tree.py.

The process-tree helpers walk /proc and the child-subreaper machinery to find
and kill a launcher's descendants. The Windows Toolhelp arms cannot run here,
but the POSIX /proc parsing and the bounded-walk/dedup logic can, driven with a
fake pathlib.Path over a synthetic /proc and a faked enumeration seam.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.core import process_tree

# --------------------------------------------------------------------------
# A fake pathlib.Path over a synthetic /proc.
# --------------------------------------------------------------------------


class _StatFile:
    def __init__(self, text: str | None, raises: bool) -> None:
        self._text = text
        self._raises = raises

    def read_text(self, **_kwargs: Any) -> str:
        if self._raises:
            raise OSError("stat unreadable")
        return self._text or ""


class _Entry:
    def __init__(
        self, name: str, *, stat_text: str | None = None, stat_raises: bool = False
    ) -> None:
        self.name = name
        self._stat_text = stat_text
        self._stat_raises = stat_raises

    def __truediv__(self, other: Any) -> _StatFile:
        assert str(other) == "stat"
        return _StatFile(self._stat_text, self._stat_raises)


class _Cfg:
    def __init__(self) -> None:
        self.children_text: str | None = None
        self.children_raises: bool = False
        self.entries: list[_Entry] = []
        self.proc_raises: bool = False


def _install_fake_proc(monkeypatch: pytest.MonkeyPatch, cfg: _Cfg) -> None:
    class _P:
        def __init__(self, spec: Any) -> None:
            self.s = str(spec)

        def read_text(self, **_kwargs: Any) -> str:
            if self.s.endswith("/children"):
                if cfg.children_raises:
                    raise OSError("no children file")
                return cfg.children_text or ""
            raise OSError("unexpected read")

        def iterdir(self) -> Any:
            if self.s == "/proc":
                if cfg.proc_raises:
                    raise OSError("no /proc")
                return iter(cfg.entries)
            raise OSError("unexpected iterdir")

        def exists(self) -> bool:
            return True

        def __truediv__(self, other: Any) -> _P:
            return _P(self.s + "/" + str(other))

    monkeypatch.setattr(process_tree, "Path", _P)


def _stat(pid: int, ppid: int, pgrp: int) -> str:
    # "pid (comm) state ppid pgrp ..." -- fields after ") " are index 0=state,
    # 1=ppid, 2=pgrp, matching the module's parse.
    return f"{pid} (some proc) S {ppid} {pgrp} 0 0 0"


# --------------------------------------------------------------------------
# _enable_linux_child_subreaper
# --------------------------------------------------------------------------


def test_subreaper_is_disabled_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.core.process_tree.sys.platform", "win32")
    assert process_tree._enable_linux_child_subreaper() is False


def test_subreaper_survives_a_prctl_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.core.process_tree.sys.platform", "linux")

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("no prctl")

    monkeypatch.setattr("headless_re_mcp.core.process_tree.ctypes.CDLL", _boom)
    assert process_tree._enable_linux_child_subreaper() is False


# --------------------------------------------------------------------------
# _enumerate_direct_children_proc / _scan_proc_ppid
# --------------------------------------------------------------------------


def test_direct_children_skips_non_numeric_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _Cfg()
    cfg.children_text = "10 20 notapid 30"
    _install_fake_proc(monkeypatch, cfg)
    assert process_tree.enumerate_direct_children(999, max_pids=8) == [10, 20, 30]


def test_direct_children_falls_back_to_proc_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _Cfg()
    cfg.children_raises = True  # no task/children file -> /proc scan
    cfg.entries = [
        _Entry("not-a-pid"),  # non-digit name, skipped
        _Entry("7", stat_raises=True),  # stat unreadable -> skipped
        _Entry("8", stat_text="8 (x"),  # no ')' -> skipped
        _Entry("9", stat_text="9 (x) S"),  # too few fields -> ppid parse skip
        _Entry("11", stat_text=_stat(11, 999, 999)),  # ppid matches
        _Entry("12", stat_text=_stat(12, 5, 5)),  # ppid mismatch
    ]
    _install_fake_proc(monkeypatch, cfg)
    assert process_tree.enumerate_direct_children(999, max_pids=8) == [11]


def test_proc_scan_returns_empty_when_proc_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _Cfg()
    cfg.children_raises = True
    cfg.proc_raises = True
    _install_fake_proc(monkeypatch, cfg)
    assert process_tree.enumerate_direct_children(999, max_pids=8) == []


# --------------------------------------------------------------------------
# collect_process_group
# --------------------------------------------------------------------------


def test_collect_group_returns_empty_when_proc_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _Cfg()
    cfg.proc_raises = True
    _install_fake_proc(monkeypatch, cfg)
    assert process_tree.collect_process_group(4321) == []


def test_collect_group_parses_and_bounds_members(monkeypatch: pytest.MonkeyPatch) -> None:
    pgid = 4321
    entries: list[_Entry] = [
        _Entry("bogus"),  # non-digit name
        _Entry("7", stat_raises=True),  # stat unreadable
        _Entry("8", stat_text="8 (x"),  # no ')' close
        _Entry("9", stat_text="9 (x) S 1"),  # too few fields for pgrp
        _Entry("10", stat_text=_stat(10, 1, 999)),  # different group
    ]
    # Many matching members to trip the descendant bound.
    entries += [
        _Entry(str(100 + i), stat_text=_stat(100 + i, 1, pgid)) for i in range(70)
    ]
    cfg = _Cfg()
    cfg.entries = entries
    _install_fake_proc(monkeypatch, cfg)

    members = process_tree.collect_process_group(pgid)

    assert len(members) == process_tree._MAX_KILL_DESCENDANTS
    assert all(m >= 100 for m in members)


# --------------------------------------------------------------------------
# collect_descendants dedup and bounds
# --------------------------------------------------------------------------


def test_collect_descendants_dedupes_already_seen_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = {1: [2, 3], 2: [3], 3: []}
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, **_kw: list(tree.get(pid, [])),
    )
    found = process_tree.collect_descendants(1)
    assert found == [2, 3]  # 3 is not added twice


def test_collect_descendants_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    wide = list(range(1000, 1100))  # 100 direct children > the 64 cap
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, **_kw: wide if pid == 1 else [],
    )
    found = process_tree.collect_descendants(1)
    assert len(found) == process_tree._MAX_KILL_DESCENDANTS


# --------------------------------------------------------------------------
# _reap_terminated and terminate_leftover_process_tree
# --------------------------------------------------------------------------


def test_reap_swallows_a_waitpid_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_LINUX_CHILD_SUBREAPER", True)

    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("transient waitpid failure")

    monkeypatch.setattr("headless_re_mcp.core.process_tree.os.waitpid", _raise)
    # Returns after the short deadline instead of raising or hanging.
    process_tree._reap_terminated([4321], 0.02)


def test_terminate_leftover_returns_empty_when_enumeration_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(_pid: int) -> Any:
        raise RuntimeError("tree enumeration failed")

    monkeypatch.setattr(process_tree, "collect_process_tree", _boom)
    result = process_tree.terminate_leftover_process_tree(SimpleNamespace(pid=4321))
    assert result == []
