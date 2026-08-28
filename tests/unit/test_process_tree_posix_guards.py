"""The /proc enumeration guards that keep a timeout kill from missing an orphan.

A CLI timeout (jadx/apktool/Ghidra start a JVM, webcrack starts node) walks the
launcher's descendants and its POSIX session group to find what to kill. That
walk parses ``/proc/<pid>/stat`` for every process on the box, so it has to
survive everything a live /proc throws at it mid-scan: an entry that vanished
between listdir and open, a stat line in an unexpected shape, a /proc that is
not even listable. If any of those raised, the kill would abort and leave the
orphan holding a core and a lock on the sample.

These build a fake /proc on the real filesystem and redirect the module's
``Path`` at it, so the real ``iterdir``/``read_text`` run against controlled
contents -- no monkeypatching of the parse itself. Linux-only: the format and
the group semantics are POSIX, and the module takes the Windows branch on nt.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core import process_tree

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="/proc stat parsing is a POSIX mechanism (skip != pass)",
)


def _redirect_proc(monkeypatch: pytest.MonkeyPatch, fake_root: Path) -> None:
    """Point the module's ``Path`` at ``fake_root`` for any /proc path."""
    real_path = Path

    def factory(p: Any = ".") -> Path:
        text = str(p)
        if text == "/proc" or text.startswith("/proc/"):
            return real_path(text.replace("/proc", str(fake_root), 1))
        return real_path(text)

    monkeypatch.setattr(process_tree, "Path", factory)


def _make_proc(tmp_path: Path, entries: dict[str, str | None]) -> Path:
    """Build a fake /proc. A None stat becomes a directory read_text cannot read."""
    root = tmp_path / "proc"
    root.mkdir()
    for name, stat in entries.items():
        entry = root / name
        entry.mkdir()
        if stat is None:
            (entry / "stat").mkdir()  # read_text on a directory raises OSError
        else:
            (entry / "stat").write_text(stat, encoding="ascii")
    return root


# ---------------------------------------------------------------------------
# _scan_proc_ppid: skip everything malformed, honor the bound.
# ---------------------------------------------------------------------------
def test_scan_proc_ppid_skips_every_malformed_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_proc(
        tmp_path,
        {
            "cpuinfo": "not a pid dir",  # non-digit name -> skipped
            "100": "100 (self) S 1 100 0",  # pid == parent -> skipped
            "200": None,  # stat unreadable -> OSError skip
            "300": "300 (noparen S 1",  # no ')' -> skipped
            "400": "400 (x) S",  # fields[1] missing -> IndexError skip
            "500": "500 (child) S 100 500 0",  # ppid == 100 -> a match
        },
    )
    _redirect_proc(monkeypatch, fake)
    assert process_tree._scan_proc_ppid(100, 64) == [500]


def test_scan_proc_ppid_stops_at_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_proc(
        tmp_path,
        {
            "501": "501 (a) S 100 501 0",
            "502": "502 (b) S 100 502 0",
        },
    )
    _redirect_proc(monkeypatch, fake)
    found = process_tree._scan_proc_ppid(100, 1)
    assert len(found) == 1


# ---------------------------------------------------------------------------
# _enumerate_direct_children_proc: the children file, then its fallback.
# ---------------------------------------------------------------------------
def test_children_file_is_parsed_skipping_junk_and_bounding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "proc"
    (fake / "700" / "task" / "700").mkdir(parents=True)
    # A non-integer token in the middle must be skipped, and the limit must
    # stop collection before the third pid.
    (fake / "700" / "task" / "700" / "children").write_text(
        "10 abc 20 30", encoding="ascii"
    )
    _redirect_proc(monkeypatch, fake)
    assert process_tree._enumerate_direct_children_proc(700, 2) == [10, 20]


def test_missing_children_file_falls_back_to_the_ppid_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No children file for pid 800, so the reader raises and the function
    # falls back to scanning /proc by ppid, which finds 810.
    fake = _make_proc(tmp_path, {"810": "810 (c) S 800 810 0"})
    _redirect_proc(monkeypatch, fake)
    assert process_tree._enumerate_direct_children_proc(800, 64) == [810]


# ---------------------------------------------------------------------------
# collect_process_group: match by recorded pgrp, survive the same junk.
# ---------------------------------------------------------------------------
def test_collect_process_group_matches_the_recorded_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_proc(
        tmp_path,
        {
            "settings": "not a pid",  # non-digit -> skipped
            "900": "900 (leader) S 1 900 0",  # pid == pgid -> skipped
            "910": None,  # stat unreadable -> OSError skip
            "920": "920 (noparen S 1 900",  # no ')' -> skipped
            "930": "930 (x) S 1",  # fields[2] missing -> IndexError skip
            "940": "940 (member) S 1 900 0",  # pgrp == 900 -> a match
        },
    )
    _redirect_proc(monkeypatch, fake)
    assert process_tree.collect_process_group(900) == [940]


def test_collect_process_group_rejects_a_non_positive_pgid() -> None:
    assert process_tree.collect_process_group(0) == []


def test_collect_process_group_stops_at_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process_tree, "_MAX_KILL_DESCENDANTS", 1)
    fake = _make_proc(
        tmp_path,
        {
            "941": "941 (a) S 1 900 0",
            "942": "942 (b) S 1 900 0",
        },
    )
    _redirect_proc(monkeypatch, fake)
    assert len(process_tree.collect_process_group(900)) == 1


# ---------------------------------------------------------------------------
# collect_descendants: the breadth/depth bounds and the seen-set dedup.
# ---------------------------------------------------------------------------
def test_collect_descendants_dedups_a_child_seen_at_another_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # pid 10 and 20 are level-1 children; 10 also lists 20 (already seen) and a
    # fresh 30. The seen-set must skip the repeat rather than recurse it twice.
    tree = {1: [10, 20], 10: [20, 30], 20: []}
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, *, max_pids: list(tree.get(pid, [])),
    )
    assert process_tree.collect_descendants(1) == [10, 20, 30]


def test_collect_descendants_stops_at_the_descendant_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_tree, "_MAX_KILL_DESCENDANTS", 1)
    monkeypatch.setattr(
        process_tree,
        "enumerate_direct_children",
        lambda pid, *, max_pids: [10, 20] if pid == 1 else [],
    )
    found = process_tree.collect_descendants(1)
    assert found == [10]
