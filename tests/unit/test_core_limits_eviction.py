"""Direct coverage for the shared bounding helpers in core/limits.

These functions cap the capture directories that the artifact retention walker
cannot see (device screenshots, jsre unpack trees), and gate the PE rebuild on
free memory. The service tests exercise them indirectly; this pins the parts
that only fire on the edges -- the memory probe degrading to "don't guess", the
eviction loop that must keep the newest entry, and the deletion helpers'
handling of symlinks and failures -- so a refactor of the ceilings cannot
silently turn a bound into either an outage or an unbounded directory.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from headless_re_mcp.core import limits


def _try_symlink(src: Path, dst: Path) -> bool:
    try:
        os.symlink(src, dst)
    except (OSError, NotImplementedError):
        return False
    return True


def _age(path: Path, mtime: float) -> None:
    os.utime(path, (mtime, mtime))


# --------------------------------------------------------------------------- #
# available_memory_bytes: never guess                                         #
# --------------------------------------------------------------------------- #
def test_available_memory_multiplies_pages_by_page_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    readings = {"SC_AVPHYS_PAGES": 1000, "SC_PAGE_SIZE": 4096}
    monkeypatch.setattr(os, "sysconf", lambda name: readings[name])
    assert limits.available_memory_bytes() == 1000 * 4096


def test_available_memory_returns_none_when_sysconf_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")

    def _raise(name: str) -> int:
        raise ValueError(name)

    monkeypatch.setattr(os, "sysconf", _raise)
    assert limits.available_memory_bytes() is None


def test_available_memory_returns_none_on_a_negative_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "sysconf", lambda name: -1)
    assert limits.available_memory_bytes() is None


# --------------------------------------------------------------------------- #
# rebuild_would_exhaust_memory                                                #
# --------------------------------------------------------------------------- #
def test_rebuild_allows_when_free_memory_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown free-memory reading must allow the work, not refuse it."""
    monkeypatch.setattr(limits, "available_memory_bytes", lambda: None)
    exhausts, estimate, available = limits.rebuild_would_exhaust_memory(1024)
    assert exhausts is False
    assert estimate == 1024 * limits.PE_REBUILD_MEMORY_FACTOR
    assert available is None


def test_rebuild_refuses_when_estimate_exceeds_the_headroom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(limits, "available_memory_bytes", lambda: 1_000_000)
    exhausts, estimate, available = limits.rebuild_would_exhaust_memory(10_000_000)
    assert exhausts is True
    assert available == 1_000_000
    assert estimate == 10_000_000 * limits.PE_REBUILD_MEMORY_FACTOR


def test_rebuild_allows_a_dump_that_fits_within_headroom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(limits, "available_memory_bytes", lambda: 1_000_000_000)
    exhausts, _estimate, _available = limits.rebuild_would_exhaust_memory(1024)
    assert exhausts is False


# --------------------------------------------------------------------------- #
# capped_file_size                                                            #
# --------------------------------------------------------------------------- #
def test_capped_file_size_deletes_a_file_over_the_cap(tmp_path: Path) -> None:
    big = tmp_path / "shot.png"
    big.write_bytes(b"x" * 100)
    size, over = limits.capped_file_size(big, cap=10)
    assert over is True
    assert size == 100
    assert not big.exists()


def test_capped_file_size_keeps_a_file_within_the_cap(tmp_path: Path) -> None:
    ok = tmp_path / "shot.png"
    ok.write_bytes(b"x" * 8)
    size, over = limits.capped_file_size(ok, cap=64)
    assert over is False
    assert size == 8
    assert ok.exists()


def test_capped_file_size_reports_zero_for_a_missing_file(tmp_path: Path) -> None:
    size, over = limits.capped_file_size(tmp_path / "gone.png", cap=64)
    assert (size, over) == (0, False)


# --------------------------------------------------------------------------- #
# prune_capped_dir                                                            #
# --------------------------------------------------------------------------- #
def test_prune_is_a_noop_on_a_path_that_is_not_a_directory(tmp_path: Path) -> None:
    plain = tmp_path / "file"
    plain.write_bytes(b"x")
    assert limits.prune_capped_dir(plain, max_entries=1, max_bytes=1) == 0


class _UnreadableDir:
    """Passes is_dir() but denies iterdir(), like a capture directory whose
    permissions were dropped or that was removed between the two calls."""

    def is_dir(self) -> bool:
        return True

    def iterdir(self) -> object:
        raise OSError("permission denied")


def test_prune_returns_zero_when_the_directory_becomes_unreadable() -> None:
    """The listing can fail *after* the is_dir() check -- a capture directory the
    service can no longer read (a dropped permission, or a TOCTOU race where the
    directory is torn down between is_dir and iterdir). prune must degrade to
    "removed nothing" rather than let the OSError escape and take the whole
    retention pass down; a directory it cannot read is one it simply cannot
    reclaim this round, not a fatal error for every other capture dir behind it.
    """
    assert limits.prune_capped_dir(_UnreadableDir(), max_entries=1, max_bytes=1) == 0  # type: ignore[arg-type]


def test_prune_evicts_the_oldest_until_the_entry_cap_holds(tmp_path: Path) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    for index in range(4):
        entry = root / f"e{index}.bin"
        entry.write_bytes(b"x" * 10)
        _age(entry, 100 + index)  # e0 oldest, e3 newest
    removed = limits.prune_capped_dir(root, max_entries=2, max_bytes=10_000)
    assert removed == 2
    survivors = {p.name for p in root.iterdir()}
    assert survivors == {"e2.bin", "e3.bin"}


def test_prune_evicts_the_oldest_until_the_byte_cap_holds(tmp_path: Path) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    for index in range(3):
        entry = root / f"e{index}.bin"
        entry.write_bytes(b"x" * 100)
        _age(entry, 200 + index)
    removed = limits.prune_capped_dir(root, max_entries=100, max_bytes=150)
    assert removed == 2
    assert {p.name for p in root.iterdir()} == {"e2.bin"}


def test_prune_keeps_the_newest_even_when_it_alone_exceeds_the_cap(tmp_path: Path) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    only = root / "huge.bin"
    only.write_bytes(b"x" * 1000)
    removed = limits.prune_capped_dir(root, max_entries=1, max_bytes=10)
    assert removed == 0
    assert only.exists()


def test_prune_ignores_children_it_cannot_stat(tmp_path: Path) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    if not _try_symlink(root / "missing-target", root / "dangling"):
        pytest.skip("symlinks are unavailable on this platform")
    # The only child is a dangling symlink whose stat() fails, so no entry is
    # collected and prune reports nothing removed rather than raising.
    assert limits.prune_capped_dir(root, max_entries=1, max_bytes=1) == 0


def test_prune_terminates_when_a_deletion_keeps_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A child that cannot be removed is still popped, so the loop cannot spin;
    it just reports it evicted nothing."""
    root = tmp_path / "captures"
    root.mkdir()
    for index in range(3):
        entry = root / f"e{index}.bin"
        entry.write_bytes(b"x" * 10)
        _age(entry, 300 + index)
    monkeypatch.setattr(limits, "_remove_entry", lambda path: False)
    removed = limits.prune_capped_dir(root, max_entries=1, max_bytes=1)
    assert removed == 0
    assert len(list(root.iterdir())) == 3


def test_prune_sizes_and_evicts_subdirectories(tmp_path: Path) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    old_sub = root / "old"
    old_sub.mkdir()
    (old_sub / "a.bin").write_bytes(b"x" * 50)
    new_sub = root / "new"
    new_sub.mkdir()
    (new_sub / "b.bin").write_bytes(b"x" * 50)
    _age(old_sub / "a.bin", 400)
    _age(new_sub / "b.bin", 401)
    _age(old_sub, 400)
    _age(new_sub, 401)
    removed = limits.prune_capped_dir(root, max_entries=1, max_bytes=10_000)
    assert removed == 1
    assert not old_sub.exists()
    assert new_sub.exists()


def test_prune_uses_the_full_subdir_size_not_the_file_capped_partial(
    tmp_path: Path,
) -> None:
    """A subdir with more files than _dir_size counts must not defeat the byte cap.

    prune_capped_dir is the only bound on the jsre spill root, whose children are
    js.unpack_bundle's unpack-<uuid>/ trees. webcrack splits a large bundle into
    one file per module -- thousands of them -- so one tree can hold far more
    files than _dir_size's 4096-file cap. _dir_size returned only that many files'
    bytes, so a big tree of small files read as smaller than the byte cap and the
    cap silently stopped reclaiming: the fail-open dir_size_over_cap was written
    to close, and that prune_capped_dir now measures subdirectories with. Here the
    old tree holds more one-byte files than the cap, so its true size clears
    max_bytes only because the files past the 4096th count; the entry cap is set
    high so only the byte cap can act, and the old tree (oldest) must be evicted
    while the newer file survives. With the old _dir_size the tree measured at the
    cap, total stayed under max_bytes, and nothing was removed.
    """
    file_cap = limits._DIR_SIZE_FILE_CAP
    root = tmp_path / "jsre"
    root.mkdir()
    old_tree = root / "unpack-old"
    old_tree.mkdir()
    for index in range(file_cap + 500):
        (old_tree / f"m{index}.js").write_bytes(b"x")
    newer = root / "spill.txt"
    newer.write_bytes(b"x")
    # Oldest tree, newer file, so the byte-cap eviction takes the tree first.
    _age(old_tree, 700)
    _age(newer, 701)
    # Between the file-capped partial (file_cap bytes) and the true size
    # (file_cap + 500 bytes): the old _dir_size reads under it, a full walk over.
    max_bytes = file_cap + 200
    removed = limits.prune_capped_dir(root, max_entries=100, max_bytes=max_bytes)
    assert removed == 1
    assert not old_tree.exists()
    assert newer.exists()


# --------------------------------------------------------------------------- #
# _dir_size and _remove_entry                                                 #
# --------------------------------------------------------------------------- #
def test_dir_size_stops_counting_at_the_file_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(limits, "_DIR_SIZE_FILE_CAP", 1)
    sub = tmp_path / "tree"
    sub.mkdir()
    (sub / "nested").mkdir()
    (sub / "a.bin").write_bytes(b"x" * 10)
    (sub / "nested" / "b.bin").write_bytes(b"x" * 10)
    # With the file cap at one, exactly one file's bytes are summed before the
    # walk bails out; the nested directory entry is skipped, not counted.
    assert limits._dir_size(sub) == 10


def test_dir_size_sums_files_and_skips_nested_directories(tmp_path: Path) -> None:
    sub = tmp_path / "tree"
    (sub / "nested").mkdir(parents=True)
    (sub / "a.bin").write_bytes(b"x" * 10)
    (sub / "b.bin").write_bytes(b"x" * 20)
    (sub / "nested" / "c.bin").write_bytes(b"x" * 30)
    # Below the file cap, so the walk visits every entry: the two top-level
    # files and the nested one sum to 60, while the directory entries add zero.
    assert limits._dir_size(sub) == 60


class _ChildStatRaises:
    """A walked child that raises on inspection, like a file removed out from
    under the walk (a concurrent unpack overwrite, or a broken device pull)."""

    def is_file(self) -> bool:
        raise OSError("child vanished mid-walk")

    def stat(self) -> object:
        raise OSError("child vanished mid-walk")


class _DirWithABadChild:
    def rglob(self, _pattern: str) -> object:
        yield _ChildStatRaises()


class _DirWhoseWalkRaises:
    def rglob(self, _pattern: str) -> object:
        raise OSError("directory torn down mid-walk")


def test_dir_size_skips_a_child_that_raises_mid_walk() -> None:
    """One child failing inspection must not abort the whole size estimate; it is
    skipped and the walk continues, so a subdirectory being reclaimed while it is
    measured undercounts by that child rather than raising and stalling the prune
    that called it."""
    assert limits._dir_size(_DirWithABadChild()) == 0  # type: ignore[arg-type]


def test_dir_size_returns_what_it_counted_when_the_walk_itself_raises() -> None:
    """If the traversal itself fails (the directory is gone by the time it is
    measured), _dir_size returns the bytes tallied so far -- here zero -- instead
    of propagating. A size it cannot finish measuring must not crash eviction."""
    assert limits._dir_size(_DirWhoseWalkRaises()) == 0  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# dir_size_over_cap (the size backstop's measurement)                          #
# --------------------------------------------------------------------------- #
def test_dir_size_over_cap_short_circuits_on_a_single_fat_file(tmp_path: Path) -> None:
    """A tree past the cap is reported over without walking to the last byte."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "big.bin").write_bytes(b"x" * 500)
    measured, over = limits.dir_size_over_cap(tree, 100)
    assert over is True
    assert measured >= 500


def test_dir_size_over_cap_walks_a_small_tree_in_full(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    (tree / "nested").mkdir(parents=True)
    (tree / "a.bin").write_bytes(b"x" * 10)
    (tree / "nested" / "b.bin").write_bytes(b"x" * 20)
    measured, over = limits.dir_size_over_cap(tree, 1000)
    assert over is False
    assert measured == 30


def test_dir_size_over_cap_catches_a_many_small_files_tree(tmp_path: Path) -> None:
    """The gap ``_dir_size`` left: bytes past its file cap were never counted.

    ``_dir_size`` stops after ``_DIR_SIZE_FILE_CAP`` (4096) files and returns the
    partial sum, which the backstop read as "under cap" -- so a tree whose first
    4096 files are small but whose *total* is over the cap survived. That is the
    real apktool/jadx shape: one dex disassembles to hundreds of thousands of
    tiny per-class files. Here 5000 one-byte files sum to 5000 bytes; with the
    cap at 4096 the total genuinely exceeds it, but only because every file past
    the 4096th is counted. ``_dir_size`` would have returned exactly 4096 and
    called it safe.
    """
    tree = tmp_path / "tree"
    tree.mkdir()
    for index in range(5000):
        (tree / f"f{index}.smali").write_bytes(b"x")
    # _dir_size caps out at its file limit and under-reports the tree as safe.
    assert limits._dir_size(tree) == limits._DIR_SIZE_FILE_CAP
    # The short-circuiting backstop measurement sees the real overflow.
    measured, over = limits.dir_size_over_cap(tree, 4096)
    assert over is True
    assert measured > 4096


def test_dir_size_over_cap_fails_closed_past_the_file_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file-count flood is refused even when the bytes never cross the cap.

    Empty (or near-empty) files never move the byte total, so without a file
    ceiling the walk would stat() every one of millions of inodes before
    answering "small". The ceiling turns that into a fail-closed refusal: a tree
    with that many files is not a legitimate capture. Shrink the ceiling so the
    test needs only a handful of zero-byte files rather than millions.
    """
    monkeypatch.setattr(limits, "_TREE_SIZE_FILE_CEILING", 3)
    tree = tmp_path / "tree"
    tree.mkdir()
    for index in range(5):
        (tree / f"empty{index}").write_bytes(b"")
    measured, over = limits.dir_size_over_cap(tree, 1_000_000_000)
    assert over is True
    assert measured == 0


def test_dir_size_over_cap_survives_a_walk_that_raises(tmp_path: Path) -> None:
    """A directory torn down mid-measure answers from what it counted, never crashes."""
    measured, over = limits.dir_size_over_cap(_DirWhoseWalkRaises(), 100)  # type: ignore[arg-type]
    assert measured == 0
    assert over is False


def test_remove_entry_deletes_a_file(tmp_path: Path) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    assert limits._remove_entry(target) is True
    assert not target.exists()


def test_remove_entry_deletes_a_directory_tree(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    (tree / "inner").mkdir(parents=True)
    (tree / "inner" / "f.bin").write_bytes(b"x")
    assert limits._remove_entry(tree) is True
    assert not tree.exists()


def test_remove_entry_unlinks_a_symlink_without_touching_its_target(
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "keep.bin").write_bytes(b"x")
    link = tmp_path / "link"
    if not _try_symlink(real_dir, link):
        pytest.skip("symlinks are unavailable on this platform")
    assert limits._remove_entry(link) is True
    assert not link.exists()
    assert real_dir.exists()
    assert (real_dir / "keep.bin").exists()


def test_remove_entry_reports_failure_for_a_missing_path(tmp_path: Path) -> None:
    assert limits._remove_entry(tmp_path / "never") is False
