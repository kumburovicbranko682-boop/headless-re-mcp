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
from typing import Any

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


def test_prune_keeps_the_named_path_even_when_it_is_the_oldest(tmp_path: Path) -> None:
    """``keep`` protects the just-written path against age-based eviction.

    The entry cap forces three younger captures out, but the one the caller
    named survives even though it is the oldest -- the guarantee the docstring
    makes, now honoured explicitly rather than hoped for from age alone.
    """
    root = tmp_path / "captures"
    root.mkdir()
    keep = root / "just-written.bin"
    keep.write_bytes(b"x" * 10)
    _age(keep, 100)  # the oldest entry of the four
    for index in range(3):
        other = root / f"old{index}.bin"
        other.write_bytes(b"x" * 10)
        _age(other, 200 + index)
    removed = limits.prune_capped_dir(root, max_entries=1, max_bytes=10_000, keep=keep)
    assert removed == 3
    assert {p.name for p in root.iterdir()} == {"just-written.bin"}


def test_prune_keeps_the_just_written_path_under_an_mtime_tie(tmp_path: Path) -> None:
    """A tie must not let the just-written capture be the one evicted.

    All four entries share one mtime, so age cannot single out the newest. The
    fresh file is even named to sort first, so the deterministic name tiebreak
    would evict it first -- ``keep`` is what overrides that and keeps it.
    """
    root = tmp_path / "captures"
    root.mkdir()
    keep = root / "aaa-just-written.bin"
    for name in ("aaa-just-written.bin", "m.bin", "y.bin", "z.bin"):
        entry = root / name
        entry.write_bytes(b"x" * 10)
        _age(entry, 500)  # one identical mtime across all four: a pure tie
    removed = limits.prune_capped_dir(root, max_entries=1, max_bytes=10_000, keep=keep)
    assert removed == 3
    assert {p.name for p in root.iterdir()} == {"aaa-just-written.bin"}


def test_prune_breaks_mtime_ties_by_name_not_directory_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tied mtimes resolve by name, deterministically, not by iterdir order.

    The old float-mtime sort was stable, so a directory of equally-aged
    captures kept whatever ``iterdir`` happened to return last -- arbitrary,
    and different from one filesystem to the next. Forcing a reversed directory
    order shows the fix keeps the name-max regardless of what order the
    filesystem hands back.
    """
    root = tmp_path / "captures"
    root.mkdir()
    for name in ("a.bin", "b.bin", "c.bin", "d.bin"):
        entry = root / name
        entry.write_bytes(b"x" * 10)
        _age(entry, 700)  # one identical mtime across all four

    real_iterdir = Path.iterdir

    def _reversed_iterdir(self: Path) -> Any:
        return iter(sorted(real_iterdir(self), key=lambda item: item.name, reverse=True))

    monkeypatch.setattr(Path, "iterdir", _reversed_iterdir)

    removed = limits.prune_capped_dir(root, max_entries=1, max_bytes=10_000)
    assert removed == 3
    assert {p.name for p in root.iterdir()} == {"d.bin"}


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
