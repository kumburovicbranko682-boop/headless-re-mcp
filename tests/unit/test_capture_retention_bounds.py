"""Graceful degradation of the unregistered-capture retention pruner.

Device screenshots (adb) and JS/WASM unpack trees (jsre) are keyed by serial or
by a throwaway uuid, so the artifact retention walker never sees them:
``prune_capped_dir`` is the only thing bounding their disk use, and it runs
opportunistically right after each capture. It therefore must never raise over a
filesystem it does not fully control -- a directory that vanished, one it cannot
list, a child whose stat fails, a dangling symlink, a tree too large to walk, or
an entry it cannot delete. These pin that degrade-not-crash contract directly on
the primitives; the happy-path trimming is proven through the jsre and adb
service tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import limits
from headless_re_mcp.core.limits import _dir_size, _remove_entry, prune_capped_dir

# --- prune_capped_dir -------------------------------------------------------


def test_prune_is_a_noop_on_a_directory_that_is_not_there(tmp_path: Path) -> None:
    # A capture dir that was never created (or already gc'd) is nothing to prune.
    assert prune_capped_dir(tmp_path / "gone", max_entries=1, max_bytes=1) == 0


def test_prune_is_a_noop_on_a_path_that_is_a_file(tmp_path: Path) -> None:
    # A regular file is not a capture directory; prune declines it up front
    # rather than trying to iterate it.
    file = tmp_path / "not-a-dir"
    file.write_bytes(b"x")
    assert prune_capped_dir(file, max_entries=1, max_bytes=1) == 0


def test_prune_degrades_to_zero_when_the_directory_cannot_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # is_dir() passes but the listing itself raises (a permission or IO error
    # between the two): prune returns 0 rather than letting the OSError escape
    # into the capture path that called it.
    directory = tmp_path / "cap"
    directory.mkdir()
    (directory / "a").write_bytes(b"x")
    real_iterdir = Path.iterdir

    def boom(self: Path):
        if self == directory:
            raise OSError("EACCES")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", boom)
    assert prune_capped_dir(directory, max_entries=1, max_bytes=1) == 0


def test_prune_skips_a_child_whose_stat_fails(tmp_path: Path) -> None:
    # A dangling symlink's stat() follows the link and raises: that one child is
    # skipped, leaving no countable entries, so prune is a no-op rather than a
    # crash -- and the link itself is left alone, not removed.
    directory = tmp_path / "cap"
    directory.mkdir()
    dangling = directory / "dangling"
    dangling.symlink_to(directory / "does-not-exist")
    assert prune_capped_dir(directory, max_entries=1, max_bytes=1) == 0
    assert dangling.is_symlink()


def test_prune_keeps_counting_when_a_delete_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # _remove_entry returning False (a delete that could not happen) must not
    # wedge the loop nor count as removed: the pruner pops the entry and moves
    # on, so an undeletable file cannot spin it forever. With every delete
    # failing it pops down to the retained newest and stops, having removed none.
    directory = tmp_path / "cap"
    directory.mkdir()
    for index in range(3):
        (directory / f"f{index}.bin").write_bytes(b"x" * 10)
    monkeypatch.setattr(limits, "_remove_entry", lambda path: False)
    removed = prune_capped_dir(directory, max_entries=1, max_bytes=1)
    assert removed == 0
    assert len(list(directory.iterdir())) == 3


# --- _dir_size --------------------------------------------------------------


def test_dir_size_counts_files_across_subdirectories_and_skips_dir_entries(
    tmp_path: Path,
) -> None:
    # Only regular files add to the size; the subdirectory entry rglob also
    # yields is skipped rather than counted.
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "a.bin").write_bytes(b"x" * 4)
    (root / "sub" / "b.bin").write_bytes(b"x" * 6)
    assert _dir_size(root) == 10


def test_dir_size_stops_at_the_file_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The walk is bounded so a capture tree with a huge fan-out cannot stall
    # retention: once the file cap is hit it stops counting. Five one-byte files
    # under a cap of two sum to exactly two before the break.
    monkeypatch.setattr(limits, "_DIR_SIZE_FILE_CAP", 2)
    root = tmp_path / "tree"
    root.mkdir()
    for index in range(5):
        (root / f"f{index}.bin").write_bytes(b"x")
    assert _dir_size(root) == 2


def test_dir_size_skips_a_file_that_vanishes_after_the_is_file_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A capture tree can be walked while a backend is still writing it, so a
    # path that is a file when checked can be gone by the time its size is read.
    # That per-child OSError is skipped and the size of the rest is still
    # returned, rather than one racing file aborting the whole measurement.
    root = tmp_path / "tree"
    root.mkdir()
    (root / "stable.bin").write_bytes(b"x" * 4)
    (root / "racing.bin").write_bytes(b"x" * 99)
    real_is_file = Path.is_file
    real_stat = Path.stat

    def is_file(self: Path) -> bool:
        return True if self.name == "racing.bin" else real_is_file(self)

    def stat(self: Path, *args: object, **kwargs: object):
        if self.name == "racing.bin":
            raise OSError("ENOENT")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(Path, "stat", stat)
    assert _dir_size(root) == 4


def test_dir_size_degrades_to_zero_when_the_walk_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If the recursive walk itself raises (the directory becomes unreadable
    # mid-measure) the size seen so far is returned rather than the error.
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.bin").write_bytes(b"x")

    def boom(self: Path, *args: object, **kwargs: object):
        raise OSError("EIO")

    monkeypatch.setattr(Path, "rglob", boom)
    assert _dir_size(root) == 0


# --- _remove_entry ----------------------------------------------------------


def test_remove_entry_returns_false_when_the_delete_raises(tmp_path: Path) -> None:
    # A path that is not there unlinks with OSError; the helper reports failure
    # rather than letting it escape into the prune loop.
    assert _remove_entry(tmp_path / "never") is False


def test_remove_entry_deletes_a_real_directory_tree(tmp_path: Path) -> None:
    # The positive companion: a real subtree is removed wholesale and reported
    # as success, so the False above is a real refusal and not a helper that
    # always declines.
    victim = tmp_path / "tree"
    (victim / "nested").mkdir(parents=True)
    (victim / "nested" / "f.bin").write_bytes(b"x")
    assert _remove_entry(victim) is True
    assert not victim.exists()
