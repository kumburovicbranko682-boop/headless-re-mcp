"""Disk-walk bounds inside ``measure_usage``.

``test_retention_usage_cache_refresh.py`` pins the ``UsageCache._refresh`` arcs;
this pins the walk itself. It must give up on a huge tree rather than stall a
health probe, and that ceiling has to count every entry it examines -- not only
files -- or a tree of empty directories walks unbounded even though the file
count never climbs.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.retention import measure_usage


def test_a_small_tree_is_totalled_and_not_truncated(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"f{index}.bin").write_bytes(b"x" * 10)

    usage = measure_usage(tmp_path, file_limit=100)

    assert usage.files == 3
    assert usage.bytes == 30
    assert usage.truncated is False


def test_a_flood_of_empty_directories_still_bounds_the_walk(tmp_path: Path) -> None:
    """A files-only ceiling never trips on empty directories.

    rglob yields directories too, and measure_usage stats every entry, so a tree
    that is all empty directories used to walk the whole thing -- the file count
    stays zero, so ``files >= file_limit`` was never true. The ceiling now counts
    entries examined, so it trips here even though no file is ever found, which is
    what keeps a hostile or runaway producer from turning this into the slowest
    part of a health probe.
    """
    for index in range(50):
        (tmp_path / f"dir{index}").mkdir()

    usage = measure_usage(tmp_path, file_limit=10)

    assert usage.truncated is True
    assert usage.files == 0


def test_the_ceiling_counts_files_toward_the_same_bound(tmp_path: Path) -> None:
    for index in range(50):
        (tmp_path / f"f{index}.bin").write_bytes(b"x")

    usage = measure_usage(tmp_path, file_limit=10)

    assert usage.truncated is True
    # The walk stopped at the ceiling, so it saw at most that many files.
    assert usage.files <= 10
