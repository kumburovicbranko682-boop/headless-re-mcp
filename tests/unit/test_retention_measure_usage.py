"""Pin the disk-walk bounds inside ``measure_usage``.

``test_retention_usage_cache_refresh.py`` already points here for the walk
bounds, but this module was missing, so the three degradation arcs were
unpinned: a walk that hits the file cap must return a floor marked
``truncated`` instead of stalling on a huge tree, an entry whose ``stat``
fails (a dangling symlink, a file deleted mid-walk) must be skipped rather
than abort the walk, and a walk the OS refuses outright must degrade to a
truncated floor instead of raising. Each arm matters because callers treat
``truncated=False`` as "this number is the whole story" when enforcing the
artifact budget.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.retention import measure_usage


def test_walk_stops_at_the_file_cap_and_says_the_answer_is_a_floor(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"artifact-{index}.bin").write_bytes(b"x" * 10)

    usage = measure_usage(tmp_path, file_limit=2)

    # The walk gives up as soon as the cap is met: exactly two files counted,
    # and the result is flagged as a floor rather than a total.
    assert usage.truncated is True
    assert usage.files == 2
    assert usage.bytes == 20


def test_an_entry_whose_stat_fails_is_skipped_not_fatal(tmp_path: Path) -> None:
    # A directory stats fine but is not a file: walked past, never counted.
    (tmp_path / "nested").mkdir()
    (tmp_path / "real.bin").write_bytes(b"y" * 7)
    # A dangling symlink: rglob yields it, but stat() follows the link and
    # raises. The walk must skip it and keep counting.
    (tmp_path / "gone.lnk").symlink_to(tmp_path / "no-such-target")

    usage = measure_usage(tmp_path)

    assert usage.truncated is False
    assert usage.files == 1
    assert usage.bytes == 7


def test_a_refused_walk_degrades_to_a_truncated_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _refuse(self: Path, pattern: str) -> object:
        raise OSError("walk refused")

    monkeypatch.setattr(Path, "rglob", _refuse)

    usage = measure_usage(tmp_path)

    # Nothing was counted, and the caller is told the zero is a floor, not a
    # measurement of an empty tree.
    assert usage.truncated is True
    assert usage.files == 0
    assert usage.bytes == 0


def test_an_empty_tree_is_a_complete_answer_not_a_floor(tmp_path: Path) -> None:
    usage = measure_usage(tmp_path)

    assert usage.truncated is False
    assert usage.files == 0
    assert usage.bytes == 0
    assert usage.as_json() == {"bytes": 0, "files": 0, "truncated": False}
