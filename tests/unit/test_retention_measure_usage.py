"""Pin the bounded artifact-tree walk's three fail-closed exits.

``measure_usage`` totals the artifact root but must never stall or raise on a
hostile tree. It bounds itself three ways, and each marks the answer as a floor
rather than a measurement (``truncated``) or quietly skips what it cannot read:

* a file-count ceiling that stops the walk early,
* a per-entry ``stat`` failure that is skipped instead of aborting the total,
* a walk-level ``OSError`` that returns what was counted so far, truncated.

The happy path runs through the observability and retention suites; these pin
the three defensive exits a healthy filesystem never takes on its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.retention import measure_usage


def test_the_file_ceiling_stops_the_walk_and_marks_the_total_a_floor(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}.bin").write_bytes(b"x")
    usage = measure_usage(tmp_path, file_limit=3)
    assert usage.truncated is True
    assert usage.files == 3


def test_an_unreadable_entry_is_skipped_without_aborting_the_total(tmp_path: Path) -> None:
    (tmp_path / "real.bin").write_bytes(b"1234")
    # A dangling symlink: ``stat`` (which follows the link) raises, exercising the
    # inner skip. If that skip were absent the error would escape to the outer
    # handler and the whole total would come back truncated instead.
    (tmp_path / "dangling").symlink_to(tmp_path / "missing-target")
    usage = measure_usage(tmp_path)
    assert usage.truncated is False
    assert usage.files == 1
    assert usage.bytes == 4


def test_a_walk_level_oserror_returns_the_running_total_as_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(self: Path, pattern: str) -> object:
        raise OSError("directory vanished mid-walk")

    monkeypatch.setattr(Path, "rglob", _boom)
    usage = measure_usage(tmp_path)
    assert usage.truncated is True
    assert usage.files == 0
    assert usage.bytes == 0
