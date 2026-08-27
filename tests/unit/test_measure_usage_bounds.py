"""measure_usage totals the artifact tree honestly, even when it cannot finish.

Artifact GC runs on session close for every line -- a web session's HAR and
screenshots, an APK pull, a PE dump alike -- and it decides whether to collect
from what ``measure_usage`` reports. So the walk must never stall on a huge tree
or crash on an unreadable entry: it caps the number of files it will stat and
returns ``truncated=True`` (the byte total is then a floor, not the whole
story), and it steps over any single path it cannot stat rather than aborting
the whole measurement.

The happy walk is exercised in the retention tests; this pins the two adverse
conditions, both with a real temp tree -- no monkeypatching of the walk itself.
"""

from __future__ import annotations

import os
from pathlib import Path

from headless_re_mcp.core.retention import measure_usage

_FILE_BYTES = 512


def _make_files(root: Path, count: int, *, size: int = _FILE_BYTES) -> None:
    for index in range(count):
        (root / f"f{index}.bin").write_bytes(b"\x00" * size)


def test_a_readable_tree_is_totalled_exactly_and_not_truncated(tmp_path: Path) -> None:
    """The baseline: every file counted, bytes summed, truncated False."""
    _make_files(tmp_path, 4)
    (tmp_path / "nested").mkdir()
    _make_files(tmp_path / "nested", 2)
    usage = measure_usage(tmp_path)
    assert usage.files == 6
    assert usage.bytes == 6 * _FILE_BYTES
    assert usage.truncated is False


def test_the_file_limit_caps_the_walk_and_flags_a_floor(tmp_path: Path) -> None:
    """Past the file limit the walk stops early: the count stops at the limit and
    the byte total is declared a floor, so a caller never mistakes an early stop
    for a reassuringly small tree."""
    _make_files(tmp_path, 10)
    usage = measure_usage(tmp_path, file_limit=3)
    assert usage.truncated is True
    assert usage.files == 3
    # The reported bytes reflect only what was actually counted -- a floor.
    assert usage.bytes == 3 * _FILE_BYTES


def test_a_file_that_cannot_be_stated_is_skipped_not_fatal(tmp_path: Path) -> None:
    """A broken symlink cannot be stat'd; the walk steps over it and still totals
    the readable files rather than aborting the whole measurement."""
    _make_files(tmp_path, 2)
    os.symlink(tmp_path / "does-not-exist", tmp_path / "broken-link")
    usage = measure_usage(tmp_path)
    # Only the two real files are counted; the broken link is neither counted nor
    # fatal, and the walk still completes (not truncated).
    assert usage.files == 2
    assert usage.bytes == 2 * _FILE_BYTES
    assert usage.truncated is False


def test_an_empty_root_is_zero_and_complete(tmp_path: Path) -> None:
    usage = measure_usage(tmp_path)
    assert usage.files == 0
    assert usage.bytes == 0
    assert usage.truncated is False
