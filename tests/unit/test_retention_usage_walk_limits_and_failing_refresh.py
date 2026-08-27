"""Usage measurement bounds and the cache's behavior when the walk fails."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest

from headless_re_mcp.core import retention
from headless_re_mcp.core.retention import DiskUsage, UsageCache, measure_usage


def test_the_walk_stops_at_the_file_limit_and_reports_a_floor(tmp_path: Path) -> None:
    # The cap exists so a huge artifact tree cannot stall the caller; the
    # answer must say it stopped early rather than pass off a partial total
    # as the whole tree.
    for index in range(3):
        (tmp_path / f"f{index}.bin").write_bytes(b"x" * 10)

    usage = measure_usage(tmp_path, file_limit=2)

    assert usage.files == 2
    assert usage.bytes == 20
    assert usage.truncated is True


def test_a_broken_symlink_is_skipped_not_counted(tmp_path: Path) -> None:
    # stat() follows links, so a dangling one raises mid-walk. One bad entry
    # must cost only itself: the file is skipped and the rest of the tree is
    # still totalled as a complete (untruncated) answer.
    (tmp_path / "real.bin").write_bytes(b"x" * 4)
    (tmp_path / "ghost").symlink_to(tmp_path / "nope.bin")

    usage = measure_usage(tmp_path)

    assert usage == DiskUsage(bytes=4, files=1, truncated=False)


def test_a_walk_that_dies_midway_reports_what_it_saw_as_a_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # rglob itself can raise partway through -- a directory deleted or made
    # unreadable during the walk. What was counted so far is still a valid
    # floor, so it is returned as truncated instead of being thrown away.
    seen = tmp_path / "seen.bin"
    seen.write_bytes(b"x" * 32)

    def dying_walk(self: Path, pattern: str) -> Iterator[Path]:
        yield seen
        raise OSError("directory vanished during the walk")

    monkeypatch.setattr(Path, "rglob", dying_walk)

    usage = measure_usage(tmp_path)

    assert usage == DiskUsage(bytes=32, files=1, truncated=True)


def test_a_repeat_measurement_failure_keeps_the_last_value_and_alerts_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A broken walk must not evict the last good number (stale beats unknown
    # for an informational field), and it must page once on the transition to
    # failing, not once per retry at the refresh cadence.
    alerts: list[str] = []
    monkeypatch.setattr(retention, "record_alert", lambda name, **kwargs: alerts.append(str(name)))
    (tmp_path / "artifact.bin").write_bytes(b"x" * 8)
    cache = UsageCache(ttl_s=3600.0)
    cache._refresh(tmp_path)

    def broken_walk(root: Path, *, file_limit: int = 0) -> NoReturn:
        raise RuntimeError("walk exploded")

    monkeypatch.setattr(retention, "measure_usage", broken_walk)
    cache._refresh(tmp_path)
    cache._refresh(tmp_path)

    assert alerts == ["artifact_usage_measurement_failing"]
    # now= is pinned to the last attempt so the read is fresh and no
    # background refresh thread is spawned by the assertion itself.
    value = cache.get(tmp_path, now=cache._at)
    assert value == DiskUsage(bytes=8, files=1, truncated=False)
