"""Failure handling for background artifact-usage measurement."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from headless_re_mcp.core.retention import measure_usage


def test_measure_usage_bounds_the_walk_on_a_directory_flood(tmp_path: Path) -> None:
    """The cap must bound the walk on a tree that is mostly empty directories.

    This runs behind the readiness probe, and the cap exists so the walk never
    becomes the slowest part of that probe. A files-only cap does not bound the
    walk it is there to bound: a directory bomb an analysed sample unpacked into
    the artifact root has few files, so the cap never trips and the walk grows
    with the tree, and the supervisor restarts a healthy service on the late
    answer. rglob yields every top-level entry before it descends, so five empty
    directories against a cap of three spend the budget on directories and the
    walk stops before it reaches the file nested behind one of them: truncated
    is set and the file is never counted. A files-only cap skips the
    directories, descends, and returns a complete, untruncated answer -- so
    truncated=True and files=0 are exactly the difference the fix makes.
    """
    root = tmp_path / "artifacts"
    root.mkdir()
    for index in range(5):
        (root / f"d{index}").mkdir()
    (root / "d0" / "deep.bin").write_bytes(b"x" * 10)

    usage = measure_usage(root, file_limit=3)

    assert usage.truncated is True
    assert usage.files == 0


def test_measure_usage_counts_a_small_tree_without_truncating(tmp_path: Path) -> None:
    """A tree comfortably under the cap is summed in full and not flagged.

    Directories now count toward the entry cap, so this pins that counting them
    did not start truncating an ordinary tree: three files and their two
    directories are five entries, well under the cap, so every byte is summed
    and truncated stays false.
    """
    root = tmp_path / "artifacts"
    (root / "sub").mkdir(parents=True)
    (root / "a.bin").write_bytes(b"x" * 10)
    (root / "b.bin").write_bytes(b"x" * 20)
    (root / "sub" / "c.bin").write_bytes(b"x" * 30)

    usage = measure_usage(root, file_limit=100)

    assert usage.truncated is False
    assert usage.files == 3
    assert usage.bytes == 60


def test_a_failed_usage_walk_is_reported_and_throttled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken background walk must not create one failed thread per probe.

    The initial implementation cleared ``_refreshing`` after an exception but
    left the cache empty. The very next readiness request therefore started a
    new daemon thread immediately, regardless of the TTL, and the exception
    never reached the service's alert stream.
    """
    from headless_re_mcp.core import retention as module

    attempts: list[float] = []
    alerts: list[str] = []
    healthy = False

    def walk(root: Path, *, file_limit: int = 0) -> module.DiskUsage:
        attempts.append(time.monotonic())
        if not healthy:
            raise RuntimeError("directory iterator failed")
        return module.DiskUsage(bytes=23, files=1, truncated=False)

    monkeypatch.setattr(module, "measure_usage", walk)
    monkeypatch.setattr(
        module,
        "record_alert",
        lambda kind, **kwargs: alerts.append(kind),
    )
    cache = module.UsageCache(ttl_s=0.05)

    def wait_until_idle() -> None:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            with cache._lock:
                if not cache._refreshing:
                    return
            time.sleep(0.005)
        raise AssertionError("usage refresh did not finish")

    first = cache.get(tmp_path)
    wait_until_idle()
    second = cache.get(tmp_path)
    wait_until_idle()

    assert first.truncated is True and second.truncated is True
    assert len(attempts) == 1, "the TTL must throttle a failed walk too"
    assert alerts == ["artifact_usage_measurement_failing"]

    healthy = True
    deadline = time.monotonic() + 2.0
    while time.monotonic() - cache._at < cache.ttl_s:
        if time.monotonic() >= deadline:
            raise AssertionError("failed measurement did not leave the TTL window")
        time.sleep(0.01)
    cache.get(tmp_path)
    wait_until_idle()

    measured = cache.get(tmp_path)
    assert measured.files == 1 and measured.bytes == 23
    assert alerts[-1] == "artifact_usage_measurement_recovered"
