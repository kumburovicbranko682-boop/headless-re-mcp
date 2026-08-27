"""Failure handling for background artifact-usage measurement."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from headless_re_mcp.core import retention as retention_module


def test_measure_usage_truncates_at_the_file_limit(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"f{index}.bin").write_bytes(b"x")
    usage = retention_module.measure_usage(tmp_path, file_limit=1)
    assert usage.truncated is True
    assert usage.files == 1


def test_measure_usage_gives_up_when_the_walk_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom_rglob(self: Path, pattern: str) -> object:
        raise OSError("directory iterator failed")

    monkeypatch.setattr(Path, "rglob", boom_rglob)
    usage = retention_module.measure_usage(tmp_path)
    assert usage.truncated is True
    assert usage.files == 0


def test_refresh_keeps_the_last_value_and_alerts_only_once_across_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a good measurement, repeated failures keep the last value and the
    alert fires once, not on every failed pass."""
    alerts: list[str] = []
    monkeypatch.setattr(
        retention_module, "record_alert", lambda kind, **kwargs: alerts.append(kind)
    )

    def boom(root: Path, *, file_limit: int = 0) -> retention_module.DiskUsage:
        raise RuntimeError("walk failed")

    monkeypatch.setattr(retention_module, "measure_usage", boom)
    cache = retention_module.UsageCache(ttl_s=0.05)
    cache._value = retention_module.DiskUsage(bytes=10, files=1, truncated=False)
    cache._failing = False

    cache._refresh(tmp_path)
    cache._refresh(tmp_path)

    # The prior measurement is retained rather than zeroed out.
    assert cache._value.bytes == 10
    assert cache._value.files == 1
    # A run of failures is a single alert, not one per pass.
    assert alerts == ["artifact_usage_measurement_failing"]


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
