"""Failure handling for background artifact-usage measurement."""

from __future__ import annotations

import time
from pathlib import Path

import pytest


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
