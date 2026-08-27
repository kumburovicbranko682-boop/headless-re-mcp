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


def test_a_refused_refresh_thread_does_not_throw_or_wedge_the_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OS thread exhaustion must neither raise out of get() nor stop refreshing.

    get() sets ``_refreshing`` under the lock and then starts the daemon thread
    outside it. When ``Thread.start()`` raises (the OS refused a new thread) the
    original code let that RuntimeError escape a method the readiness/metrics
    path treats as a safe non-blocking read, and left ``_refreshing`` stuck True
    forever -- a stale cache can only be refreshed by a fresh claim, so the walk
    never ran again even after threads freed up.
    """
    from headless_re_mcp.core import retention as module

    walk_calls: list[float] = []

    def walk(root: Path, *, file_limit: int = 0) -> module.DiskUsage:
        walk_calls.append(time.monotonic())
        return module.DiskUsage(bytes=42, files=2, truncated=False)

    monkeypatch.setattr(module, "measure_usage", walk)

    refuse = True

    class Refusing:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._target = kwargs.get("target")
            self._args = kwargs.get("args", ())

        def start(self) -> None:
            if refuse:
                raise RuntimeError("can't start new thread")
            # Run synchronously so the test does not depend on scheduling.
            assert callable(self._target)
            self._target(*self._args)  # type: ignore[misc]

    monkeypatch.setattr(module, "Thread", Refusing)
    cache = module.UsageCache(ttl_s=0.05)

    # The refused start must be swallowed: get() returns the cold-start floor
    # rather than propagating RuntimeError, and the claim is released.
    floor = cache.get(tmp_path)
    assert floor.truncated is True and floor.bytes == 0
    assert walk_calls == []
    with cache._lock:
        assert cache._refreshing is False

    # Once threads are available again the very next probe must be able to
    # claim and refresh -- proving the cache was not permanently wedged.
    refuse = False
    cache.get(tmp_path)
    assert len(walk_calls) == 1
    measured = cache.get(tmp_path)
    assert measured.files == 2 and measured.bytes == 42
