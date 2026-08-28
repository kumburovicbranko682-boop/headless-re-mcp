"""The `meta.tool_metrics` aggregation contract: percentile math, the
window-vs-lifetime honesty split, and fail-closed limit validation.

``telemetry.metrics()`` is what an agent (and the ``/metrics`` scrape) reads to
decide whether a tool is slow or failing. Existing tests cover that lifetime
counters survive ring eviction, but not the numbers a rate/latency dashboard is
actually built from: the percentile values themselves, and the honest shape of a
tool whose latencies have rolled out of the window while its call total lives
on. A silent off-by-one in ``_percentile`` or an omitted-when-evicted tool would
mislead exactly when the operator is looking hardest.
"""

from __future__ import annotations

from headless_re_mcp.telemetry import TelemetryRing, record_tool_call


def test_percentiles_are_nearest_rank_over_the_sampled_window() -> None:
    """p50/p95/max are read off the sorted sample, not interpolated or invented.

    101 samples make ``fraction * (n - 1)`` land on an exact integer index, so
    the asserted values do not depend on how ``round`` breaks a .5 tie: p50 is
    the 51st value, p95 the 96th, max the last.
    """
    ring = TelemetryRing(capacity=200)
    for value in range(1, 102):
        record_tool_call("demo.latency", ok=True, duration_ms=float(value), ring=ring)

    tool = next(item for item in ring.metrics()["tools"] if item["tool"] == "demo.latency")

    assert tool["calls"] == 101
    assert tool["p50_ms"] == 51.0
    assert tool["p95_ms"] == 96.0
    assert tool["max_ms"] == 101.0


def test_a_single_sample_is_its_own_percentile() -> None:
    """One call must not crash the percentile math or fabricate a spread."""
    ring = TelemetryRing()
    record_tool_call("demo.one", ok=True, duration_ms=7.0, ring=ring)

    tool = next(item for item in ring.metrics()["tools"] if item["tool"] == "demo.one")

    assert tool["p50_ms"] == 7.0
    assert tool["p95_ms"] == 7.0
    assert tool["max_ms"] == 7.0


def test_a_tool_evicted_from_the_window_is_listed_with_zeroed_latency() -> None:
    """A tool whose samples rolled off still appears, with live totals.

    Latency comes from the evicting window, so once a tool's samples are gone the
    honest answer is "ran this many times, no recent latency to show" -- zeroed
    p50/p95/max and calls==0, but calls_total intact. Dropping the tool from the
    list entirely (it is absent from ``buckets``) would hide a tool the operator
    knows ran; that it comes back via ``set(totals)`` is the contract here.
    """
    ring = TelemetryRing(capacity=2)
    record_tool_call("aaa.evicted", ok=False, duration_ms=5.0, ring=ring)
    record_tool_call("zzz.recent", ok=True, duration_ms=1.0, ring=ring)
    record_tool_call("zzz.recent", ok=True, duration_ms=2.0, ring=ring)

    metrics = ring.metrics()
    by_tool = {item["tool"]: item for item in metrics["tools"]}

    assert "aaa.evicted" in by_tool, "a tool must not vanish just because its window rolled"
    evicted = by_tool["aaa.evicted"]
    assert evicted["calls"] == 0
    assert evicted["calls_total"] == 1
    assert evicted["failures_total"] == 1
    assert evicted["p50_ms"] == 0.0
    assert evicted["p95_ms"] == 0.0
    assert evicted["max_ms"] == 0.0

    assert metrics["sampled_calls"] == 2
    assert metrics["calls_total"] == 3
    assert metrics["failures_total"] == 1


def test_recent_clamps_a_non_positive_limit_to_empty() -> None:
    ring = TelemetryRing()
    for index in range(3):
        record_tool_call(f"demo.{index}", ok=True, duration_ms=1.0, ring=ring)

    assert ring.recent(0) == []
    assert ring.recent(-5) == []


def test_tool_metrics_rejects_a_bad_limit_fail_closed() -> None:
    """The service handler bounds ``limit`` before it reaches the ring, and a
    bool is not an accepted count (``True`` is an int subclass, so a naive check
    would let ``limit=True`` through as 1)."""
    from headless_re_mcp.core.service import AnalysisService

    analysis = AnalysisService()
    try:
        for bad in (True, -1, 201):
            result = analysis.tool_metrics(limit=bad)
            assert result.ok is False, f"limit={bad!r} should be refused"
            assert result.error is not None and result.error.code == "invalid_request"

        good = analysis.tool_metrics(limit=5)
        assert good.ok is True, good.error
        assert good.data is not None
        assert "tools" in good.data
        assert len(good.data["recent"]) <= 5
    finally:
        analysis.close_all()
