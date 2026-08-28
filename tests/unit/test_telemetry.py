from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from headless_re_mcp.telemetry import TelemetryRing, instrument, record_tool_call


def test_ring_is_bounded_and_returns_newest_first() -> None:

    ring = TelemetryRing(capacity=3)

    for index in range(5):

        record_tool_call(f"tool.{index}", ok=True, duration_ms=float(index), ring=ring)

    recent = ring.recent(10)

    assert [item["tool"] for item in recent] == ["tool.4", "tool.3", "tool.2"]

    assert ring.metrics()["sampled_calls"] == 3

    assert ring.capacity == 3


def test_instrument_records_success_and_envelope_failure() -> None:

    ring = TelemetryRing()

    def ok_handler(value: int) -> dict[str, Any]:

        return {"ok": True, "value": value}

    def failing_handler() -> dict[str, Any]:

        return {"ok": False, "error": {"code": "invalid_request"}}

    instrument(ok_handler, name="demo.ok", ring=ring)(value=1)

    instrument(failing_handler, name="demo.fail", ring=ring)()

    metrics = ring.metrics()

    assert metrics["sampled_calls"] == 2

    assert metrics["failures"] == 1

    by_tool = {item["tool"]: item for item in metrics["tools"]}

    assert by_tool["demo.ok"]["failures"] == 0

    assert by_tool["demo.fail"]["failures"] == 1

    assert ring.recent(1)[0]["error_code"] == "invalid_request"


def test_instrument_preserves_signature_and_reraises() -> None:

    ring = TelemetryRing()

    def boom(session_id: str) -> dict[str, Any]:

        """Original doc."""

        raise RuntimeError("nope")

    observed = instrument(boom, name="demo.boom", ring=ring)

    assert observed.__doc__ == "Original doc."

    assert observed.__wrapped__ is boom  # type: ignore[attr-defined]

    with pytest.raises(RuntimeError):

        observed(session_id="s")

    record = ring.recent(1)[0]

    assert record["ok"] is False

    assert record["error_code"] == "RuntimeError"


def test_registered_tools_are_instrumented_by_the_adapter() -> None:

    """The wrapper is only useful if registration actually installs it."""

    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.mcp.server import create_server
    from headless_re_mcp.telemetry import TELEMETRY
    from headless_re_mcp.tools.catalog import COMMAND_CATALOG

    analysis = AnalysisService()

    try:

        create_server(analysis)

        TELEMETRY.clear()

        payload = COMMAND_CATALOG.invoke("session.list", {})

    finally:

        analysis.close_all()

    assert payload["ok"] is True

    recent = TELEMETRY.recent(5)

    assert recent, "adapter registration did not instrument the handler"

    assert recent[0]["tool"] == "session.list"

    assert recent[0]["ok"] is True

    assert recent[0]["duration_ms"] >= 0.0


def test_record_emits_structured_json_log(caplog: pytest.LogCaptureFixture) -> None:

    ring = TelemetryRing()

    with caplog.at_level(logging.INFO, logger="headless_re_mcp.telemetry"):

        record_tool_call("demo.log", ok=True, duration_ms=1.5, ring=ring)

    payload = json.loads(caplog.records[-1].message)

    assert payload["event"] == "tool_call"

    assert payload["tool"] == "demo.log"

    assert payload["ok"] is True

    assert payload["duration_ms"] == 1.5


def test_totals_survive_window_eviction_while_sampled_counts_do_not() -> None:
    """Lifetime counters must not fall when the recent-window ring rolls.

    The window answers latency ("what is happening now") and evicts; the totals
    answer rate and error-budget ("how many, ever") and must not. The ring keeps
    the two in separate structures precisely so that once a session outruns the
    window, ``calls_total`` keeps climbing while the sampled ``calls`` saturates
    at the retained tail -- and, sharper still, the failures here all land in the
    evicted head, so the window reports zero while the lifetime counter still
    holds all three. If a refactor ever recomputed ``calls_total`` /
    ``failures_total`` from the window (the obvious simplification the split
    exists to forbid), every rate and error budget built on them would silently
    understate the moment the ring rolled -- and nothing pinned that today. This
    drives one tool ten calls deep into a four-slot window, with the only three
    failures at the front, and holds the lifetime counters to the true totals
    while the sampled counts see only what the window still holds.
    """
    ring = TelemetryRing(capacity=4)
    for index in range(10):
        # The three failures are the oldest calls, so the four-slot window has
        # evicted every one of them by the tenth call: sampled failures fall to
        # zero while the lifetime failure counter must still read three.
        record_tool_call(
            "demo.tool", ok=index >= 3, duration_ms=float(index), ring=ring
        )

    metrics = ring.metrics()
    tool = {item["tool"]: item for item in metrics["tools"]}["demo.tool"]

    assert tool["calls"] == 4, "sampled calls saturate at the window capacity"
    assert tool["failures"] == 0, "the only failures were evicted from the window"
    assert tool["calls_total"] == 10, "the lifetime counter keeps every call"
    assert tool["failures_total"] == 3, "the lifetime counter keeps every failure"

    assert metrics["sampled_calls"] == 4
    assert metrics["failures"] == 0, "the window-level failure count also evicts"
    assert metrics["calls_total"] == 10, "the process-wide lifetime call count is whole"
    assert metrics["failures_total"] == 3, "the process-wide lifetime failures are whole"


def test_metrics_percentiles_come_from_the_sampled_latencies() -> None:
    """p50/p95/max are read from the sorted window by nearest-rank.

    The percentiles feed an operator dashboard, but nothing pinned the numbers
    they produce from a known latency distribution -- a change to the rank
    formula (an off-by-one on the index, a different rounding, a switch to a
    linear-interpolation method) would ship silently. With durations 0..100 ms in
    the window, nearest-rank on the 0-based sorted list puts p50 at 50, p95 at 95
    and max at the top sample, so this holds the three published figures to exact
    values.
    """
    ring = TelemetryRing(capacity=256)
    for milliseconds in range(0, 101):
        record_tool_call(
            "demo.slow", ok=True, duration_ms=float(milliseconds), ring=ring
        )

    tool = {item["tool"]: item for item in ring.metrics()["tools"]}["demo.slow"]

    assert tool["p50_ms"] == 50.0
    assert tool["p95_ms"] == 95.0
    assert tool["max_ms"] == 100.0
