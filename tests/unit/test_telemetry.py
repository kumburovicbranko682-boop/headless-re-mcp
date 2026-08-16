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
    assert ring.retained() == 3


def test_metrics_recent_page_says_when_the_ring_has_more() -> None:
    """A 20-call page used to look like the whole ring.

    Measured: 50 records, tool_metrics(limit=20) returned recent of
    length 20 and no total. The other 30 looked like they never ran.
    """
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.telemetry import TELEMETRY

    TELEMETRY.clear()
    try:
        for index in range(50):
            record_tool_call(f"tool.{index}", ok=True, duration_ms=1.0)
        service = AnalysisService()
        try:
            result = service.tool_metrics(limit=20)
            assert result.ok and result.data is not None
            assert len(result.data["recent"]) == 20
            assert result.data["recent_total"] == 50
            assert result.data["recent_has_more"] is True
        finally:
            service.close_all()
    finally:
        TELEMETRY.clear()


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
