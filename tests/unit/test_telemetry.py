from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from headless_re_mcp.telemetry import (
    TelemetryRing,
    instrument,
    record_alert,
    record_tool_call,
)


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


def test_alert_python_level_matches_its_declared_severity(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A severity="info" recovery alert must not be emitted at WARNING level.

    record_alert used to call _LOGGER.warning unconditionally, so a recovery the
    watchdog deliberately marks "info" (health back, worker reconnected) landed
    at Python WARNING. An operator routing on level -- the usual "page on
    WARNING+" -- was then paged for good news. The record's level now follows the
    severity field, while an unknown severity stays WARNING as a safe default.
    """
    with caplog.at_level(logging.INFO, logger="headless_re_mcp.telemetry"):
        record_alert("session_health_recovered", severity="info", fields={"n": 1})
        record_alert("session_health_lost", severity="warning")
        record_alert("weird", severity="not-a-level")

    by_kind = {json.loads(rec.message)["kind"]: rec for rec in caplog.records}
    assert by_kind["session_health_recovered"].levelno == logging.INFO
    assert by_kind["session_health_lost"].levelno == logging.WARNING
    # An unrecognised severity is treated as WARNING, not silently downgraded.
    assert by_kind["weird"].levelno == logging.WARNING
    # The JSON payload still carries the declared severity verbatim.
    assert json.loads(by_kind["session_health_recovered"].message)["severity"] == "info"
