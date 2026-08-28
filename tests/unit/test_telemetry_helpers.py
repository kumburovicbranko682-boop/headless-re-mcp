"""Guard/edge coverage for the telemetry helpers.

``test_telemetry.py`` covers the ring, the instrument wrapper and the JSON log
line. These pin the remaining branches of ``telemetry.py``: the idempotent
logging-config path, the lifetime-totals snapshot, the envelope ok/error-code
readers, and the signature probe tolerating a handler it cannot introspect.
"""

from __future__ import annotations

import inspect
import json
import logging
from pathlib import Path

import pytest

import headless_re_mcp.telemetry as telemetry
from headless_re_mcp.telemetry import (
    ToolCallRecord,
    _envelope_error_code,
    _envelope_ok,
    _session_parameter_index,
)


def test_configure_telemetry_logging_attaches_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attaches: list[Path] = []

    def fake_attach(logger_name: str, path: Path, *, formatter: object) -> Path:
        attaches.append(path)
        return path

    monkeypatch.delenv("HEADLESS_RE_TELEMETRY_LOG", raising=False)
    monkeypatch.setattr(telemetry, "_LOG_PATH", None)
    monkeypatch.setattr(telemetry, "resolve_log_dir", lambda log_dir=None: tmp_path)
    monkeypatch.setattr(telemetry, "attach_rotating_handler", fake_attach)

    expected = (tmp_path / "telemetry.jsonl").resolve()
    first = telemetry.configure_telemetry_logging()
    second = telemetry.configure_telemetry_logging()  # already configured -> returns cached path

    assert first == expected
    assert second == expected
    assert attaches == [expected], "the handler must be attached exactly once"


def test_configure_telemetry_logging_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEADLESS_RE_TELEMETRY_LOG", "off")
    monkeypatch.setattr(telemetry, "_LOG_PATH", None)
    assert telemetry.configure_telemetry_logging() is None


def test_totals_returns_an_independent_snapshot() -> None:
    ring = telemetry.TelemetryRing()
    ring.add(ToolCallRecord(tool="t", ok=True, duration_ms=1.0, at="now"))
    ring.add(ToolCallRecord(tool="t", ok=False, duration_ms=2.0, at="now"))

    snapshot = ring.totals()
    assert snapshot["t"].calls == 2
    assert snapshot["t"].failures == 1

    # Mutating the snapshot must not reach back into the ring's live counters.
    snapshot["t"].calls = 999
    assert ring.totals()["t"].calls == 2


def test_envelope_ok_defaults_true_without_an_ok_field() -> None:
    assert _envelope_ok("not a dict") is True
    assert _envelope_ok({"value": 1}) is True
    assert _envelope_ok({"ok": False}) is False


def test_envelope_error_code_reads_string_codes_only() -> None:
    assert _envelope_error_code("not a dict") is None
    assert _envelope_error_code({"error": "boom"}) is None  # error is not an object
    assert _envelope_error_code({"error": {"code": 123}}) is None  # code is not a string
    assert _envelope_error_code({"error": {"code": "invalid_request"}}) == "invalid_request"


def test_session_parameter_index_finds_and_tolerates_missing() -> None:
    def with_session(session_id: str) -> dict[str, object]:
        return {}

    def without_session(value: int) -> dict[str, object]:
        return {}

    assert _session_parameter_index(with_session) == 0
    assert _session_parameter_index(without_session) is None


def test_session_parameter_index_tolerates_unintrospectable_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(_: object) -> object:
        raise ValueError("no signature found")

    monkeypatch.setattr(inspect, "signature", refuse)

    def handler(session_id: str) -> dict[str, object]:
        return {}

    assert _session_parameter_index(handler) is None


def test_telemetry_log_path_reports_the_active_sink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sentinel = tmp_path / "telemetry.jsonl"
    monkeypatch.setattr(telemetry, "_LOG_PATH", sentinel)
    assert telemetry.telemetry_log_path() == sentinel


def test_record_alert_emits_a_structured_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="headless_re_mcp.telemetry"):
        telemetry.record_alert("thing_failing", fields={"error": "boom"})

    payload = json.loads(caplog.records[-1].message)
    assert payload["event"] == "alert"
    assert payload["kind"] == "thing_failing"
    assert payload["severity"] == "warning"
    assert payload["error"] == "boom"


def test_instrument_reads_session_id_from_a_positional_argument() -> None:
    ring = telemetry.TelemetryRing()

    def handler(session_id: str) -> dict[str, object]:
        return {"ok": True}

    telemetry.instrument(handler, name="demo.pos", ring=ring)("sess-42")

    assert ring.recent(1)[0]["session_id"] == "sess-42"
