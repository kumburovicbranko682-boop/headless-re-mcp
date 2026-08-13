"""Cover the pieces an operator needs to run this as a long-lived service."""

from __future__ import annotations

import json
import logging
import threading
import time
import tomllib
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import headless_re_mcp.telemetry as telemetry_module
from headless_re_mcp.config import Settings
from headless_re_mcp.core.readiness import build_info, probe_artifact_root, readiness_report
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.logging_setup import UtcFormatter, resolve_log_dir
from headless_re_mcp.metrics_exposition import render
from headless_re_mcp.telemetry import (
    TelemetryRing,
    configure_telemetry_logging,
    instrument,
    record_tool_call,
)
from headless_re_mcp.web.app import create_app

TOKEN = "test-token-value-0123456789abcdef"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )


class _BrokenRepository:
    def list_unclean_sessions(self) -> list[dict[str, Any]]:
        raise OSError("database is locked")


class _WorkingRepository:
    def list_unclean_sessions(self) -> list[dict[str, Any]]:
        return []


@pytest.fixture
def telemetry_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    logger = logging.getLogger(telemetry_module.LOGGER_NAME)
    for handler in list(logger.handlers):
        handler.close()
    logger.handlers.clear()
    logger.propagate = True
    monkeypatch.setattr(telemetry_module, "_LOG_PATH", None)
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("HEADLESS_RE_TELEMETRY_LOG", raising=False)
    yield tmp_path / "telemetry.jsonl"
    for handler in list(logger.handlers):
        handler.close()
    logger.handlers.clear()
    logger.propagate = True


def test_telemetry_records_reach_a_file(telemetry_log: Path) -> None:
    """Without a handler these records were formatted and then discarded."""
    path = configure_telemetry_logging()

    assert path == telemetry_log
    record_tool_call("demo.persisted", ok=True, duration_ms=2.5, session_id="sess-1")

    lines = [line for line in telemetry_log.read_text(encoding="utf-8").splitlines() if line]
    payload = json.loads(lines[-1])
    assert payload["event"] == "tool_call"
    assert payload["tool"] == "demo.persisted"
    assert payload["session_id"] == "sess-1"


def test_telemetry_sink_can_be_disabled(
    telemetry_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HEADLESS_RE_TELEMETRY_LOG", "off")

    assert configure_telemetry_logging() is None
    record_tool_call("demo.quiet", ok=True, duration_ms=1.0)
    assert not telemetry_log.exists()


def test_telemetry_logger_does_not_propagate_to_root(telemetry_log: Path) -> None:
    """On stdio a root handler on stdout would corrupt the JSON-RPC stream."""
    configure_telemetry_logging()

    assert logging.getLogger(telemetry_module.LOGGER_NAME).propagate is False


def test_session_id_is_captured_from_either_call_style() -> None:
    ring = TelemetryRing()

    def handler(session_id: str, value: int = 0) -> dict[str, Any]:
        return {"ok": True, "value": value}

    instrument(handler, name="demo.kw", ring=ring)(session_id="from-kwarg")
    instrument(handler, name="demo.pos", ring=ring)("from-positional")

    by_tool = {item["tool"]: item["session_id"] for item in ring.recent(5)}
    assert by_tool["demo.kw"] == "from-kwarg"
    assert by_tool["demo.pos"] == "from-positional"


def test_totals_survive_the_window_rolling() -> None:
    """A counter that falls when the ring evicts makes every rate wrong."""
    ring = TelemetryRing(capacity=2)

    for index in range(5):
        record_tool_call("demo.busy", ok=index % 2 == 0, duration_ms=1.0, ring=ring)

    metrics = ring.metrics()
    assert metrics["sampled_calls"] == 2
    assert metrics["calls_total"] == 5
    assert metrics["failures_total"] == 2
    tool = next(item for item in metrics["tools"] if item["tool"] == "demo.busy")
    assert tool["calls_total"] == 5


def test_utc_formatter_does_not_lie_about_the_zone() -> None:
    formatter = UtcFormatter("%(asctime)sZ")
    record = logging.LogRecord("n", logging.INFO, "p", 1, "m", None, None)
    record.created = 0.0

    assert formatter.format(record).startswith("1970-01-01 00:00:00")


def test_resolve_log_dir_prefers_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path / "logs"))

    resolved = resolve_log_dir()

    assert resolved == tmp_path / "logs"
    assert resolved.is_dir()


def test_readiness_fails_when_the_store_is_unreachable(tmp_path: Path) -> None:
    report = readiness_report(
        repository=_BrokenRepository(),
        artifact_root=tmp_path,
        open_sessions=0,
        backends=[],
        telemetry_log=None,
    )

    assert report["ready"] is False
    store = next(item for item in report["checks"] if item["name"] == "store")
    assert "database is locked" in store["detail"]


def test_readiness_survives_one_unhealthy_backend(tmp_path: Path) -> None:
    """One broken session must not drain the whole instance."""
    report = readiness_report(
        repository=_WorkingRepository(),
        artifact_root=tmp_path,
        open_sessions=2,
        backends=[{"healthy": False}, {"healthy": True}],
        telemetry_log=None,
    )

    assert report["ready"] is True
    assert report["backends"] == {"total": 2, "unhealthy": 1}
    assert report["sessions"]["open"] == 2


def test_artifact_root_probe_reports_a_file_in_the_way(tmp_path: Path) -> None:
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("", encoding="utf-8")

    check = probe_artifact_root(blocked)

    assert check.ok is False


def test_artifact_probe_leaves_nothing_behind(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"

    assert probe_artifact_root(root).ok is True
    assert list(root.iterdir()) == []


def test_two_readiness_probes_at_once_do_not_fail_each_other(tmp_path: Path) -> None:
    """Sharing one probe file makes concurrent checks report a false failure.

    Readiness routes are synchronous, so the server runs them on a thread pool
    and a supervisor probing beside any other monitor gets two at once. One
    unlinking while the other still holds the file is an OSError, which reads as
    unready -- and three of those restart a process that was serving fine.
    """
    root = tmp_path / "artifacts"
    root.mkdir()
    failures: list[str] = []
    start = threading.Barrier(6)

    def hammer() -> None:
        start.wait()
        for _ in range(60):
            check = probe_artifact_root(root)
            if not check.ok:
                failures.append(check.detail)

    threads = [threading.Thread(target=hammer, name=f"probe-{i}") for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not failures, f"{len(failures)} probes failed, first: {failures[0]}"
    assert list(root.iterdir()) == [], "a probe must still clean up after itself"


def test_exposition_is_scrapeable_and_escapes_labels() -> None:
    metrics = {
        "tools": [
            {
                "tool": 'weird"name',
                "calls_total": 7,
                "failures_total": 2,
                "p50_ms": 1.5,
                "p95_ms": 9.0,
                "max_ms": 12.0,
            }
        ]
    }

    text = render(metrics, {"version": "1.2.3", "commit": "abc", "python": "3.12.0"}, None)

    assert "# TYPE headless_re_tool_calls_total counter" in text
    assert 'headless_re_tool_calls_total{tool="weird\\"name"} 7.0' in text
    assert 'headless_re_build_info{version="1.2.3",commit="abc",python="3.12.0"} 1.0' in text
    assert text.endswith("\n")


def test_exposition_includes_readiness_when_supplied() -> None:
    text = render(
        {"tools": []},
        build_info(),
        {"ready": False, "sessions": {"open": 3}, "backends": {"total": 1, "unhealthy": 1}},
    )

    assert "headless_re_ready 0.0" in text
    assert "headless_re_sessions_open 3.0" in text
    assert "headless_re_backends_unhealthy 1.0" in text


def test_healthz_names_the_running_build(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    try:
        client = TestClient(create_app(service, token=TOKEN, settings=settings))
        body = client.get("/healthz").json()
    finally:
        service.close_all()

    assert body["ok"] is True
    assert body["build"]["version"]
    assert "commit" in body["build"]


def test_readyz_reports_ready_without_a_token(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    try:
        client = TestClient(create_app(service, token=TOKEN, settings=settings))
        response = client.get("/readyz")
    finally:
        service.close_all()

    assert response.status_code == 200
    assert response.json()["data"]["ready"] is True


def test_readyz_returns_503_when_a_dependency_is_broken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A probe that stays green through a broken store keeps a dead instance in rotation."""
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    monkeypatch.setattr(service, "repository", _BrokenRepository())
    try:
        client = TestClient(create_app(service, token=TOKEN, settings=settings))
        response = client.get("/readyz")
    finally:
        service.close_all()

    assert response.status_code == 503
    assert response.json()["data"]["ready"] is False


def test_metrics_endpoint_serves_prometheus_text(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    try:
        client = TestClient(create_app(service, token=TOKEN, settings=settings))
        response = client.get("/metrics")
    finally:
        service.close_all()

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "headless_re_build_info" in response.text


def test_version_has_one_source_of_truth() -> None:
    """The literal in __init__ and the one in pyproject drifted apart once."""
    from headless_re_mcp import __version__

    root = Path(__file__).resolve().parents[2]
    declared = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))

    assert __version__ == declared["project"]["version"]


def test_instrumented_call_latency_is_measured_not_invented() -> None:
    ring = TelemetryRing()

    def slow() -> dict[str, Any]:
        time.sleep(0.01)
        return {"ok": True}

    instrument(slow, name="demo.slow", ring=ring)()

    assert ring.recent(1)[0]["duration_ms"] >= 10.0
