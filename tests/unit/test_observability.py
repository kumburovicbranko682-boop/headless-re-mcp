"""Cover the pieces an operator needs to run this as a long-lived service."""

from __future__ import annotations

import io
import json
import logging
import sqlite3
import tempfile
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
    def list_unclean_sessions(self, **_: object) -> tuple[list[dict[str, Any]], int]:
        raise OSError("database is locked")


class _WorkingRepository:
    def list_unclean_sessions(self, **_: object) -> tuple[list[dict[str, Any]], int]:
        return [], 0


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


def test_resolve_log_dir_survives_an_unresolvable_tilde(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad HEADLESS_RE_LOG_DIR must degrade to the temp dir, not stop startup.

    ``Path.expanduser`` raises RuntimeError -- not OSError -- when the user in
    ``~user/...`` does not exist, so this used to escape the fallback and kill
    the process inside install_global_exception_hooks.
    """
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", "~nosuchuser-headless-re/logs")

    resolved = resolve_log_dir()

    assert resolved == Path(tempfile.gettempdir()) / "headless-re-mcp" / "logs"
    assert resolved.is_dir()


def test_resolve_log_dir_survives_an_embedded_nul(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """mkdir raises ValueError for a NUL in the path; OSError alone missed it."""
    monkeypatch.delenv("HEADLESS_RE_LOG_DIR", raising=False)

    resolved = resolve_log_dir(Path("/tmp/bad\x00dir"))

    assert resolved == Path(tempfile.gettempdir()) / "headless-re-mcp" / "logs"
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


def test_disk_usage_is_not_reported_before_it_has_been_measured() -> None:
    """A zero here reads as the disk having been emptied.

    The artifact walk runs in the background so a readiness probe never waits
    on it, and until the first one finishes the answer is zero bytes marked
    truncated -- a floor, not a measurement. The supervisor restarts the
    console often enough that a scrape lands in that window. No sample is the
    honest answer: a gap in the series says nothing, a zero says something
    false.
    """
    def document(disk: dict[str, object]) -> str:
        return render({}, build_info(), readiness={"ready": True, "disk": disk})

    not_yet = document({"bytes": 0, "truncated": True, "budget_bytes": 100})
    assert "headless_re_artifact_bytes " not in not_yet
    assert "headless_re_artifact_budget_bytes " in not_yet, "the budget is configuration"

    measured = document({"bytes": 4096, "truncated": False, "budget_bytes": 100})
    assert "headless_re_artifact_bytes 4096" in measured

    partial = document({"bytes": 4096, "truncated": True, "budget_bytes": 100})
    assert "headless_re_artifact_bytes 4096" in partial, "a capped walk is still a real floor"


def test_a_collector_that_has_stopped_working_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken collector stops enforcing the byte budget, silently.

    Not raising is right, since retention runs from ordinary paths such as
    closing a session and must not fail them. But it was also not reported, so
    the only symptom was disk use climbing past the budget with nothing to
    explain it. Once, because collection runs on every registration.
    """
    from headless_re_mcp.core import retention as retention_module

    alerts: list[str] = []
    monkeypatch.setattr(
        retention_module, "record_alert", lambda kind, **kwargs: alerts.append(kind)
    )

    class Broken:
        def __init__(self) -> None:
            self.works = False

        def gc_artifacts(self, *, max_total_bytes: int) -> dict[str, object]:
            if not self.works:
                raise sqlite3.OperationalError("database disk image is malformed")
            return {"removed": []}

    collector = Broken()
    policy = retention_module.ArtifactRetention(max_total_bytes=1024, min_interval_s=0.0)

    assert policy.maybe_collect(collector) is None
    assert policy.maybe_collect(collector) is None
    assert alerts == ["artifact_collection_failing"], f"once, not per call: {alerts}"

    collector.works = True
    assert policy.maybe_collect(collector) is not None
    assert alerts[-1] == "artifact_collection_recovered", "and says when it is working again"


def test_routine_stdio_logs_do_not_go_on_the_pipe_a_client_may_not_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stderr on stdio is a pipe the client owns, and may never drain.

    The SDK logs every request at INFO. A client that does not read that fills
    the buffer, and the server then blocks inside write() and answers nothing
    further -- silently, and permanently. Measured against a client that never
    read it: the server stopped answering at the 25th tool call, and survived
    900 once the routine records went to a file instead.

    Warnings still reach stderr. They are where a client surfaces a real
    problem, and they are rare enough not to accumulate.
    """
    from headless_re_mcp.cli import _keep_routine_logs_off_the_pipe

    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path))
    # Configured against a private logger rather than the root one: attaching
    # closes the handlers already there, and closing pytest's own capture
    # handler breaks whatever test runs next.
    name = "probe.stdio.logging"
    private = logging.getLogger(name)
    try:
        _keep_routine_logs_off_the_pipe(name)
        stderr_handlers = [
            handler
            for handler in private.handlers
            if isinstance(handler, logging.StreamHandler)
            and not isinstance(handler, logging.FileHandler)
        ]
        assert len(stderr_handlers) == 1, "exactly one stream handler, and it is the loud one"
        assert stderr_handlers[0].level == logging.WARNING

        captured = io.StringIO()
        stderr_handlers[0].setStream(captured)
        logging.getLogger(f"{name}.server").info("processing request of type CallToolRequest")
        logging.getLogger(f"{name}.server").warning("a real problem")

        assert "CallToolRequest" not in captured.getvalue(), "routine chatter must stay off stderr"
        assert "a real problem" in captured.getvalue(), "a warning must still reach the client"

        written = (tmp_path / "mcp-stdio.log").read_text(encoding="utf-8", errors="replace")
        assert "CallToolRequest" in written, "and must still be recorded somewhere"
    finally:
        for handler in list(private.handlers):
            private.removeHandler(handler)
            handler.close()


def test_the_readiness_probe_never_waits_for_the_disk_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The walk is capped by file count, not by time, so it cannot be inline.

    Measured here: 938 files took 154ms and 50,000 -- the cap -- took 5.9s. The
    supervisor allows a probe five seconds before counting a strike, and disk
    use is reported rather than gated, so an informational field was deciding
    whether the process looked alive. Worse, a walk slower than the TTL leaves
    every probe refreshing, which is three late answers in a row and a restart.
    """
    from headless_re_mcp.core import retention as module

    walks: list[float] = []

    def slow_walk(root: Path, *, file_limit: int = 0) -> module.DiskUsage:
        walks.append(time.perf_counter())
        time.sleep(0.6)
        return module.DiskUsage(bytes=4096, files=7, truncated=False)

    monkeypatch.setattr(module, "measure_usage", slow_walk)
    cache = module.UsageCache(ttl_s=0.05)

    started = time.perf_counter()
    first = cache.get(tmp_path)
    elapsed = time.perf_counter() - started

    assert elapsed < 0.2, f"the probe waited {elapsed:.2f}s on a walk it must not run"
    assert first.files == 0 and first.truncated is True, "an unmeasured floor, said as one"

    for _ in range(100):
        if cache.get(tmp_path).files == 7:
            break
        time.sleep(0.02)
    measured = cache.get(tmp_path)
    assert measured.files == 7, "the background walk must land"
    assert measured.bytes == 4096

    time.sleep(0.1)  # let it go stale
    started = time.perf_counter()
    stale = cache.get(tmp_path)
    assert time.perf_counter() - started < 0.2, "a stale value is still served immediately"
    assert stale.files == 7, "the previous answer stands until a new one arrives"

    assert len(walks) <= 3, f"one refresh at a time, saw {len(walks)}"


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

    # Daemon threads plus an aliveness check: a probe wedged in a file lock
    # would otherwise outlive its timed join silently and then hang interpreter
    # shutdown after the whole suite has passed -- the one phase no per-test
    # watchdog covers.
    threads = [threading.Thread(target=hammer, name=f"probe-{i}", daemon=True) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads), "a probe thread wedged"
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


def test_a_newline_in_a_label_cannot_forge_an_exposition_line() -> None:
    """A raw newline or backslash in a label value would break the scrape.

    Prometheus requires backslash, double-quote and newline escaped inside a
    label value. An unescaped newline does not merely mangle one value -- it
    ends the metric line early and the remainder parses as a new sample, so a
    tool name is a place an adversary-controlled string could forge a series.
    Pin all three escapes.
    """
    metrics = {
        "tools": [
            {
                "tool": 'a\nb\\c"d',
                "calls_total": 1,
                "failures_total": 0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "max_ms": 0.0,
            }
        ]
    }

    text = render(metrics, {"version": "v", "commit": "c", "python": "p"}, None)

    assert 'tool="a\\nb\\\\c\\"d"' in text
    # No physical newline survived inside the value: every non-header line that
    # mentions the tool is one complete sample, not a fragment split by \n.
    for line in text.splitlines():
        if line.startswith("#") or not line:
            continue
        assert line.count("{") <= 1, f"a label value leaked a line break: {line!r}"


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
    assert body["started_at"]


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
