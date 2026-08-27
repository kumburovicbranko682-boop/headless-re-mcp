"""Coverage for the supervisor readiness probe and report serialization."""

from __future__ import annotations

from headless_re_mcp.supervisor import SupervisorReport, probe_ready


def test_probe_ready_rejects_a_non_http_scheme() -> None:
    ok, detail = probe_ready("ftp://example/health", timeout=0.1)
    assert ok is False
    assert detail == "unreachable: ValueError"


def test_probe_ready_reports_unreachable_for_a_refused_port() -> None:
    # Nothing listens on port 1; the probe must build the query path and report
    # unreachable rather than hang or raise.
    ok, detail = probe_ready("http://127.0.0.1:1/readyz?verbose=1", timeout=0.3)
    assert ok is False
    assert detail.startswith("unreachable:")


def test_supervisor_report_serializes_to_json() -> None:
    report = SupervisorReport(
        starts=2,
        crash_restarts=1,
        unhealthy_restarts=0,
        stopped_reason="deadline",
        last_exit_code=0,
    )
    payload = report.as_json()
    assert payload == {
        "starts": 2,
        "crash_restarts": 1,
        "unhealthy_restarts": 0,
        "stopped_reason": "deadline",
        "last_exit_code": 0,
    }
