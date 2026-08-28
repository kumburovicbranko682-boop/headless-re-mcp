"""proxy.timings folds captured per-flow timestamps into a latency view.

The core is fold_timings, pure over the summary rows joined to the recorder's
timestamp map, so these drive it with fake rows plus one end-to-end capture
through _FlowRecorder to prove the timestamps are recorded.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import _FlowRecorder, fold_timings
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _row(fid: str, *, status: int | None = 200) -> dict[str, Any]:
    return {
        "id": fid,
        "method": "GET",
        "url": f"https://h/{fid}",
        "host": "h",
        "status": status,
    }


def test_fold_timings_computes_phases_and_sorts_slowest_first() -> None:
    rows = [_row("1"), _row("2")]
    timings = {
        "1": {"req_start": 0.0, "req_end": 0.1, "resp_start": 0.2, "resp_end": 1.2},
        "2": {"req_start": 0.0, "req_end": 0.05, "resp_start": 0.06, "resp_end": 0.16},
    }
    result = fold_timings(rows, timings)
    assert result["count"] == 2
    assert result["total"] == 2
    first = result["flows"][0]
    assert first["id"] == "1"
    assert first["total_ms"] == 1200
    assert first["waiting_ms"] == 100
    assert first["request_ms"] == 100
    assert first["response_ms"] == 1000
    agg = result["aggregate"]
    assert agg["timed"] == 2
    assert agg["slowest_ms"] == 1200
    assert agg["fastest_ms"] == 160
    assert agg["average_ms"] == 680


def test_fold_timings_marks_flows_without_timing_null() -> None:
    result = fold_timings([_row("3", status=None)], {})
    row = result["flows"][0]
    assert row["total_ms"] is None
    assert row["waiting_ms"] is None
    assert result["aggregate"]["timed"] == 0
    assert result["aggregate"]["slowest_ms"] is None
    assert result["aggregate"]["average_ms"] is None


def test_fold_timings_guards_inconsistent_timestamps() -> None:
    # Response timestamps precede the request start: total/waiting are impossible,
    # so they come back null while the intra-message phases still compute.
    timings = {"1": {"req_start": 5.0, "req_end": 5.1, "resp_start": 4.0, "resp_end": 4.5}}
    result = fold_timings([_row("1")], timings)
    row = result["flows"][0]
    assert row["total_ms"] is None
    assert row["waiting_ms"] is None
    assert row["request_ms"] == 100
    assert row["response_ms"] == 500
    assert result["aggregate"]["timed"] == 0


def test_fold_timings_pages_rows() -> None:
    rows = [_row(str(i)) for i in range(5)]
    timings = {
        str(i): {"req_start": 0.0, "req_end": 0.0, "resp_start": 0.0, "resp_end": i / 10}
        for i in range(5)
    }
    result = fold_timings(rows, timings, limit=2)
    assert result["count"] == 2
    assert result["total"] == 5
    assert result["has_more"] is True
    # Slowest first: flow "4" (400ms) leads.
    assert result["flows"][0]["id"] == "4"


def test_recorder_captures_flow_timestamps() -> None:
    recorder = _FlowRecorder()
    recorder.response(
        SimpleNamespace(
            id="f1",
            request=SimpleNamespace(
                method="GET",
                pretty_url="http://h/a",
                host="h",
                timestamp_start=1000.0,
                timestamp_end=1000.1,
            ),
            response=SimpleNamespace(
                status_code=200,
                headers={"content-type": "text/html"},
                timestamp_start=1000.3,
                timestamp_end=1000.5,
            ),
        )
    )
    result = fold_timings(recorder.snapshot(), recorder.timings_snapshot())
    assert result["aggregate"]["timed"] == 1
    row = result["flows"][0]
    assert row["total_ms"] == 500
    assert row["request_ms"] == 100
    assert row["response_ms"] == 200


def test_recorder_omits_timing_without_timestamps() -> None:
    # A fake flow with no timestamp attributes (as the other recorder tests use)
    # records no timing entry, and clear() drops any that were captured.
    recorder = _FlowRecorder()
    recorder.response(
        SimpleNamespace(
            id="f2",
            request=SimpleNamespace(method="GET", pretty_url="http://h/b", host="h"),
            response=SimpleNamespace(status_code=200, headers={}),
        )
    )
    assert recorder.timings_snapshot() == {}
    recorder.clear()
    assert recorder.timings_snapshot() == {}


def test_proxy_timings_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.timings")
    assert "total_ms" in doc
    assert "waiting_ms" in doc
    assert "aggregate" in doc
    assert "slowest" in doc
