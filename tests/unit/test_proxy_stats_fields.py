"""proxy.stats folds the captured flows into an aggregate triage summary.

summarize_flows is pure over the summary rows the recorder produces, so these
pin the roll-up (method mix, status classes, ranked hosts/content-types, error
and body-omitted counts, byte total) without standing up a real proxy, plus a
recorder round-trip so the row shape the tool reads stays in agreement.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_TOP_STATS,
    _FlowRecorder,
    summarize_flows,
)
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


def _rows() -> list[dict[str, Any]]:
    return [
        {"method": "GET", "host": "api.example", "status": 200,
         "content_type": "application/json; charset=utf-8", "response_size": 100},
        {"method": "get", "host": "api.example", "status": 200,
         "content_type": "application/json", "response_size": 50},
        {"method": "POST", "host": "api.example", "status": 500,
         "content_type": "text/html", "response_size": 20},
        {"method": "GET", "host": "cdn.example", "status": 304,
         "content_type": "", "response_size": 0},
        {"method": "GET", "host": "evil.example", "status": None,
         "content_type": "", "response_size": 0, "error": True,
         "error_msg": "net::ERR_CONNECTION_REFUSED"},
        {"method": "PUT", "host": "api.example", "status": 404,
         "content_type": "application/json", "response_size": 10,
         "body_omitted": True},
    ]


def test_stats_tallies_methods_status_and_bytes() -> None:
    stats = summarize_flows(_rows(), dropped=3, top=10)

    assert stats["total"] == 6
    assert stats["dropped"] == 3
    # method is upper-cased, so "get" and "GET" fold together (4 GETs total).
    assert stats["methods"] == {"GET": 4, "POST": 1, "PUT": 1}
    assert stats["status_classes"] == {"2xx": 2, "3xx": 1, "4xx": 1, "5xx": 1, "none": 1}
    assert stats["errors"] == 1
    assert stats["body_omitted"] == 1
    assert stats["total_response_bytes"] == 180


def test_stats_ranks_hosts_and_normalises_content_types() -> None:
    stats = summarize_flows(_rows(), top=10)

    # api.example has 4 hits, the busiest host, and ranks first.
    assert stats["top_hosts"][0] == {"host": "api.example", "count": 4}
    assert stats["host_count"] == 3

    # The "; charset=utf-8" tail is dropped, so both json rows fold into one type.
    by_type = {row["content_type"]: row["count"] for row in stats["top_content_types"]}
    assert by_type["application/json"] == 3
    assert by_type["text/html"] == 1
    # Empty content types are not counted.
    assert "" not in by_type
    assert stats["content_type_count"] == 2


def test_stats_top_caps_the_ranked_lists() -> None:
    rows = [
        {"method": "GET", "host": f"h{i}.example", "status": 200,
         "content_type": "text/plain", "response_size": 1}
        for i in range(20)
    ]
    stats = summarize_flows(rows, top=5)
    assert len(stats["top_hosts"]) == 5
    assert stats["host_count"] == 20
    # Even a caller asking for more than the ceiling is clamped.
    wide = summarize_flows(rows, top=_MAX_TOP_STATS + 100)
    assert len(wide["top_hosts"]) == 20  # only 20 distinct hosts exist


def test_stats_handles_an_empty_capture() -> None:
    stats = summarize_flows([], dropped=0)
    assert stats["total"] == 0
    assert stats["methods"] == {}
    assert stats["status_classes"] == {}
    assert stats["top_hosts"] == []
    assert stats["total_response_bytes"] == 0


def test_stats_matches_recorder_row_shape() -> None:
    """Feeding the recorder's own snapshot must produce a coherent summary."""
    recorder = _FlowRecorder(capacity=8)
    recorder.response(
        SimpleNamespace(
            id="a",
            request=SimpleNamespace(method="GET", pretty_url="http://h/a", host="h"),
            response=SimpleNamespace(status_code=200, headers={"content-type": "text/html"}),
        )
    )
    recorder.error(
        SimpleNamespace(
            id="b",
            request=SimpleNamespace(method="GET", pretty_url="http://h/b", host="h"),
            response=None,
            error=SimpleNamespace(msg="boom"),
        )
    )
    stats = summarize_flows(recorder.snapshot())
    assert stats["total"] == 2
    assert stats["status_classes"] == {"2xx": 1, "none": 1}
    assert stats["errors"] == 1
    assert stats["top_hosts"] == [{"host": "h", "count": 2}]


def test_proxy_stats_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.stats")
    assert "status_classes" in doc
    assert "top_hosts" in doc
    assert "dropped" in doc
    assert "total_response_bytes" in doc
