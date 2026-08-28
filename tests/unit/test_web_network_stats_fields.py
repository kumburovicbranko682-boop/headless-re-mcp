"""web.network.stats folds captured requests into an aggregate triage summary.

summarize_requests is pure over the rows the CDP wiring records, so these pin
the roll-up (method mix, status classes with a pending bucket, resource-type
tally, host parsing, bare-mime normalisation, top-N caps) without a live
browser, plus a backend round-trip via the same _get seam other web field
tests use.
"""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_TOP_STATS,
    WebBackend,
    summarize_requests,
)
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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
        {"url": "https://api.example/a", "method": "GET", "resourceType": "XHR",
         "status": 200, "mimeType": "application/json"},
        {"url": "https://api.example/b", "method": "get", "resourceType": "Fetch",
         "status": 204, "mimeType": "application/json; charset=utf-8"},
        {"url": "https://cdn.example/x.js", "method": "GET", "resourceType": "Script",
         "status": 200, "mimeType": "text/javascript"},
        {"url": "https://cdn.example/y.png", "method": "GET", "resourceType": "Image",
         "status": 404, "mimeType": "text/html"},
        {"url": "https://api.example/c", "method": "POST", "resourceType": "Fetch",
         "status": None, "mimeType": None},
        {"url": "https://api.example/d", "method": "GET", "resourceType": "Document",
         "status": 500, "mimeType": "text/html"},
    ]


class _FakeHandle:
    def __init__(self, rows: list[dict[str, Any]], *, dropped: int) -> None:
        self.lock = Lock()
        self.requests = {str(i): row for i, row in enumerate(rows)}
        self.requests_dropped = dropped


def test_stats_tallies_methods_status_and_resource_types() -> None:
    stats = summarize_requests(_rows(), dropped=2, top=10)

    assert stats["total"] == 6
    assert stats["dropped"] == 2
    assert stats["pending"] == 1
    # "get" folds into "GET" (5 GETs total).
    assert stats["methods"] == {"GET": 5, "POST": 1}
    assert stats["status_classes"] == {"2xx": 3, "4xx": 1, "5xx": 1, "pending": 1}
    assert stats["resource_types"]["fetch"] == 2
    assert stats["resource_types"]["xhr"] == 1


def test_stats_parses_hosts_and_normalises_mime() -> None:
    stats = summarize_requests(_rows(), top=10)

    assert stats["top_hosts"][0] == {"host": "api.example", "count": 4}
    assert stats["host_count"] == 2

    by_mime = {row["mime_type"]: row["count"] for row in stats["top_mime_types"]}
    # The "; charset=utf-8" tail is dropped, so both json rows fold together.
    assert by_mime["application/json"] == 2
    assert by_mime["text/html"] == 2
    assert stats["mime_type_count"] == 3  # json, javascript, html


def test_stats_top_caps_the_ranked_lists() -> None:
    rows = [
        {"url": f"https://h{i}.example/", "method": "GET", "resourceType": "Script",
         "status": 200, "mimeType": "text/javascript"}
        for i in range(20)
    ]
    stats = summarize_requests(rows, top=5)
    assert len(stats["top_hosts"]) == 5
    assert stats["host_count"] == 20
    wide = summarize_requests(rows, top=_MAX_TOP_STATS + 100)
    assert len(wide["top_hosts"]) == 20  # only 20 distinct hosts exist


def test_stats_handles_an_empty_capture() -> None:
    stats = summarize_requests([], dropped=0)
    assert stats["total"] == 0
    assert stats["pending"] == 0
    assert stats["methods"] == {}
    assert stats["status_classes"] == {}
    assert stats["top_hosts"] == []


def test_stats_skips_unparseable_hosts() -> None:
    rows = [
        {"url": "about:blank", "method": "GET", "resourceType": "Document",
         "status": 200, "mimeType": "text/html"},
        {"url": "data:text/html,hi", "method": "GET", "resourceType": "Document",
         "status": 200, "mimeType": "text/html"},
    ]
    stats = summarize_requests(rows)
    assert stats["host_count"] == 0
    assert stats["top_hosts"] == []


def test_backend_network_stats_reads_the_handle(monkeypatch: Any) -> None:
    backend = WebBackend()
    handle = _FakeHandle(_rows(), dropped=3)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    payload = backend.network_stats("s", top=10)
    assert payload["total"] == 6
    assert payload["dropped"] == 3
    assert payload["top_hosts"][0]["host"] == "api.example"


def test_web_network_stats_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.network.stats")
    assert "status_classes" in doc
    assert "resource_types" in doc
    assert "top_hosts" in doc
    assert "pending" in doc
