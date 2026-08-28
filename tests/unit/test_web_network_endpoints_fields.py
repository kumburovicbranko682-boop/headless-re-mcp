"""web.network.endpoints must collapse the capture into a route-grouped surface.

Aggregates request rows only (no bodies), so a fake handle drives every case:
id-normalisation of path segments, method/status/content-type/resource-type
roll-up per route, ranking, paging, filters, the has_query flag and the
service-layer wiring. It is the browser-side analogue of proxy.endpoints.
"""

from __future__ import annotations

import ast
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
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


def _row(
    request_id: str,
    *,
    url: str,
    method: str = "GET",
    status: int | None = 200,
    mime: str | None = "application/json",
    rtype: str | None = "XHR",
) -> dict[str, Any]:
    return {
        "requestId": request_id,
        "url": url,
        "method": method,
        "status": status,
        "mimeType": mime,
        "resourceType": rtype,
        "_har": {"secret": "kept-out"},
    }


class _FakeHandle:
    def __init__(self, rows: list[dict[str, Any]], *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict(
            (row["requestId"], row) for row in rows
        )
        self.requests_dropped = dropped


def _backend(monkeypatch: Any, rows: list[dict[str, Any]], *, dropped: int = 0) -> WebBackend:
    backend = WebBackend()
    handle = _FakeHandle(rows, dropped=dropped)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    return backend


def test_numeric_ids_fold_into_one_route(monkeypatch: Any) -> None:
    """/users/1 and /users/2 collapse to /users/{id} with a summed count."""
    rows = [
        _row("a", url="http://api.example.com/users/1"),
        _row("b", url="http://api.example.com/users/2"),
        _row("c", url="http://api.example.com/users/profile"),
    ]
    backend = _backend(monkeypatch, rows)
    out = backend.network_endpoints("s")
    by_path = {e["path"]: e for e in out["endpoints"]}
    assert by_path["/users/{id}"]["count"] == 2
    assert by_path["/users/{id}"]["methods"] == ["GET"]
    assert "/users/profile" in by_path
    assert out["captured"] == 3
    assert out["normalized"] is True


def test_normalize_false_keeps_raw_paths(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://api.example.com/users/1"),
        _row("b", url="http://api.example.com/users/2"),
    ]
    backend = _backend(monkeypatch, rows)
    out = backend.network_endpoints("s", normalize=False)
    paths = {e["path"] for e in out["endpoints"]}
    assert paths == {"/users/1", "/users/2"}
    assert out["normalized"] is False


def test_rollups_capture_method_status_ctype_rtype(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/x", method="GET", status=200, mime="application/json", rtype="XHR"),
        _row("b", url="http://h/x", method="POST", status=500, mime="text/html", rtype="Fetch"),
    ]
    backend = _backend(monkeypatch, rows)
    (endpoint,) = backend.network_endpoints("s")["endpoints"]
    assert endpoint["methods"] == ["GET", "POST"]
    assert endpoint["status_classes"] == {"2xx": 1, "5xx": 1}
    assert endpoint["resource_types"] == ["Fetch", "XHR"]
    ctypes = {c["content_type"]: c["count"] for c in endpoint["content_types"]}
    assert ctypes == {"application/json": 1, "text/html": 1}


def test_pending_request_has_no_status_class(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/p", status=None, mime=None)]
    backend = _backend(monkeypatch, rows)
    (endpoint,) = backend.network_endpoints("s")["endpoints"]
    assert endpoint["status_classes"] == {"pending": 1}
    assert endpoint["content_types"] == []


def test_has_query_flag(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/search?q=1"),
        _row("b", url="http://h/plain"),
    ]
    backend = _backend(monkeypatch, rows)
    by_path = {e["path"]: e for e in backend.network_endpoints("s")["endpoints"]}
    assert by_path["/search"].get("has_query") is True
    assert "has_query" not in by_path["/plain"]


def test_grouping_splits_by_host(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://api.one.com/data"),
        _row("b", url="http://api.two.com/data"),
    ]
    backend = _backend(monkeypatch, rows)
    out = backend.network_endpoints("s")
    hosts = {e["host"] for e in out["endpoints"]}
    assert hosts == {"api.one.com", "api.two.com"}
    assert out["total"] == 2


def test_host_strips_credentials(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://user:pass@api.example.com/data")]
    backend = _backend(monkeypatch, rows)
    (endpoint,) = backend.network_endpoints("s")["endpoints"]
    assert endpoint["host"] == "api.example.com"


def test_ranking_is_count_then_host_then_path(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/rare"),
        _row("b", url="http://h/common"),
        _row("c", url="http://h/common"),
    ]
    backend = _backend(monkeypatch, rows)
    paths = [e["path"] for e in backend.network_endpoints("s")["endpoints"]]
    assert paths[0] == "/common"  # highest count first


def test_method_filter(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/x", method="GET"),
        _row("b", url="http://h/y", method="POST"),
    ]
    backend = _backend(monkeypatch, rows)
    out = backend.network_endpoints("s", method="post")
    assert out["total"] == 1
    assert out["endpoints"][0]["path"] == "/y"
    assert out["filter"] == {"method": "POST"}


def test_resource_type_filter(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/api", rtype="XHR"),
        _row("b", url="http://h/page", rtype="Document"),
    ]
    backend = _backend(monkeypatch, rows)
    out = backend.network_endpoints("s", resource_type="xhr")
    assert {e["path"] for e in out["endpoints"]} == {"/api"}
    assert out["filter"] == {"resource_type": "xhr"}


def test_content_type_and_status_filters(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/j", mime="application/json", status=200),
        _row("b", url="http://h/h", mime="text/html", status=404),
    ]
    backend = _backend(monkeypatch, rows)
    ctype = backend.network_endpoints("s", content_type="json")
    assert {e["path"] for e in ctype["endpoints"]} == {"/j"}
    code = backend.network_endpoints("s", status=404)
    assert {e["path"] for e in code["endpoints"]} == {"/h"}


def test_host_filter_substring(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://api.one.com/x"),
        _row("b", url="http://cdn.two.com/y"),
    ]
    backend = _backend(monkeypatch, rows)
    out = backend.network_endpoints("s", host="one.com")
    assert {e["host"] for e in out["endpoints"]} == {"api.one.com"}


def test_pagination_windows_routes(monkeypatch: Any) -> None:
    rows = [_row(f"r{i}", url=f"http://h/route{i}") for i in range(5)]
    backend = _backend(monkeypatch, rows)
    page = backend.network_endpoints("s", offset=1, limit=2)
    assert page["offset"] == 1
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True


def test_dropped_is_surfaced(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/x")]
    backend = _backend(monkeypatch, rows, dropped=7)
    out = backend.network_endpoints("s")
    assert out["dropped"] == 7


def test_empty_capture_is_clean_zero(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, [])
    out = backend.network_endpoints("s")
    assert out["endpoints"] == []
    assert out["total"] == 0
    assert out["captured"] == 0
    assert "filter" not in out


def test_content_types_are_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.web.client._MAX_ENDPOINT_CTYPES", 2
    )
    rows = [
        _row(f"r{i}", url="http://h/x", mime=f"type/{i}")
        for i in range(5)
    ]
    backend = _backend(monkeypatch, rows)
    (endpoint,) = backend.network_endpoints("s")["endpoints"]
    assert len(endpoint["content_types"]) == 2
    assert endpoint["content_types_truncated"] is True


def test_har_payload_is_not_leaked(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/x")]
    backend = _backend(monkeypatch, rows)
    (endpoint,) = backend.network_endpoints("s")["endpoints"]
    assert "_har" not in endpoint
    assert endpoint["example_id"] == "a"


def test_service_wraps_unknown_session_as_failure() -> None:
    service = AnalysisService(Settings.load())
    result = service.web_network_endpoints("no-such-session")
    assert not result.ok
    assert result.error is not None


def test_docstring_names_the_contract() -> None:
    doc = _tool_docstring("web.network.endpoints")
    for token in ("proxy.endpoints", "resource_type", "normalize", "has_more", "endpoints"):
        assert token in doc, token
