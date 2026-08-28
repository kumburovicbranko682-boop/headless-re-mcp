"""proxy.endpoints rolls the capture up per API endpoint.

proxy.hosts is one row per host (too coarse to see which API was called) and
proxy.flows one row per request (too granular on a busy capture); proxy.endpoints
sits between them, aggregating the retained flows by (method, host, request path)
with volatile path segments folded into placeholders. These cover the
aggregation and field shapes, the id/UUID/hex path normalisation (and the
normalize=False escape hatch), busiest-first ordering, the content_type_filter
and name_filter, the per-row set caps and the distinct-endpoint ceiling, paging,
the dropped/total_flows accounting, an integration pass through the real
recorder, the service routing, and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_HOST_CONTENT_TYPES,
    ProxyBackend,
    _FlowRecorder,
    _normalize_request_path,
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


def _backend_with(items: list[dict[str, Any]], monkeypatch: Any) -> ProxyBackend:
    recorder = SimpleNamespace(snapshot=lambda: list(items))
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    return backend


def _flow(
    seq: int,
    method: str,
    url: str,
    host: str,
    *,
    status: int | None = 200,
    content_type: str = "",
    failed: bool = False,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": str(seq),
        "seq": seq,
        "method": method,
        "url": url,
        "host": host,
        "status": status,
        "content_type": content_type,
    }
    if failed:
        item["failed"] = True
    return item


def test_normalize_request_path_folds_volatile_segments() -> None:
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert _normalize_request_path("/v1/users/123") == "/v1/users/{num}"
    assert _normalize_request_path(f"/v1/orders/{uuid}") == "/v1/orders/{uuid}"
    assert _normalize_request_path("/blob/" + "a" * 40) == "/blob/{hex}"
    # A real path segment is never mistaken for an id; short hex-ish words stay.
    assert _normalize_request_path("/v1/login") == "/v1/login"
    assert _normalize_request_path("/img/logo.png") == "/img/logo.png"
    assert _normalize_request_path("") == "/"
    # Trailing slash is preserved so /a and /a/ stay distinct endpoints.
    assert _normalize_request_path("/a/") == "/a/"


def test_proxy_endpoints_aggregates_and_orders_by_flow_count(monkeypatch: Any) -> None:
    items = [
        _flow(1, "GET", "https://api.x.com/v1/users/1", "api.x.com",
              status=200, content_type="application/json"),
        _flow(2, "GET", "https://api.x.com/v1/users/2", "api.x.com",
              status=200, content_type="application/json"),
        _flow(3, "GET", "https://api.x.com/v1/users/3", "api.x.com",
              status=404, content_type="application/json"),
        _flow(4, "POST", "https://api.x.com/v1/login", "api.x.com",
              status=200, content_type="application/json"),
        _flow(5, "GET", "https://cdn.x.com/img/logo.png", "cdn.x.com",
              status=200, content_type="image/png"),
    ]
    payload = _backend_with(items, monkeypatch).endpoints("s")
    assert payload["total"] == 3
    assert payload["total_flows"] == 5
    assert payload["dropped"] == 0
    assert payload["endpoints_truncated"] is False
    rows = payload["endpoints"]
    # Busiest first; the two single-flow endpoints tie and break on host.
    assert [(r["method"], r["host"], r["path"]) for r in rows] == [
        ("GET", "api.x.com", "/v1/users/{num}"),
        ("POST", "api.x.com", "/v1/login"),
        ("GET", "cdn.x.com", "/img/logo.png"),
    ]
    users = rows[0]
    assert users["flows"] == 3
    assert users["failed"] == 0
    assert users["statuses"] == {"200": 2, "404": 1}
    assert users["content_types"] == ["application/json"]
    # example_url is the first concrete instance (query intact), first_flow its id.
    assert users["example_url"] == "https://api.x.com/v1/users/1"
    assert users["first_flow"] == "1"


def test_proxy_endpoints_normalize_false_keeps_exact_paths(monkeypatch: Any) -> None:
    items = [
        _flow(1, "GET", "https://api.x.com/v1/users/1", "api.x.com"),
        _flow(2, "GET", "https://api.x.com/v1/users/2", "api.x.com"),
        _flow(3, "GET", "https://api.x.com/v1/users/3", "api.x.com"),
    ]
    payload = _backend_with(items, monkeypatch).endpoints("s", normalize=False)
    assert payload["total"] == 3
    paths = {row["path"] for row in payload["endpoints"]}
    assert paths == {"/v1/users/1", "/v1/users/2", "/v1/users/3"}


def test_proxy_endpoints_folds_uuid_and_hex(monkeypatch: Any) -> None:
    uuid_a = "550e8400-e29b-41d4-a716-446655440000"
    uuid_b = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    sha = "b" * 40
    items = [
        _flow(1, "GET", f"https://h/o/{uuid_a}", "h"),
        _flow(2, "GET", f"https://h/o/{uuid_b}", "h"),
        _flow(3, "GET", f"https://h/f/{sha}", "h"),
    ]
    payload = _backend_with(items, monkeypatch).endpoints("s")
    by_path = {row["path"]: row for row in payload["endpoints"]}
    assert by_path["/o/{uuid}"]["flows"] == 2
    assert by_path["/f/{hex}"]["flows"] == 1


def test_proxy_endpoints_content_type_filter_narrows_the_rollup(monkeypatch: Any) -> None:
    items = [
        _flow(1, "GET", "https://h/api/a", "h", content_type="application/json"),
        _flow(2, "GET", "https://h/img/a.png", "h", content_type="image/png"),
        _flow(3, "POST", "https://h/api/b", "h", content_type="application/json; charset=utf-8"),
    ]
    payload = _backend_with(items, monkeypatch).endpoints("s", content_type_filter="json")
    # Only the two JSON flows fed the rollup; total_flows reflects that.
    assert payload["total"] == 2
    assert payload["total_flows"] == 2
    assert all("json" in row["content_types"][0] for row in payload["endpoints"])


def test_proxy_endpoints_name_filter_before_paging(monkeypatch: Any) -> None:
    items = [
        _flow(1, "GET", "https://api.x.com/v1/users/1", "api.x.com"),
        _flow(2, "POST", "https://api.x.com/v1/login", "api.x.com"),
        _flow(3, "GET", "https://cdn.x.com/img/a.png", "cdn.x.com"),
    ]
    # Matches host, path or method (case-insensitive).
    by_host = _backend_with(items, monkeypatch).endpoints("s", name_filter="cdn")
    assert {r["host"] for r in by_host["endpoints"]} == {"cdn.x.com"}
    by_path = _backend_with(items, monkeypatch).endpoints("s", name_filter="login")
    assert [r["path"] for r in by_path["endpoints"]] == ["/v1/login"]
    by_method = _backend_with(items, monkeypatch).endpoints("s", name_filter="post")
    assert [r["method"] for r in by_method["endpoints"]] == ["POST"]
    # total is the match count; total_flows still counts the whole capture.
    assert by_method["total"] == 1
    assert by_method["total_flows"] == 3


def test_proxy_endpoints_counts_failed_flows(monkeypatch: Any) -> None:
    items = [
        _flow(1, "GET", "https://h/api/a", "h", status=200),
        _flow(2, "GET", "https://h/api/a", "h", status=None, failed=True),
    ]
    row = _backend_with(items, monkeypatch).endpoints("s")["endpoints"][0]
    assert row["flows"] == 2
    assert row["failed"] == 1
    # The failed flow has no status, so it is not tallied.
    assert row["statuses"] == {"200": 1}


def test_proxy_endpoints_caps_a_hostile_set_and_flags_truncated(monkeypatch: Any) -> None:
    # One endpoint answered with an unbounded variety of content-types.
    items = [
        _flow(index + 1, "GET", "https://h/api/a", "h", content_type=f"type/{index}")
        for index in range(_MAX_HOST_CONTENT_TYPES + 8)
    ]
    row = _backend_with(items, monkeypatch).endpoints("s")["endpoints"][0]
    assert len(row["content_types"]) == _MAX_HOST_CONTENT_TYPES
    assert row["truncated"] is True


def test_proxy_endpoints_caps_distinct_endpoints(monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.proxy.client._MAX_ENDPOINTS", 1)
    items = [
        _flow(1, "GET", "https://h/a", "h"),
        _flow(2, "GET", "https://h/b", "h"),
    ]
    payload = _backend_with(items, monkeypatch).endpoints("s")
    assert payload["total"] == 1
    assert payload["endpoints_truncated"] is True


def test_proxy_endpoints_pages_and_reports_has_more(monkeypatch: Any) -> None:
    items = [_flow(i + 1, "GET", f"https://h/p{i:02d}", "h") for i in range(5)]
    payload = _backend_with(items, monkeypatch).endpoints("s", offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["offset"] == 0


def test_proxy_endpoints_reports_ring_evictions_in_dropped(monkeypatch: Any) -> None:
    items = [_flow(95, "GET", "https://h/a", "h"), _flow(100, "GET", "https://h/a", "h")]
    payload = _backend_with(items, monkeypatch).endpoints("s")
    assert payload["dropped"] == 98


def test_proxy_endpoints_via_real_recorder(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=50)
    for index in range(4):
        request = SimpleNamespace(
            method="GET",
            pretty_url=f"http://api.test/v1/items/{index}?t={index}",
            host="api.test",
        )
        response = SimpleNamespace(status_code=200, headers={"content-type": "application/json"})
        recorder.response(SimpleNamespace(id=str(index), request=request, response=response))
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    payload = backend.endpoints("s")
    assert payload["total"] == 1
    row = payload["endpoints"][0]
    assert row["method"] == "GET"
    assert row["host"] == "api.test"
    assert row["path"] == "/v1/items/{num}"
    assert row["flows"] == 4
    assert row["content_types"] == ["application/json"]


def test_service_proxy_endpoints_routes_to_backend(monkeypatch: Any) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_endpoints(session_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured.update(kwargs)
            return {"endpoints": [], "total": 0}

        monkeypatch.setattr(service._proxy_backend, "endpoints", fake_endpoints)
        result = service.proxy_endpoints(
            "sess", limit=5, name_filter="api", content_type_filter="json", normalize=False
        )
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["limit"] == 5
        assert captured["name_filter"] == "api"
        assert captured["content_type_filter"] == "json"
        assert captured["normalize"] is False
    finally:
        service.close_all()


def test_proxy_endpoints_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("proxy.endpoints").split())
    assert "example_url" in doc
    assert "first_flow" in doc
    assert "endpoints_truncated" in doc
    assert "normalize" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "proxy.endpoints" in _READ_ONLY_NAMES
