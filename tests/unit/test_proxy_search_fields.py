"""proxy.search greps the retained capture for a substring across flows.

proxy.flows filters on the summary (url, content-type, failed); proxy.search
answers the question it cannot -- "which flow *contains* this value" -- by
scanning each retained flow's url, request/response headers and decoded
request/response bodies. These cover the per-location matching, the
case-insensitive substring, the gzip-decoded body, the url/content-type
pre-filters, paging, the body-omitted and scan-capped paths, the query
validation, service routing, and the read-only classification.
"""

from __future__ import annotations

import ast
import gzip
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _MAX_SEARCH_QUERY,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _FlowRecorder,
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


def _flow_obj(
    fid: str,
    *,
    method: str = "GET",
    url: str = "http://api.test/",
    host: str = "api.test",
    req_headers: dict[str, str] | None = None,
    req_body: bytes = b"",
    status: int | None = 200,
    resp_headers: dict[str, str] | None = None,
    resp_body: bytes = b"",
    content_encoding: str = "",
) -> Any:
    resp_h = dict(resp_headers or {})
    if content_encoding:
        resp_h["content-encoding"] = content_encoding
    request = SimpleNamespace(
        method=method,
        pretty_url=url,
        host=host,
        headers=dict(req_headers or {}),
        raw_content=req_body,
        content=req_body,
        timestamp_start=1000.0,
    )
    response = SimpleNamespace(
        status_code=status,
        headers=resp_h,
        raw_content=resp_body,
    )
    return SimpleNamespace(id=fid, request=request, response=response)


def _recorder(flows: list[Any]) -> _FlowRecorder:
    recorder = _FlowRecorder(capacity=100)
    for flow in flows:
        recorder.response(flow)
    return recorder


def _backend(recorder: Any, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    return backend


def test_proxy_search_finds_in_response_body(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", url="http://api.test/a", resp_body=b'{"token":"SECRET_TOKEN_ABC"}'),
            _flow_obj("2", url="http://api.test/b", resp_body=b'{"ok":true}'),
        ]
    )
    out = _backend(rec, monkeypatch).search("s", query="secret_token")
    assert out["query"] == "secret_token"
    assert out["total"] == 1
    assert out["scan_capped"] is False
    row = out["flows"][0]
    assert row["id"] == "1"
    assert len(row["matches"]) == 1
    match = row["matches"][0]
    assert match["where"] == "response_body"
    assert match["count"] == 1
    assert "SECRET_TOKEN_ABC" in match["snippet"]


def test_proxy_search_finds_in_request_body_and_headers(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj(
                "1",
                method="POST",
                req_headers={"Authorization": "Bearer XYZ789"},
                req_body=b"password=hunter2&user=admin",
            )
        ]
    )
    backend = _backend(rec, monkeypatch)
    body_hit = backend.search("s", query="hunter2")["flows"][0]["matches"]
    assert [m["where"] for m in body_hit] == ["request_body"]
    header_hit = backend.search("s", query="bearer xyz789")["flows"][0]["matches"]
    assert [m["where"] for m in header_hit] == ["request_headers"]


def test_proxy_search_finds_in_url(monkeypatch: Any) -> None:
    rec = _recorder([_flow_obj("1", url="http://api.test/item?ref=42ABCdef")])
    row = _backend(rec, monkeypatch).search("s", query="42abcdef")["flows"][0]
    assert [m["where"] for m in row["matches"]] == ["url"]
    # Body was retained, so this is a full match, not a url-only fallback.
    assert "body_omitted" not in row


def test_proxy_search_decodes_gzip_response(monkeypatch: Any) -> None:
    payload = gzip.compress(b"deep in a compressed body: gzipped-needle here")
    rec = _recorder(
        [_flow_obj("1", resp_headers={"content-type": "text/html"},
                   resp_body=payload, content_encoding="gzip")]
    )
    row = _backend(rec, monkeypatch).search("s", query="gzipped-needle")["flows"][0]
    assert [m["where"] for m in row["matches"]] == ["response_body"]
    assert "gzipped-needle" in row["matches"][0]["snippet"]


def test_proxy_search_no_match_is_empty(monkeypatch: Any) -> None:
    rec = _recorder([_flow_obj("1", resp_body=b"nothing to see")])
    out = _backend(rec, monkeypatch).search("s", query="absent-value")
    assert out["total"] == 0
    assert out["flows"] == []


def test_proxy_search_reports_all_locations_and_counts(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj(
                "1",
                url="http://api.test/needle",
                resp_body=b"needle and needle and needle",
            )
        ]
    )
    matches = _backend(rec, monkeypatch).search("s", query="needle")["flows"][0]["matches"]
    where = {m["where"]: m for m in matches}
    assert set(where) == {"url", "response_body"}
    assert where["response_body"]["count"] == 3
    assert where["url"]["count"] == 1


def test_proxy_search_url_filter_narrows_search(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", url="http://api.test/x", host="api.test", resp_body=b"shared-value"),
            _flow_obj("2", url="http://cdn.test/y", host="cdn.test", resp_body=b"shared-value"),
        ]
    )
    out = _backend(rec, monkeypatch).search("s", query="shared-value", url_filter="cdn.test")
    assert out["total"] == 1
    assert out["flows"][0]["id"] == "2"


def test_proxy_search_content_type_filter_narrows_search(monkeypatch: Any) -> None:
    rec = _recorder(
        [
            _flow_obj("1", resp_headers={"content-type": "application/json"}, resp_body=b"v-value"),
            _flow_obj("2", resp_headers={"content-type": "text/html"}, resp_body=b"v-value"),
        ]
    )
    out = _backend(rec, monkeypatch).search("s", query="v-value", content_type_filter="json")
    assert out["total"] == 1
    assert out["flows"][0]["id"] == "1"


def test_proxy_search_pages_and_reports_has_more(monkeypatch: Any) -> None:
    rec = _recorder(
        [_flow_obj(str(i), url=f"http://api.test/{i}", resp_body=b"hit-me") for i in range(5)]
    )
    out = _backend(rec, monkeypatch).search("s", query="hit-me", offset=0, limit=2)
    assert out["count"] == 2
    assert out["total"] == 5
    assert out["has_more"] is True
    assert out["offset"] == 0


def test_proxy_search_marks_body_omitted_when_not_retained(monkeypatch: Any) -> None:
    # A summary whose raw body the ring did not retain: only the url is
    # searchable, and a url hit must be flagged body_omitted.
    summary = {"id": "1", "seq": 1, "method": "GET",
               "url": "http://api.test/omitted-needle", "host": "api.test", "status": 200}
    stub = SimpleNamespace(
        snapshot=lambda: [summary],
        raw=lambda fid: _OMITTED_BODY,
    )
    backend = _backend(stub, monkeypatch)
    row = backend.search("s", query="omitted-needle")["flows"][0]
    assert row["body_omitted"] is True
    assert [m["where"] for m in row["matches"]] == ["url"]


def test_proxy_search_scan_budget_caps_the_walk(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_SEARCH_SCAN_BYTES", 8)
    rec = _recorder(
        [
            _flow_obj("1", url="http://api.test/1", resp_body=b"needle-in-a-longer-body"),
            _flow_obj("2", url="http://api.test/2", resp_body=b"needle-in-a-longer-body"),
        ]
    )
    out = _backend(rec, monkeypatch).search("s", query="needle")
    assert out["scan_capped"] is True
    # The first flow's body already blew the tiny budget, so the second went
    # unsearched even though it also matched.
    assert out["total"] == 1


def test_proxy_search_empty_query_is_invalid_params(monkeypatch: Any) -> None:
    rec = _recorder([_flow_obj("1")])
    backend = _backend(rec, monkeypatch)
    with pytest.raises(ProxyError) as info:
        backend.search("s", query="   ")
    assert info.value.code == "invalid_params"


def test_proxy_search_overlong_query_is_invalid_params(monkeypatch: Any) -> None:
    rec = _recorder([_flow_obj("1")])
    backend = _backend(rec, monkeypatch)
    with pytest.raises(ProxyError) as info:
        backend.search("s", query="x" * (_MAX_SEARCH_QUERY + 1))
    assert info.value.code == "invalid_params"


def test_service_proxy_search_routes_to_backend(monkeypatch: Any) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_search(session_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured.update(kwargs)
            return {"query": kwargs["query"], "flows": [], "total": 0}

        monkeypatch.setattr(service._proxy_backend, "search", fake_search)
        result = service.proxy_search("sess", "needle", limit=5, url_filter="api")
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["query"] == "needle"
        assert captured["limit"] == 5
        assert captured["url_filter"] == "api"
    finally:
        service.close_all()


def test_service_proxy_search_invalid_query_is_failure() -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        # Query is validated before the session lookup, so an empty query fails
        # as invalid_params even with no proxy running.
        result = service.proxy_search("whatever", "")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_proxy_search_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("proxy.search").split())
    assert "matches" in doc
    assert "response_body" in doc
    assert "scan_capped" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "proxy.search" in _READ_ONLY_NAMES
