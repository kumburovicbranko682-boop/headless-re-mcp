"""proxy.endpoints must collapse a capture into a route-grouped API surface.

Aggregates summary rows only (no bodies), so a fake recorder drives every case:
id-normalisation of path segments, method/status/content-type roll-up per route,
ranking, paging, filters and the websocket/has_query flags.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.urlpath import (
    is_variable_segment as _is_variable_segment,
)
from headless_re_mcp.backends.common.urlpath import (
    normalize_endpoint_path as _normalize_endpoint_path,
)
from headless_re_mcp.backends.proxy.client import (
    ProxyBackend,
    _endpoint_path,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
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


class _FakeRecorder:
    def __init__(self, summaries: list[dict[str, Any]]) -> None:
        self._summaries = summaries

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._summaries)


def _summary(
    flow_id: str,
    *,
    seq: int,
    method: str = "GET",
    url: str = "http://api.example.com/",
    host: str = "api.example.com",
    status: int | None = 200,
    ctype: str = "application/json",
    websocket: bool = False,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": flow_id,
        "seq": seq,
        "method": method,
        "url": url,
        "host": host,
        "status": status,
        "content_type": ctype,
    }
    if websocket:
        row["websocket"] = True
    return row


def _backend(monkeypatch: Any, summaries: list[dict[str, Any]]) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = _FakeRecorder(summaries)
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    return backend


# --- path normalisation helpers ---------------------------------------------


@pytest.mark.parametrize(
    "segment,expected",
    [
        ("123", True),
        ("0042", True),
        ("550e8400-e29b-41d4-a716-446655440000", True),  # uuid
        ("deadbeefcafe", True),  # 12-char hex
        ("a1b2c3", False),  # short hex, likely a real name
        ("users", False),
        ("v1", False),
        ("aB3d9F2h1K4m6P8r0T2v4X6z", True),  # 24-char mixed token
        ("thisisalongwordwithoutdigits", False),  # long but no digit -> route name
    ],
)
def test_is_variable_segment(segment: str, expected: bool) -> None:
    assert _is_variable_segment(segment) is expected


def test_normalize_path_folds_ids() -> None:
    assert _normalize_endpoint_path("/api/users/123/orders/456") == "/api/users/{id}/orders/{id}"
    assert _normalize_endpoint_path("/api/users/profile") == "/api/users/profile"
    assert _normalize_endpoint_path("/") == "/"


def test_endpoint_path_splits_query() -> None:
    assert _endpoint_path("http://h/a/b?x=1") == ("/a/b", True)
    assert _endpoint_path("http://h/a/b") == ("/a/b", False)
    assert _endpoint_path("http://h") == ("/", False)


# --- the endpoints aggregation ----------------------------------------------


def test_numeric_ids_fold_into_one_route(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, url="http://api.example.com/users/1"),
        _summary("b", seq=2, url="http://api.example.com/users/2"),
        _summary("c", seq=3, url="http://api.example.com/users/profile"),
    ]
    out = _backend(monkeypatch, summaries).endpoints("s")
    assert out["total"] == 2
    assert out["normalized"] is True
    by_path = {e["path"]: e for e in out["endpoints"]}
    assert by_path["/users/{id}"]["count"] == 2
    assert by_path["/users/{id}"]["example_id"] == "a"  # first flow of the group
    assert by_path["/users/profile"]["count"] == 1


def test_normalize_false_keeps_exact_paths(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, url="http://api.example.com/users/1"),
        _summary("b", seq=2, url="http://api.example.com/users/2"),
    ]
    out = _backend(monkeypatch, summaries).endpoints("s", normalize=False)
    assert out["total"] == 2
    assert out["normalized"] is False
    assert {e["path"] for e in out["endpoints"]} == {"/users/1", "/users/2"}


def test_method_status_and_content_type_rollup(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, method="GET", url="http://h/x", status=200, ctype="application/json"),
        _summary(
            "b", seq=2, method="POST", url="http://h/x", status=404,
            ctype="text/html; charset=utf-8",
        ),
        _summary("c", seq=3, method="GET", url="http://h/x", status=200, ctype="application/json"),
    ]
    (ep,) = _backend(monkeypatch, summaries).endpoints("s")["endpoints"]
    assert ep["methods"] == ["GET", "POST"]
    assert ep["status_classes"] == {"2xx": 2, "4xx": 1}
    ctypes = {row["content_type"]: row["count"] for row in ep["content_types"]}
    assert ctypes == {"application/json": 2, "text/html": 1}  # charset stripped
    assert ep["count"] == 3


def test_pending_status_and_query_and_websocket_flags(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, url="http://h/search?q=1", status=None),
        _summary("b", seq=2, url="ws://h/live", host="h", status=101, websocket=True, ctype=""),
    ]
    out = _backend(monkeypatch, summaries).endpoints("s")
    by_path = {e["path"]: e for e in out["endpoints"]}
    assert by_path["/search"]["status_classes"] == {"pending": 1}
    assert by_path["/search"]["has_query"] is True
    assert by_path["/live"]["websocket"] is True


def test_ranked_by_count_then_host_then_path(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, url="http://h/rare"),
        _summary("b", seq=2, url="http://h/common"),
        _summary("c", seq=3, url="http://h/common"),
    ]
    out = _backend(monkeypatch, summaries).endpoints("s")
    assert [e["path"] for e in out["endpoints"]] == ["/common", "/rare"]


def test_paging(monkeypatch: Any) -> None:
    summaries = [
        _summary(str(i), seq=i, url=f"http://h/r{i:02d}") for i in range(10)
    ]
    backend = _backend(monkeypatch, summaries)
    first = backend.endpoints("s", offset=0, limit=4)
    assert first["count"] == 4 and first["total"] == 10 and first["has_more"] is True
    last = backend.endpoints("s", offset=8, limit=4)
    assert last["count"] == 2 and last["has_more"] is False


def test_filter_narrows_and_is_echoed(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, method="GET", url="http://h/x"),
        _summary("b", seq=2, method="POST", url="http://h/y"),
    ]
    out = _backend(monkeypatch, summaries).endpoints("s", method="post")
    assert out["captured"] == 2  # whole ring still reported
    assert out["total"] == 1
    assert out["endpoints"][0]["path"] == "/y"
    assert out["filter"] == {"method": "POST"}


def test_dropped_reflects_ring_eviction(monkeypatch: Any) -> None:
    # seq of the last row exceeds the retained count -> the difference was evicted.
    summaries = [
        _summary("a", seq=98, url="http://h/x"),
        _summary("b", seq=99, url="http://h/y"),
        _summary("c", seq=100, url="http://h/z"),
    ]
    out = _backend(monkeypatch, summaries).endpoints("s")
    assert out["captured"] == 3
    assert out["dropped"] == 97


def test_empty_capture(monkeypatch: Any) -> None:
    out = _backend(monkeypatch, []).endpoints("s")
    assert out["endpoints"] == []
    assert out["total"] == 0 and out["captured"] == 0 and out["dropped"] == 0
    assert out["has_more"] is False


def test_service_wiring_reports_invalid_state_without_a_proxy() -> None:
    service = AnalysisService(Settings.load())
    try:
        result = service.proxy_endpoints("no-such-session")
        assert not result.ok and result.error is not None
        assert result.error.code == "invalid_state", result.error
    finally:
        service.close_all()


def test_docstring_names_the_fields() -> None:
    doc = _tool_docstring("proxy.endpoints")
    for token in ("endpoints", "path", "methods", "status_classes", "example_id", "normalize"):
        assert token in doc, token
