"""proxy.search must filter the retained ring, not merely page it.

The backend logic (predicate matching, the error pseudo-class, pagination over
matches, and the honesty fields scanned/dropped/filters) runs against a real
_FlowRecorder fed canned flows, so a regression in the filter would surface as a
wrong match set rather than a silently unfiltered page.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import (
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


def _completed(
    recorder: _FlowRecorder,
    flow_id: str,
    method: str,
    url: str,
    host: str,
    status: int,
    content_type: str,
) -> None:
    request = SimpleNamespace(method=method, pretty_url=url, host=host)
    response = SimpleNamespace(status_code=status, headers={"content-type": content_type})
    recorder.response(SimpleNamespace(id=flow_id, request=request, response=response))


def _errored(
    recorder: _FlowRecorder, flow_id: str, method: str, url: str, host: str, msg: str
) -> None:
    request = SimpleNamespace(method=method, pretty_url=url, host=host)
    recorder.error(
        SimpleNamespace(
            id=flow_id,
            request=request,
            response=None,
            error=SimpleNamespace(msg=msg),
        )
    )


def _backend_over(monkeypatch: Any, recorder: _FlowRecorder) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def _mixed_capture() -> _FlowRecorder:
    recorder = _FlowRecorder(capacity=50)
    _completed(
        recorder,
        "a",
        "GET",
        "https://api.example.com/a",
        "api.example.com",
        200,
        "application/json",
    )
    _completed(
        recorder,
        "b",
        "POST",
        "https://api.example.com/b",
        "api.example.com",
        201,
        "application/json; charset=utf-8",
    )
    _completed(
        recorder, "c", "GET", "https://cdn.example.com/c", "cdn.example.com", 404, "text/html"
    )
    _completed(
        recorder, "d", "GET", "https://api.example.com/d", "api.example.com", 500, "text/plain"
    )
    _errored(recorder, "e", "POST", "http://other.test/e", "other.test", "connection refused")
    return recorder


def test_search_filters_by_host_method_status_and_type(monkeypatch: Any) -> None:
    """Each predicate narrows the set; combined predicates are ANDed.

    Measured over the 5-flow capture: host 'example.com' -> the 4 example.com
    flows (the other.test errored flow excluded); method 'post' -> the two POSTs;
    status_class '2xx' -> the 200 and 201; content_type 'json' matches the raw
    header so it catches 'application/json; charset=utf-8' too; host
    'api.example.com' AND method GET -> only /a and /d.
    """
    backend = _backend_over(monkeypatch, _mixed_capture())

    by_host = backend.search("s", host="example.com")
    assert {row["id"] for row in by_host["flows"]} == {"a", "b", "c", "d"}
    assert by_host["total"] == 4
    assert by_host["scanned"] == 5

    by_method = backend.search("s", method="post")
    assert {row["id"] for row in by_method["flows"]} == {"b", "e"}

    by_status = backend.search("s", status_class="2xx")
    assert {row["id"] for row in by_status["flows"]} == {"a", "b"}

    by_type = backend.search("s", content_type="json")
    assert {row["id"] for row in by_type["flows"]} == {"a", "b"}

    combined = backend.search("s", host="api.example.com", method="GET")
    assert {row["id"] for row in combined["flows"]} == {"a", "d"}
    assert combined["filters"] == {
        "host": "api.example.com",
        "method": "GET",
        "url": "",
        "content_type": "",
        "status_class": "",
    }


def test_search_error_pseudo_class_matches_only_failed_flows(
    monkeypatch: Any,
) -> None:
    """status_class 'error' is the only way to select the null-status flow.

    The errored flow carries error=true and status None, so no numeric class
    (e.g. 5xx) matches it; 'error' matches it and nothing else.
    """
    backend = _backend_over(monkeypatch, _mixed_capture())

    errored = backend.search("s", status_class="error")
    assert {row["id"] for row in errored["flows"]} == {"e"}
    assert errored["flows"][0].get("error") is True
    assert errored["flows"][0].get("status") is None

    server_errors = backend.search("s", status_class="5xx")
    assert {row["id"] for row in server_errors["flows"]} == {"d"}
    assert "e" not in {row["id"] for row in server_errors["flows"]}


def test_search_with_no_filters_returns_the_whole_ring(monkeypatch: Any) -> None:
    """Empty predicates do not constrain, so search degrades to flows.

    total equals scanned equals the retained count, and every normalised filter
    comes back empty -- an all-empty call is not silently treated as 'match
    nothing'.
    """
    backend = _backend_over(monkeypatch, _mixed_capture())
    payload = backend.search("s")
    assert payload["total"] == 5
    assert payload["scanned"] == 5
    assert payload["count"] == 5
    assert all(value == "" for value in payload["filters"].values())
    assert "items" not in payload
    assert "results" not in payload


def test_search_paginates_matches_and_scans_the_whole_ring(
    monkeypatch: Any,
) -> None:
    """Pagination is over the match set; scanned stays the full retained count.

    offset/limit page the matches (total is the match count, not the page), and
    scanned reports how many flows were examined so a small page is not read as
    the whole capture.
    """
    backend = _backend_over(monkeypatch, _mixed_capture())
    first = backend.search("s", host="example.com", offset=0, limit=2)
    assert first["count"] == 2
    assert first["total"] == 4
    assert first["scanned"] == 5
    assert first["has_more"] is True

    last = backend.search("s", host="example.com", offset=2, limit=2)
    assert last["count"] == 2
    assert last["has_more"] is False

    normalized = backend.search("s", host="example.com", offset=-5, limit=0)
    assert normalized["offset"] == 0
    assert normalized["count"] == 1


def test_search_rejects_a_bad_status_class(monkeypatch: Any) -> None:
    """A status_class outside {1xx..5xx, error} is invalid_params, not silent.

    Accepting an unknown class and matching nothing would read as 'no such
    flows'; the caller is told the predicate itself was wrong instead.
    """
    backend = _backend_over(monkeypatch, _mixed_capture())
    with pytest.raises(ProxyError) as excinfo:
        backend.search("s", status_class="boom")
    assert excinfo.value.code == "invalid_params"


def test_search_description_names_its_fields() -> None:
    doc = _tool_docstring("proxy.search")
    assert "proxy.flows" in doc
    assert "proxy.summary" in doc
    assert "status_class" in doc
    assert "scanned" in doc
    assert "substring" in doc
