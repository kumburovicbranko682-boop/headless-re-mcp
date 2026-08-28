"""proxy.endpoints folds the capture into distinct method+host+path endpoints."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder
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


def _respond(
    recorder: _FlowRecorder,
    fid: str,
    method: str,
    url: str,
    host: str,
    status: int,
    content_type: str = "text/plain",
) -> None:
    request = SimpleNamespace(method=method, pretty_url=url, host=host)
    response = SimpleNamespace(status_code=status, headers={"content-type": content_type})
    recorder.response(SimpleNamespace(id=fid, request=request, response=response))


def _find(endpoints: list[dict], method: str, path: str) -> dict | None:
    for entry in endpoints:
        if entry["method"] == method and entry["path"] == path:
            return entry
    return None


def test_proxy_endpoints_folds_by_method_host_path(monkeypatch: Any) -> None:
    """Distinct method+host+path rows, with the query string stripped.

    Two GETs to /api/user with different query strings fold to one endpoint hit
    twice; a POST to the same path is a separate endpoint; a repeated hit that
    returns a second status widens the endpoint's status set.
    """
    recorder = _FlowRecorder(capacity=50)
    _respond(recorder, "1", "GET", "http://api/api/user?id=1", "api", 200)
    _respond(recorder, "2", "GET", "http://api/api/user?id=2", "api", 200)
    _respond(recorder, "3", "GET", "http://api/api/user?id=3", "api", 404)
    _respond(recorder, "4", "POST", "http://api/api/user", "api", 201)
    _respond(recorder, "5", "GET", "http://api/health", "api", 200)

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.endpoints("s")

    assert result["flows_folded"] == 5
    assert result["total"] == 3  # GET /api/user, POST /api/user, GET /health
    assert result["count"] == 3
    assert result["has_more"] is False

    get_user = _find(result["endpoints"], "GET", "/api/user")
    assert get_user is not None
    assert get_user["host"] == "api"
    assert get_user["count"] == 3  # the query string was stripped, so all fold
    assert get_user["statuses"] == [200, 404]  # distinct, sorted
    assert get_user["failed"] == 0
    assert get_user["websocket"] is False

    post_user = _find(result["endpoints"], "POST", "/api/user")
    assert post_user is not None
    assert post_user["count"] == 1
    assert post_user["statuses"] == [201]

    # Busiest endpoint ranks first.
    assert result["endpoints"][0] == get_user


def test_proxy_endpoints_marks_failed_and_websocket(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=50)
    # A WebSocket upgrade endpoint.
    _respond(recorder, "ws", "GET", "http://d/socket", "d", 101, "")
    recorder.websocket_message(
        SimpleNamespace(
            id="ws",
            websocket=SimpleNamespace(
                messages=[SimpleNamespace(from_client=True, content=b"hi")]
            ),
        )
    )
    # A failed flow: no response, so no status but a failed tally.
    recorder.error(
        SimpleNamespace(
            id="dead",
            request=SimpleNamespace(
                method="GET", pretty_url="http://c/gone", host="c", headers={}
            ),
            response=None,
            error=SimpleNamespace(msg="connection refused"),
        )
    )

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.endpoints("s")

    socket = _find(result["endpoints"], "GET", "/socket")
    assert socket is not None
    assert socket["websocket"] is True

    gone = _find(result["endpoints"], "GET", "/gone")
    assert gone is not None
    assert gone["failed"] == 1
    assert gone["statuses"] == []  # a failed hit contributes no status code


def test_proxy_endpoints_caps_and_reports_more(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=100)
    for index in range(10):
        _respond(recorder, str(index), "GET", f"http://h/p{index}", "h", 200)

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.endpoints("s", limit=4)
    assert result["count"] == 4
    assert result["total"] == 10
    assert result["has_more"] is True


def test_proxy_endpoints_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.endpoints")
    assert doc, "proxy.endpoints is missing its docstring"
    assert "method" in doc
    assert "path" in doc
    assert "statuses" in doc
    assert "flows_folded" in doc
    assert "has_more" in doc
