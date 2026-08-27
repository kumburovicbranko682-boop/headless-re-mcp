"""proxy.search greps the whole capture for a substring and says where it hit."""

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


def _respond(
    recorder: _FlowRecorder,
    fid: str,
    method: str,
    url: str,
    host: str,
    status: int,
    *,
    req_headers: dict[str, str] | None = None,
    resp_headers: dict[str, str] | None = None,
    req_body: bytes | None = None,
    resp_body: bytes | None = None,
) -> None:
    request = SimpleNamespace(
        method=method, pretty_url=url, host=host, headers=req_headers or {}
    )
    if req_body is not None:
        request.raw_content = req_body
    response = SimpleNamespace(
        status_code=status, headers=resp_headers or {"content-type": "text/plain"}
    )
    if resp_body is not None:
        response.raw_content = resp_body
    recorder.response(SimpleNamespace(id=fid, request=request, response=response))


def _backend(recorder: _FlowRecorder, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    return backend


def test_proxy_search_finds_the_needle_and_names_where(monkeypatch: Any) -> None:
    """A substring must be found across url, headers, bodies and frames.

    Build a mixed capture and assert search reports, per flow, exactly which
    part matched -- so an analyst hunting a token learns not just which flow but
    where in it the value lives.
    """
    recorder = _FlowRecorder(capacity=50)
    _respond(recorder, "1", "GET", "http://a/beacon?x=1", "a", 200, resp_body=b'{"ok":true}')
    _respond(
        recorder,
        "2",
        "POST",
        "http://b/login",
        "b",
        200,
        req_body=b'{"password":"hunter2"}',
        resp_body=b'{"token":"SECRET_TOKEN_ABC"}',
    )
    _respond(
        recorder,
        "3",
        "GET",
        "http://c/health",
        "c",
        200,
        resp_headers={"content-type": "text/plain", "x-trace": "findme-trace-42"},
    )
    _respond(recorder, "ws", "GET", "http://d/socket", "d", 101)
    recorder.websocket_message(
        SimpleNamespace(
            id="ws",
            websocket=SimpleNamespace(
                messages=[SimpleNamespace(from_client=True, content=b"subscribe:SECRET_TOKEN_ABC")]
            ),
        )
    )
    backend = _backend(recorder, monkeypatch)

    # response_body match on flow 2 and the websocket frame on flow ws.
    hit = backend.search("s", "secret_token")
    by_id = {row["id"]: row for row in hit["matches"]}
    assert set(by_id) == {"2", "ws"}
    assert by_id["2"]["where"] == ["response_body"]
    assert by_id["ws"]["where"] == ["websocket"]
    assert hit["query"] == "secret_token"
    assert hit["total"] == 2
    assert hit["scanned"] == 4
    assert hit["truncated"] is False

    # url match, case-insensitive.
    assert [m["id"] for m in backend.search("s", "BEACON")["matches"]] == ["1"]
    # request_body match.
    login = backend.search("s", "hunter2")["matches"]
    assert [m["id"] for m in login] == ["2"]
    assert login[0]["where"] == ["request_body"]
    # response header match.
    trace = backend.search("s", "findme-trace")["matches"]
    assert [m["id"] for m in trace] == ["3"]
    assert trace[0]["where"] == ["response_headers"]


def test_proxy_search_can_match_several_places_in_one_flow(monkeypatch: Any) -> None:
    """When the needle is in both url and body, where lists both."""
    recorder = _FlowRecorder(capacity=10)
    _respond(
        recorder,
        "1",
        "POST",
        "http://api/token/refresh",
        "api",
        200,
        req_body=b"grant=token",
        resp_body=b'{"token":"abc"}',
    )
    backend = _backend(recorder, monkeypatch)

    row = backend.search("s", "token")["matches"][0]
    assert row["where"] == ["url", "request_body", "response_body"]


def test_proxy_search_include_bodies_false_skips_bodies(monkeypatch: Any) -> None:
    """A metadata-only pass must not read bodies, only url/headers/frames."""
    recorder = _FlowRecorder(capacity=10)
    _respond(recorder, "1", "POST", "http://b/login", "b", 200, req_body=b"pw=hunter2")
    backend = _backend(recorder, monkeypatch)

    # The body carries hunter2, but a metadata-only pass must not see it.
    assert backend.search("s", "hunter2", include_bodies=False)["total"] == 0
    assert backend.search("s", "hunter2", include_bodies=False)["bodies_scanned"] == 0
    # The url still matches without touching bodies.
    assert backend.search("s", "login", include_bodies=False)["total"] == 1


def test_proxy_search_truncates_but_counts_all(monkeypatch: Any) -> None:
    """More matches than the limit clip the list and flag truncated."""
    recorder = _FlowRecorder(capacity=20)
    for index in range(5):
        _respond(recorder, str(index), "GET", f"http://a/match{index}", "a", 200)
    backend = _backend(recorder, monkeypatch)

    hit = backend.search("s", "match", limit=2)
    assert hit["count"] == 2
    assert hit["total"] == 5
    assert hit["truncated"] is True


def test_proxy_search_rejects_an_empty_query(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=5)
    backend = _backend(recorder, monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.search("s", "   ")
    assert excinfo.value.code == "invalid_params"


def test_proxy_search_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.search")
    assert doc, "proxy.search is missing its docstring"
    assert "where" in doc
    assert "request_body" in doc
    assert "response_body" in doc
    assert "include_bodies" in doc
    assert "truncated" in doc
