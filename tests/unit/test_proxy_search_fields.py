"""proxy.search must find a literal across bodies/headers/url and locate the hit."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

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


def _flow(
    *,
    method: str = "GET",
    url: str = "http://x/",
    host: str = "x",
    req_headers: dict[str, str] | None = None,
    req_body: bytes = b"",
    status: int = 200,
    resp_headers: dict[str, str] | None = None,
    resp_body: bytes = b"",
) -> Any:
    request = SimpleNamespace(
        method=method,
        pretty_url=url,
        host=host,
        headers=req_headers or {},
        raw_content=req_body,
    )
    response = SimpleNamespace(
        status_code=status,
        headers=resp_headers or {"content-type": "text/plain"},
        raw_content=resp_body,
    )
    return SimpleNamespace(request=request, response=response)


class _FakeRecorder:
    """A recorder whose snapshot rows and raw flows are set explicitly.

    Lets a test drive proxy.search across the retained/omitted/evicted cases
    without pushing multi-megabyte bodies through the real ring just to force a
    body-omission.
    """

    def __init__(self, summaries: list[dict[str, Any]], raws: dict[str, Any]) -> None:
        self._summaries = summaries
        self._raws = raws

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._summaries)

    def raw(self, flow_id: str) -> Any:
        return self._raws.get(flow_id)


def _summary(flow_id: str, *, seq: int, method: str, url: str, host: str, status: int,
             ctype: str) -> dict[str, Any]:
    return {
        "id": flow_id,
        "seq": seq,
        "method": method,
        "url": url,
        "host": host,
        "status": status,
        "content_type": ctype,
    }


def _backend(monkeypatch: Any, recorder: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_proxy_search_finds_a_body_hit_and_locates_it(monkeypatch: Any) -> None:
    """A needle in one response body must return that flow, located and snippeted.

    Only the matching flow comes back; matched_in names response_body, the
    snippet carries the hit in context, searched counts the flows whose bodies
    were readable, and body_unavailable is zero.
    """
    summaries = [
        _summary("a", seq=1, method="GET", url="http://api/1", host="api",
                 status=200, ctype="application/json"),
        _summary("b", seq=2, method="GET", url="http://api/2", host="api",
                 status=200, ctype="application/json"),
    ]
    raws = {
        "a": _flow(url="http://api/1", resp_body=b'{"ok":true}'),
        "b": _flow(url="http://api/2", resp_body=b'{"token":"tok-MARKER-9449"}'),
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.search("s", "tok-MARKER-9449")
    assert out["total"] == 1
    assert out["count"] == 1
    assert out["captured"] == 2
    assert out["searched"] == 2
    assert out["body_unavailable"] == 0
    match = out["matches"][0]
    assert match["id"] == "b"
    assert match["matched_in"] == ["response_body"]
    assert match["match_count"] == 1
    assert match["snippet_from"] == "response_body"
    assert "tok-MARKER-9449" in match["snippet"]
    assert "filter" not in out


def test_proxy_search_is_case_insensitive_unless_asked(monkeypatch: Any) -> None:
    """Default search folds case; case_sensitive makes it exact."""
    summaries = [_summary("a", seq=1, method="GET", url="http://x/1", host="x",
                          status=200, ctype="text/plain")]
    raws = {"a": _flow(resp_body=b"Authorization: Bearer sk-live-abc")}
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    assert backend.search("s", "bearer")["total"] == 1
    assert backend.search("s", "bearer", case_sensitive=True)["total"] == 0
    exact = backend.search("s", "Bearer", case_sensitive=True)
    assert exact["total"] == 1
    assert exact["case_sensitive"] is True


def test_proxy_search_ranks_locations_and_lists_every_hit(monkeypatch: Any) -> None:
    """A needle in several parts lists them priority-first, snippet from the top.

    When the same string appears in the request headers and the URL, matched_in
    is ordered response_body > request_body > response_headers > request_headers
    > url, and the snippet is taken from the highest-priority location present.
    """
    summaries = [_summary("a", seq=1, method="POST", url="http://api/secret-path",
                          host="api", status=200, ctype="application/json")]
    raws = {
        "a": _flow(
            method="POST",
            url="http://api/secret-path",
            req_headers={"x-trace": "secret-path-token"},
            resp_body=b"{}",
        )
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.search("s", "secret-path")
    match = out["matches"][0]
    assert match["matched_in"] == ["request_headers", "url"]
    assert match["snippet_from"] == "request_headers"


def test_proxy_search_reuses_the_flow_filters(monkeypatch: Any) -> None:
    """The proxy.flows filter surface narrows candidates before searching.

    A host filter restricts which flows are scanned; captured still reports the
    whole ring and the echoed filter records what was applied.
    """
    summaries = [
        _summary("a", seq=1, method="GET", url="http://api.example.com/1",
                 host="api.example.com", status=200, ctype="application/json"),
        _summary("b", seq=2, method="GET", url="http://cdn.other.com/2",
                 host="cdn.other.com", status=200, ctype="text/plain"),
    ]
    raws = {
        "a": _flow(url="http://api.example.com/1", resp_body=b"needle-here"),
        "b": _flow(url="http://cdn.other.com/2", resp_body=b"needle-here"),
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.search("s", "needle-here", host="api.example.com")
    assert out["captured"] == 2
    assert out["total"] == 1
    assert out["matches"][0]["id"] == "a"
    assert out["searched"] == 1  # only the api candidate was scanned
    assert out["filter"] == {"host": "api.example.com"}


def test_proxy_search_still_searches_url_when_body_unavailable(monkeypatch: Any) -> None:
    """A body-omitted/evicted flow is still searchable by its URL.

    When raw() returns the omitted sentinel, the body/headers cannot be read but
    the summary URL can, so a URL hit still comes back and body_unavailable
    discloses that the body was not scanned.
    """
    summaries = [
        _summary("a", seq=1, method="GET", url="http://x/needle-in-url", host="x",
                 status=200, ctype="text/plain"),
    ]
    raws = {"a": _OMITTED_BODY}
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.search("s", "needle-in-url")
    assert out["total"] == 1
    assert out["searched"] == 0
    assert out["body_unavailable"] == 1
    match = out["matches"][0]
    assert match["matched_in"] == ["url"]
    assert match["snippet_from"] == "url"


def test_proxy_search_paginates_over_matches(monkeypatch: Any) -> None:
    """offset/limit page the matching flows and has_more reflects the matches."""
    summaries = []
    raws = {}
    for index in range(7):
        fid = str(index)
        summaries.append(
            _summary(fid, seq=index + 1, method="GET", url=f"http://x/{index}",
                     host="x", status=200, ctype="text/plain")
        )
        raws[fid] = _flow(url=f"http://x/{index}", resp_body=b"hit")
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    first = backend.search("s", "hit", offset=0, limit=3)
    assert first["total"] == 7
    assert first["count"] == 3
    assert first["has_more"] is True
    second = backend.search("s", "hit", offset=6, limit=3)
    assert second["count"] == 1
    assert second["has_more"] is False


def test_proxy_search_over_the_real_recorder(monkeypatch: Any) -> None:
    """End to end over the actual ring: a body pushed in is found by content."""
    recorder = _FlowRecorder(capacity=10)
    recorder.response(
        _flow(
            method="POST",
            url="http://api/login",
            host="api",
            req_headers={"content-type": "application/json"},
            req_body=b'{"user":"bob","pass":"hunter2"}',
            status=200,
            resp_headers={"content-type": "application/json"},
            resp_body=b'{"session":"sess-abc"}',
        )
    )
    backend = _backend(monkeypatch, recorder)

    body_hit = backend.search("s", "hunter2")
    assert body_hit["total"] == 1
    assert body_hit["matches"][0]["matched_in"] == ["request_body"]

    resp_hit = backend.search("s", "sess-abc")
    assert resp_hit["total"] == 1
    assert resp_hit["matches"][0]["matched_in"] == ["response_body"]

    miss = backend.search("s", "not-present-anywhere")
    assert miss["total"] == 0
    assert miss["matches"] == []


def test_proxy_search_rejects_bad_query(monkeypatch: Any) -> None:
    """An empty or oversized query is invalid_params before any scan."""
    backend = _backend(monkeypatch, _FakeRecorder([], {}))
    with pytest.raises(ProxyError) as empty:
        backend.search("s", "")
    assert empty.value.code == "invalid_params"
    with pytest.raises(ProxyError) as huge:
        backend.search("s", "x" * (_MAX_SEARCH_QUERY + 1))
    assert huge.value.code == "invalid_params"


def test_proxy_search_docstring_names_the_fields() -> None:
    doc = _tool_docstring("proxy.search")
    for token in ("matches", "matched_in", "snippet", "captured", "searched",
                  "body_unavailable", "filter"):
        assert token in doc, token
