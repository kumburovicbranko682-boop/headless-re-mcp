"""proxy.search scans url/host/headers/bodies for a literal substring.

The core is search_flows, pure over the recorder's two views (the summary rows
plus a flow_id -> raw-flow lookup), so these drive it with fake rows and a fake
lookup returning minimal request/response stand-ins. No live proxy needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    search_flows,
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


class _Headers:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        del multi
        return list(self._items)


class _Part:
    def __init__(self, headers: list[tuple[str, str]], body: bytes) -> None:
        self.headers = _Headers(headers)
        self.raw_content = body


def _flow(
    *,
    req_headers: list[tuple[str, str]] | None = None,
    req_body: bytes = b"",
    resp_headers: list[tuple[str, str]] | None = None,
    resp_body: bytes = b"",
) -> Any:
    return SimpleNamespace(
        request=_Part(req_headers or [], req_body),
        response=_Part(resp_headers or [], resp_body),
    )


def _row(flow_id: str, method: str, url: str, host: str, status: int) -> dict[str, Any]:
    return {
        "id": flow_id,
        "method": method,
        "url": url,
        "host": host,
        "status": status,
    }


def _rows() -> list[dict[str, Any]]:
    return [
        _row("1", "GET", "https://api.example/login", "api.example", 200),
        _row("2", "POST", "https://api.example/token", "api.example", 201),
        _row("3", "GET", "https://cdn.other/app.js", "cdn.other", 200),
    ]


def test_search_matches_url_and_host_from_the_summary() -> None:
    result = search_flows(_rows(), lambda _id: None, "example")
    assert result["count"] == 2  # both api.example rows
    assert result["scanned"] == 3
    ids = {m["id"] for m in result["matches"]}
    assert ids == {"1", "2"}
    for match in result["matches"]:
        assert "host" in match["matched_in"]


def test_search_reaches_into_headers_and_bodies() -> None:
    raw = {
        "2": _flow(
            req_headers=[("Authorization", "Bearer sekret-42")],
            req_body=b'{"password":"hunter2"}',
            resp_body=b'{"token":"sekret-42"}',
        )
    }
    result = search_flows(_rows(), lambda flow_id: raw.get(flow_id), "sekret-42")
    assert result["count"] == 1
    match = result["matches"][0]
    assert match["id"] == "2"
    assert "request_headers" in match["matched_in"]
    assert "response_body" in match["matched_in"]
    # A header/body hit carries a bounded snippet around the match.
    assert "sekret-42" in match["snippets"]["request_headers"]


def test_search_is_case_insensitive_by_default() -> None:
    raw = {"1": _flow(resp_body=b"Set-Cookie: SessionID=ABC")}
    ci = search_flows(_rows(), lambda flow_id: raw.get(flow_id), "sessionid")
    assert ci["count"] == 1
    cs = search_flows(
        _rows(), lambda flow_id: raw.get(flow_id), "sessionid", case_sensitive=True
    )
    assert cs["count"] == 0


def test_search_counts_flows_whose_body_was_evicted() -> None:
    """An omitted flow can only match url/host; report it in body_unavailable."""
    result = search_flows(
        _rows(),
        lambda flow_id: _OMITTED_BODY if flow_id == "2" else None,
        "no-such-token",
    )
    assert result["count"] == 0
    assert result["body_unavailable"] == 1


def test_search_caps_the_result_list() -> None:
    rows = [
        _row(str(i), "GET", f"https://h/{i}", "h", 200) for i in range(10)
    ]
    result = search_flows(rows, lambda _id: None, "https", limit=3)
    assert result["count"] == 3
    assert result["truncated"] is True


def test_search_on_an_empty_capture() -> None:
    result = search_flows([], lambda _id: None, "anything")
    assert result["count"] == 0
    assert result["scanned"] == 0
    assert result["truncated"] is False
    assert result["body_unavailable"] == 0


def test_proxy_search_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.search")
    assert "matched_in" in doc
    assert "snippets" in doc
    assert "body_unavailable" in doc
    assert "case_sensitive" in doc
