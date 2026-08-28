"""proxy.endpoints folds flows into distinct (method, host, path) endpoints.

The core is fold_endpoints, pure over the recorder's summary rows, so these
drive it directly with fake rows. No live proxy needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy.client import fold_endpoints
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


def _row(method: str, url: str, host: str, status: int | None, **extra: Any) -> dict[str, Any]:
    row = {"method": method, "url": url, "host": host, "status": status}
    row.update(extra)
    return row


def test_endpoints_collapse_query_strings() -> None:
    rows = [
        _row("GET", "https://api.example/search?q=a", "api.example", 200),
        _row("GET", "https://api.example/search?q=b", "api.example", 200),
        _row("GET", "https://api.example/search?q=c", "api.example", 404),
    ]
    result = fold_endpoints(rows)
    assert result["total"] == 1
    endpoint = result["endpoints"][0]
    assert endpoint["method"] == "GET"
    assert endpoint["host"] == "api.example"
    assert endpoint["path"] == "/search"
    assert endpoint["hits"] == 3
    assert endpoint["statuses"] == [200, 404]


def test_endpoints_split_on_method_and_path() -> None:
    rows = [
        _row("GET", "https://h/a", "h", 200),
        _row("POST", "https://h/a", "h", 201),
        _row("GET", "https://h/b", "h", 200),
    ]
    result = fold_endpoints(rows)
    assert result["total"] == 3
    keys = {(e["method"], e["path"]) for e in result["endpoints"]}
    assert keys == {("GET", "/a"), ("POST", "/a"), ("GET", "/b")}


def test_endpoints_count_errors_and_rank_by_hits() -> None:
    rows = [
        _row("GET", "https://h/hot", "h", 200),
        _row("GET", "https://h/hot", "h", 200),
        _row("GET", "https://h/cold", "h", None, error=True),
    ]
    result = fold_endpoints(rows)
    # Busiest endpoint first.
    assert result["endpoints"][0]["path"] == "/hot"
    assert result["endpoints"][0]["hits"] == 2
    cold = next(e for e in result["endpoints"] if e["path"] == "/cold")
    assert cold["errors"] == 1
    assert cold["statuses"] == []  # a null status contributes no code


def test_endpoints_derive_host_from_url_when_row_lacks_it() -> None:
    rows = [_row("GET", "https://derived.host/x", "", 200)]
    result = fold_endpoints(rows)
    assert result["endpoints"][0]["host"] == "derived.host"


def test_endpoints_cap_the_returned_list() -> None:
    rows = [_row("GET", f"https://h/{i}", "h", 200) for i in range(10)]
    result = fold_endpoints(rows, limit=3)
    assert result["count"] == 3
    assert result["total"] == 10
    assert result["truncated"] is True


def test_endpoints_on_an_empty_capture() -> None:
    result = fold_endpoints([])
    assert result["total"] == 0
    assert result["total_flows"] == 0
    assert result["endpoints"] == []


def test_proxy_endpoints_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.endpoints")
    assert "statuses" in doc
    assert "total_flows" in doc
    assert "hits" in doc
