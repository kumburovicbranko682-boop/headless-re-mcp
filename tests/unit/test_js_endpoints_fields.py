"""js.endpoints extracts the network surface (URLs, hosts, paths) from JS.

js.strings returns every literal; js.endpoints is the higher-signal cut on the
same lexer -- the URLs, hosts and request paths a bundle references. These cover
URL and path extraction, escape-decoding, dedup/aggregation, the host summary,
comment/regex safety (reused lexer), the include_paths toggle, the filter,
the collect cap, client paging, the webcrack-free path, errors, service routing,
and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre import js_strings as js_strings_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_strings import extract_endpoints
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _by_value(source: str, **kwargs: Any) -> dict[str, dict[str, Any]]:
    endpoints, _hosts, _ht, _sc = extract_endpoints(source, **kwargs)
    return {e["value"]: e for e in endpoints}


def test_extracts_absolute_url_with_scheme_and_host() -> None:
    endpoints, hosts, ht, capped = extract_endpoints('var a = "https://api.test/v1/users";')
    assert capped is False and ht is False
    assert len(endpoints) == 1
    row = endpoints[0]
    assert row["value"] == "https://api.test/v1/users"
    assert row["kind"] == "url"
    assert row["scheme"] == "https"
    assert row["host"] == "api.test"
    assert row["count"] == 1
    assert hosts == ["api.test"]


def test_deduplicates_and_counts_occurrences() -> None:
    src = 'a="https://d.test/x"; b="https://d.test/x";'
    endpoints, _hosts, _ht, _sc = extract_endpoints(src)
    assert len(endpoints) == 1
    assert endpoints[0]["count"] == 2
    assert endpoints[0]["first_offset"] == src.index('"')


def test_decodes_hex_escaped_url() -> None:
    src = r'var u = "\x68\x74\x74\x70://ex.test/beacon";'
    endpoints = _by_value(src)
    assert "http://ex.test/beacon" in endpoints


def test_extracts_request_paths() -> None:
    src = "a='/api/login'; b='/users/profile'; c='/x'; d='/';"
    endpoints = _by_value(src)
    assert "/api/login" in endpoints  # single api segment
    assert "/users/profile" in endpoints  # two segments
    assert endpoints["/api/login"]["kind"] == "path"
    assert endpoints["/api/login"]["host"] == ""
    # '/x' is one non-api segment and '/' is empty: neither is an endpoint.
    assert "/x" not in endpoints
    assert "/" not in endpoints


def test_include_paths_false_drops_relative_paths() -> None:
    src = "a='/api/login'; b=\"https://api.test/x\";"
    endpoints = _by_value(src, include_paths=False)
    assert "/api/login" not in endpoints
    assert "https://api.test/x" in endpoints


def test_host_summary_is_distinct_and_sorted() -> None:
    src = 'a="https://b.test/1"; b="https://a.test/2"; c="https://b.test/3";'
    _endpoints, hosts, _ht, _sc = extract_endpoints(src)
    assert hosts == ["a.test", "b.test"]


def test_trailing_punctuation_is_stripped() -> None:
    endpoints = _by_value('var s = "see https://a.test/x.";')
    assert "https://a.test/x" in endpoints


def test_urls_in_comments_are_not_extracted() -> None:
    src = "// https://comment.test/nope\nvar s = '/api/real';"
    endpoints = _by_value(src)
    assert "/api/real" in endpoints
    assert all("comment.test" not in v for v in endpoints)


def test_urls_in_regex_literals_are_not_extracted() -> None:
    src = "var re = /https:\\/\\/inregex/; var s = \"https://real.test/ok\";"
    endpoints = _by_value(src)
    assert "https://real.test/ok" in endpoints
    assert all("inregex" not in v for v in endpoints)


def test_websocket_scheme_is_recognised() -> None:
    row = _by_value('var w = "wss://rt.test/socket";')["wss://rt.test/socket"]
    assert row["kind"] == "url"
    assert row["scheme"] == "wss"
    assert row["host"] == "rt.test"


def test_name_filter_matches_host_or_value() -> None:
    src = 'a="https://api.test/x"; b="https://cdn.test/y"; c="/api/z";'
    endpoints, _hosts, _ht, _sc = extract_endpoints(src, name_filter="cdn")
    assert [e["value"] for e in endpoints] == ["https://cdn.test/y"]


def test_sorted_by_count_descending() -> None:
    src = 'x="https://a.test/1";y="https://a.test/1";z="https://b.test/2";'
    endpoints, _hosts, _ht, _sc = extract_endpoints(src)
    assert endpoints[0]["value"] == "https://a.test/1"
    assert endpoints[0]["count"] == 2


def test_collect_cap_sets_scan_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(js_strings_mod, "_MAX_ENDPOINTS_COLLECT", 2)
    src = ";".join(f'x="https://h{i}.test/p"' for i in range(5))
    endpoints, _hosts, _ht, capped = extract_endpoints(src)
    assert capped is True
    assert len(endpoints) == 2


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bundle.js"
    p.write_text(text, encoding="utf-8")
    return p


def test_client_endpoints_pages_and_summarises(tmp_path: Path) -> None:
    src = ";".join(f'u="https://h{i:02d}.test/p"' for i in range(10))
    out = JsClient().endpoints(_write(tmp_path, src), limit=3)
    assert out["count"] == 3
    assert out["total"] == 10
    assert out["has_more"] is True
    assert len(out["hosts"]) == 10
    assert out["scan_capped"] is False


def test_client_endpoints_works_without_webcrack(tmp_path: Path) -> None:
    client = JsClient(executable=None)
    assert client.available is False
    out = client.endpoints(_write(tmp_path, 'fetch("https://x.test/api");'))
    assert [e["value"] for e in out["endpoints"]] == ["https://x.test/api"]


def test_client_endpoints_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        JsClient().endpoints(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_client_endpoints_page_limit_is_capped(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_JS_ENDPOINTS_PAGE", 2)
    src = ";".join(f'u="https://h{i:02d}.test/p"' for i in range(6))
    out = JsClient().endpoints(_write(tmp_path, src), limit=1000)
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_service_js_endpoints_routes_to_client(tmp_path: Path) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        src = 'a="https://api.example.com/token"; b="https://cdn.other.com/x";'
        p = _write(tmp_path, src)
        result = service.js_endpoints(str(p), name_filter="api.example")
        assert result.ok and result.data is not None
        assert [e["value"] for e in result.data["endpoints"]] == [
            "https://api.example.com/token"
        ]
        assert result.data["total"] == 1
        assert result.data["hosts"] == ["api.example.com"]
    finally:
        service.close_all()


def test_js_endpoints_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("js.endpoints").split())
    assert "endpoints" in doc
    assert "hosts" in doc
    assert "include_paths" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "js.endpoints" in _READ_ONLY_NAMES
