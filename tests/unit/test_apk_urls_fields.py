"""apk.urls extracts schemed URLs from the DEX string pool.

It mocks the parsed analysis with a fake string pool and checks: only schemed
URLs are kept (schemeless paths ignored), host/scheme parsing (path/query/
userinfo stripped, scheme lowercased), trailing-punctuation trimming, dedup and
sorting, the per-string length clamp, pagination, both scan ceilings, and the
tool docstring.
"""

from __future__ import annotations

import ast
import types
from pathlib import Path

import headless_re_mcp.backends.apk.client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


class _Str:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _Analysis:
    def __init__(self, values: list[str]) -> None:
        self._strings = [_Str(v) for v in values]

    def get_strings(self) -> list[_Str]:
        return self._strings


def _client(values: list[str]) -> ApkClient:
    client = ApkClient()
    parsed = types.SimpleNamespace(analysis=_Analysis(values))
    client._parsed = lambda _path: parsed  # type: ignore[method-assign,return-value]
    return client


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_extracts_dedups_and_sorts_urls() -> None:
    values = [
        "visit https://api.example.com/v1/users?x=1 now",
        "http://cdn.example.net/a.js",
        "nothing to see",
        "https://api.example.com/v1/users?x=1",  # duplicate
    ]
    payload = _client(values).urls(Path("d.apk"))
    assert payload["total"] == 2
    assert payload["urls"] == [
        {"url": "http://cdn.example.net/a.js", "host": "cdn.example.net", "scheme": "http"},
        {
            "url": "https://api.example.com/v1/users?x=1",
            "host": "api.example.com",
            "scheme": "https",
        },
    ]


def test_userinfo_and_scheme_normalisation() -> None:
    payload = _client(["ftp://user:pass@files.example.org/x", "HTTPS://Example.COM/p"]).urls(
        Path("d")
    )
    by_scheme = {row["scheme"]: row for row in payload["urls"]}
    assert by_scheme["ftp"]["host"] == "files.example.org"
    # scheme is lowercased; the host keeps its original casing.
    assert by_scheme["https"]["host"] == "Example.COM"


def test_trailing_punctuation_and_brackets_are_trimmed() -> None:
    payload = _client(["see https://example.com/path.", "(https://paren.example.com)"]).urls(
        Path("d")
    )
    urls = {row["url"] for row in payload["urls"]}
    assert "https://example.com/path" in urls
    assert "https://paren.example.com" in urls


def test_schemeless_strings_are_ignored() -> None:
    payload = _client(["/api/v1/users", "www.example.com", "just text"]).urls(Path("d"))
    assert payload["urls"] == []
    assert payload["total"] == 0


def test_per_string_length_clamp(monkeypatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_STRING_LEN", 20)
    # The URL sits past the 20-char clamp, so it is never seen.
    payload = _client(["x" * 25 + "https://late.example.com/x"]).urls(Path("d"))
    assert payload["urls"] == []


def test_pagination_reports_total_and_has_more() -> None:
    values = [f"https://h{i:02d}.example.com/" for i in range(5)]
    payload = _client(values).urls(Path("d"), offset=1, limit=2)
    assert payload["total"] == 5
    assert payload["count"] == 2
    assert payload["offset"] == 1
    assert [row["host"] for row in payload["urls"]] == ["h01.example.com", "h02.example.com"]
    assert payload["has_more"] is True


def test_url_collect_ceiling_sets_scan_capped(monkeypatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_URLS_COLLECT", 1)
    payload = _client(["https://a.example.com https://b.example.com"]).urls(Path("d"))
    assert payload["total"] == 1
    assert payload["scan_capped"] is True


def test_string_scan_ceiling_sets_scan_capped(monkeypatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_URL_STRINGS_SCAN", 1)
    values = ["https://a.example.com/", "https://b.example.com/", "https://c.example.com/"]
    payload = _client(values).urls(Path("d"))
    # Only the first string is scanned before the ceiling stops the walk.
    assert payload["total"] == 1
    assert payload["scan_capped"] is True


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.urls")
    assert "Answers with" in doc
    assert "urls" in doc and "host" in doc and "scheme" in doc
    assert "scan_capped" in doc
