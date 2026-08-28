"""web.meta reads the page head's identity, bounded and normalised.

Driven through the _get/_runner seam with a fake page whose evaluate() returns
the shape the in-page script produces. No real browser is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _parse_meta_refresh
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Page:
    def __init__(self, result: dict[str, Any], url: str) -> None:
        self._result = result
        self.url = url

    def evaluate(self, script: str, cfg: dict[str, Any]) -> dict[str, Any]:
        del script, cfg
        return self._result


def _backend_with(monkeypatch: Any, result: dict[str, Any], url: str) -> WebBackend:
    backend = WebBackend()
    page = _Page(result, url)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _head() -> dict[str, Any]:
    return {
        "title": "Sign in",
        "charset": "UTF-8",
        "lang": "en",
        "base": "https://example.com/",
        "metas": [
            {
                "name": "viewport",
                "property": "",
                "http_equiv": "",
                "charset": "",
                "content": "width=device-width",
            },
            {
                "name": "",
                "property": "og:title",
                "http_equiv": "",
                "charset": "",
                "content": "Example",
            },
        ],
        "meta_total": 2,
        "links": [
            {"rel": "canonical", "href": "https://example.com/login", "type": ""},
            {"rel": "icon", "href": "https://example.com/favicon.ico", "type": "image/x-icon"},
        ],
        "link_total": 2,
        "refresh": None,
        "csp": None,
    }


def test_meta_reports_identity(monkeypatch: Any) -> None:
    payload = _backend_with(monkeypatch, _head(), "https://example.com/login").meta("s")
    assert payload["title"] == "Sign in"
    assert payload["charset"] == "UTF-8"
    assert payload["lang"] == "en"
    assert payload["base"] == "https://example.com/"
    assert payload["url"] == "https://example.com/login"


def test_meta_captures_meta_and_link_rows(monkeypatch: Any) -> None:
    payload = _backend_with(monkeypatch, _head(), "https://example.com/login").meta("s")
    assert payload["meta_count"] == 2
    assert payload["meta_total"] == 2
    assert payload["metas_truncated"] is False
    props = {m["property"] for m in payload["metas"]}
    assert "og:title" in props

    rels = {link["rel"]: link for link in payload["links"]}
    assert rels["canonical"]["href"] == "https://example.com/login"
    assert rels["icon"]["type"] == "image/x-icon"


def test_meta_decodes_a_refresh_redirect(monkeypatch: Any) -> None:
    head = _head()
    head["refresh"] = "5; url=https://evil.example.net/landing"
    payload = _backend_with(monkeypatch, head, "https://example.com/login").meta("s")
    assert payload["refresh"] == {"delay": 5, "url": "https://evil.example.net/landing"}


def test_meta_surfaces_a_csp_meta(monkeypatch: Any) -> None:
    head = _head()
    head["csp"] = "default-src 'self'"
    payload = _backend_with(monkeypatch, head, "https://example.com/login").meta("s")
    assert payload["csp"] == "default-src 'self'"


def test_meta_reports_truncation(monkeypatch: Any) -> None:
    head = _head()
    head["meta_total"] = 900
    head["link_total"] = 500
    payload = _backend_with(monkeypatch, head, "https://example.com/login").meta("s")
    assert payload["metas_truncated"] is True
    assert payload["links_truncated"] is True


def test_parse_meta_refresh_variants() -> None:
    assert _parse_meta_refresh("0; url=/next") == {"delay": 0, "url": "/next"}
    assert _parse_meta_refresh("10") == {"delay": 10, "url": None}
    # Quoted target is unquoted.
    assert _parse_meta_refresh("3; URL='https://a.test/x'") == {
        "delay": 3,
        "url": "https://a.test/x",
    }
    # Unparseable content is no redirect at all.
    assert _parse_meta_refresh("not a refresh") is None
    assert _parse_meta_refresh("") is None
    assert _parse_meta_refresh(None) is None


def test_web_meta_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.meta")
    assert "refresh" in doc
    assert "csp" in doc
    assert "metas_truncated" in doc
    assert "canonical" in doc
