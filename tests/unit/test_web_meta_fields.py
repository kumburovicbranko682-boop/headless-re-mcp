"""web.meta assembles the page head: title/charset/base plus meta and link tags.

These mock the browser handle's page.evaluate so the shaping -- the per-meta
{content + whichever identifying key was set}, the per-link {href,rel,type},
the two caps with their truncation flags, and a non-dict payload -- is pinned
without a live browser.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_LINK_ITEMS,
    _MAX_META_ITEMS,
    WebBackend,
    WebError,
)
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


class _FakePage:
    def __init__(self, payload: Any, *, raises: Exception | None = None) -> None:
        self._payload = payload
        self._raises = raises
        self.calls: list[Any] = []

    def evaluate(self, script: str, arg: Any = None) -> Any:
        del script
        self.calls.append(arg)
        if self._raises is not None:
            raise self._raises
        return self._payload


class _MetaRunner:
    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()


class _MetaHandle:
    def __init__(self, page: _FakePage) -> None:
        self.page = page
        self.runner = _MetaRunner()


def _backend_with(monkeypatch: Any, page: _FakePage) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _MetaHandle(page))
    return backend


def test_web_meta_reads_identity_metas_and_links(monkeypatch: Any) -> None:
    payload = {
        "url": "https://bank.example/login",
        "title": "Sign in",
        "charset": "UTF-8",
        "base": "https://cdn.example/app/",
        "metas": [
            {
                "name": None,
                "property": None,
                "http_equiv": None,
                "content": None,
                "charset": "utf-8",
            },
            {
                "name": "description",
                "property": None,
                "http_equiv": None,
                "content": "Log in",
                "charset": None,
            },
            {
                "name": None,
                "property": "og:url",
                "http_equiv": None,
                "content": "https://other.example/",
                "charset": None,
            },
            {
                "name": None,
                "property": None,
                "http_equiv": "refresh",
                "content": "0;url=https://evil.example/",
                "charset": None,
            },
        ],
        "meta_total": 4,
        "links": [
            {"rel": "canonical", "href": "https://bank.example/login", "type": None},
            {
                "rel": "manifest",
                "href": "https://bank.example/app.webmanifest",
                "type": "application/manifest+json",
            },
        ],
        "link_total": 2,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.meta("s")

    assert result["url"] == "https://bank.example/login"
    assert result["title"] == "Sign in"
    assert result["charset"] == "UTF-8"
    # The <base href> silently rebases every relative URL: it must surface.
    assert result["base"] == "https://cdn.example/app/"

    metas = result["metas"]
    assert result["meta_count"] == result["meta_total"] == 4
    assert result["metas_truncated"] is False
    # Each entry keeps only the identifying key it actually set.
    assert metas[0] == {"content": "", "charset": "utf-8"}
    assert metas[1] == {"content": "Log in", "name": "description"}
    assert metas[2] == {"content": "https://other.example/", "property": "og:url"}
    # The client-side redirect is the point of surfacing http-equiv.
    assert metas[3] == {"content": "0;url=https://evil.example/", "http_equiv": "refresh"}

    links = result["links"]
    assert result["link_count"] == result["link_total"] == 2
    assert result["links_truncated"] is False
    assert links[0] == {"href": "https://bank.example/login", "rel": "canonical"}
    assert links[1]["rel"] == "manifest"
    assert links[1]["type"] == "application/manifest+json"


def test_web_meta_reports_meta_and_link_overflow(monkeypatch: Any) -> None:
    # The browser slices at the caps; the *_total counts drive the flags.
    payload = {
        "url": "https://x/",
        "title": "",
        "charset": "UTF-8",
        "base": "",
        "metas": [
            {"name": f"m{i}", "property": None, "http_equiv": None, "content": "", "charset": None}
            for i in range(_MAX_META_ITEMS)
        ],
        "meta_total": _MAX_META_ITEMS + 7,
        "links": [
            {"rel": "preload", "href": f"https://x/{i}.js", "type": None}
            for i in range(_MAX_LINK_ITEMS)
        ],
        "link_total": _MAX_LINK_ITEMS + 3,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.meta("s")
    assert result["meta_count"] == _MAX_META_ITEMS
    assert result["meta_total"] == _MAX_META_ITEMS + 7
    assert result["metas_truncated"] is True
    assert result["link_count"] == _MAX_LINK_ITEMS
    assert result["link_total"] == _MAX_LINK_ITEMS + 3
    assert result["links_truncated"] is True


def test_web_meta_reports_a_bare_page(monkeypatch: Any) -> None:
    payload = {
        "url": "about:blank",
        "title": "",
        "charset": "UTF-8",
        "base": "",
        "metas": [],
        "meta_total": 0,
        "links": [],
        "link_total": 0,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.meta("s")
    assert result["metas"] == []
    assert result["links"] == []
    assert result["meta_count"] == result["meta_total"] == 0
    assert result["link_count"] == result["link_total"] == 0
    assert result["metas_truncated"] is False
    assert result["links_truncated"] is False


def test_web_meta_survives_a_non_dict_payload(monkeypatch: Any) -> None:
    backend = _backend_with(monkeypatch, _FakePage(["not", "an", "object"]))
    result = backend.meta("s")
    assert result["metas"] == []
    assert result["links"] == []
    assert result["url"] == ""
    assert result["title"] == ""


def test_web_meta_maps_an_evaluate_crash_to_backend_error(monkeypatch: Any) -> None:
    backend = _backend_with(
        monkeypatch, _FakePage(None, raises=RuntimeError("Execution context was destroyed"))
    )
    with pytest.raises(WebError) as excinfo:
        backend.meta("s")
    assert excinfo.value.code == "backend_error"


def test_web_meta_passes_the_caps_to_the_page(monkeypatch: Any) -> None:
    page = _FakePage(
        {
            "url": "",
            "title": "",
            "charset": "",
            "base": "",
            "metas": [],
            "meta_total": 0,
            "links": [],
            "link_total": 0,
        }
    )
    backend = _backend_with(monkeypatch, page)
    backend.meta("s")
    assert page.calls, "the in-page script was never evaluated"
    cfg = page.calls[0]
    assert cfg["maxMetas"] == _MAX_META_ITEMS
    assert cfg["maxLinks"] == _MAX_LINK_ITEMS


def test_web_meta_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.meta")
    assert doc, "web.meta is missing its docstring"
    assert "base" in doc
    assert "http_equiv" in doc
    assert "canonical" in doc
    assert "metas_truncated" in doc
