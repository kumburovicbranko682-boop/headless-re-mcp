"""web.links maps the page's outbound anchors and subresources with origins.

These mock the browser handle's page.evaluate so the shaping -- the resolved
absolute href/url, the same/cross-origin external flag, the distinct-origin
roll-up, the two caps, and a non-dict payload -- is pinned without a browser.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_ANCHORS,
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


class _LinksRunner:
    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()


class _LinksHandle:
    def __init__(self, page: _FakePage) -> None:
        self.page = page
        self.runner = _LinksRunner()


def _backend_with(monkeypatch: Any, page: _FakePage) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _LinksHandle(page))
    return backend


def _anchor(href: str, origin: str, **kw: Any) -> dict[str, Any]:
    row = {"href": href, "text": kw.get("text", ""), "target": kw.get("target"),
           "rel": kw.get("rel"), "origin": origin}
    return row


def test_web_links_classifies_origins_and_externality(monkeypatch: Any) -> None:
    """Anchors and resources must carry absolute urls, the external flag, and
    feed the distinct-origin roll-up ranked by hit count."""
    payload = {
        "page_origin": "https://app.example",
        "anchors": [
            _anchor("https://app.example/home", "https://app.example", text="Home"),
            _anchor("https://app.example/help", "https://app.example", text="Help"),
            _anchor("https://evil.test/steal", "https://evil.test", text="Claim",
                    target="_blank", rel="noopener"),
            _anchor("mailto:abuse@app.example", "mailto:", text="Mail us"),
        ],
        "anchor_total": 4,
        "resources": [
            {"url": "https://cdn.example/a.js", "kind": "script", "origin": "https://cdn.example"},
            {"url": "https://app.example/s.css", "kind": "stylesheet",
             "origin": "https://app.example"},
            {"url": "https://evil.test/x.js", "kind": "script", "origin": "https://evil.test"},
        ],
        "resource_total": 3,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.links("s")

    assert result["page_origin"] == "https://app.example"
    assert result["link_count"] == result["link_total"] == 4
    assert result["links_truncated"] is False

    by_href = {link["href"]: link for link in result["links"]}
    assert by_href["https://app.example/home"]["external"] is False
    steal = by_href["https://evil.test/steal"]
    assert steal["external"] is True
    assert steal["target"] == "_blank"
    assert steal["rel"] == "noopener"
    assert steal["text"] == "Claim"
    # A mailto anchor is off-origin: it buckets under its scheme and reads external.
    assert by_href["mailto:abuse@app.example"]["external"] is True

    res_by_url = {r["url"]: r for r in result["resources"]}
    assert res_by_url["https://cdn.example/a.js"]["external"] is True
    assert res_by_url["https://cdn.example/a.js"]["kind"] == "script"
    assert res_by_url["https://app.example/s.css"]["external"] is False

    # The origin roll-up counts hits across anchors AND resources. app.example
    # appears twice as anchor + once as resource = 3; it is the busiest.
    origins = {row["origin"]: row["count"] for row in result["origins"]}
    assert origins["https://app.example"] == 3
    assert origins["https://evil.test"] == 2  # one anchor + one script
    assert origins["https://cdn.example"] == 1
    assert origins["mailto:"] == 1
    assert result["origins"][0]["origin"] == "https://app.example"  # busiest first

    assert result["origin_count"] == 4
    # Off-site distinct origins: evil.test, cdn.example, mailto: -> 3.
    assert result["external_count"] == 3


def test_web_links_reports_resource_overflow(monkeypatch: Any) -> None:
    # The browser slices resources at the cap; resource_total drives truncation.
    emitted = [
        {"url": f"https://cdn/{i}.js", "kind": "script", "origin": "https://cdn"}
        for i in range(10)
    ]
    payload = {
        "page_origin": "https://p",
        "anchors": [],
        "anchor_total": 0,
        "resources": emitted,
        "resource_total": 42,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.links("s")
    assert result["resource_count"] == 10
    assert result["resource_total"] == 42
    assert result["resources_truncated"] is True


def test_web_links_reports_a_page_with_no_links(monkeypatch: Any) -> None:
    payload = {
        "page_origin": "https://p",
        "anchors": [],
        "anchor_total": 0,
        "resources": [],
        "resource_total": 0,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.links("s")
    assert result["links"] == []
    assert result["resources"] == []
    assert result["origins"] == []
    assert result["origin_count"] == result["external_count"] == 0
    assert result["links_truncated"] is False
    assert result["resources_truncated"] is False


def test_web_links_survives_a_non_dict_payload(monkeypatch: Any) -> None:
    backend = _backend_with(monkeypatch, _FakePage("not-an-object"))
    result = backend.links("s")
    assert result["links"] == []
    assert result["resources"] == []
    assert result["page_origin"] == ""


def test_web_links_maps_an_evaluate_crash_to_backend_error(monkeypatch: Any) -> None:
    backend = _backend_with(
        monkeypatch, _FakePage(None, raises=RuntimeError("context destroyed"))
    )
    with pytest.raises(WebError) as excinfo:
        backend.links("s")
    assert excinfo.value.code == "backend_error"


def test_web_links_passes_the_caps_to_the_page(monkeypatch: Any) -> None:
    page = _FakePage(
        {"page_origin": "", "anchors": [], "anchor_total": 0, "resources": [],
         "resource_total": 0}
    )
    backend = _backend_with(monkeypatch, page)
    backend.links("s")
    assert page.calls, "the in-page script was never evaluated"
    cfg = page.calls[0]
    assert cfg["maxAnchors"] == _MAX_ANCHORS
    assert cfg["maxResources"] > 0
    assert cfg["maxValueChars"] > 0


def test_web_links_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.links")
    assert doc, "web.links is missing its docstring"
    assert "external" in doc
    assert "origins" in doc
    assert "resources" in doc
    assert "page_origin" in doc
