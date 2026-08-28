"""web.links maps outbound anchors and subresource origins, bounded.

Driven through the _get/_runner seam with a fake page whose evaluate() returns
the shape the in-page script produces. No real browser is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _fold_links
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


def _dump() -> dict[str, Any]:
    return {
        "anchors": [
            {"href": "https://example.com/about", "text": "About", "target": "", "rel": ""},
            {
                "href": "https://evil.example.net/collect",
                "text": "Click",
                "target": "_blank",
                "rel": "noopener",
            },
            {"href": "mailto:hi@example.com", "text": "Mail", "target": "", "rel": ""},
        ],
        "anchor_total": 3,
        "resources": [
            {"url": "https://cdn.stranger.io/x.js", "kind": "script"},
            {"url": "https://example.com/app.css", "kind": "link"},
        ],
        "resource_total": 2,
    }


def test_links_classify_anchor_external_by_host() -> None:
    payload = _fold_links(_dump(), "https://example.com/home")
    by_href = {a["href"]: a for a in payload["anchors"]}
    assert by_href["https://example.com/about"]["external"] is False
    assert by_href["https://evil.example.net/collect"]["external"] is True
    # A mailto anchor has no host, so it is neither external nor an origin.
    assert by_href["mailto:hi@example.com"]["host"] == ""
    assert by_href["mailto:hi@example.com"]["external"] is False


def test_links_roll_up_origins_ranked_with_external_flag() -> None:
    payload = _fold_links(_dump(), "https://example.com/home")
    origins = {o["origin"]: o for o in payload["origins"]}
    # example.com appears twice (anchor + css), stranger and evil once each.
    assert origins["https://example.com"]["count"] == 2
    assert origins["https://example.com"]["external"] is False
    assert origins["https://cdn.stranger.io"]["external"] is True
    assert origins["https://evil.example.net"]["external"] is True
    # mailto contributes no origin.
    assert "mailto:hi@example.com" not in origins
    assert payload["external_origin_count"] == 2
    # Ranked by count: example.com (2) leads.
    assert payload["origins"][0]["origin"] == "https://example.com"


def test_links_classify_resources_by_kind_and_host() -> None:
    payload = _fold_links(_dump(), "https://example.com/home")
    by_url = {r["url"]: r for r in payload["resources"]}
    assert by_url["https://cdn.stranger.io/x.js"]["kind"] == "script"
    assert by_url["https://cdn.stranger.io/x.js"]["external"] is True
    assert by_url["https://example.com/app.css"]["external"] is False


def test_links_report_truncation() -> None:
    raw = _dump()
    raw["anchor_total"] = 900
    raw["resource_total"] = 700
    payload = _fold_links(raw, "https://example.com/home")
    assert payload["anchors_truncated"] is True
    assert payload["resources_truncated"] is True


def test_links_run_through_the_backend_seam(monkeypatch: Any) -> None:
    payload = _backend_with(monkeypatch, _dump(), "https://example.com/home").links("s")
    assert payload["url"] == "https://example.com/home"
    assert payload["anchor_count"] == 3
    assert payload["resource_count"] == 2


def test_web_links_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.links")
    assert "origins" in doc
    assert "external" in doc
    assert "resources" in doc
    assert "anchors_truncated" in doc
