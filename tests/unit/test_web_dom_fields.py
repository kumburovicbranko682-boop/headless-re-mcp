"""web.dom.snapshot description must name html and truncated."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend
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
    url = "https://example/app"

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script
        html = "x" * (_MAX_INLINE_BODY + 50)
        return {"html": html[:cap], "truncated": True}

    def title(self) -> str:
        return "Example"


def test_web_dom_snapshot_names_html_and_says_when_it_was_cut(
    monkeypatch: Any,
) -> None:
    """The catalog said HTML and never named the payload.

    Measured: truncated True, html 200000 chars (the cap), no content, dom
    or body field. Looking for those after a successful call reads as a
    missing document, and a 200000-char string with no truncated flag
    reads as the whole page.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s")
    assert "content" not in payload
    assert "dom" not in payload
    assert "body" not in payload
    assert payload["truncated"] is True
    assert payload["url"] == "https://example/app"
    assert payload["title"] == "Example"
    assert len(payload["html"]) == _MAX_INLINE_BODY
    doc = _tool_docstring("web.dom.snapshot")
    assert "html" in doc
    assert "truncated" in doc


class _EscapePage:
    url = "https://example/app"

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script, cap
        return {"html": "d" * 3000, "truncated": False}

    def title(self) -> str:
        return "Example"


def test_web_dom_snapshot_bounds_html_by_encoded_size(monkeypatch: Any) -> None:
    """An escape-heavy DOM must not push the reply past the result budget.

    dom_snapshot keeps no spill copy, so an oversized html would take the whole
    reply down with it at the transport. Shrink the budget and confirm the html
    is trimmed to fit the encoded budget and flagged truncated, rather than
    returned whole.
    """
    import json

    from headless_re_mcp.backends.common import json_budget
    from headless_re_mcp.backends.web import client as web_client

    monkeypatch.setattr(json_budget, "RESULT_BUDGET_BYTES", 500)
    monkeypatch.setattr(web_client, "_WEB_FIELD_RESERVE", 100)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_EscapePage()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s")
    assert payload["truncated"] is True
    assert len(payload["html"]) < 3000
    assert len(json.dumps(payload["html"], ensure_ascii=False).encode("utf-8")) <= 500 - 100
