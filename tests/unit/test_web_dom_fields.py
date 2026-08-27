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

    def __init__(self, html: str) -> None:
        self._html = html

    def content(self) -> str:
        return self._html

    def title(self) -> str:
        return "Example"


def test_web_dom_snapshot_spills_the_full_document_when_it_is_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A truncated inline DOM with no path is a dead end for a real SPA.

    Measured: a document past the inline cap comes back with html as a 200 KB
    preview, truncated True, bytes at the full length, and html_path to the
    whole document on disk -- so the complete DOM is retrievable, not lost. No
    content, dom or body field.
    """
    html = "x" * (_MAX_INLINE_BODY + 5000)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page(html)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s", tmp_path)
    assert "content" not in payload
    assert "dom" not in payload
    assert "body" not in payload
    assert payload["truncated"] is True
    assert payload["url"] == "https://example/app"
    assert payload["title"] == "Example"
    assert len(payload["html"]) <= _MAX_INLINE_BODY
    assert payload["bytes"] == len(html.encode("utf-8"))
    spilled = Path(payload["html_path"])
    assert spilled.read_text(encoding="utf-8") == html
    doc = _tool_docstring("web.dom.snapshot")
    assert "html" in doc
    assert "truncated" in doc
    assert "html_path" in doc


def test_web_dom_snapshot_inlines_a_small_document_without_spilling(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A small page returns inline and leaves no spill file behind."""
    html = "<html><body>hi</body></html>"
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page(html)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s", tmp_path)
    assert payload["truncated"] is False
    assert payload["html"] == html
    assert "html_path" not in payload
    assert list(tmp_path.iterdir()) == []
