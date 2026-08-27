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


class _MultibytePage:
    """Emulate the in-browser clip faithfully: it counts code units, not bytes."""

    url = "https://example/app"

    def __init__(self, char_count: int) -> None:
        self._html = "\u6587" * char_count  # CJK: 3 UTF-8 bytes per char

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script
        text = self._html
        over = len(text) > cap
        return {"html": text[:cap] if over else text, "truncated": over}

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


def test_web_dom_snapshot_caps_inline_html_by_bytes_not_characters(
    monkeypatch: Any,
) -> None:
    """A multibyte page under the code-unit clip still blew the byte budget.

    _MAX_INLINE_BODY is a byte budget everywhere else in this backend
    (_spill_text encodes to UTF-8 and caps on len(payload)). dom_snapshot
    applied it as a character count, so 100000 CJK chars -- 300000 bytes, well
    over the 200000-byte cap, but only half the 200000 code-unit clip -- were
    inlined whole and flagged truncated=False. The response html must be capped
    on its real UTF-8 size and marked truncated when the cap bites, like every
    sibling reader.
    """
    backend = WebBackend()
    page = _MultibytePage(100_000)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s")
    assert len(payload["html"].encode("utf-8")) <= _MAX_INLINE_BODY
    assert len(payload["html"]) < 100_000
    assert payload["truncated"] is True
