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
    """A page whose HTML fits the character cap but blows the byte budget.

    Each character is three UTF-8 bytes, so a run just under the character cap
    is still nearly three times _MAX_INLINE_BODY bytes. The browser slice keeps
    the whole run (its cap counts characters), which is exactly the case the
    old Python guard missed: it clipped and flagged on character length, which
    can never exceed the cap the script already applied.
    """

    url = "https://example/app"

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script
        # Two-thirds of the character cap, all 3-byte characters -> the run is
        # under `cap` characters (so the browser does not truncate) but roughly
        # twice _MAX_INLINE_BODY bytes.
        html = "\u4e2d" * ((_MAX_INLINE_BODY // 3) * 2)
        return {"html": html[:cap], "truncated": False}

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


def test_web_dom_snapshot_bounds_inline_html_by_bytes_not_characters(
    monkeypatch: Any,
) -> None:
    """The inline HTML honours the byte budget script.source/network.get use.

    _MAX_INLINE_BODY is a byte budget: script.source and network.get encode to
    UTF-8 and cap on len(bytes). dom.snapshot capped on characters, so a page of
    3-byte characters that fit the character cap returned ~2x the byte budget --
    the browser did not truncate (its cap counts characters) and the Python side
    re-checked in characters too, so it neither shrank nor flagged the payload.
    The reply must be no larger than the byte budget and must say it was cut.
    """
    backend = WebBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(page=_MultibytePage())
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s")
    assert len(payload["html"].encode("utf-8")) <= _MAX_INLINE_BODY
    # The browser reported no truncation (character count under the cap); the
    # byte clip is what caught the overflow, so truncated must still be True.
    assert payload["truncated"] is True
