"""web.navigate description must name url and title."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
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
    url = "https://old/"

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> None:
        self.url = url

    def title(self) -> str:
        return "Example"


def test_web_navigate_puts_the_result_in_url_and_title(monkeypatch: Any) -> None:
    """The catalog said navigate and never named the payload.

    Measured: url and title, no navigated, ok or page field. Looking for
    those after a successful call reads as a failed navigation.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.navigate("s", "https://example/app")
    assert "navigated" not in payload
    assert "ok" not in payload
    assert "page" not in payload
    assert payload["url"] == "https://example/app"
    assert payload["title"] == "Example"
    # goto returned no response here, so status is null rather than absent.
    assert payload["status"] is None
    doc = _tool_docstring("web.navigate")
    assert "Answers with url" in doc
    assert "title" in doc
    assert "status" in doc
