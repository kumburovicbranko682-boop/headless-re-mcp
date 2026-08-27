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

    def __init__(self, response: Any = None) -> None:
        self._response = response

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> Any:
        self.url = url
        return self._response

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
    doc = _tool_docstring("web.navigate")
    assert "Answers with url" in doc
    assert "title" in doc
    assert "status" in doc


def test_web_navigate_surfaces_the_http_status_so_an_error_page_is_visible(
    monkeypatch: Any,
) -> None:
    """A 404/500 page still navigates; the status is how a caller sees it.

    page.goto returns the main-frame response, which carries the HTTP status.
    Dropping it reported an error page as a clean load -- the same partial
    success this campaign has been surfacing elsewhere.
    """
    backend = WebBackend()
    page = _Page(response=SimpleNamespace(status=404))
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.navigate("s", "https://example/missing")
    assert payload["status"] == 404
    assert payload["url"] == "https://example/missing"


def test_web_navigate_omits_status_when_the_navigation_returned_none(
    monkeypatch: Any,
) -> None:
    """A same-document/about:blank navigation has no response; do not invent one."""
    backend = WebBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(page=_Page(response=None))
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.navigate("s", "https://example/app")
    assert "status" not in payload
