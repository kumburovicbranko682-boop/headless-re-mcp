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
        return None

    def title(self) -> str:
        return "Example"


class _StatusPage:
    """A page whose navigation lands on a real HTTP response with a status."""

    url = "https://old/"

    def __init__(self, status: int) -> None:
        self._status = status

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> Any:
        self.url = url
        return SimpleNamespace(status=self._status)

    def title(self) -> str:
        return "Gated"


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


def test_web_navigate_surfaces_the_http_status(monkeypatch: Any) -> None:
    """A 403 wall must not read as a clean navigation.

    page.goto succeeds for any HTTP response and only raises on a transport
    failure, so a gated 403/404 landing used to report url and title with no
    hint the request was refused. The status the response already carried is
    now surfaced so an unattended caller can see the wall.
    """
    backend = WebBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(page=_StatusPage(403))
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.navigate("s", "https://example/gated")
    assert payload["status"] == 403
    assert payload["url"] == "https://example/gated"
    doc = _tool_docstring("web.navigate")
    assert "status" in doc


def test_web_navigate_status_is_none_for_a_same_document_navigation(
    monkeypatch: Any,
) -> None:
    """goto returns None for a same-document navigation; status must be null."""
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.navigate("s", "https://example/app#section")
    assert payload["status"] is None
