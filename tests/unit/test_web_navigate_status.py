"""web.navigate / web.open must surface the main document's HTTP status.

Playwright's page.goto only raises on a network-level failure; a page that
answered 403/404/500 is a *successful* goto that returns a Response. The old
code discarded that Response, so an error landing page read as a clean load.
These tests pin that status now comes back, and that a missing response is
reported as null rather than dropped.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.tools.web import build_web_tools


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Response:
    def __init__(self, status: Any) -> None:
        self.status = status


class _Page:
    def __init__(self, response: Any) -> None:
        self._response = response
        self.url = "https://old/"

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> Any:
        self.url = url
        return self._response

    def title(self) -> str:
        return "T"


def _backend(monkeypatch: Any, response: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(page=_Page(response))
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_a_404_landing_is_reported_not_read_as_a_clean_load(monkeypatch: Any) -> None:
    """A goto that resolved to a 404 page comes back with status 404."""
    backend = _backend(monkeypatch, _Response(404))
    payload = backend.navigate("s", "https://example/missing")
    assert payload["status"] == 404
    assert payload["url"] == "https://example/missing"


def test_a_200_load_reports_status_200(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _Response(200))
    payload = backend.navigate("s", "https://example/ok")
    assert payload["status"] == 200


def test_no_response_yields_null_status_not_a_missing_key(monkeypatch: Any) -> None:
    """Same-document jumps return no response; status must be an explicit null."""
    backend = _backend(monkeypatch, None)
    payload = backend.navigate("s", "https://example/#anchor")
    assert "status" in payload
    assert payload["status"] is None


def test_a_string_status_is_coerced_to_an_int(monkeypatch: Any) -> None:
    """Whatever the driver hands back, status is a plain int or null."""
    backend = _backend(monkeypatch, _Response("301"))
    payload = backend.navigate("s", "https://example/redir")
    assert payload["status"] == 301


def test_a_response_without_a_status_is_null_not_a_crash(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, SimpleNamespace())  # no .status attribute
    payload = backend.navigate("s", "https://example/weird")
    assert payload["status"] is None


def _open_summary_literal() -> str:
    source = Path(WebBackend.open.__code__.co_filename).read_text(encoding="utf-8")
    marker = source.index("summary = {")
    return source[marker : source.index("}", marker) + 1]


def test_web_open_summary_includes_status() -> None:
    """web.open is launch-heavy to run; assert its summary literal carries status."""
    literal = _open_summary_literal()
    assert '"status"' in literal
    assert '"opened"' in literal


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


def test_both_docstrings_name_status() -> None:
    assert "status" in _tool_docstring("web.open")
    assert "status" in _tool_docstring("web.navigate")
