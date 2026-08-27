"""web.page reads the live url/title/readyState and stays honest about them."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_URL_BYTES, WebBackend
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
    def __init__(self, url: str, ready: Any, *, raise_eval: bool = False) -> None:
        self.url = url
        self._ready = ready
        self._raise_eval = raise_eval

    def title(self) -> str:
        return "Example App"

    def evaluate(self, script: str) -> Any:
        if self._raise_eval:
            raise RuntimeError("execution context was destroyed")
        return self._ready


def _backend_for(page: _Page, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_page_reports_live_url_title_and_ready_state(monkeypatch: Any) -> None:
    """The current values are read now, not carried over from navigate.

    Measured: url and title from the live page plus ready_state complete.
    An agent confirming where a redirect landed needs the value as it is at
    call time, not the goto-time snapshot.
    """
    backend = _backend_for(_Page("https://example/app#route", "complete"), monkeypatch)
    payload = backend.page_info("s")
    assert payload["url"] == "https://example/app#route"
    assert payload["title"] == "Example App"
    assert payload["ready_state"] == "complete"
    assert "url_truncated" not in payload
    assert "html" not in payload
    doc = _tool_docstring("web.page")
    assert "ready_state" in doc
    assert "url" in doc


def test_web_page_omits_ready_state_when_evaluation_is_blocked(
    monkeypatch: Any,
) -> None:
    """A page that cannot evaluate omits ready_state rather than guessing.

    An agent must not read a missing readyState as "settled"; the field is
    simply absent so the reader knows the load state is unknown, while url
    and title still come back.
    """
    page = _Page("https://example/app", None, raise_eval=True)
    backend = _backend_for(page, monkeypatch)
    payload = backend.page_info("s")
    assert "ready_state" not in payload
    assert payload["url"] == "https://example/app"
    assert payload["title"] == "Example App"


def test_web_page_omits_ready_state_when_value_is_not_a_string(
    monkeypatch: Any,
) -> None:
    """A non-string readyState (odd runtime) is dropped, not coerced."""
    backend = _backend_for(_Page("https://example/", {"unexpected": True}), monkeypatch)
    payload = backend.page_info("s")
    assert "ready_state" not in payload


def test_web_page_flags_a_truncated_url(monkeypatch: Any) -> None:
    """A URL past the buffer is cut and url_truncated says so.

    Measured: a url longer than the metadata bound comes back cut with
    url_truncated True, so the value is never read as the whole address.
    """
    long_url = "https://example/" + ("a" * (_MAX_URL_BYTES + 100))
    backend = _backend_for(_Page(long_url, "interactive"), monkeypatch)
    payload = backend.page_info("s")
    assert payload["url_truncated"] is True
    assert len(payload["url"].encode("utf-8")) <= _MAX_URL_BYTES
    assert payload["ready_state"] == "interactive"
