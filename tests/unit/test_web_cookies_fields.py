"""web.cookies reads the browser context's cookie jar, bounded and normalised.

Driven through the _get/_runner seam with a fake context whose cookies() returns
Playwright-shaped dicts. No real browser is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_COOKIE_VALUE_CHARS,
    WebBackend,
)
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


class _Context:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies = cookies

    def cookies(self) -> list[dict[str, Any]]:
        return self._cookies


def _backend_with(monkeypatch: Any, cookies: list[dict[str, Any]]) -> WebBackend:
    backend = WebBackend()
    handle = SimpleNamespace(
        context=_Context(cookies),
        page=SimpleNamespace(url="https://example/app"),
    )
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_cookies_normalise_flags_and_expiry(monkeypatch: Any) -> None:
    jar = [
        {
            "name": "sid",
            "value": "abc123",
            "domain": "example.com",
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax",
            "expires": 1893456000.0,
        },
        {
            "name": "csrftoken",
            "value": "tok",
            "domain": "example.com",
            "path": "/",
            "httpOnly": False,
            "secure": False,
            "sameSite": "None",
            "expires": -1,
        },
    ]
    payload = _backend_with(monkeypatch, jar).cookies("s")

    assert payload["url"] == "https://example/app"
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["truncated"] is False

    by_name = {c["name"]: c for c in payload["cookies"]}
    sid = by_name["sid"]
    assert sid["http_only"] is True
    assert sid["secure"] is True
    assert sid["same_site"] == "Lax"
    assert sid["expires"] == 1893456000.0
    assert sid["session"] is False

    csrf = by_name["csrftoken"]
    # A -1 expiry is a session cookie: null expires, session true.
    assert csrf["expires"] is None
    assert csrf["session"] is True


def test_cookies_clip_a_long_value(monkeypatch: Any) -> None:
    jar = [
        {
            "name": "jwt",
            "value": "y" * (_MAX_COOKIE_VALUE_CHARS + 50),
            "domain": "x",
            "path": "/",
        }
    ]
    payload = _backend_with(monkeypatch, jar).cookies("s")
    cookie = payload["cookies"][0]
    assert len(cookie["value"]) == _MAX_COOKIE_VALUE_CHARS
    assert cookie["value_truncated"] is True


def test_cookies_default_missing_flags(monkeypatch: Any) -> None:
    """A cookie dict without httpOnly/secure/sameSite reads as false/null."""
    jar = [{"name": "a", "value": "1", "domain": "x", "path": "/"}]
    payload = _backend_with(monkeypatch, jar).cookies("s")
    cookie = payload["cookies"][0]
    assert cookie["http_only"] is False
    assert cookie["secure"] is False
    assert cookie["same_site"] is None
    assert cookie["session"] is True


def test_cookies_handle_an_empty_jar(monkeypatch: Any) -> None:
    payload = _backend_with(monkeypatch, []).cookies("s")
    assert payload["count"] == 0
    assert payload["total"] == 0
    assert payload["cookies"] == []


def test_web_cookies_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.cookies")
    assert "http_only" in doc
    assert "same_site" in doc
    assert "session" in doc
    assert "expires" in doc
