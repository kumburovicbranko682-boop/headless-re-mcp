"""web.cookies exposes the browser context's cookies for auth analysis.

Session ids, auth tokens and CSRF values live in cookies, and nothing in the
web surface read them. These pin the reader: normalized snake_case fields,
full values up to the 8192-byte cap with value_truncated past it, session
cookies reported with expires null and session true, a stable domain/path/name
sort, and offset/limit pagination. The docstring must name the returned fields.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_COOKIE_VALUE, WebBackend
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


class _FakeContext:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies = cookies

    def cookies(self) -> list[dict[str, Any]]:
        return self._cookies


class _FakeHandle:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self.context = _FakeContext(cookies)


class _FakeRunner:
    def call(self, fn: Any) -> Any:
        return fn()


def _backend_with(monkeypatch: Any, cookies: list[dict[str, Any]]) -> WebBackend:
    backend = WebBackend()
    handle = _FakeHandle(cookies)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _FakeRunner())
    return backend


def test_cookies_are_normalized_and_sorted(monkeypatch: Any) -> None:
    cookies = [
        {
            "name": "session",
            "value": "abc123",
            "domain": "example.com",
            "path": "/",
            "expires": 1893456000.0,
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax",
        },
        {
            "name": "csrf",
            "value": "tok",
            "domain": "example.com",
            "path": "/",
            "expires": -1,
            "httpOnly": False,
            "secure": False,
            "sameSite": "Strict",
        },
    ]
    backend = _backend_with(monkeypatch, cookies)
    payload = backend.cookies("s", limit=100)
    assert "jar" not in payload
    assert "store" not in payload
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["offset"] == 0
    assert payload["has_more"] is False
    # sorted by domain, path, name -> csrf before session
    first = payload["cookies"][0]
    assert first["name"] == "csrf"
    assert first["http_only"] is False
    assert first["secure"] is False
    assert first["same_site"] == "Strict"
    # a negative expiry is a session cookie: expires null, session true
    assert first["expires"] is None
    assert first["session"] is True
    assert "value_truncated" not in first
    second = payload["cookies"][1]
    assert second["name"] == "session"
    assert second["expires"] == 1893456000.0
    assert second["session"] is False
    assert second["value"] == "abc123"


def test_a_long_value_is_capped_and_flagged(monkeypatch: Any) -> None:
    big = "j" * (_MAX_COOKIE_VALUE + 500)
    cookies = [
        {"name": "jwt", "value": big, "domain": "d", "path": "/", "expires": -1}
    ]
    backend = _backend_with(monkeypatch, cookies)
    payload = backend.cookies("s", limit=10)
    entry = payload["cookies"][0]
    assert len(entry["value"].encode("utf-8")) <= _MAX_COOKIE_VALUE
    assert entry["value_truncated"] is True


def test_pagination_reports_has_more(monkeypatch: Any) -> None:
    cookies = [
        {"name": f"c{index:03d}", "value": "v", "domain": "d", "path": "/", "expires": -1}
        for index in range(25)
    ]
    backend = _backend_with(monkeypatch, cookies)
    payload = backend.cookies("s", offset=0, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    page2 = backend.cookies("s", offset=10, limit=10)
    assert page2["cookies"][0]["name"] == "c010"


def test_missing_expiry_is_a_session_cookie(monkeypatch: Any) -> None:
    cookies = [{"name": "x", "value": "y", "domain": "d", "path": "/"}]
    backend = _backend_with(monkeypatch, cookies)
    entry = backend.cookies("s", limit=10)["cookies"][0]
    assert entry["session"] is True
    assert entry["expires"] is None


def test_web_cookies_docstring_names_the_returned_fields() -> None:
    doc = _tool_docstring("web.cookies")
    assert "Answers with cookies" in doc
    assert "same_site" in doc
    assert "has_more" in doc
