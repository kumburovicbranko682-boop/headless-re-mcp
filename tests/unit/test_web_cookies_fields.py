"""web.cookies must surface the cookie jar honestly: httpOnly, bounds, pages."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_COOKIE_VALUE_BYTES,
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


class _Handle:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self.context = _Context(cookies)


def _backend(monkeypatch: Any, cookies: list[dict[str, Any]]) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle(cookies))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_cookies_surfaces_httponly_and_the_security_attributes(
    monkeypatch: Any,
) -> None:
    """The httpOnly session token document.cookie hides must come back here.

    A JS eval reading document.cookie could never see the httpOnly session
    cookie; context.cookies() does, which is the whole point of the tool.
    Each entry carries the security-relevant attributes.
    """
    backend = _backend(
        monkeypatch,
        [
            {
                "name": "session",
                "value": "secret-token",
                "domain": "example.com",
                "path": "/",
                "expires": 1893456000.0,
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            }
        ],
    )
    payload = backend.cookies("s")
    assert "jar" not in payload
    assert "storage" not in payload
    assert payload["total"] == 1
    cookie = payload["cookies"][0]
    assert cookie["name"] == "session"
    assert cookie["value"] == "secret-token"
    assert cookie["http_only"] is True
    assert cookie["secure"] is True
    assert cookie["same_site"] == "Lax"
    assert "value_truncated" not in cookie
    doc = _tool_docstring("web.cookies")
    assert "http_only" in doc
    assert "has_more" in doc


def test_web_cookies_sorts_and_paginates_the_jar(monkeypatch: Any) -> None:
    """offset/limit page a jar sorted by (domain, path, name) with has_more."""
    jar = [
        {"name": "b", "value": "1", "domain": "z.com", "path": "/"},
        {"name": "a", "value": "2", "domain": "a.com", "path": "/"},
        {"name": "c", "value": "3", "domain": "m.com", "path": "/"},
    ]
    backend = _backend(monkeypatch, jar)
    payload = backend.cookies("s", offset=0, limit=2)
    assert [c["domain"] for c in payload["cookies"]] == ["a.com", "m.com"]
    assert payload["count"] == 2
    assert payload["total"] == 3
    assert payload["offset"] == 0
    assert payload["has_more"] is True


def test_web_cookies_bounds_a_hostile_value_and_flags_it(monkeypatch: Any) -> None:
    """A cookie value over the per-cookie cap is cut and marked, not dropped.

    One oversized cookie cannot balloon the reply, and the truncation is
    honest: value_truncated says the token was cut rather than silently short.
    """
    backend = _backend(
        monkeypatch,
        [
            {
                "name": "big",
                "value": "A" * (_MAX_COOKIE_VALUE_BYTES + 100),
                "domain": "example.com",
                "path": "/",
            }
        ],
    )
    payload = backend.cookies("s")
    cookie = payload["cookies"][0]
    assert len(cookie["value"].encode("utf-8")) <= _MAX_COOKIE_VALUE_BYTES
    assert cookie["value_truncated"] is True
