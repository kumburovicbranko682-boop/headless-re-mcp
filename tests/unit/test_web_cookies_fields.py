"""web.cookies must read the CDP jar, surface HttpOnly, and stay bounded."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_COOKIE_VALUE,
    _MAX_COOKIES,
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


class _Cdp:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies = cookies

    def send(self, method: str, params: Any = None) -> dict[str, Any]:
        assert method == "Network.getAllCookies"
        return {"cookies": self._cookies}


def _backend(cookies: list[dict[str, Any]], monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    handle = SimpleNamespace(cdp=_Cdp(cookies))
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_cookies_surfaces_httponly_and_the_security_flags(monkeypatch: Any) -> None:
    """The point of reading the jar is HttpOnly tokens JS cannot see."""
    cookies = [
        {
            "name": "sid",
            "value": "secret",
            "domain": "app.example.com",
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "session": False,
            "expires": 1893456000.0,
            "size": 9,
            "sameSite": "Lax",
        },
        {
            "name": "csrf",
            "value": "t",
            "domain": "app.example.com",
            "path": "/",
            "httpOnly": False,
            "secure": False,
            "session": True,
        },
    ]
    out = _backend(cookies, monkeypatch).cookies("s")
    assert out["count"] == 2
    assert out["total"] == 2
    assert out["has_more"] is False
    assert out["collection_truncated"] is False
    first = out["cookies"][0]
    assert first["name"] == "sid"
    assert first["value"] == "secret"
    assert first["http_only"] is True
    assert first["secure"] is True
    assert first["session"] is False
    assert first["expires"] == 1893456000.0
    assert first["size"] == 9
    assert first["same_site"] == "Lax"
    # Optional fields the browser did not report stay off the row.
    second = out["cookies"][1]
    assert second["session"] is True
    assert "expires" not in second
    assert "size" not in second
    assert "same_site" not in second
    doc = _tool_docstring("web.cookies")
    assert "http_only" in doc
    assert "domain_filter" in doc
    assert "read-only" in doc


def test_web_cookies_clips_a_huge_value_and_marks_it(monkeypatch: Any) -> None:
    cookies = [
        {
            "name": "big",
            "value": "A" * (_MAX_COOKIE_VALUE + 100),
            "domain": "x",
            "path": "/",
        }
    ]
    out = _backend(cookies, monkeypatch).cookies("s")
    row = out["cookies"][0]
    assert len(row["value"].encode()) <= _MAX_COOKIE_VALUE
    assert row["value_truncated"] is True


def test_web_cookies_filters_by_domain_before_paging(monkeypatch: Any) -> None:
    cookies = [
        {"name": "a", "value": "1", "domain": "app.example.com", "path": "/"},
        {"name": "b", "value": "2", "domain": "tracker.ads.net", "path": "/"},
        {"name": "c", "value": "3", "domain": "cdn.EXAMPLE.com", "path": "/"},
    ]
    out = _backend(cookies, monkeypatch).cookies("s", domain_filter="example.com")
    assert {c["name"] for c in out["cookies"]} == {"a", "c"}
    assert out["total"] == 2


def test_web_cookies_caps_the_collected_universe(monkeypatch: Any) -> None:
    cookies = [
        {"name": f"n{index}", "value": "v", "domain": "x", "path": "/"}
        for index in range(_MAX_COOKIES + 5)
    ]
    out = _backend(cookies, monkeypatch).cookies("s", limit=1000)
    assert out["total"] == _MAX_COOKIES
    assert out["collection_truncated"] is True
    assert out["count"] == _MAX_COOKIES
