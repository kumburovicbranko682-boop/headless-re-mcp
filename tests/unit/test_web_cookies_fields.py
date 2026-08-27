"""web.cookies must return the whole jar, HttpOnly included, and page it.

The per-request Cookie headers in web.network.list only show what a given
request carried; they never show an HttpOnly session cookie that page JS
cannot read either. web.cookies reads the live CDP jar, so these pin that it
surfaces HttpOnly cookies with a stable field set and pages like every other
capture reader.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError
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


class _Cdp:
    def __init__(self, cookies: list[dict[str, Any]], *, raise_on_send: bool = False) -> None:
        self._cookies = cookies
        self._raise = raise_on_send

    def send(self, method: str, *args: Any) -> dict[str, Any]:
        del method, args
        if self._raise:
            raise RuntimeError("cdp went away")
        return {"cookies": self._cookies}


class _Handle:
    def __init__(self, cookies: list[dict[str, Any]], *, raise_on_send: bool = False) -> None:
        self.cdp = _Cdp(cookies, raise_on_send=raise_on_send)


class _Runner:
    def call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return fn()


def _backend_for(handle: _Handle, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Runner())
    return backend


def test_cookies_returns_the_full_jar_including_httponly(monkeypatch: Any) -> None:
    # A normal cookie and an HttpOnly one document.cookie could never read.
    jar = [
        {
            "name": "plain",
            "value": "v1",
            "domain": "127.0.0.1",
            "path": "/",
            "httpOnly": False,
            "secure": False,
            "session": True,
            "expires": -1,
            "size": 7,
            "sameSite": None,
        },
        {
            "name": "secret",
            "value": "tok",
            "domain": "127.0.0.1",
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "session": False,
            "expires": 1_900_000_000,
            "size": 9,
            "sameSite": "Strict",
        },
    ]
    backend = _backend_for(_Handle(jar), monkeypatch)
    result = backend.cookies("s")

    assert result["total"] == 2
    assert result["count"] == 2
    by_name = {c["name"]: c for c in result["cookies"]}
    assert by_name["secret"]["httpOnly"] is True
    assert by_name["secret"]["sameSite"] == "Strict"
    # sameSite absent from CDP passes through as null, not a missing key.
    assert by_name["plain"]["sameSite"] is None
    assert "priority" in by_name["plain"]  # normalised even when CDP omitted it
    assert by_name["plain"]["priority"] is None


def test_cookies_paginate(monkeypatch: Any) -> None:
    jar = [
        {"name": f"c{i}", "value": str(i), "domain": "x", "path": "/"} for i in range(5)
    ]
    backend = _backend_for(_Handle(jar), monkeypatch)

    page = backend.cookies("s", offset=1, limit=2)
    assert page["offset"] == 1
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True

    tail = backend.cookies("s", offset=4, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False


def test_cookies_fault_soft_when_cdp_fails(monkeypatch: Any) -> None:
    backend = _backend_for(_Handle([], raise_on_send=True), monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.cookies("s")
    assert excinfo.value.code == "backend_error"


def test_cookies_docstring_names_the_httponly_edge_and_fields() -> None:
    doc = " ".join(_tool_docstring("web.cookies").split())
    assert "httpOnly" in doc
    assert "document.cookie" in doc
    assert "has_more" in doc
