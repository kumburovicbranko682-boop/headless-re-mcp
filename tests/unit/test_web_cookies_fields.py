"""web.cookies must surface each cookie's security flags, bounded and JSON-safe.

The flags (http_only/secure/same_site), not the value, are what an auth review
reads, so these drive WebBackend.cookies with a fake CDP that returns crafted
Network.getAllCookies payloads.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADER_VALUE_BYTES,
    WebBackend,
    _normalize_cookie,
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


class _CookieCdp:
    def __init__(self, response: Any) -> None:
        self._response = response

    def send(self, method: str, params: dict[str, Any] | None = None) -> Any:
        assert method == "Network.getAllCookies", method
        return self._response


class _Handle:
    def __init__(self, response: Any) -> None:
        self.lock = Lock()
        self.cdp = _CookieCdp(response)


def _cookies(response: Any, monkeypatch: Any) -> dict[str, Any]:
    backend = WebBackend()
    handle = _Handle(response)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    return backend.cookies("s")


def test_returns_cookies_with_security_flags(monkeypatch: Any) -> None:
    response = {
        "cookies": [
            {
                "name": "sid",
                "value": "abc123",
                "domain": "example.com",
                "path": "/",
                "secure": False,
                "httpOnly": False,
                "session": True,
                "sameSite": "None",
                "expires": -1,
            },
            {
                "name": "csrf",
                "value": "tok",
                "domain": "example.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "session": False,
                "sameSite": "Strict",
                "expires": 4102444800.0,
            },
        ]
    }
    payload = _cookies(response, monkeypatch)
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["has_more"] is False
    by_name = {c["name"]: c for c in payload["cookies"]}
    # The script-reachable, plaintext, cross-site session cookie: the risky one.
    sid = by_name["sid"]
    assert sid["http_only"] is False
    assert sid["secure"] is False
    assert sid["same_site"] == "None"
    assert sid["session"] is True
    assert sid["expires"] is None  # -1 -> session cookie -> null, not a pre-epoch date
    csrf = by_name["csrf"]
    assert csrf["http_only"] is True
    assert csrf["secure"] is True
    assert csrf["expires"] == 4102444800.0


def test_value_is_capped_and_flagged(monkeypatch: Any) -> None:
    huge = "v" * (_MAX_HEADER_VALUE_BYTES * 4)
    response = {"cookies": [{"name": "big", "value": huge}]}
    cookie = _cookies(response, monkeypatch)["cookies"][0]
    assert len(cookie["value"].encode()) <= _MAX_HEADER_VALUE_BYTES
    assert cookie["value_truncated"] is True


def test_empty_when_no_cookies(monkeypatch: Any) -> None:
    payload = _cookies({"cookies": []}, monkeypatch)
    assert payload["cookies"] == []
    assert payload["count"] == 0
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_malformed_response_degrades_to_empty(monkeypatch: Any) -> None:
    # A CDP reply missing the cookies key (or a non-list) must not crash the read.
    assert _cookies({}, monkeypatch)["cookies"] == []
    assert _cookies({"cookies": "nope"}, monkeypatch)["cookies"] == []


def test_a_flood_of_large_cookies_is_bounded_by_encoded_size(monkeypatch: Any) -> None:
    value = "x" * (_MAX_HEADER_VALUE_BYTES - 64)
    response = {
        "cookies": [
            {"name": f"c{i}", "value": value, "domain": "example.com", "path": "/"}
            for i in range(500)
        ]
    }
    payload = _cookies(response, monkeypatch)
    # The window is trimmed to fit the result budget; total still reports the whole
    # set and has_more flags the trim so the caller does not read a page as all.
    assert payload["total"] == 500
    assert payload["count"] < 500
    assert payload["has_more"] is True
    assert len(json.dumps(payload).encode()) <= 262144


def test_normalize_cookie_coerces_and_defaults() -> None:
    # Missing flags default to False; a non-numeric expires becomes null.
    cookie = _normalize_cookie({"name": "n", "value": "v", "expires": "soon"})
    assert cookie["secure"] is False
    assert cookie["http_only"] is False
    assert cookie["session"] is False
    assert cookie["same_site"] == ""
    assert cookie["expires"] is None


def test_docstring_names_the_security_flags() -> None:
    doc = _tool_docstring("web.cookies")
    assert "http_only" in doc
    assert "secure" in doc
    assert "same_site" in doc
    assert "has_more" in doc
