"""web.cookies bounds, sorts and stays honest about the context's cookies."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_COOKIE_VALUE_BYTES,
    _MAX_COOKIES,
    WebBackend,
    _summarize_cookies,
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


def _cookie(name: str, value: str, domain: str, path: str = "/", **extra: Any) -> dict[str, Any]:
    entry = {"name": name, "value": value, "domain": domain, "path": path}
    entry.update(extra)
    return entry


def test_summarize_cookies_maps_fields_and_sorts() -> None:
    """Playwright keys become snake_case and the list sorts by domain/name/path.

    Measured: httpOnly/sameSite map to http_only/same_site, expires passes
    through, and a session cookie (expires -1) is flagged session True while a
    persistent one is session False. Order is by (domain, name, path) so a
    later page aims at the same window. The field is cookies, not items.
    """
    raw = [
        _cookie(
            "sid", "abc", "b.example.com", httpOnly=True, secure=True, sameSite="Lax", expires=-1
        ),
        _cookie("token", "xyz", "a.example.com", expires=1893456000.0, secure=False),
    ]
    payload = _summarize_cookies(raw, offset=0, limit=50)
    assert "items" not in payload
    assert payload["total"] == 2
    assert payload["count"] == 2
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert [c["domain"] for c in payload["cookies"]] == ["a.example.com", "b.example.com"]
    persistent = payload["cookies"][0]
    assert persistent["name"] == "token"
    assert persistent["expires"] == 1893456000.0
    assert persistent["session"] is False
    assert persistent["secure"] is False
    session_cookie = payload["cookies"][1]
    assert session_cookie["name"] == "sid"
    assert session_cookie["http_only"] is True
    assert session_cookie["secure"] is True
    assert session_cookie["same_site"] == "Lax"
    assert session_cookie["session"] is True


def test_summarize_cookies_omits_flags_the_driver_did_not_report() -> None:
    """A cookie with no httpOnly/secure/expires omits those keys, not false.

    An agent must not read a missing httpOnly as "not http-only"; the flag is
    simply absent so the reader knows it is unknown.
    """
    payload = _summarize_cookies([_cookie("k", "v", "x.test")], offset=0, limit=10)
    cookie = payload["cookies"][0]
    assert "http_only" not in cookie
    assert "secure" not in cookie
    assert "same_site" not in cookie
    assert "expires" not in cookie
    assert "session" not in cookie


def test_summarize_cookies_truncates_a_large_value_and_reports_full_size() -> None:
    """A big token is cut, value_truncated is set, and value_bytes is the full size.

    Measured: a value past the per-value cap comes back cut with value_truncated
    True and value_bytes equal to the original byte length, so a clipped token is
    never read as the whole thing.
    """
    big = "j" * (_MAX_COOKIE_VALUE_BYTES + 500)
    payload = _summarize_cookies([_cookie("jwt", big, "x.test")], offset=0, limit=10)
    cookie = payload["cookies"][0]
    assert cookie["value_truncated"] is True
    assert cookie["value_bytes"] == len(big.encode("utf-8"))
    assert len(cookie["value"].encode("utf-8")) <= _MAX_COOKIE_VALUE_BYTES


def test_summarize_cookies_skips_non_dicts_and_non_list() -> None:
    """Odd runtime shapes degrade to a safe empty answer, not an exception."""
    payload = _summarize_cookies(["not-a-dict", 42, None], offset=0, limit=10)
    assert payload["cookies"] == []
    assert payload["total"] == 0
    assert _summarize_cookies(None, offset=0, limit=10)["total"] == 0


def test_summarize_cookies_paginates_and_caps_the_scan() -> None:
    """A filled page reports has_more; more than the collect cap sets scan_capped."""
    raw = [_cookie(f"c{index:04d}", "v", "x.test") for index in range(_MAX_COOKIES + 5)]
    page0 = _summarize_cookies(raw, offset=0, limit=10)
    assert page0["count"] == 10
    assert page0["total"] == _MAX_COOKIES
    assert page0["has_more"] is True
    assert page0["scan_capped"] is True


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Ctx:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies = cookies

    def cookies(self) -> list[dict[str, Any]]:
        return self._cookies


def test_web_cookies_backend_reads_the_context(monkeypatch: Any) -> None:
    """The backend method reads context.cookies() through the session runner."""
    backend = WebBackend()
    ctx = _Ctx([_cookie("sid", "abc", "example.com", httpOnly=True)])
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(context=ctx))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.cookies("s")
    assert payload["total"] == 1
    assert payload["cookies"][0]["name"] == "sid"
    assert payload["cookies"][0]["http_only"] is True
    doc = _tool_docstring("web.cookies")
    assert "cookies" in doc
    assert "value_truncated" in doc
    assert "session" in doc
