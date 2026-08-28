"""proxy.cookies folds the capture's Set-Cookie / Cookie headers into a jar.

These drive the real _FlowRecorder with fake flows whose headers mimic
mitmproxy's Headers (get_all for the repeatable Set-Cookie, get for lookups),
so the fold -- name+domain keying, the sticky HttpOnly/Secure/SameSite flags,
the response-vs-request origin, the set/sent counts and the cap -- is pinned
without a live proxy.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_COOKIES,
    ProxyBackend,
    _FlowRecorder,
    _parse_set_cookie,
)
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Headers:
    """A minimal stand-in for mitmproxy's Headers: repeatable, case-insensitive."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    def get(self, name: str, default: str = "") -> str:
        low = name.casefold()
        for key, value in self._pairs:
            if key.casefold() == low:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        low = name.casefold()
        return [value for key, value in self._pairs if key.casefold() == low]

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        del multi
        return list(self._pairs)


def _flow(
    recorder: _FlowRecorder,
    fid: str,
    method: str,
    url: str,
    host: str,
    status: int,
    *,
    set_cookies: tuple[str, ...] = (),
    cookie: str | None = None,
    content_type: str = "text/html",
) -> None:
    req_pairs = [("Host", host)]
    if cookie is not None:
        req_pairs.append(("Cookie", cookie))
    request = SimpleNamespace(
        method=method, pretty_url=url, host=host, headers=_Headers(req_pairs)
    )
    resp_pairs = [("content-type", content_type)]
    for value in set_cookies:
        resp_pairs.append(("Set-Cookie", value))
    response = SimpleNamespace(status_code=status, headers=_Headers(resp_pairs))
    recorder.response(SimpleNamespace(id=fid, request=request, response=response))


def _by_name(cookies: list[dict], name: str) -> dict:
    return next(c for c in cookies if c["name"] == name)


def test_parse_set_cookie_lifts_pair_and_attributes() -> None:
    parsed = _parse_set_cookie(
        "session=abc123; Domain=.example.com; Path=/app; HttpOnly; Secure; "
        "SameSite=Lax; Max-Age=3600"
    )
    assert parsed is not None
    assert parsed["name"] == "session"
    assert parsed["value"] == "abc123"
    assert parsed["domain"] == "example.com"  # the leading dot is dropped
    assert parsed["path"] == "/app"
    assert parsed["http_only"] is True
    assert parsed["secure"] is True
    assert parsed["same_site"] == "Lax"
    assert parsed["max_age"] == "3600"


def test_parse_set_cookie_rejects_a_valueless_header() -> None:
    assert _parse_set_cookie("") is None
    assert _parse_set_cookie("   ") is None
    assert _parse_set_cookie("HttpOnly") is None  # no name=value pair


def test_proxy_cookies_folds_set_cookie_with_flags(monkeypatch: Any) -> None:
    """A server minting a session cookie must surface with its flag posture.

    A login response sets an HttpOnly+Secure session plus a plain tracking
    cookie in two Set-Cookie lines; a later response re-sets the session. The
    fold must key by name+domain, count both sets, keep the newest value and the
    sticky flags, and default the flags off on the flag-less tracking cookie.
    """
    recorder = _FlowRecorder(capacity=50)
    _flow(
        recorder,
        "1",
        "POST",
        "https://app.example/login",
        "app.example",
        200,
        set_cookies=(
            "session=tok-1; Domain=app.example; Path=/; HttpOnly; Secure; SameSite=Strict",
            "track=1; Path=/",
        ),
    )
    _flow(
        recorder,
        "2",
        "GET",
        "https://app.example/home",
        "app.example",
        200,
        set_cookies=("session=tok-2; Domain=app.example; Path=/; HttpOnly; Secure;",),
    )

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.cookies("s")

    assert result["flows_scanned"] == 2
    assert result["total"] == result["count"] == 2
    assert result["has_more"] is False

    session = _by_name(result["cookies"], "session")
    assert session["origin"] == "response"
    assert session["domain"] == "app.example"
    assert session["set_count"] == 2
    assert session["value"] == "tok-2"  # the most recent Set-Cookie wins
    assert session["http_only"] is True
    assert session["secure"] is True
    assert session["same_site"] == "Strict"

    track = _by_name(result["cookies"], "track")
    assert track["origin"] == "response"
    # Flags default to False, so an absent flag never reads as "set".
    assert track["http_only"] is False
    assert track["secure"] is False


def test_proxy_cookies_merges_request_sent_cookies(monkeypatch: Any) -> None:
    """A cookie the client sends but no capture set must show origin=request.

    One flow sets 'sid'; a second flow sends 'sid' back plus a 'pref' the
    capture never saw set. 'sid' stays origin=response with sent_count bumped;
    'pref' is a request-only cookie keyed to the host it went to.
    """
    recorder = _FlowRecorder(capacity=50)
    _flow(
        recorder,
        "1",
        "GET",
        "https://api.example/a",
        "api.example",
        200,
        set_cookies=("sid=xyz; Domain=api.example; Path=/",),
    )
    _flow(
        recorder,
        "2",
        "GET",
        "https://api.example/b",
        "api.example",
        200,
        cookie="sid=xyz; pref=dark",
    )

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.cookies("s")

    sid = _by_name(result["cookies"], "sid")
    assert sid["origin"] == "response"
    assert sid["set_count"] == 1
    assert sid["sent_count"] == 1

    pref = _by_name(result["cookies"], "pref")
    assert pref["origin"] == "request"
    assert pref["domain"] == "api.example"
    assert pref["set_count"] == 0
    assert pref["sent_count"] == 1
    # A request-only cookie carries no server posture.
    assert "value" not in pref
    assert "http_only" not in pref


def test_proxy_cookies_ranks_response_before_request(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=50)
    _flow(
        recorder,
        "1",
        "GET",
        "https://h.example/x",
        "h.example",
        200,
        set_cookies=("bbb=1; Domain=h.example",),
        cookie="aaa=2",
    )

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.cookies("s")
    # 'bbb' is response-set, 'aaa' is request-only; the server posture ranks
    # first despite the alphabetical order.
    assert [c["name"] for c in result["cookies"]] == ["bbb", "aaa"]


def test_proxy_cookies_caps_and_reports_more(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=_MAX_COOKIES + 100)
    for index in range(_MAX_COOKIES + 5):
        _flow(
            recorder,
            str(index),
            "GET",
            f"https://h.example/{index}",
            "h.example",
            200,
            set_cookies=(f"c{index:05d}=v; Domain=h.example",),
        )

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.cookies("s", limit=50)
    assert result["count"] == 50
    assert result["total"] == _MAX_COOKIES + 5
    assert result["has_more"] is True


def test_proxy_cookies_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.cookies")
    assert doc, "proxy.cookies is missing its docstring"
    assert "origin" in doc
    assert "http_only" in doc
    assert "same_site" in doc
    assert "set_count" in doc
    assert "has_more" in doc
