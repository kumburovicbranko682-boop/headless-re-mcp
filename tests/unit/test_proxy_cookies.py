"""proxy.cookies must parse Set-Cookie/Cookie via mitmproxy and stay honest.

Real mitmproxy Request/Response objects drive the parsing, so a regression in
attribute handling, dedup, value truncation, or the omitted-flow accounting
surfaces as a wrong cookie row rather than a plausible-looking but false one.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from mitmproxy.http import Headers, Request, Response

from headless_re_mcp.backends.proxy.client import (
    _MAX_COOKIE_VALUE,
    _OMITTED_BODY,
    ProxyBackend,
    _FlowRecorder,
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


def _flow(host: str, *, set_cookie: list[bytes] | None = None, cookie: bytes | None = None) -> Any:
    resp_headers = Headers([(b"set-cookie", value) for value in (set_cookie or [])])
    req_headers = Headers([(b"cookie", cookie)] if cookie is not None else [])
    request = Request.make("GET", f"http://{host}/", b"", req_headers)
    response = Response.make(200, b"", resp_headers)
    return SimpleNamespace(request=request, response=response)


def _backend_over(monkeypatch: Any, flows: list[Any], *, omitted: int = 0) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = SimpleNamespace(retained_flows=lambda: (list(flows), omitted))
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_cookies_parses_set_cookie_with_all_flags(monkeypatch: Any) -> None:
    """A server Set-Cookie yields value, domain, path and the three flags.

    Domain comes from the attribute; secure/http_only are presence, not value;
    same_site carries its string.
    """
    flow = _flow(
        "api.example.com",
        set_cookie=[b"sid=abc123; Domain=.example.com; Path=/api; Secure; HttpOnly; SameSite=Lax"],
    )
    payload = _backend_over(monkeypatch, [flow]).cookies("s")
    assert payload["count"] == 1
    row = payload["cookies"][0]
    assert row == {
        "name": "sid",
        "value": "abc123",
        "domain": ".example.com",
        "path": "/api",
        "source": "response",
        "secure": True,
        "http_only": True,
        "same_site": "Lax",
    }


def test_cookies_defaults_domain_to_the_flow_host(monkeypatch: Any) -> None:
    """A Set-Cookie without Domain is scoped to the host that sent it."""
    flow = _flow("cdn.example.com", set_cookie=[b"a=1; Path=/"])
    row = _backend_over(monkeypatch, [flow]).cookies("s")["cookies"][0]
    assert row["domain"] == "cdn.example.com"
    assert row["secure"] is False
    assert row["same_site"] == ""


def test_cookies_reports_request_cookies_as_source_request(monkeypatch: Any) -> None:
    """Cookies the client sent are name/value with no flags, source=request."""
    flow = _flow("x.test", cookie=b"theme=dark; token=zzz")
    payload = _backend_over(monkeypatch, [flow]).cookies("s")
    by_name = {c["name"]: c for c in payload["cookies"]}
    assert set(by_name) == {"theme", "token"}
    assert by_name["theme"]["source"] == "request"
    assert by_name["theme"]["domain"] == "x.test"
    assert by_name["theme"]["path"] == ""


def test_cookies_dedup_keeps_the_newest_response_value(monkeypatch: Any) -> None:
    """Same name+domain across flows collapses to one row, newest wins.

    retained_flows is oldest-first, so the later flow's value is the current
    one.
    """
    old = _flow("h", set_cookie=[b"sid=OLD; Domain=h"])
    new = _flow("h", set_cookie=[b"sid=NEW; Domain=h"])
    payload = _backend_over(monkeypatch, [old, new]).cookies("s")
    assert payload["count"] == 1
    assert payload["cookies"][0]["value"] == "NEW"


def test_cookies_truncates_a_huge_value_and_says_so(monkeypatch: Any) -> None:
    """A JWT-sized value is capped, with value_truncated and the real length.

    Copying a clipped token to replay a session would fail silently; the flags
    make the cut explicit.
    """
    big = b"j=" + b"x" * (_MAX_COOKIE_VALUE + 500)
    flow = _flow("h", set_cookie=[big])
    row = _backend_over(monkeypatch, [flow]).cookies("s")["cookies"][0]
    assert len(row["value"]) == _MAX_COOKIE_VALUE
    assert row["value_truncated"] is True
    assert row["value_length"] == _MAX_COOKIE_VALUE + 500


def test_cookies_paginate_over_the_deduped_set(monkeypatch: Any) -> None:
    flows = [_flow("h", set_cookie=[f"c{index}=v; Domain=h".encode()]) for index in range(25)]
    backend = _backend_over(monkeypatch, flows)
    first = backend.cookies("s", offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    last = backend.cookies("s", offset=20, limit=10)
    assert last["count"] == 5
    assert last["has_more"] is False


def test_cookies_reports_flows_it_could_not_read(monkeypatch: Any) -> None:
    """flows_omitted (bodies evicted) keeps a short list from reading as few."""
    flow = _flow("h", set_cookie=[b"a=1; Domain=h"])
    payload = _backend_over(monkeypatch, [flow], omitted=4).cookies("s")
    assert payload["flows_scanned"] == 1
    assert payload["flows_omitted"] == 4
    assert "items" not in payload


def test_retained_flows_skips_the_omitted_sentinel() -> None:
    """The recorder returns whole flows and counts the evicted ones separately."""
    recorder = _FlowRecorder(capacity=10)
    recorder._raw["a"] = _flow("h", set_cookie=[b"a=1"])
    recorder._raw["b"] = _OMITTED_BODY
    recorder._raw["c"] = _flow("h", set_cookie=[b"c=1"])
    flows, omitted = recorder.retained_flows()
    assert len(flows) == 2
    assert omitted == 1


def test_cookies_description_names_its_fields() -> None:
    doc = _tool_docstring("proxy.cookies")
    assert "Set-Cookie" in doc
    assert "value_truncated" in doc
    assert "flows_omitted" in doc
    assert "source" in doc
    assert "cookies, not" in doc
