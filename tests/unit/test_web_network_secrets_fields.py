"""web.network.secrets must enumerate auth/secret material from a browser capture.

Reads the request/response headers CDP recorded per request plus the URL query,
so a fake handle drives every case: authorization schemes and JWT decoding,
API-key headers, cookies (request Cookie and response Set-Cookie, including CDP's
newline-joined repeats), secret-ish query params, cross-request deduplication,
redaction vs reveal, the kind/host filters, pagination and the service wiring. It
is the browser-side twin of proxy.secrets, sharing backends/common/secrets.
"""

from __future__ import annotations

import ast
import base64
import json
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
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


def _b64(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_jwt(header: dict[str, Any], payload: dict[str, Any]) -> str:
    return f"{_b64(header)}.{_b64(payload)}.sig"


def _row(
    request_id: str,
    *,
    url: str,
    method: str = "GET",
    status: int | None = 200,
    mime: str | None = "application/json",
    rtype: str | None = "XHR",
    req_headers: dict[str, str] | None = None,
    resp_headers: dict[str, str] | None = None,
    har: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if har is None:
        har = {}
        if req_headers is not None:
            har["request_headers"] = req_headers
        if resp_headers is not None:
            har["response_headers"] = resp_headers
    return {
        "requestId": request_id,
        "url": url,
        "method": method,
        "status": status,
        "mimeType": mime,
        "resourceType": rtype,
        "_har": har,
    }


class _FakeHandle:
    def __init__(self, rows: list[dict[str, Any]], *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict(
            (row["requestId"], row) for row in rows
        )
        self.requests_dropped = dropped


def _backend(monkeypatch: Any, rows: list[dict[str, Any]], *, dropped: int = 0) -> WebBackend:
    backend = WebBackend()
    handle = _FakeHandle(rows, dropped=dropped)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    return backend


def test_authorization_bearer_jwt_is_decoded(monkeypatch: Any) -> None:
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "123", "iss": "acme", "exp": 1700000000, "role": "admin"},
    )
    rows = [
        _row("a", url="http://api.example.com/me", req_headers={"Authorization": f"Bearer {token}"})
    ]
    out = _backend(monkeypatch, rows).network_secrets("s")
    (sec,) = out["secrets"]
    assert sec["kind"] == "authorization"
    assert sec["scheme"] == "Bearer"
    assert sec["location"] == "request"
    assert sec["example_id"] == "a"
    assert sec["value"] != token  # redacted by default
    assert sec["jwt"]["header"] == {"alg": "HS256", "typ": "JWT"}
    assert sec["jwt"]["claims"]["iss"] == "acme"
    assert sec["jwt"]["claims"]["exp"] == 1700000000
    assert "role" in sec["jwt"]["claim_names"]  # custom claim listed by name only
    assert "role" not in sec["jwt"]["claims"]


def test_basic_authorization_has_scheme_but_no_jwt(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/x", req_headers={"Authorization": "Basic dXNlcjpwYXNz"})
    ]
    (sec,) = _backend(monkeypatch, rows).network_secrets("s")["secrets"]
    assert sec["kind"] == "authorization"
    assert sec["scheme"] == "Basic"
    assert "jwt" not in sec


def test_api_key_header_is_detected(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/x", req_headers={"X-API-Key": "sk-abcdef123456"})]
    (sec,) = _backend(monkeypatch, rows).network_secrets("s")["secrets"]
    assert sec["kind"] == "api_key_header"
    assert sec["name"] == "X-API-Key"
    assert sec["value_length"] == len("sk-abcdef123456")


def test_request_cookie_flags_session(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/x", req_headers={"Cookie": "sessionid=abc123def; theme=dark"})
    ]
    out = _backend(monkeypatch, rows).network_secrets("s")
    by_name = {s["name"]: s for s in out["secrets"]}
    assert by_name["sessionid"]["kind"] == "cookie"
    assert by_name["sessionid"]["session"] is True
    assert by_name["theme"]["session"] is False


def test_set_cookie_from_response_carries_attributes(monkeypatch: Any) -> None:
    rows = [
        _row(
            "a",
            url="http://h/x",
            resp_headers={"Set-Cookie": "auth=xyz789; HttpOnly; Path=/; Secure"},
        )
    ]
    (sec,) = _backend(monkeypatch, rows).network_secrets("s")["secrets"]
    assert sec["kind"] == "set_cookie"
    assert sec["location"] == "response"
    assert sec["name"] == "auth"
    assert sec["session"] is True  # HttpOnly marks it session-ish
    assert sec["cookie_attributes"]["httponly"] is True
    assert sec["cookie_attributes"]["path"] == "/"


def test_newline_joined_set_cookie_splits_into_two(monkeypatch: Any) -> None:
    """CDP joins repeated Set-Cookie with newlines; each must scan separately."""
    rows = [
        _row("a", url="http://h/x", resp_headers={"Set-Cookie": "a=1\nsession=deadbeefcafe"})
    ]
    out = _backend(monkeypatch, rows).network_secrets("s")
    names = {s["name"] for s in out["secrets"]}
    assert names == {"a", "session"}


def test_secret_query_param_is_detected(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/cb?token=abcd1234&x=1")]
    out = _backend(monkeypatch, rows).network_secrets("s")
    (sec,) = out["secrets"]
    assert sec["kind"] == "query_param"
    assert sec["name"] == "token"
    assert sec["location"] == "request"


def test_reveal_returns_full_value(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/x", req_headers={"X-Api-Key": "topsecretvalue999"})]
    backend = _backend(monkeypatch, rows)
    redacted = backend.network_secrets("s")["secrets"][0]
    revealed = backend.network_secrets("s", reveal=True)["secrets"][0]
    assert redacted["value"] != "topsecretvalue999"
    assert revealed["value"] == "topsecretvalue999"
    assert revealed["value_sha256"] == redacted["value_sha256"]  # correlation id stable


def test_same_secret_across_requests_dedups_with_count(monkeypatch: Any) -> None:
    rows = [
        _row(f"r{i}", url=f"http://h/{i}", req_headers={"X-API-Key": "shared-key-abcdef"})
        for i in range(3)
    ]
    out = _backend(monkeypatch, rows).network_secrets("s")
    assert out["total"] == 1
    (sec,) = out["secrets"]
    assert sec["count"] == 3


def test_hosts_accumulate_across_requests(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://one.example.com/x", req_headers={"X-API-Key": "k-abcdef123"}),
        _row("b", url="http://two.example.com/y", req_headers={"X-API-Key": "k-abcdef123"}),
    ]
    (sec,) = _backend(monkeypatch, rows).network_secrets("s")["secrets"]
    assert sorted(sec["hosts"]) == ["one.example.com", "two.example.com"]


def test_kind_filter_keeps_one_category(monkeypatch: Any) -> None:
    rows = [
        _row(
            "a",
            url="http://h/x?token=qq11",
            req_headers={"Authorization": "Bearer aaa.bbb.ccc", "X-API-Key": "kkk111"},
        )
    ]
    out = _backend(monkeypatch, rows).network_secrets("s", kind="query_param")
    assert {s["kind"] for s in out["secrets"]} == {"query_param"}
    assert out["kind"] == "query_param"


def test_host_filter_narrows_the_capture(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://api.example.com/x", req_headers={"X-API-Key": "one-abcdef"}),
        _row("b", url="http://cdn.other.com/y", req_headers={"X-API-Key": "two-abcdef"}),
    ]
    out = _backend(monkeypatch, rows).network_secrets("s", host="api.example.com")
    assert out["total"] == 1
    assert out["secrets"][0]["hosts"] == ["api.example.com"]
    assert out["filter"] == {"host": "api.example.com"}


def test_status_filter_matches_exact_code(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/x", status=200, req_headers={"X-API-Key": "aaa-111111"}),
        _row("b", url="http://h/y", status=403, req_headers={"X-API-Key": "bbb-222222"}),
    ]
    out = _backend(monkeypatch, rows).network_secrets("s", status=403)
    assert out["total"] == 1
    assert out["secrets"][0]["value_length"] == len("bbb-222222")


def test_headers_unavailable_still_scans_url_query(monkeypatch: Any) -> None:
    rows = [
        _row("a", url="http://h/cb?access_token=zzz999", har={}),  # no headers retained
        _row("b", url="http://h/x", req_headers={"X-API-Key": "kkk-abcdef"}),
    ]
    out = _backend(monkeypatch, rows).network_secrets("s")
    assert out["scanned"] == 1
    assert out["headers_unavailable"] == 1
    kinds = {s["kind"] for s in out["secrets"]}
    assert kinds == {"query_param", "api_key_header"}


def test_kind_counts_tally_categories(monkeypatch: Any) -> None:
    rows = [
        _row(
            "a",
            url="http://h/x?token=qqq111",
            req_headers={"X-API-Key": "kkk-aaaaaa", "Cookie": "sid=bbbbbb"},
        )
    ]
    out = _backend(monkeypatch, rows).network_secrets("s")
    assert out["kind_counts"] == {"query_param": 1, "api_key_header": 1, "cookie": 1}


def test_secret_rows_hide_internal_fields(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/x", req_headers={"X-API-Key": "abcdef123456"})]
    (sec,) = _backend(monkeypatch, rows).network_secrets("s")["secrets"]
    assert not any(k.startswith("_") for k in sec)
    assert "hosts" in sec and "value_sha256" in sec


def test_pagination_windows_the_rows(monkeypatch: Any) -> None:
    rows = [
        _row(f"r{i}", url=f"http://h/{i}", req_headers={"X-API-Key": f"key-{i}-abcdef"})
        for i in range(5)
    ]
    out = _backend(monkeypatch, rows).network_secrets("s", offset=1, limit=2)
    assert out["offset"] == 1
    assert out["count"] == 2
    assert out["total"] == 5
    assert out["has_more"] is True


def test_collect_cap_discloses(monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.common.secrets.MAX_SECRETS_COLLECT", 2)
    rows = [
        _row(f"r{i}", url=f"http://h/{i}", req_headers={"X-API-Key": f"key-{i}-abcdef"})
        for i in range(5)
    ]
    out = _backend(monkeypatch, rows).network_secrets("s")
    assert out["collect_capped"] is True
    assert out["total"] == 2


def test_empty_capture_is_clean_zero(monkeypatch: Any) -> None:
    out = _backend(monkeypatch, []).network_secrets("s")
    assert out["secrets"] == []
    assert out["total"] == 0
    assert out["captured"] == 0
    assert out["kind_counts"] == {}
    assert "filter" not in out
    assert "kind" not in out


def test_dropped_is_surfaced(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/x", req_headers={"X-API-Key": "abcdef123456"})]
    out = _backend(monkeypatch, rows, dropped=9).network_secrets("s")
    assert out["dropped"] == 9


def test_unknown_kind_is_invalid_params(monkeypatch: Any) -> None:
    rows = [_row("a", url="http://h/x")]
    backend = _backend(monkeypatch, rows)
    with pytest.raises(WebError) as excinfo:
        backend.network_secrets("s", kind="bogus")
    assert excinfo.value.code == "invalid_params"


def test_service_wraps_unknown_session_as_failure() -> None:
    service = AnalysisService(Settings.load())
    result = service.web_network_secrets("no-such-session")
    assert not result.ok
    assert result.error is not None


def test_docstring_names_the_contract() -> None:
    doc = _tool_docstring("web.network.secrets")
    for token in ("proxy.secrets", "Authorization", "Set-Cookie", "reveal", "secrets"):
        assert token in doc, token
