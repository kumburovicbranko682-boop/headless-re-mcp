"""proxy.secrets must enumerate auth/secret material from a capture.

Reads request/response headers and the URL query, so a fake recorder drives
every case: authorization schemes and JWT decoding, API-key headers, cookies
(request Cookie and response Set-Cookie), secret-ish query params, cross-flow
deduplication, redaction vs reveal, the kind filter and pagination.
"""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _decode_jwt,
    _redact_value,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
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
    """A minimal mitmproxy-like header container supporting multi values."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        return list(self._pairs)

    def get(self, name: str, default: str = "") -> str:
        for key, value in self._pairs:
            if key.lower() == name.lower():
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        return [value for key, value in self._pairs if key.lower() == name.lower()]


def _flow(
    *,
    url: str = "http://api.example.com/",
    req_headers: list[tuple[str, str]] | None = None,
    resp_headers: list[tuple[str, str]] | None = None,
) -> Any:
    request = SimpleNamespace(headers=_Headers(req_headers or []), pretty_url=url)
    response = SimpleNamespace(headers=_Headers(resp_headers or []))
    return SimpleNamespace(request=request, response=response)


class _FakeRecorder:
    def __init__(self, summaries: list[dict[str, Any]], raws: dict[str, Any]) -> None:
        self._summaries = summaries
        self._raws = raws

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._summaries)

    def raw(self, flow_id: str) -> Any:
        return self._raws.get(flow_id)


def _summary(
    flow_id: str,
    *,
    seq: int,
    method: str = "GET",
    url: str = "http://api.example.com/",
    host: str = "api.example.com",
    status: int | None = 200,
    ctype: str = "application/json",
) -> dict[str, Any]:
    return {
        "id": flow_id,
        "seq": seq,
        "method": method,
        "url": url,
        "host": host,
        "status": status,
        "content_type": ctype,
    }


def _backend(monkeypatch: Any, recorder: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    return backend


def _b64url(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _make_jwt(header: dict[str, Any], payload: dict[str, Any], sig: str = "c2ln") -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.{sig}"


# --- redaction / JWT helpers ------------------------------------------------


def test_redact_value_masks_the_middle() -> None:
    out = _redact_value("abcdefghijklmnop")
    assert out.startswith("abcd")
    assert out.endswith("mnop")
    assert "\u2026" in out
    assert "efghij" not in out


def test_redact_value_handles_short_values() -> None:
    assert _redact_value("ab") == "\u2026"
    assert "\u2026" in _redact_value("abcdef")


def test_decode_jwt_recovers_header_and_registered_claims() -> None:
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT", "kid": "k1"},
        {"iss": "auth.example.com", "sub": "user-1", "exp": 2000000000, "role": "admin"},
    )
    decoded = _decode_jwt(token)
    assert decoded is not None
    assert decoded["header"] == {"alg": "HS256", "typ": "JWT", "kid": "k1"}
    assert decoded["claims"]["iss"] == "auth.example.com"
    assert decoded["claims"]["exp"] == 2000000000
    # A custom claim's name is disclosed but its value is not interpreted.
    assert "role" in decoded["claim_names"]
    assert "role" not in decoded["claims"]


def test_decode_jwt_rejects_non_jwt() -> None:
    assert _decode_jwt("not-a-jwt") is None
    assert _decode_jwt("a.b") is None


# --- header / query extraction ----------------------------------------------


def test_authorization_bearer_is_extracted_with_scheme(monkeypatch: Any) -> None:
    raws = {"a": _flow(req_headers=[("Authorization", "Bearer abcdefghijklmnop")])}
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    out = backend.secrets("s")
    assert out["total"] == 1
    (secret,) = out["secrets"]
    assert secret["kind"] == "authorization"
    assert secret["name"] == "Authorization"
    assert secret["scheme"] == "Bearer"
    assert secret["location"] == "request"
    assert secret["value_length"] == len("abcdefghijklmnop")
    assert secret["value"].startswith("abcd")  # redacted by default
    assert secret["count"] == 1
    assert out["scanned"] == 1
    assert out["kind_counts"] == {"authorization": 1}


def test_authorization_bearer_decodes_a_jwt(monkeypatch: Any) -> None:
    token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"iss": "idp", "exp": 1999999999})
    raws = {"a": _flow(req_headers=[("authorization", f"Bearer {token}")])}
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    out = backend.secrets("s")
    (secret,) = out["secrets"]
    assert secret["scheme"] == "Bearer"
    assert secret["jwt"]["header"]["alg"] == "RS256"
    assert secret["jwt"]["claims"]["iss"] == "idp"


def test_basic_authorization_scheme(monkeypatch: Any) -> None:
    raws = {"a": _flow(req_headers=[("Authorization", "Basic dXNlcjpwYXNz")])}
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    (secret,) = backend.secrets("s")["secrets"]
    assert secret["scheme"] == "Basic"
    assert "jwt" not in secret


def test_known_api_key_header(monkeypatch: Any) -> None:
    raws = {"a": _flow(req_headers=[("X-API-Key", "key-1234567890")])}
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    (secret,) = backend.secrets("s")["secrets"]
    assert secret["kind"] == "api_key_header"
    assert secret["name"] == "X-API-Key"


def test_heuristic_api_key_header(monkeypatch: Any) -> None:
    """An unknown x-*-token header still classifies as an API-key carrier."""
    raws = {"a": _flow(req_headers=[("X-Custom-Token", "tok-abcdefghij")])}
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    (secret,) = backend.secrets("s")["secrets"]
    assert secret["kind"] == "api_key_header"
    assert secret["name"] == "X-Custom-Token"


def test_request_cookies_are_split_and_session_flagged(monkeypatch: Any) -> None:
    raws = {
        "a": _flow(req_headers=[("Cookie", "sessionid=deadbeefcafe; _ga=GA1.2.3.4")])
    }
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    out = backend.secrets("s", kind="cookie")
    by_name = {s["name"]: s for s in out["secrets"]}
    assert by_name["sessionid"]["session"] is True
    assert by_name["sessionid"]["location"] == "request"
    assert by_name["_ga"]["session"] is False


def test_set_cookie_captures_attributes(monkeypatch: Any) -> None:
    raws = {
        "a": _flow(
            resp_headers=[
                ("Set-Cookie", "auth=tok-abcdefghij; HttpOnly; Secure; SameSite=Lax")
            ]
        )
    }
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    (secret,) = backend.secrets("s")["secrets"]
    assert secret["kind"] == "set_cookie"
    assert secret["name"] == "auth"
    assert secret["location"] == "response"
    assert secret["session"] is True
    assert secret["cookie_attributes"]["httponly"] is True
    assert secret["cookie_attributes"]["secure"] is True
    assert secret["cookie_attributes"]["samesite"] == "Lax"


def test_secret_query_param_extracted_and_plain_param_ignored(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, url="http://api.example.com/cb?access_token=zzzz1234&page=2")
    ]
    backend = _backend(monkeypatch, _FakeRecorder(summaries, {"a": _flow()}))
    out = backend.secrets("s")
    names = {s["name"] for s in out["secrets"]}
    assert "access_token" in names
    assert "page" not in names
    token = next(s for s in out["secrets"] if s["name"] == "access_token")
    assert token["kind"] == "query_param"


def test_identical_secret_across_flows_folds_with_count_and_hosts(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, host="api.one.com"),
        _summary("b", seq=2, host="api.two.com"),
    ]
    raws = {
        "a": _flow(req_headers=[("Authorization", "Bearer sametoken12345")]),
        "b": _flow(req_headers=[("Authorization", "Bearer sametoken12345")]),
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))
    out = backend.secrets("s")
    assert out["total"] == 1
    (secret,) = out["secrets"]
    assert secret["count"] == 2
    assert secret["hosts"] == ["api.one.com", "api.two.com"]
    assert secret["example_id"] == "a"


def test_reveal_returns_the_full_value(monkeypatch: Any) -> None:
    raws = {"a": _flow(req_headers=[("X-API-Key", "key-1234567890")])}
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    redacted = backend.secrets("s")["secrets"][0]
    revealed = backend.secrets("s", reveal=True)["secrets"][0]
    assert redacted["value"] != "key-1234567890"
    assert revealed["value"] == "key-1234567890"
    assert revealed["value_sha256"] == redacted["value_sha256"]  # same underlying secret


def test_kind_filter_keeps_one_category(monkeypatch: Any) -> None:
    raws = {
        "a": _flow(
            req_headers=[
                ("Authorization", "Bearer abcdefghij"),
                ("Cookie", "sid=zzzzzzzzzz"),
            ]
        )
    }
    backend = _backend(monkeypatch, _FakeRecorder([_summary("a", seq=1)], raws))
    out = backend.secrets("s", kind="authorization")
    assert out["kind"] == "authorization"
    assert {s["kind"] for s in out["secrets"]} == {"authorization"}


def test_unknown_kind_is_invalid_params(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _FakeRecorder([], {}))
    with pytest.raises(ProxyError) as excinfo:
        backend.secrets("s", kind="bogus")
    assert excinfo.value.code == "invalid_params"


def test_host_filter_narrows_candidates(monkeypatch: Any) -> None:
    summaries = [
        _summary("a", seq=1, host="api.one.com"),
        _summary("b", seq=2, host="api.two.com"),
    ]
    raws = {
        "a": _flow(req_headers=[("Authorization", "Bearer one-1234567890")]),
        "b": _flow(req_headers=[("Authorization", "Bearer two-1234567890")]),
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))
    out = backend.secrets("s", host="one.com")
    assert out["total"] == 1
    assert out["filter"] == {"host": "one.com"}


def test_omitted_body_still_scans_the_url_query(monkeypatch: Any) -> None:
    """A body-omitted flow yields no header secrets but its URL query is read."""
    summaries = [_summary("a", seq=1, url="http://api.example.com/x?api_key=zzzz1234")]
    backend = _backend(monkeypatch, _FakeRecorder(summaries, {"a": _OMITTED_BODY}))
    out = backend.secrets("s")
    assert out["headers_unavailable"] == 1
    assert out["scanned"] == 0
    assert {s["name"] for s in out["secrets"]} == {"api_key"}


def test_pagination_windows_the_secret_list(monkeypatch: Any) -> None:
    summaries = []
    raws = {}
    for i in range(5):
        fid = f"f{i}"
        summaries.append(_summary(fid, seq=i + 1))
        raws[fid] = _flow(req_headers=[("X-API-Key", f"key-{i}-abcdefghij")])
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))
    page = backend.secrets("s", offset=1, limit=2)
    assert page["offset"] == 1
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True


def test_collect_cap_discloses(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.proxy.client._MAX_SECRETS_COLLECT", 2
    )
    summaries = []
    raws = {}
    for i in range(5):
        fid = f"f{i}"
        summaries.append(_summary(fid, seq=i + 1))
        raws[fid] = _flow(req_headers=[("X-API-Key", f"key-{i}-abcdefghij")])
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))
    out = backend.secrets("s")
    assert out["collect_capped"] is True
    assert out["total"] == 2


def test_empty_capture_is_a_clean_zero(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _FakeRecorder([], {}))
    out = backend.secrets("s")
    assert out["total"] == 0
    assert out["secrets"] == []
    assert out["captured"] == 0
    assert out["kind_counts"] == {}


def test_service_wraps_unknown_session_as_failure() -> None:
    service = AnalysisService(Settings.load())
    result = service.proxy_secrets("no-such-session")
    assert not result.ok
    assert result.error is not None


def test_docstring_frames_it_as_a_traffic_secret_scan() -> None:
    doc = _tool_docstring("proxy.secrets")
    for token in ("Authorization", "jwt", "reveal", "value_sha256", "kind", "has_more"):
        assert token in doc, token
