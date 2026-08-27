"""web.network.get description must name body_truncated, not truncated."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADER_VALUE_BYTES,
    _MAX_HEADERS_ENCODED,
    _MAX_INLINE_BODY,
    WebBackend,
    _bounded_headers,
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
    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"body": "z" * (_MAX_INLINE_BODY + 25), "base64Encoded": False}


class _Handle:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x"}}
    response_headers = {
        "r1": {
            "response_headers": {
                "set-cookie": "sid=abc",
                "content-security-policy": "default-src 'self'",
            },
            "headers_truncated": False,
        }
    }
    request_headers = {"r1": {"user-agent": "gate/1.0", "cookie": "sid=abc"}}
    cdp = _Cdp()


def test_web_network_get_names_body_truncated_not_truncated(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said a spill and never named the cut flag.

    Measured: body_truncated True, truncated absent, body 200000 chars
    (the cap), body_path set. Looking for truncated after a successful
    call reads as a complete body.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    repeated = backend.network_get("s", "r1", tmp_path)
    assert "truncated" not in payload
    assert payload["body_truncated"] is True
    assert len(payload["body"]) == _MAX_INLINE_BODY
    assert "body_path" in payload
    assert payload["body_path"] != repeated["body_path"]
    assert Path(str(payload["body_path"])).is_file()
    assert Path(str(repeated["body_path"])).is_file()
    doc = _tool_docstring("web.network.get")
    assert "body_truncated" in doc
    assert "body_path" in doc


def test_web_network_get_returns_captured_response_headers(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """network_get surfaces the response headers captured at responseReceived.

    Set-Cookie/CSP and friends are the security-relevant metadata a body alone
    cannot answer, so a working read returns them as a str->str map with
    headers_truncated flagged honestly.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["response_headers"]["set-cookie"] == "sid=abc"
    assert payload["response_headers"]["content-security-policy"] == "default-src 'self'"
    assert payload["headers_truncated"] is False
    assert payload["request_headers"]["user-agent"] == "gate/1.0"
    assert payload["request_headers"]["cookie"] == "sid=abc"
    assert payload["request_headers_truncated"] is False
    doc = _tool_docstring("web.network.get")
    assert "response_headers" in doc
    assert "request_headers" in doc


def test_web_network_get_response_headers_empty_when_unseen(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A request with no recorded response reports empty headers, not a crash.

    The id is in requests but absent from response_headers (no responseReceived
    fired), so the field must default to an empty map with headers_truncated
    False rather than raising or omitting the key.
    """

    class _NoHeaders:
        lock = Lock()
        requests = {"r2": {"requestId": "r2", "url": "https://y"}}
        response_headers: dict[str, dict[str, object]] = {}
        request_headers: dict[str, dict[str, str]] = {}
        cdp = _Cdp()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _NoHeaders())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r2", tmp_path)
    assert payload["response_headers"] == {}
    assert payload["headers_truncated"] is False
    assert payload["request_headers"] == {}
    assert payload["request_headers_truncated"] is False


def test_web_network_get_returns_request_body_when_present(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A request marked has_post_data returns the sent body via getRequestPostData.

    The POST payload an API call sent is the request-side counterpart to the
    response body; a working read fetches it on demand and returns it inline.
    """

    class _CdpPost:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            if method == "Network.getRequestPostData":
                return {"postData": '{"user":"admin"}'}
            return {"body": "resp-body", "base64Encoded": False}

    class _PostHandle:
        lock = Lock()
        requests = {"r3": {"requestId": "r3", "url": "https://api", "has_post_data": True}}
        response_headers: dict[str, dict[str, object]] = {}
        request_headers: dict[str, dict[str, str]] = {}
        cdp = _CdpPost()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _PostHandle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r3", tmp_path)
    assert payload["request_body"] == '{"user":"admin"}'
    assert payload["request_body_truncated"] is False
    assert "request_body_path" not in payload
    doc = _tool_docstring("web.network.get")
    assert "request_body" in doc
    assert "has_post_data" in doc


def test_web_network_get_request_body_error_does_not_fail_the_read(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A discarded post body surfaces request_body_error, not a failed read.

    getRequestPostData raises once the browser has dropped the data; the
    response body still reads, so the whole call must not fail -- the request
    side degrades to a request_body_error note.
    """

    class _CdpDropped:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            if method == "Network.getRequestPostData":
                raise RuntimeError("No post data for requestId")
            return {"body": "resp-body", "base64Encoded": False}

    class _PostHandle:
        lock = Lock()
        requests = {"r4": {"requestId": "r4", "url": "https://api", "has_post_data": True}}
        response_headers: dict[str, dict[str, object]] = {}
        request_headers: dict[str, dict[str, str]] = {}
        cdp = _CdpDropped()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _PostHandle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r4", tmp_path)
    assert payload["body"] == "resp-body"
    assert "request_body" not in payload
    assert "No post data" in payload["request_body_error"]


def test_bounded_headers_coerces_bytes_keys_and_values() -> None:
    """Non-str header keys/values are coerced so the map is JSON-safe.

    CDP normally yields str headers, but a bytes value must not reach the JSON
    serializer as bytes -- it would crash the whole reply. Coerce to str.
    """
    headers, truncated = _bounded_headers({b"Set-Cookie": b"sid=abc", "X-Ok": "1"})
    assert headers == {"Set-Cookie": "sid=abc", "X-Ok": "1"}
    assert truncated is False
    json.dumps(headers)


def test_bounded_headers_caps_a_giant_value() -> None:
    """A single oversized header value is capped and flagged truncated."""
    headers, truncated = _bounded_headers({"X-Big": "v" * (_MAX_HEADER_VALUE_BYTES * 4)})
    assert truncated is True
    assert len(headers["X-Big"].encode("utf-8")) <= _MAX_HEADER_VALUE_BYTES


def test_bounded_headers_bounds_a_flood_by_encoded_size() -> None:
    """Hundreds of large headers are trimmed so the map fits its encoded budget.

    A hostile origin could otherwise push megabytes of headers into the reply
    and get the whole network_get discarded for a summary. The map must stay
    within _MAX_HEADERS_ENCODED and report truncated.
    """
    flood = {f"X-Header-{i:04d}": "v" * 1000 for i in range(400)}
    headers, truncated = _bounded_headers(flood)
    assert truncated is True
    assert len(headers) < len(flood)
    assert len(json.dumps(headers).encode("utf-8")) <= _MAX_HEADERS_ENCODED
