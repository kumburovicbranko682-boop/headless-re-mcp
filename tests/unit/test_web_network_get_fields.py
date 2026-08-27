"""web.network.get description must name body_truncated, not truncated."""

from __future__ import annotations

import ast
import base64
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend
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


class _CdpBodies:
    """Serves a response body and a request payload for the same request."""

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "Network.getRequestPostData":
            return {"postData": '{"user":"alice","token":"s3cr3t"}'}
        return {"body": '{"ok":true}', "base64Encoded": False}


class _HandleWithBody:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x", "has_request_body": True}}
    cdp = _CdpBodies()


class _CdpNoPostData:
    """Response body only; the browser no longer retains the payload."""

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "Network.getRequestPostData":
            raise RuntimeError("No resource with given identifier found")
        return {"body": '{"ok":true}', "base64Encoded": False}


class _HandleLostBody:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x", "has_request_body": True}}
    cdp = _CdpNoPostData()


class _HandleNoBody:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x"}}
    cdp = _CdpBodies()


def test_web_network_get_returns_the_request_body(tmp_path: Path, monkeypatch: Any) -> None:
    """The request payload used to be dropped, leaving only the response.

    Measured: a request flagged as carrying a body comes back with
    request_body (the sent JSON) and request_body_truncated alongside the
    response body; a GET with no body has no request_body key; and a payload
    the browser has since evicted lands as request_body_error, not a crash.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())

    monkeypatch.setattr(backend, "_get", lambda session_id: _HandleWithBody())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["request_body"] == '{"user":"alice","token":"s3cr3t"}'
    assert payload["request_body_truncated"] is False
    assert "request_body_path" not in payload
    assert payload["body"] == '{"ok":true}'

    monkeypatch.setattr(backend, "_get", lambda session_id: _HandleNoBody())
    plain = backend.network_get("s", "r1", tmp_path)
    assert "request_body" not in plain
    assert "request_body_error" not in plain

    monkeypatch.setattr(backend, "_get", lambda session_id: _HandleLostBody())
    lost = backend.network_get("s", "r1", tmp_path)
    assert "request_body" not in lost
    assert "identifier" in lost["request_body_error"]

    doc = _tool_docstring("web.network.get")
    assert "request_body" in doc


_BINARY_BODY = b"\x89PNG\r\n\x1a\n" + bytes(range(64))


class _CdpBinaryBody:
    """Serves a binary response the way CDP does: base64 text + a flag."""

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "body": base64.b64encode(_BINARY_BODY).decode("ascii"),
            "base64Encoded": True,
        }


class _HandleBinary:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x/logo.png"}}
    cdp = _CdpBinaryBody()


def test_web_network_get_decodes_a_binary_response_to_real_bytes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A base64 response must land as the resource, not as base64 text.

    body_path used to hold the base64 string CDP returned, so saving an image
    or feeding a wasm/protobuf body downstream got the wrong bytes. Now the
    spilled file is the decoded payload, body_bytes is its true length, and a
    bounded base64 preview stands in for the (non-text) body.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    monkeypatch.setattr(backend, "_get", lambda session_id: _HandleBinary())

    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["base64_encoded"] is True
    assert payload["body"] == ""
    assert payload["body_bytes"] == len(_BINARY_BODY)
    assert payload["body_base64_truncated"] is False
    # The preview decodes back to the head of the resource...
    assert base64.b64decode(payload["body_base64"]) == _BINARY_BODY
    # ...and the spilled artifact is the decoded bytes, not base64 text.
    spilled = Path(str(payload["body_path"]))
    assert spilled.is_file()
    assert spilled.read_bytes() == _BINARY_BODY

    doc = _tool_docstring("web.network.get")
    assert "body_bytes" in doc
    assert "body_base64" in doc
