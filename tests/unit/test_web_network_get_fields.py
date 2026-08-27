"""web.network.get description must name body_truncated, not truncated."""

from __future__ import annotations

import ast
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
