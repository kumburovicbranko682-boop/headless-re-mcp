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
    assert "request_body" in doc


class _RecordingCdp:
    def __init__(self, post: str = "user=alice&pw=secret") -> None:
        self.calls: list[str] = []
        self._post = post

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(method)
        if method == "Network.getResponseBody":
            return {"body": "resp", "base64Encoded": False}
        if method == "Network.getRequestPostData":
            return {"postData": self._post}
        return {}


class _PostHandle:
    def __init__(self, post: str = "user=alice&pw=secret", *, has_post: bool = True) -> None:
        self.lock = Lock()
        entry: dict[str, Any] = {"requestId": "r1", "url": "https://x", "method": "POST"}
        if has_post:
            entry["has_post_data"] = True
        self.requests = {"r1": entry}
        self.cdp = _RecordingCdp(post)


def test_web_network_get_returns_the_request_post_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Symmetric with proxy.flow.get: the payload the page sent is recoverable.

    Measured: a POST row -> request_body holds the postData, no spill for a
    small body, and the getRequestPostData CDP call was made.
    """
    backend = WebBackend()
    handle = _PostHandle()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == "resp"
    assert payload["request_body"] == "user=alice&pw=secret"
    assert payload["request_body_truncated"] is False
    assert "request_body_path" not in payload
    assert "Network.getRequestPostData" in handle.cdp.calls


def test_web_network_get_spills_a_large_request_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A request body past the inline buffer spills like the response body."""
    backend = WebBackend()
    handle = _PostHandle("p" * (_MAX_INLINE_BODY + 25))
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["request_body_truncated"] is True
    assert len(payload["request_body"]) == _MAX_INLINE_BODY
    assert "request_body_path" in payload
    assert Path(str(payload["request_body_path"])).is_file()


def test_web_network_get_skips_request_body_when_the_row_had_none(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A GET (no has_post_data) never triggers a getRequestPostData call."""
    backend = WebBackend()
    handle = _PostHandle(has_post=False)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert "request_body" not in payload
    assert "Network.getRequestPostData" not in handle.cdp.calls


def test_web_network_get_strips_the_har_only_inline_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The inline post_data is a har.export-only ring detail; network.get pulls
    the full request_body via CDP, so the redundant preview must not leak out.
    """
    backend = WebBackend()
    handle = _PostHandle()
    handle.requests["r1"]["post_data"] = "user=alice&pw=secret"
    handle.requests["r1"]["post_data_truncated"] = False
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert "post_data" not in payload
    assert "post_data_truncated" not in payload
    # The canonical, full body is still there under request_body.
    assert payload["request_body"] == "user=alice&pw=secret"


class _ListBodyHandle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests = {
            "r1": {
                "url": "https://x/login",
                "method": "POST",
                "status": 200,
                "post_data": "user=alice",
                "post_data_truncated": False,
                "request_headers": [{"name": "content-type", "value": "text/plain"}],
            }
        }
        self.requests_dropped = 0


def test_web_network_list_strips_the_har_only_inline_body(monkeypatch: Any) -> None:
    """network.list is a lean index; the inline POST body stays off it, like the
    header lists already do.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _ListBodyHandle())
    row = backend.network_list("s", offset=0, limit=10)["requests"][0]
    assert "post_data" not in row
    assert "post_data_truncated" not in row
    assert "request_headers" not in row
    assert row["url"] == "https://x/login"


class _PostErrorCdp:
    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "Network.getResponseBody":
            return {"body": "resp", "base64Encoded": False}
        raise RuntimeError("No resource with given identifier found")


class _PostErrorHandle:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x", "has_post_data": True}}
    cdp = _PostErrorCdp()


def test_web_network_get_soft_errors_a_missing_request_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A per-body CDP failure is a note, not a lost response body."""
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _PostErrorHandle())
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == "resp"
    assert "request_body" not in payload
    assert "request_body_error" in payload
