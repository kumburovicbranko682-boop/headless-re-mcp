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


class _CdpNoBody:
    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("No resource with given identifier found")


class _Handle:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x"}}
    cdp = _Cdp()


class _HandleNoBody:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x", "status": 302}}
    cdp = _CdpNoBody()


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


def test_web_network_get_keeps_the_documented_shape_when_the_body_is_missing(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A body-less request (redirect, evicted body) must not drop body fields.

    CDP raises "No resource with given identifier found" for such requests. The
    call used to return only the request metadata plus body_error, so a caller
    reading result["body"] hit a missing key on exactly the failure path. The
    documented body/base64_encoded/body_truncated must survive alongside the
    explanation, and no artifact is written.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _HandleNoBody())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == ""
    assert payload["base64_encoded"] is False
    assert payload["body_truncated"] is False
    assert "No resource" in payload["body_error"]
    assert "body_path" not in payload
    # The request metadata still rides along.
    assert payload["url"] == "https://x"
    assert payload["status"] == 302
    # Nothing was spilled for an empty body.
    assert list(tmp_path.iterdir()) == []
    doc = _tool_docstring("web.network.get")
    assert "body_error" in doc
