"""web.network.get description must name body_truncated, not truncated."""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend, WebError
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


class _RaisingRunner:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def call(self, work: Any, timeout: float | None = None) -> Any:
        raise self._exc


def test_a_wedged_browser_during_body_fetch_is_a_failure_not_a_soft_body_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A session-level WebError must not be folded into body_error.

    network_get degrades a real getResponseBody miss (body evicted, no body for
    the request) into an ok envelope carrying body_error. A wedged, timed-out,
    or closed runner raises WebError, and folding that in the same way answers
    ok=True for a dead session: the caller reads a request that "succeeded but
    had no body" when the browser stopped responding. script_source already
    re-raises WebError here; network_get must match.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(
        backend,
        "_runner",
        lambda handle: _RaisingRunner(WebError("timeout", "browser did not respond")),
    )
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "r1", tmp_path)
    assert caught.value.code == "timeout"


def test_a_genuine_body_fetch_miss_still_degrades_to_body_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """CDP failing to return a body is not a session failure and stays soft."""
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(
        backend,
        "_runner",
        lambda handle: _RaisingRunner(RuntimeError("No resource with given identifier found")),
    )
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["requestId"] == "r1"
    assert "No resource" in payload["body_error"]
