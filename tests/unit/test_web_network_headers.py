"""web.network.get exposes bounded response headers; web.network.list omits them.

CDP delivers response headers in the ``Network.responseReceived`` event, but the
backend used to keep only status and mimeType, so redirect Location, CSP,
Set-Cookie and custom auth headers were unreachable on the CDP line even though
the proxy line's flow_get returned them. Headers are now captured under three
ceilings (count, per-value, total) into each request and surfaced by
network_get; network_list stays lean.
"""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADER_ITEMS,
    _MAX_HEADER_VALUE_BYTES,
    WebBackend,
    _bounded_headers,
    _WebSession,
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


class _RecordingCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        del method, params
        return {}

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        del timeout
        return work()


class _BodyCdp:
    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        del method, params
        return {"body": "hello", "base64Encoded": False}


def test_bounded_headers_caps_count_value_and_total() -> None:
    # Per-value clip.
    out, truncated = _bounded_headers({"x-big": "v" * (_MAX_HEADER_VALUE_BYTES + 50)})
    assert truncated is True
    assert len(out["x-big"].encode("utf-8")) == _MAX_HEADER_VALUE_BYTES

    # Count cap: far more names than the item ceiling.
    many = {f"h{i}": "y" for i in range(_MAX_HEADER_ITEMS + 25)}
    capped, capped_truncated = _bounded_headers(many)
    assert capped_truncated is True
    assert len(capped) <= _MAX_HEADER_ITEMS

    # A non-dict (a request still in flight, or a malformed event) is empty.
    empty, empty_truncated = _bounded_headers(None)
    assert empty == {}
    assert empty_truncated is False

    # A small, well-formed map is copied verbatim and not flagged.
    good, good_truncated = _bounded_headers({"content-type": "text/html"})
    assert good == {"content-type": "text/html"}
    assert good_truncated is False


def test_on_response_captures_bounded_headers() -> None:
    """The response handler stores the header map next to status/mimeType."""
    cdp = _RecordingCdp()
    handle = _WebSession(object(), object(), object(), object(), cdp)
    WebBackend()._wire_events(handle)
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {"url": "https://x/", "method": "GET"},
            "type": "Document",
        }
    )
    cdp.handlers["Network.responseReceived"](
        {
            "requestId": "r1",
            "response": {
                "status": 302,
                "mimeType": "text/html",
                "headers": {"Location": "https://y/", "Set-Cookie": "a=b"},
            },
        }
    )
    entry = handle.requests["r1"]
    assert entry["status"] == 302
    assert entry["response_headers"]["Location"] == "https://y/"
    assert entry["response_headers"]["Set-Cookie"] == "a=b"
    assert "headers_truncated" not in entry


def test_network_get_returns_response_headers(monkeypatch: Any, tmp_path: Path) -> None:
    backend = WebBackend()

    class _Handle:
        lock = Lock()
        requests = {
            "r1": {
                "requestId": "r1",
                "url": "https://x/",
                "status": 200,
                "response_headers": {"content-type": "application/json"},
            }
        }
        cdp = _BodyCdp()

    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["response_headers"] == {"content-type": "application/json"}
    assert payload["body"] == "hello"
    doc = _tool_docstring("web.network.get")
    assert "response_headers" in doc


def test_network_list_omits_response_headers() -> None:
    backend = WebBackend()
    handle = _WebSession(object(), object(), object(), object(), object())
    handle.requests["r1"] = {
        "requestId": "r1",
        "url": "https://x/",
        "status": 200,
        "response_headers": {"content-type": "application/json"},
        "headers_truncated": True,
    }
    backend._sessions["s"] = handle
    result = backend.network_list("s")
    row = result["requests"][0]
    assert "response_headers" not in row
    assert "headers_truncated" not in row
    # The summary fields survive the strip.
    assert row["url"] == "https://x/"
    assert row["status"] == 200
    doc = _tool_docstring("web.network.list")
    assert "web.network.get" in doc
