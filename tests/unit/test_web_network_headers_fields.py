"""web network capture must retain bounded request/response headers.

Headers (Authorization, Set-Cookie, CSP, Location) are central to web triage.
They ride in the capture ring for the web.network.get detail view, are bounded
so a hostile server cannot balloon the ring, and are kept out of the
web.network.list summary so a page of rows stays lean.
"""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADER_VALUE_BYTES,
    _MAX_HEADERS,
    _MAX_METADATA_BYTES,
    WebBackend,
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


class _Cdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str) -> None:
        del method

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class _RingHandle:
    """Enough of a session for _wire_events and network_list to run."""

    def __init__(self) -> None:
        self.lock = Lock()
        self.requests: dict[str, Any] = {}
        self.scripts: dict[str, Any] = {}
        from collections import deque

        self.console: deque[Any] = deque()
        self.requests_dropped = 0
        self.scripts_dropped = 0
        self.console_dropped = 0
        self.cdp = _Cdp()


def _wired() -> _RingHandle:
    handle = _RingHandle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    return handle


def test_network_capture_keeps_request_and_response_headers() -> None:
    """A captured request carries the Authorization and Set-Cookie it saw."""
    handle = _wired()
    handle.cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://api.example/login",
                "method": "POST",
                "headers": {"Authorization": "Bearer tok", "X-Trace": "abc"},
            },
            "type": "XHR",
        }
    )
    handle.cdp.handlers["Network.responseReceived"](
        {
            "requestId": "r1",
            "response": {
                "status": 200,
                "mimeType": "application/json",
                "headers": {"Set-Cookie": "sid=xyz; HttpOnly", "Content-Type": "application/json"},
            },
        }
    )
    entry = handle.requests["r1"]
    assert entry["request_headers"]["Authorization"] == "Bearer tok"
    assert entry["request_headers"]["X-Trace"] == "abc"
    assert entry["response_headers"]["Set-Cookie"] == "sid=xyz; HttpOnly"
    assert "request_headers_truncated" not in entry
    assert "response_headers_truncated" not in entry


def test_network_list_omits_headers_to_stay_lean() -> None:
    """The list summary drops the header maps; the detail view keeps them."""
    handle = _wired()
    handle.cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://api.example/x",
                "method": "GET",
                "headers": {"Authorization": "Bearer tok"},
            },
            "type": "XHR",
        }
    )
    backend = WebBackend()
    # network_list reads from the handle; point the backend at ours.
    backend._get = lambda session_id: handle  # type: ignore[method-assign,assignment]
    listed = backend.network_list("s")
    row = listed["requests"][0]
    assert "request_headers" not in row
    assert "response_headers" not in row
    # The ring entry still has them for web.network.get.
    assert handle.requests["r1"]["request_headers"]["Authorization"] == "Bearer tok"
    doc = _tool_docstring("web.network.get")
    assert "request_headers" in doc
    assert "response_headers" in doc


def test_header_capture_is_bounded_in_count_and_value() -> None:
    """A hostile header set is capped in count and per-value, and flagged."""
    handle = _wired()
    many = {f"H{i}": "v" for i in range(_MAX_HEADERS + 20)}
    handle.cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://api.example/x",
                "method": "GET",
                "headers": {**many, "Big": "A" * (_MAX_HEADER_VALUE_BYTES + 100)},
            },
            "type": "XHR",
        }
    )
    entry = handle.requests["r1"]
    assert len(entry["request_headers"]) <= _MAX_HEADERS
    assert entry["request_headers_truncated"] is True
    for value in entry["request_headers"].values():
        assert len(value.encode("utf-8")) <= _MAX_HEADER_VALUE_BYTES
    # Header names are bounded like other metadata.
    for name in entry["request_headers"]:
        assert len(name.encode("utf-8")) <= _MAX_METADATA_BYTES
