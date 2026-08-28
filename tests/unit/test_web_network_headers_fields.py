"""web.network.headers exposes the captured per-request header maps.

Covers the capture handlers (driven through the _wire_events seam with a fake
CDP) and the network_headers query method (driven through the _get seam), plus
the header-bounding helper.
"""

from __future__ import annotations

import ast
from collections import OrderedDict, deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADERS,
    WebBackend,
    _bounded_header_map,
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


class _Handle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.headers: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.console: deque[dict[str, Any]] = deque()
        self.requests_dropped = 0
        self.scripts_dropped = 0
        self.console_dropped = 0
        self.cdp = _Cdp()


def test_bounded_header_map_caps_count() -> None:
    big = {f"h{i}": "v" for i in range(_MAX_HEADERS + 20)}
    out, truncated = _bounded_header_map(big)
    assert len(out) == _MAX_HEADERS
    assert truncated is True


def test_bounded_header_map_caps_value_length() -> None:
    out, truncated = _bounded_header_map({"x-big": "a" * 100_000})
    assert truncated is True
    assert len(out["x-big"]) < 100_000


def test_capture_records_request_and_response_headers() -> None:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    cdp = handle.cdp
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://api.example/login",
                "method": "POST",
                "headers": {"Authorization": "Bearer tok", "Cookie": "sid=abc"},
            },
            "type": "XHR",
        }
    )
    cdp.handlers["Network.responseReceived"](
        {
            "requestId": "r1",
            "response": {
                "status": 200,
                "mimeType": "application/json",
                "headers": {"Set-Cookie": "sid=def; HttpOnly", "Content-Type": "application/json"},
            },
        }
    )

    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    payload = backend.network_headers("s", "r1")
    assert payload["request_headers"]["Authorization"] == "Bearer tok"
    assert payload["response_headers"]["Set-Cookie"] == "sid=def; HttpOnly"
    assert payload["request_header_count"] == 2
    assert payload["response_header_count"] == 2
    assert payload["status"] == 200
    assert payload["headers_truncated"] is False


def test_headers_empty_response_for_a_request_with_no_reply() -> None:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    handle.cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r2",
            "request": {"url": "https://x/y", "method": "GET", "headers": {"Accept": "*/*"}},
            "type": "Document",
        }
    )
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    payload = backend.network_headers("s", "r2")
    assert payload["request_headers"] == {"Accept": "*/*"}
    assert payload["response_headers"] == {}
    assert payload["response_header_count"] == 0


def test_headers_unknown_request_id_is_not_found() -> None:
    from headless_re_mcp.backends.web.client import WebError

    handle = _Handle()
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    try:
        backend.network_headers("s", "nope")
    except WebError as exc:
        assert exc.code == "not_found"
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected WebError not_found")


def test_web_network_headers_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.network.headers")
    assert "request_headers" in doc
    assert "response_headers" in doc
    assert "headers_truncated" in doc
    assert "not_found" in doc
