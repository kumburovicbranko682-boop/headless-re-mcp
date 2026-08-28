"""web.network.post_data exposes the captured per-request upload body.

Covers the capture path (driven through the _wire_events seam with a fake CDP)
and the network_post_data query method (driven through the _get seam).
"""

from __future__ import annotations

import ast
from collections import OrderedDict, deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_POST_BODY_BYTES,
    WebBackend,
    WebError,
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
        self.post_data: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.console: deque[dict[str, Any]] = deque()
        self.requests_dropped = 0
        self.scripts_dropped = 0
        self.console_dropped = 0
        self.cdp = _Cdp()


def _backend_over(handle: _Handle) -> WebBackend:
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    return backend


def _send_request(handle: _Handle, params: dict[str, Any]) -> None:
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    handle.cdp.handlers["Network.requestWillBeSent"](params)


def test_capture_records_a_post_body() -> None:
    handle = _Handle()
    _send_request(
        handle,
        {
            "requestId": "r1",
            "request": {
                "url": "https://api.example/login",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "hasPostData": True,
                "postData": '{"user":"a","pass":"b"}',
            },
            "type": "XHR",
        },
    )
    payload = _backend_over(handle).network_post_data("s", "r1")
    assert payload["has_post_data"] is True
    assert payload["data"] == '{"user":"a","pass":"b"}'
    assert payload["size"] == len('{"user":"a","pass":"b"}')
    assert payload["content_type"] == "application/json"
    assert payload["method"] == "POST"
    assert payload["truncated"] is False


def test_get_request_has_no_body() -> None:
    handle = _Handle()
    _send_request(
        handle,
        {
            "requestId": "r2",
            "request": {"url": "https://x/y", "method": "GET", "headers": {}},
            "type": "Document",
        },
    )
    payload = _backend_over(handle).network_post_data("s", "r2")
    assert payload["has_post_data"] is False
    assert payload["data"] == ""
    assert payload["size"] == 0


def test_has_post_data_without_inline_body_is_still_recorded() -> None:
    handle = _Handle()
    _send_request(
        handle,
        {
            "requestId": "r3",
            "request": {
                "url": "https://x/upload",
                "method": "PUT",
                "headers": {"content-type": "application/octet-stream"},
                "hasPostData": True,
            },
            "type": "XHR",
        },
    )
    payload = _backend_over(handle).network_post_data("s", "r3")
    assert payload["has_post_data"] is True
    assert payload["data"] == ""
    assert payload["content_type"] == "application/octet-stream"


def test_large_post_body_is_bounded() -> None:
    handle = _Handle()
    _send_request(
        handle,
        {
            "requestId": "r4",
            "request": {
                "url": "https://x/big",
                "method": "POST",
                "headers": {"Content-Type": "text/plain"},
                "hasPostData": True,
                "postData": "A" * 200_000,
            },
            "type": "XHR",
        },
    )
    payload = _backend_over(handle).network_post_data("s", "r4")
    assert payload["truncated"] is True
    assert payload["size"] <= _MAX_POST_BODY_BYTES + 8
    assert payload["size"] < 200_000


def test_unknown_request_id_is_not_found() -> None:
    handle = _Handle()
    backend = _backend_over(handle)
    try:
        backend.network_post_data("s", "nope")
    except WebError as exc:
        assert exc.code == "not_found"
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected WebError not_found")


def test_web_network_post_data_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.network.post_data")
    assert "has_post_data" in doc
    assert "content_type" in doc
    assert "truncated" in doc
    assert "not_found" in doc
