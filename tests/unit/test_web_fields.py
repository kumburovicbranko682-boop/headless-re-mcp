"""web tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADER_VALUE_BYTES,
    _MAX_METADATA_BYTES,
    _MAX_URL_BYTES,
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


class _FakeHandle:
    def __init__(self, count: int, *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.console = deque({"text": str(index)} for index in range(count))
        self.requests = {
            str(index): {
                "requestId": str(index),
                "url": f"https://example/{index}",
                "method": "GET",
                "resourceType": "XHR",
                "status": 200,
                "mimeType": "application/json",
            }
            for index in range(count)
        }
        self.scripts = {
            str(index): {
                "scriptId": str(index),
                "url": f"https://example/{index}",
                "language": "WebAssembly" if index % 2 else "JavaScript",
            }
            for index in range(count)
        }
        self.scripts_dropped = dropped
        self.console_dropped = 0
        self.requests_dropped = 0


def test_web_console_puts_messages_in_console_and_says_when_it_stopped(
    monkeypatch: Any,
) -> None:
    """The catalog said messages and never named the payload.

    Measured: 25 held, limit 10 -> count 10, has_more True, field is console
    not messages or logs. Looking for messages after a successful call reads
    as an empty console, and a full page with no has_more reads as the buffer.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(25))
    payload = backend.console("s", limit=10)
    assert "messages" not in payload
    assert "logs" not in payload
    assert payload["count"] == 10
    assert len(payload["console"]) == 10
    assert payload["has_more"] is True
    assert payload["dropped"] == 0
    doc = _tool_docstring("web.console")
    assert "Answers with console" in doc
    assert "has_more" in doc
    assert "dropped" in doc
    assert "text_truncated" in doc


def test_web_network_list_puts_the_page_in_requests_not_type(
    monkeypatch: Any,
) -> None:
    """The catalog said type and never named the list field.

    Measured: 25 held, limit 10 -> count 10, total 25, field is requests
    not items or network, and each row carries resourceType with no type
    key. Looking for type or network after a successful call reads as an
    empty capture, and a full page with no total reads as the whole log.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(25))
    payload = backend.network_list("s", offset=0, limit=10)
    assert "network" not in payload
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["offset"] == 0
    assert payload["has_more"] is True
    assert payload["dropped"] == 0
    assert len(payload["requests"]) == 10
    row = payload["requests"][0]
    assert "type" not in row
    assert row["resourceType"] == "XHR"
    normalized = backend.network_list("s", offset=-10, limit=0)
    assert normalized["offset"] == 0
    assert normalized["count"] == 1
    assert normalized["has_more"] is True
    doc = _tool_docstring("web.network.list")
    assert "Answers with requests" in doc
    assert "resourceType" in doc
    assert "total" in doc
    assert "has_more" in doc
    assert "dropped" in doc
    assert "metadata_truncated" in doc


def test_web_event_metadata_is_bounded_before_entering_capture_rings() -> None:
    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    huge = "é" * (_MAX_URL_BYTES + 1)

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "request-1",
            "request": {"url": huge, "method": huge},
            "type": huge,
        }
    )
    cdp.handlers["Network.responseReceived"](
        {
            "requestId": "request-1",
            "response": {"status": 200, "mimeType": huge},
        }
    )
    cdp.handlers["Debugger.scriptParsed"](
        {"scriptId": "script-1", "url": huge, "scriptLanguage": huge}
    )

    request = handle.requests["request-1"]
    assert len(str(request["url"]).encode()) <= _MAX_URL_BYTES
    assert len(str(request["method"]).encode()) <= _MAX_METADATA_BYTES
    assert len(str(request["resourceType"]).encode()) <= _MAX_METADATA_BYTES
    assert len(str(request["mimeType"]).encode()) <= _MAX_METADATA_BYTES
    assert request["metadata_truncated"] is True
    script = handle.scripts["script-1"]
    assert len(str(script["url"]).encode()) <= _MAX_URL_BYTES
    assert len(str(script["language"]).encode()) <= _MAX_METADATA_BYTES
    assert script["metadata_truncated"] is True


def test_web_loading_failed_marks_the_request_instead_of_leaving_it_pending() -> None:
    """Network.loadingFailed must flag the request; a blocked call has no response.

    Wire the events, open a request, then fire loadingFailed the way Chromium
    does for a blocked resource (errorText plus blockedReason). Assert the entry
    is flagged failed with the reason kept and no phantom status, and that a
    failure for an unknown/evicted request id is ignored rather than crashing.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    assert "Network.loadingFailed" in cdp.handlers
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "request-1",
            "request": {"url": "https://blocked/x", "method": "GET"},
            "type": "XHR",
        }
    )
    cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "request-1",
            "errorText": "net::ERR_BLOCKED_BY_CLIENT",
            "blockedReason": "inspector",
            "canceled": False,
        }
    )
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "ghost", "errorText": "net::ERR_ABORTED"}
    )

    entry = handle.requests["request-1"]
    assert entry["failed"] is True
    assert entry["error_text"] == "net::ERR_BLOCKED_BY_CLIENT"
    assert entry["blocked_reason"] == "inspector"
    assert entry["status"] is None
    assert "canceled" not in entry
    assert "ghost" not in handle.requests
    doc = _tool_docstring("web.network.list")
    assert "failed" in doc
    assert "error_text" in doc


def test_web_captures_bounded_request_and_response_headers() -> None:
    """Headers (auth, cookies, content type) must be captured and bounded.

    Wire the events, fire a request/response the way Chromium does (headers on
    request.headers and response.headers), and assert the entry carries
    request_headers and response_headers, that an oversized value is clipped and
    flags metadata_truncated, and that network.list omits headers while the
    stored entry keeps them for network.get.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    huge = "z" * (_MAX_HEADER_VALUE_BYTES + 500)
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://api/x",
                "method": "POST",
                "headers": {"Authorization": "Bearer secret", "X-Big": huge},
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
                "headers": {"Content-Type": "application/json", "Set-Cookie": "sid=abc"},
            },
        }
    )

    entry = handle.requests["r1"]
    assert entry["request_headers"]["Authorization"] == "Bearer secret"
    assert len(entry["request_headers"]["X-Big"].encode()) <= _MAX_HEADER_VALUE_BYTES
    assert entry["metadata_truncated"] is True
    assert entry["response_headers"]["Content-Type"] == "application/json"
    assert entry["response_headers"]["Set-Cookie"] == "sid=abc"

    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[assignment]
    row = backend.network_list("s")["requests"][0]
    assert "request_headers" not in row
    assert "response_headers" not in row
    # The list row is a copy: stripping it must not strip the stored entry.
    assert "response_headers" in handle.requests["r1"]
    doc = _tool_docstring("web.network.get")
    assert "request_headers" in doc
    assert "response_headers" in doc


def test_web_uncaught_exception_lands_in_the_console_ring() -> None:
    """Runtime.exceptionThrown must be captured; console.* is not the only source.

    Wire the events and fire an exceptionThrown the way Chromium does (the error
    lives in exceptionDetails.exception.description), then assert it enters the
    console ring as an error entry tagged source exception with the stack text,
    and that a details-less event is ignored rather than crashing the handler.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    assert "Runtime.exceptionThrown" in cdp.handlers
    cdp.handlers["Runtime.exceptionThrown"](
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "exception": {"description": "Error: boom\n    at http://x/app.js:1:1"},
            }
        }
    )
    cdp.handlers["Runtime.exceptionThrown"]({})  # malformed: must be ignored

    captured = list(handle.console)
    assert len(captured) == 1
    entry = captured[0]
    assert entry["type"] == "error"
    assert entry["source"] == "exception"
    assert "boom" in entry["text"]
    doc = _tool_docstring("web.console")
    assert "exception" in doc


def test_web_wasm_list_puts_modules_in_scripts_not_modules(
    monkeypatch: Any,
) -> None:
    """The catalog said modules and never named the payload.

    Measured: 10 parsed scripts, 5 of them WebAssembly -> count 5, field is
    scripts not modules or wasm. Looking for modules after a successful call
    reads as the page loading none.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(10, dropped=3))
    payload = backend.scripts("s", wasm_only=True)
    assert "modules" not in payload
    assert "wasm" not in payload
    assert payload["count"] == 5
    assert len(payload["scripts"]) == 5
    assert all(row["language"] == "WebAssembly" for row in payload["scripts"])
    assert payload["has_more"] is False
    assert payload["dropped"] == 3
    doc = _tool_docstring("web.wasm.list")
    assert "Answers with scripts" in doc
    assert "no modules field" in doc
    assert "has_more" in doc
