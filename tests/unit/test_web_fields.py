"""web tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADER_TEXT,
    _MAX_HEADERS,
    _MAX_METADATA_BYTES,
    _MAX_URL_BYTES,
    WebBackend,
    _cdp_headers,
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
    assert "uncaught" in doc


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
    assert "failed" in doc
    assert "error_text" in doc
    assert "blocked_reason" in doc


def test_web_network_list_filters_by_url_substring(monkeypatch: Any) -> None:
    """url_filter narrows a busy capture to one endpoint, case-insensitively."""
    backend = WebBackend()
    handle = _FakeHandle(0)
    handle.requests = {
        "1": {
            "requestId": "1",
            "url": "https://x/api/login",
            "method": "POST",
            "resourceType": "XHR",
            "status": 200,
            "mimeType": "application/json",
        },
        "2": {
            "requestId": "2",
            "url": "https://x/static/app.js",
            "method": "GET",
            "resourceType": "Script",
            "status": 200,
            "mimeType": "text/javascript",
        },
        "3": {
            "requestId": "3",
            "url": "https://x/API/logout",
            "method": "POST",
            "resourceType": "XHR",
            "status": 200,
            "mimeType": "application/json",
        },
    }
    handle.requests_dropped = 4
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    payload = backend.network_list("s", url_filter="/api/")
    assert payload["total"] == 2
    assert {row["url"] for row in payload["requests"]} == {
        "https://x/api/login",
        "https://x/API/logout",
    }
    # dropped is the ring's eviction count, unaffected by the filter.
    assert payload["dropped"] == 4
    # A blank filter returns the whole capture.
    assert backend.network_list("s", url_filter="  ")["total"] == 3
    doc = _tool_docstring("web.network.list")
    assert "url_filter" in doc


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


def test_web_marks_a_failed_request_instead_of_leaving_it_pending() -> None:
    """Network.loadingFailed, not responseReceived, carries a blocked/aborted load.

    Without wiring it a request killed by CSP/CORS or a net::ERR_* transport
    failure stays at status None, indistinguishable from one still in flight --
    and a blocked endpoint is exactly what an analyst hunts for. Measured: two
    requests sent, r1 blocked by CSP and r2 answered 200 -> r1 carries failed
    with error_text/blocked_reason and status stays None, r2 has no failed flag.
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

    for request_id, url in (("r1", "https://x/a"), ("r2", "https://x/b")):
        cdp.handlers["Network.requestWillBeSent"](
            {"requestId": request_id, "request": {"url": url, "method": "GET"}, "type": "XHR"}
        )
    cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "r1",
            "errorText": "net::ERR_BLOCKED_BY_CLIENT",
            "blockedReason": "csp",
            "canceled": False,
        }
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "r2", "response": {"status": 200, "mimeType": "text/html"}}
    )

    failed = handle.requests["r1"]
    assert failed["failed"] is True
    assert failed["error_text"] == "net::ERR_BLOCKED_BY_CLIENT"
    assert failed["blocked_reason"] == "csp"
    assert failed["canceled"] is False
    assert failed["status"] is None
    ok = handle.requests["r2"]
    assert "failed" not in ok
    assert ok["status"] == 200

    # A failure for a request never seen (evicted or pre-capture) is dropped,
    # not resurrected as a bare entry.
    cdp.handlers["Network.loadingFailed"]({"requestId": "ghost", "errorText": "x"})
    assert "ghost" not in handle.requests


def test_web_flags_a_request_that_carried_a_post_body() -> None:
    """hasPostData on requestWillBeSent is the only hint a body exists to fetch.

    CDP does not inline a large POST body in the event, so without recording
    the flag a caller cannot tell which rows web.network.get could pull a
    request body from. Measured: a POST row carries has_post_data True, a GET
    row has no such key.
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

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "p1",
            "request": {"url": "https://x/login", "method": "POST", "hasPostData": True},
            "type": "XHR",
        }
    )
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "g1", "request": {"url": "https://x/", "method": "GET"}, "type": "Document"}
    )

    assert handle.requests["p1"]["has_post_data"] is True
    assert "has_post_data" not in handle.requests["g1"]


def test_web_keeps_the_inline_post_body_cdp_delivered() -> None:
    """A small POST body is inlined in requestWillBeSent; keep it for har.export.

    CDP hands the body over in request.postData for a small payload, so storing
    a bounded copy lets the HAR export emit request.postData without a per-row
    CDP round-trip. A body past the inline cap is clipped and flagged; a row
    with no body keeps neither key.
    """
    from headless_re_mcp.backends.web.client import _MAX_POST_DATA

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

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "p1",
            "request": {
                "url": "https://x/login",
                "method": "POST",
                "hasPostData": True,
                "postData": '{"user":"alice"}',
            },
            "type": "XHR",
        }
    )
    big = "a" * (_MAX_POST_DATA + 100)
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "p2",
            "request": {
                "url": "https://x/u",
                "method": "POST",
                "hasPostData": True,
                "postData": big,
            },
            "type": "XHR",
        }
    )
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "g1", "request": {"url": "https://x/", "method": "GET"}, "type": "Document"}
    )

    assert handle.requests["p1"]["post_data"] == '{"user":"alice"}'
    assert "post_data_truncated" not in handle.requests["p1"]
    assert len(handle.requests["p2"]["post_data"]) == _MAX_POST_DATA
    assert handle.requests["p2"]["post_data_truncated"] is True
    assert "post_data" not in handle.requests["g1"]


def test_cdp_headers_unfolds_repeats_and_is_bounded() -> None:
    """CDP joins repeated names with newlines; each must survive its own entry."""
    out = _cdp_headers({"Set-Cookie": "sid=1\ntoken=2", "Content-Type": "text/html"})
    assert out == [
        {"name": "Set-Cookie", "value": "sid=1"},
        {"name": "Set-Cookie", "value": "token=2"},
        {"name": "Content-Type", "value": "text/html"},
    ]
    assert _cdp_headers(None) == []
    assert _cdp_headers("not-a-dict") == []
    assert len(_cdp_headers({f"h{i}": "v" for i in range(500)})) == _MAX_HEADERS
    clipped = _cdp_headers({"x": "y" * (10 * _MAX_HEADER_TEXT)})
    assert len(clipped[0]["value"].encode()) <= _MAX_HEADER_TEXT


def test_web_captures_headers_from_cdp_and_keeps_them_off_the_list(
    monkeypatch: Any,
) -> None:
    """Response headers (Set-Cookie/CSP/CORS) and request headers are what web
    dynamic analysis reads; CDP hands them over, so the ring entry keeps them.

    Measured: a request with Authorization/Cookie and a response setting two
    cookies -> the entry's request_headers/response_headers carry them, both
    Set-Cookie values survive, yet network.list strips both so the index stays
    lean.
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
    backend = WebBackend()
    backend._wire_events(handle)  # type: ignore[arg-type]

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://x/api",
                "method": "GET",
                "headers": {"Authorization": "Bearer t", "Cookie": "a=1"},
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
                "headers": {"Content-Type": "application/json", "Set-Cookie": "sid=1\ntoken=2"},
            },
        }
    )

    entry = handle.requests["r1"]
    assert {"name": "Authorization", "value": "Bearer t"} in entry["request_headers"]
    resp_cookies = [h["value"] for h in entry["response_headers"] if h["name"] == "Set-Cookie"]
    assert resp_cookies == ["sid=1", "token=2"]

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    listed = backend.network_list("s", offset=0, limit=10)["requests"][0]
    assert "request_headers" not in listed
    assert "response_headers" not in listed
    doc = _tool_docstring("web.network.get")
    assert "response_headers" in doc


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
