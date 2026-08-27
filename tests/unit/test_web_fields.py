"""web tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_HEADER_VALUE_BYTES,
    _MAX_HEADERS,
    _MAX_METADATA_BYTES,
    _MAX_URL_BYTES,
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
    # total for parity with every other paginated reader: has_more says there
    # is more, total says how much is buffered so the caller can size a re-read.
    assert payload["total"] == 25
    doc = _tool_docstring("web.console")
    assert "Answers with console" in doc
    assert "total" in doc
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


def test_bounded_header_map_caps_count_and_marks_truncation() -> None:
    """The header bounder caps count and flags any drop; a non-dict is empty.

    Measured: MAX+5 headers -> exactly MAX kept and truncated True; a None
    header map (CDP omits headers on some events) -> empty map, not truncated,
    so a reader never mistakes a bounded or absent map for the whole set.
    """
    headers = {f"h{i}": "v" for i in range(_MAX_HEADERS + 5)}
    out, cut = _bounded_header_map(headers)
    assert len(out) == _MAX_HEADERS
    assert cut is True
    assert _bounded_header_map(None) == ({}, False)


def test_web_captures_bounded_request_and_response_headers() -> None:
    """Headers ride the request/response events and are captured, bounded, flagged.

    CDP has no on-demand header fetch, so these events are the only chance to
    keep them. Measured: an Authorization request header is captured verbatim,
    a header value over the per-value cap is clipped and sets
    request_headers_truncated, and a Set-Cookie response header lands in
    response_headers -- the auth/cookie lines an API RE analyst most wants.
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
    big_value = "v" * (_MAX_HEADER_VALUE_BYTES + 10)
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://a.test/api",
                "method": "POST",
                "headers": {"Authorization": "Bearer tok", "X-Big": big_value},
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
                "headers": {"Set-Cookie": "sid=abc", "Content-Type": "application/json"},
            },
        }
    )
    entry = handle.requests["r1"]
    assert entry["request_headers"]["Authorization"] == "Bearer tok"
    assert len(entry["request_headers"]["X-Big"].encode()) <= _MAX_HEADER_VALUE_BYTES
    assert entry["request_headers_truncated"] is True
    assert entry["response_headers"]["Set-Cookie"] == "sid=abc"
    assert entry["response_headers"]["Content-Type"] == "application/json"
    assert "response_headers_truncated" not in entry


def test_web_network_list_omits_header_maps_from_rows(monkeypatch: Any) -> None:
    """Headers are detail-only: network.list rows must not carry them.

    Measured: a stored entry holding request_headers/response_headers -> the
    list row drops all four header keys while keeping url/method/status, so a
    1000-row page is not inflated by bounded header maps, and the stored entry
    still keeps them for network.get.
    """
    backend = WebBackend()

    class _H:
        lock = Lock()
        requests = {
            "r1": {
                "requestId": "r1",
                "url": "https://a",
                "method": "GET",
                "resourceType": "XHR",
                "status": 200,
                "mimeType": "application/json",
                "request_headers": {"Authorization": "Bearer x"},
                "request_headers_truncated": True,
                "response_headers": {"Set-Cookie": "sid=1"},
            }
        }
        requests_dropped = 0

    handle = _H()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    payload = backend.network_list("s", offset=0, limit=10)
    row = payload["requests"][0]
    assert "request_headers" not in row
    assert "request_headers_truncated" not in row
    assert "response_headers" not in row
    assert "response_headers_truncated" not in row
    assert row["url"] == "https://a"
    assert handle.requests["r1"]["request_headers"] == {"Authorization": "Bearer x"}
    doc = _tool_docstring("web.network.list")
    assert "Headers are omitted" in doc


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
