"""web tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
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


class _Cdp:
    """Records the handlers _wire_events registers so a test can drive them."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str) -> None:
        del method

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def test_web_loading_failed_marks_the_request_as_error() -> None:
    """A failed request must be distinguishable from one still in flight.

    CDP fires Network.loadingFailed (not responseReceived) for a request that
    never completes -- DNS failure, refused connection, TLS error, blocked.
    Only requestWillBeSent/responseReceived were wired, so a failed request kept
    status null forever, reading identical to a pending one. Mirror the proxy
    recorder: error=true and error_msg, status still null, while a completed
    request keeps its numeric status and no error field.
    """
    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r-fail", "request": {"url": "https://x/1", "method": "GET"}, "type": "XHR"}
    )
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "r-fail", "errorText": "net::ERR_NAME_NOT_RESOLVED"}
    )
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r-ok", "request": {"url": "https://x/2", "method": "GET"}, "type": "XHR"}
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "r-ok", "response": {"status": 200, "mimeType": "text/html"}}
    )

    failed = handle.requests["r-fail"]
    assert failed["error"] is True
    assert failed["error_msg"] == "net::ERR_NAME_NOT_RESOLVED"
    # A failed request has no HTTP status; that null plus error is the signal.
    assert failed["status"] is None

    ok = handle.requests["r-ok"]
    assert "error" not in ok
    assert ok["status"] == 200

    doc = _tool_docstring("web.network.list")
    assert "error=true" in doc
    assert "error_msg" in doc


def test_web_loading_failed_handles_blocked_bounds_and_unknown_ids() -> None:
    """A blocked reason is surfaced, oversized text is bounded, ghosts are safe.

    errorText can be empty for a CSP/mixed-content block, so blockedReason is
    folded into error_msg; the message is bounded like every other summary
    field; and a loadingFailed for a request already evicted from the ring must
    not raise or resurrect an entry.
    """
    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r-blocked",
            "request": {"url": "https://x/1", "method": "GET"},
            "type": "XHR",
        }
    )
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "r-blocked", "errorText": "", "blockedReason": "csp"}
    )
    blocked = handle.requests["r-blocked"]
    assert blocked["error"] is True
    assert "blocked: csp" in str(blocked["error_msg"])

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r-huge",
            "request": {"url": "https://x/2", "method": "GET"},
            "type": "XHR",
        }
    )
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "r-huge", "errorText": "é" * (_MAX_METADATA_BYTES + 1)}
    )
    huge = handle.requests["r-huge"]
    assert len(str(huge["error_msg"]).encode()) <= _MAX_METADATA_BYTES
    assert huge["metadata_truncated"] is True

    # A loadingFailed for an id that was never recorded must be a no-op.
    cdp.handlers["Network.loadingFailed"]({"requestId": "ghost", "errorText": "x"})
    assert "ghost" not in handle.requests


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
