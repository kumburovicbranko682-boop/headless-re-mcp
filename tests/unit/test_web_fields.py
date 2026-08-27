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


class _RecordingCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str) -> None:
        del method

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def _wired_console_handle() -> tuple[_FakeHandle, _RecordingCdp]:
    cdp = _RecordingCdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    return handle, cdp


def test_web_console_captures_the_source_location_from_the_call_stack() -> None:
    """A console.* message carries where it was logged from.

    consoleAPICalled's top stack frame names the script and line of the call.
    A console.log/warn otherwise arrives with no location -- unlike an error,
    whose text the browser annotates -- so an analyst cannot tell which script
    emitted it. The line is CDP's 0-based number shown 1-based like DevTools.
    """
    handle, cdp = _wired_console_handle()
    cdp.handlers["Runtime.consoleAPICalled"](
        {
            "type": "log",
            "args": [{"value": "hi"}],
            "stackTrace": {
                "callFrames": [
                    {"url": "https://example.com/app.js", "lineNumber": 41},
                    {"url": "https://example.com/vendor.js", "lineNumber": 7},
                ]
            },
        }
    )
    entry = handle.console[-1]
    assert entry["text"] == "hi"
    assert entry["source"] == "https://example.com/app.js:42"
    assert "metadata_truncated" not in entry


def test_web_console_omits_source_when_the_event_carries_no_stack() -> None:
    """A native or stack-less console event just has no source field."""
    handle, cdp = _wired_console_handle()
    cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "warning", "args": [{"value": "no stack"}]}
    )
    cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "log", "args": [{"value": "empty frames"}], "stackTrace": {"callFrames": []}}
    )
    for entry in handle.console:
        assert "source" not in entry


def test_web_console_source_is_bounded_and_flags_truncation() -> None:
    """An oversized source url is clipped and marked, like every other field."""
    handle, cdp = _wired_console_handle()
    huge = "https://example.com/" + "a" * (_MAX_URL_BYTES + 100)
    cdp.handlers["Runtime.consoleAPICalled"](
        {
            "type": "error",
            "args": [{"value": "boom"}],
            "stackTrace": {"callFrames": [{"url": huge, "lineNumber": 0}]},
        }
    )
    entry = handle.console[-1]
    assert len(str(entry["source"]).encode()) <= _MAX_URL_BYTES
    assert entry["metadata_truncated"] is True


def test_web_console_docstring_names_the_source_field() -> None:
    doc = _tool_docstring("web.console")
    assert "source" in doc
    assert "metadata_truncated" in doc


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
