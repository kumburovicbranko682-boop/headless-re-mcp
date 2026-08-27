"""web tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_METADATA_BYTES,
    _MAX_REDIRECTS,
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


class _CapturingCdp:
    """Records CDP handlers so a test can drive them directly."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str) -> None:
        del method

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def _wired_capture() -> tuple[_CapturingCdp, _FakeHandle]:
    cdp = _CapturingCdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    return cdp, handle


def test_web_capture_preserves_the_redirect_chain_instead_of_collapsing_it() -> None:
    """A redirected request must keep its 30x hops, not just the final URL.

    Measured: /login -302-> /sso -301-> /app, final 200. CDP reuses one
    requestId, so overwriting the entry each hop leaves only /app at status
    200 -- the two redirects that make up an auth flow vanish. The entry now
    carries redirects with each hop's status and url, in order.
    """
    cdp, handle = _wired_capture()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "https://a.test/login", "method": "GET"},
         "type": "Document"}
    )
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "https://a.test/sso", "method": "GET"},
         "type": "Document",
         "redirectResponse": {"url": "https://a.test/login", "status": 302}}
    )
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "https://a.test/app", "method": "GET"},
         "type": "Document",
         "redirectResponse": {"url": "https://a.test/sso", "status": 301}}
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "r1", "response": {"status": 200, "mimeType": "text/html"}}
    )
    entry = handle.requests["r1"]
    assert entry["url"] == "https://a.test/app"
    assert entry["status"] == 200
    assert entry["redirects"] == [
        {"status": 302, "url": "https://a.test/login"},
        {"status": 301, "url": "https://a.test/sso"},
    ]
    assert "redirects_truncated" not in entry
    doc = _tool_docstring("web.network.list")
    assert "redirects" in doc


def test_web_capture_leaves_no_redirects_field_on_a_direct_request() -> None:
    """A request that never redirected must not sprout an empty redirects list.

    Measured: a single requestWillBeSent with no redirectResponse -> the entry
    has no redirects key, so its absence cleanly means "went straight there".
    """
    cdp, handle = _wired_capture()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r2", "request": {"url": "https://a.test/x", "method": "GET"},
         "type": "XHR"}
    )
    assert "redirects" not in handle.requests["r2"]


def test_web_capture_caps_a_redirect_loop_and_flags_it() -> None:
    """A redirect loop must be bounded, and the truncation must be disclosed.

    Measured: more hops than the cap -> redirects holds exactly _MAX_REDIRECTS
    (the earliest hops), and redirects_truncated is True so the chain is not
    read as complete.
    """
    cdp, handle = _wired_capture()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r3", "request": {"url": "https://a.test/0", "method": "GET"},
         "type": "Document"}
    )
    for index in range(1, _MAX_REDIRECTS + 10):
        cdp.handlers["Network.requestWillBeSent"](
            {"requestId": "r3",
             "request": {"url": f"https://a.test/{index}", "method": "GET"},
             "type": "Document",
             "redirectResponse": {"url": f"https://a.test/{index - 1}", "status": 302}}
        )
    entry = handle.requests["r3"]
    assert len(entry["redirects"]) == _MAX_REDIRECTS
    assert entry["redirects_truncated"] is True


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
