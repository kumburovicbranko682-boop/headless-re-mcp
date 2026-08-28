"""web.network.failed lists requests the browser reported failed or blocked.

Covers both halves: the Network.loadingFailed capture handler (driven through
the _wire_events seam with a fake CDP) and the network_failed query method
(driven through the _get seam with a fake session handle).
"""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
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


def _will_be_sent(request_id: str, url: str, rtype: str) -> dict[str, Any]:
    return {"requestId": request_id, "request": {"url": url, "method": "GET"}, "type": rtype}


class _Handle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests: dict[str, dict[str, Any]] = {}
        self.scripts: dict[str, dict[str, Any]] = {}
        self.console: deque[dict[str, Any]] = deque()
        self.requests_dropped = 0
        self.scripts_dropped = 0
        self.console_dropped = 0
        self.cdp = _Cdp()


def test_loading_failed_marks_the_request_entry() -> None:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    cdp = handle.cdp

    cdp.handlers["Network.requestWillBeSent"](
        _will_be_sent("r1", "https://c2.example/beacon", "XHR")
    )
    cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "r1",
            "errorText": "net::ERR_NAME_NOT_RESOLVED",
            "canceled": False,
            "blockedReason": "",
        }
    )
    entry = handle.requests["r1"]
    assert entry["failed"] is True
    assert entry["error_text"] == "net::ERR_NAME_NOT_RESOLVED"
    assert entry["canceled"] is False
    assert "blocked_reason" not in entry


def test_loading_failed_records_blocked_reason_and_canceled() -> None:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    cdp = handle.cdp
    cdp.handlers["Network.requestWillBeSent"](
        _will_be_sent("r2", "http://insecure/img", "Image")
    )
    cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "r2",
            "errorText": "blocked",
            "canceled": True,
            "blockedReason": "mixed-content",
        }
    )
    entry = handle.requests["r2"]
    assert entry["canceled"] is True
    assert entry["blocked_reason"] == "mixed-content"


def test_a_request_with_no_failure_is_not_marked() -> None:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    cdp = handle.cdp
    cdp.handlers["Network.requestWillBeSent"](
        _will_be_sent("ok", "https://x/y", "Document")
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "ok", "response": {"status": 200, "mimeType": "text/html"}}
    )
    assert "failed" not in handle.requests["ok"]


def test_network_failed_filters_and_paginates(monkeypatch: Any) -> None:
    handle = _Handle()
    handle.requests = {
        "1": {"requestId": "1", "url": "https://a", "failed": True, "error_text": "e1"},
        "2": {"requestId": "2", "url": "https://b", "status": 200},
        "3": {"requestId": "3", "url": "https://c", "failed": True, "error_text": "e3"},
        "4": {"requestId": "4", "url": "https://d", "failed": True, "error_text": "e4"},
    }
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)

    payload = backend.network_failed("s", offset=0, limit=2)
    assert payload["total"] == 3  # only the three failed rows
    assert payload["count"] == 2
    assert payload["has_more"] is True
    assert all(row["failed"] for row in payload["requests"])


def test_network_failed_on_a_clean_capture(monkeypatch: Any) -> None:
    handle = _Handle()
    handle.requests = {"1": {"requestId": "1", "url": "https://a", "status": 200}}
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    payload = backend.network_failed("s")
    assert payload["total"] == 0
    assert payload["requests"] == []


def test_web_network_failed_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.network.failed")
    assert "error_text" in doc
    assert "blocked_reason" in doc
    assert "canceled" in doc
    assert "has_more" in doc
