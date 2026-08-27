"""web.network.list marks a failed request instead of leaving it null-forever.

A request that never gets a response -- a DNS failure, a reset connection, a
blocked tracker, a CSP or mixed-content refusal -- fires CDP's
``Network.loadingFailed`` rather than ``Network.responseReceived``, and the
reason (``net::ERR_NAME_NOT_RESOLVED``, a ``blockedReason``) appears only there.
The handler used to ignore that event, so the request entry kept its null status
forever and a failed load -- often the finding in an RE session, e.g. a beacon
the page could not reach or a tracker the browser blocked -- was indistinguishable
from a request still in flight.

The web backend now marks the matching entry ``failed: true`` with ``error_text``
(and ``blocked_reason`` when named), mirroring how the proxy backend records an
errored flow. These tests drive the CDP handlers directly; a live gate proves it
against a real Chromium failing a real subresource load.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_METADATA_BYTES,
    WebBackend,
    _WebSession,
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

    def send(self, method: str, params: Any = None) -> None:
        del method, params

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def _wired_session() -> tuple[_WebSession, _Cdp]:
    cdp = _Cdp()
    handle = _WebSession(object(), object(), object(), object(), cdp)
    WebBackend()._wire_events(handle)
    return handle, cdp


def _sent(request_id: str, url: str) -> dict[str, Any]:
    return {
        "requestId": request_id,
        "request": {"url": url, "method": "GET"},
        "type": "Image",
    }


def test_loading_failed_marks_the_request_with_its_error() -> None:
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_sent("r1", "http://x.invalid/a.png"))
    cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "r1",
            "errorText": "net::ERR_NAME_NOT_RESOLVED",
            "canceled": False,
            "type": "Image",
        }
    )
    entry = handle.requests["r1"]
    assert entry["failed"] is True
    assert entry["error_text"] == "net::ERR_NAME_NOT_RESOLVED"
    # A failure is not a response: status stays null so it is not read as 200.
    assert entry["status"] is None
    # Not canceled, so no canceled marker, and no blocked_reason either.
    assert "canceled" not in entry
    assert "blocked_reason" not in entry


def test_a_blocked_request_surfaces_the_blocked_reason() -> None:
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_sent("r2", "http://tracker.example/t.gif"))
    cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "r2",
            "errorText": "net::ERR_BLOCKED_BY_CLIENT",
            "canceled": False,
            "blockedReason": "inspector",
        }
    )
    entry = handle.requests["r2"]
    assert entry["failed"] is True
    assert entry["error_text"] == "net::ERR_BLOCKED_BY_CLIENT"
    assert entry["blocked_reason"] == "inspector"


def test_a_canceled_request_is_flagged_canceled() -> None:
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_sent("r3", "http://x.invalid/b"))
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "r3", "errorText": "net::ERR_ABORTED", "canceled": True}
    )
    assert handle.requests["r3"]["canceled"] is True


def test_loading_failed_for_an_unknown_request_id_is_ignored() -> None:
    """An eviction (or a race) must not resurrect a dropped entry."""
    handle, cdp = _wired_session()
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "ghost", "errorText": "net::ERR_FAILED"}
    )
    assert "ghost" not in handle.requests


def test_a_huge_error_text_is_bounded() -> None:
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_sent("r4", "http://x.invalid/c"))
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "r4", "errorText": "z" * (_MAX_METADATA_BYTES * 3)}
    )
    entry = handle.requests["r4"]
    assert len(entry["error_text"].encode("utf-8")) == _MAX_METADATA_BYTES
    assert entry["metadata_truncated"] is True


def test_web_network_list_docstring_names_the_failure_fields() -> None:
    doc = " ".join(_tool_docstring("web.network.list").split())
    assert "failed true" in doc
    assert "error_text" in doc
    assert "blocked_reason" in doc
