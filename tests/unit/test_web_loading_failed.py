"""A network request Chromium aborted must be distinguishable from a pending one.

Only Network.responseReceived was wired, so a request that failed to load (DNS
failure, blocked mixed content, a cancelled fetch) kept status None forever --
identical to one still in flight. These lock in that Network.loadingFailed marks
the entry (failed / error_text, plus canceled / blocked_reason when reported),
that the marking is bounded, that an unknown request id is ignored, and that the
failure fields ride through web.network.get alongside body_error.
"""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_METADATA_BYTES,
    WebBackend,
)


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
        self.requests: dict[str, dict[str, Any]] = {}
        self.requests_dropped = 0
        self.scripts: dict[str, dict[str, Any]] = {}
        self.scripts_dropped = 0
        self.console: list[dict[str, Any]] = []
        self.console_dropped = 0
        self.cdp = _Cdp()


def _wired() -> _Handle:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    return handle


def _send_request(handle: _Handle, request_id: str) -> None:
    handle.cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": request_id,
            "request": {"url": f"https://example/{request_id}", "method": "GET"},
            "type": "XHR",
        }
    )


def test_a_failed_request_is_marked_distinct_from_a_pending_one() -> None:
    handle = _wired()
    _send_request(handle, "ok")
    _send_request(handle, "boom")
    handle.cdp.handlers["Network.loadingFailed"](
        {"requestId": "boom", "errorText": "net::ERR_NAME_NOT_RESOLVED"}
    )

    pending = handle.requests["ok"]
    failed = handle.requests["boom"]
    assert pending["status"] is None
    assert "failed" not in pending
    assert failed["failed"] is True
    assert failed["error_text"] == "net::ERR_NAME_NOT_RESOLVED"
    assert failed["status"] is None


def test_failure_records_canceled_and_blocked_reason() -> None:
    handle = _wired()
    _send_request(handle, "cancel")
    _send_request(handle, "blocked")
    handle.cdp.handlers["Network.loadingFailed"](
        {"requestId": "cancel", "errorText": "net::ERR_ABORTED", "canceled": True}
    )
    handle.cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "blocked",
            "errorText": "net::ERR_BLOCKED_BY_CLIENT",
            "blockedReason": "mixed-content",
        }
    )

    cancelled = handle.requests["cancel"]
    blocked = handle.requests["blocked"]
    assert cancelled["canceled"] is True
    assert "blocked_reason" not in cancelled
    assert blocked["blocked_reason"] == "mixed-content"
    assert "canceled" not in blocked


def test_failure_metadata_is_bounded() -> None:
    handle = _wired()
    _send_request(handle, "big")
    handle.cdp.handlers["Network.loadingFailed"](
        {"requestId": "big", "errorText": "é" * (_MAX_METADATA_BYTES + 1)}
    )

    failed = handle.requests["big"]
    assert len(str(failed["error_text"]).encode()) <= _MAX_METADATA_BYTES
    assert failed["metadata_truncated"] is True


def test_loading_failed_for_an_unknown_request_is_ignored() -> None:
    handle = _wired()
    _send_request(handle, "known")
    handle.cdp.handlers["Network.loadingFailed"](
        {"requestId": "ghost", "errorText": "net::ERR_FAILED"}
    )

    assert set(handle.requests) == {"known"}
    assert "failed" not in handle.requests["known"]


class _RaisingRunner:
    def call(self, work: Any, *, timeout: float | None = None) -> Any:
        del work, timeout
        raise RuntimeError("No resource with given identifier found")


def test_network_get_carries_the_failure_fields_with_body_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = WebBackend()
    entry = {
        "requestId": "boom",
        "url": "https://example/boom",
        "method": "GET",
        "resourceType": "XHR",
        "status": None,
        "mimeType": None,
        "failed": True,
        "error_text": "net::ERR_NAME_NOT_RESOLVED",
    }
    handle = _Handle()
    handle.requests["boom"] = entry
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _RaisingRunner())

    result = backend.network_get("s", "boom", tmp_path)

    assert result["failed"] is True
    assert result["error_text"] == "net::ERR_NAME_NOT_RESOLVED"
    assert "body_error" in result
    assert "body_path" not in result


def test_wire_events_registers_the_loading_failed_handler() -> None:
    handle = _wired()
    assert "Network.loadingFailed" in handle.cdp.handlers
    # The existing handlers are still registered.
    assert "Network.responseReceived" in handle.cdp.handlers
    assert "Network.requestWillBeSent" in handle.cdp.handlers
