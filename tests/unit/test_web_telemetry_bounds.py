"""The CDP telemetry buffers stay bounded for as long as a session lives.

Every request, script and console line a page produces lands in per-session
buffers that exist until web.close. A long-lived tab (or a page that eval()s in
a loop) would grow them without limit, so each buffer evicts its oldest entries
at a cap and counts what it dropped -- the dropped counters are how a caller
learns the window is partial. Metadata is bounded too: a hostile page can put
megabytes into a URL or mimeType, and the entry must record a clipped value
flagged metadata_truncated rather than storing the original.

These drive the real CDP event handlers that open() wires, captured through a
recording fake CDP session, with the caps shrunk so eviction is observable.
"""

from __future__ import annotations

from collections import deque
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web_client
from headless_re_mcp.backends.web.client import WebBackend, _WebSession


class _RecordingCdp:
    def __init__(self) -> None:
        self.enabled: list[str] = []
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> None:
        self.enabled.append(method)

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def _wired_session() -> tuple[_WebSession, _RecordingCdp]:
    cdp = _RecordingCdp()
    handle = _WebSession(None, None, None, None, cdp)
    WebBackend()._wire_events(handle)
    return handle, cdp


def _request_event(request_id: str, url: str = "https://x/") -> dict[str, Any]:
    return {"requestId": request_id, "request": {"url": url, "method": "GET"}, "type": "Fetch"}


def test_wiring_enables_all_four_cdp_domains() -> None:
    """Telemetry is only delivered for enabled domains; all four must be on.

    loadingFailed is a Network event, so it adds a handler but no new domain --
    the four enables stay exactly these, while the handler set gains the failure
    hook so a request that never got a response is still observed.
    """
    _, cdp = _wired_session()
    assert cdp.enabled == ["Network.enable", "Runtime.enable", "Debugger.enable", "Page.enable"]
    assert set(cdp.handlers) == {
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFailed",
        "Debugger.scriptParsed",
        "Runtime.consoleAPICalled",
    }


def test_request_ring_evicts_the_oldest_and_counts_the_drops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Beyond the cap the oldest requests go, and dropped says how many did."""
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 3)
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    for index in range(5):
        on_request(_request_event(f"r{index}"))
    assert list(handle.requests) == ["r2", "r3", "r4"]
    assert handle.requests_dropped == 2


def test_oversized_request_metadata_is_clipped_and_flagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hostile URL is stored clipped with metadata_truncated, not verbatim.

    The URL is attacker-controlled page content; without the bound a single
    request could park megabytes in the buffer for the session's lifetime.
    """
    monkeypatch.setattr(web_client, "_MAX_URL_BYTES", 16)
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_request_event("r1", url="https://" + "a" * 100))
    entry = handle.requests["r1"]
    assert len(entry["url"].encode()) <= 16
    assert entry["metadata_truncated"] is True


def test_response_enriches_its_request_and_ignores_an_unknown_id() -> None:
    """A response fills in status/mime on its request; an orphan is a no-op.

    responseReceived can arrive for a request already evicted from the ring;
    that must neither crash the handler thread nor resurrect an entry.
    """
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_request_event("r1"))
    on_response = cdp.handlers["Network.responseReceived"]
    on_response({"requestId": "r1", "response": {"status": 200, "mimeType": "text/html"}})
    assert handle.requests["r1"]["status"] == 200
    assert handle.requests["r1"]["mimeType"] == "text/html"
    on_response({"requestId": "ghost", "response": {"status": 500, "mimeType": "x"}})
    assert "ghost" not in handle.requests


def test_loading_failed_marks_the_request_and_ignores_an_unknown_id() -> None:
    """loadingFailed flags its request error=true with the CDP errorText.

    A request that never produced a response (DNS/connect failure, a block, or a
    superseded fetch) otherwise kept status None forever, indistinguishable from
    one still in flight. The failure hook marks it the way the proxy marks an
    errored flow -- error=true, error_msg, null status -- and, like the response
    hook, a loadingFailed for an already-evicted id must be a no-op, never
    resurrecting a row.
    """
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_request_event("r1"))
    on_failed = cdp.handlers["Network.loadingFailed"]
    on_failed(
        {"requestId": "r1", "errorText": "net::ERR_NAME_NOT_RESOLVED", "canceled": False}
    )
    entry = handle.requests["r1"]
    assert entry["error"] is True
    assert entry["error_msg"] == "net::ERR_NAME_NOT_RESOLVED"
    assert entry["status"] is None
    # A hard failure is not a cancellation, so canceled must not be set.
    assert "canceled" not in entry
    assert "blocked_reason" not in entry

    on_failed({"requestId": "ghost", "errorText": "net::ERR_FAILED", "canceled": False})
    assert "ghost" not in handle.requests


def test_loading_failed_records_a_block_and_a_cancellation_distinctly() -> None:
    """A CSP/client block carries blocked_reason; a benign abort sets canceled.

    CDP reports both on loadingFailed, and they mean different things to an
    analyst: a block (blockedReason set) is a finding -- the browser refused the
    request -- while a plain canceled=true is usually a navigation superseding
    an in-flight fetch. Keep them separate so one is not read as the other.
    """
    handle, cdp = _wired_session()
    on_failed = cdp.handlers["Network.loadingFailed"]

    cdp.handlers["Network.requestWillBeSent"](_request_event("blocked"))
    on_failed(
        {
            "requestId": "blocked",
            "errorText": "net::ERR_BLOCKED_BY_CLIENT",
            "canceled": False,
            "blockedReason": "inspector",
        }
    )
    blocked = handle.requests["blocked"]
    assert blocked["error"] is True
    assert blocked["blocked_reason"] == "inspector"
    assert "canceled" not in blocked

    cdp.handlers["Network.requestWillBeSent"](_request_event("aborted"))
    on_failed({"requestId": "aborted", "errorText": "net::ERR_ABORTED", "canceled": True})
    aborted = handle.requests["aborted"]
    assert aborted["error"] is True
    assert aborted["canceled"] is True
    assert "blocked_reason" not in aborted


def test_loading_failed_metadata_is_clipped_and_flagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hostile errorText/blockedReason is bounded like every other metadata."""
    monkeypatch.setattr(web_client, "_MAX_METADATA_BYTES", 8)
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_request_event("r1"))
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "r1", "errorText": "e" * 100, "canceled": False}
    )
    entry = handle.requests["r1"]
    assert len(entry["error_msg"].encode()) <= 8
    assert entry["metadata_truncated"] is True


def test_oversized_mime_type_is_clipped_and_flagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A response's mimeType is bounded like every other metadata string."""
    monkeypatch.setattr(web_client, "_MAX_METADATA_BYTES", 8)
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_request_event("r1"))
    cdp.handlers["Network.responseReceived"](
        {"requestId": "r1", "response": {"status": 200, "mimeType": "m" * 100}}
    )
    entry = handle.requests["r1"]
    assert len(entry["mimeType"].encode()) <= 8
    assert entry["metadata_truncated"] is True


def test_script_ring_evicts_the_oldest_and_counts_the_drops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scriptParsed fires for every script a page parses; the ring stays capped.

    A page that eval()s in a loop parses a new script each time, so without the
    cap this dictionary grows for as long as the session is open.
    """
    monkeypatch.setattr(web_client, "_MAX_SCRIPTS", 2)
    handle, cdp = _wired_session()
    on_script = cdp.handlers["Debugger.scriptParsed"]
    for index in range(5):
        on_script({"scriptId": f"s{index}", "url": f"https://x/{index}.js"})
    assert list(handle.scripts) == ["s3", "s4"]
    assert handle.scripts_dropped == 3


def test_console_ring_keeps_the_newest_and_counts_the_drops() -> None:
    """The console deque drops oldest lines silently; the handler counts them."""
    handle, cdp = _wired_session()
    handle.console = deque(maxlen=2)
    on_console = cdp.handlers["Runtime.consoleAPICalled"]
    for index in range(4):
        on_console({"type": "log", "args": [{"value": f"line {index}"}]})
    assert [entry["text"] for entry in handle.console] == ["line 2", "line 3"]
    assert handle.console_dropped == 2
