"""web.network.list / web.har.export carry the decoded response body size.

The capture wired Network.requestWillBeSent and Network.responseReceived but
never Network.dataReceived, so every row and every HAR entry lost the response
body size: proxy.flows already answers response_size, but the browser line left
an analyst unable to tell a two-byte response from a two-megabyte one without
fetching each body, and the exported HAR wrote the -1 "unknown" sentinel for
content.size. dataReceived.dataLength is the decoded (uncompressed) byte count
-- the size web.network.get returns as the body and the number HAR content.size
wants -- so summing it is what fills both. These tests drive the real event
callbacks with recorded CDP payloads (no browser) and assert the size lands on
the row and in the HAR, and that a bodyless / cache-hit request (no dataReceived
at all) honestly stays 0 rather than inventing a size.
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend


class _CapturingCdp:
    """Records the event handlers _wire_events registers; send() is a no-op."""

    def __init__(self) -> None:
        self.handlers: dict[str, Callable[[dict[str, Any]], None]] = {}

    def send(self, *args: object, **kwargs: object) -> None:
        return None

    def on(self, name: str, callback: Callable[[dict[str, Any]], None]) -> None:
        self.handlers[name] = callback


def _wired_session() -> tuple[WebBackend, SimpleNamespace, _CapturingCdp]:
    backend = WebBackend()
    cdp = _CapturingCdp()
    handle = SimpleNamespace(
        cdp=cdp,
        lock=threading.RLock(),
        requests=OrderedDict(),
        requests_dropped=0,
        scripts=OrderedDict(),
        scripts_dropped=0,
        console=deque(maxlen=256),
        console_dropped=0,
    )
    backend._wire_events(handle)  # type: ignore[arg-type]
    return backend, handle, cdp


def test_datareceived_sums_the_decoded_size_onto_the_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, handle, cdp = _wired_session()
    fire = cdp.handlers

    fire["Network.requestWillBeSent"](
        {"requestId": "1", "type": "XHR", "request": {"url": "http://x/big", "method": "GET"}}
    )
    # Two chunks: the total decoded body length is their sum.
    fire["Network.dataReceived"]({"requestId": "1", "dataLength": 4000, "encodedDataLength": 0})
    fire["Network.dataReceived"]({"requestId": "1", "dataLength": 1000, "encodedDataLength": 0})
    fire["Network.responseReceived"](
        {"requestId": "1", "response": {"status": 200, "mimeType": "application/json"}}
    )

    # A bodyless / cache-hit request fires no dataReceived at all.
    fire["Network.requestWillBeSent"](
        {
            "requestId": "2",
            "type": "Document",
            "request": {"url": "http://x/empty", "method": "GET"},
        }
    )
    fire["Network.responseReceived"](
        {"requestId": "2", "response": {"status": 204, "mimeType": "text/plain"}}
    )

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    rows = {r["url"]: r for r in backend.network_list("s")["requests"]}
    assert rows["http://x/big"]["response_size"] == 5000
    # Never fabricated: no bytes were received, so the field stays 0.
    assert rows["http://x/empty"]["response_size"] == 0


def test_a_redirect_reusing_the_request_id_resets_the_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CDP reuses one requestId across a redirect; the final hop's size must win.

    requestWillBeSent fires again for the same id on the 3xx hop, replacing the
    entry. Seeding response_size to 0 on that fresh entry means the redirect's
    (empty) body does not leak into the followed response's total.
    """
    backend, handle, cdp = _wired_session()
    fire = cdp.handlers

    fire["Network.requestWillBeSent"](
        {"requestId": "9", "type": "Document", "request": {"url": "http://x/from", "method": "GET"}}
    )
    fire["Network.dataReceived"]({"requestId": "9", "dataLength": 123})
    # The redirect: same requestId, a new requestWillBeSent for the target.
    fire["Network.requestWillBeSent"](
        {"requestId": "9", "type": "Document", "request": {"url": "http://x/to", "method": "GET"}}
    )
    fire["Network.dataReceived"]({"requestId": "9", "dataLength": 77})
    fire["Network.responseReceived"](
        {"requestId": "9", "response": {"status": 200, "mimeType": "text/html"}}
    )

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    rows = {r["url"]: r for r in backend.network_list("s")["requests"]}
    assert rows["http://x/to"]["response_size"] == 77


def test_har_export_fills_content_size_from_the_measured_body(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    backend, handle, cdp = _wired_session()
    fire = cdp.handlers

    fire["Network.requestWillBeSent"](
        {"requestId": "1", "type": "XHR", "request": {"url": "http://x/big", "method": "GET"}}
    )
    fire["Network.dataReceived"]({"requestId": "1", "dataLength": 5000})
    fire["Network.responseReceived"](
        {"requestId": "1", "response": {"status": 200, "mimeType": "application/json"}}
    )
    fire["Network.requestWillBeSent"](
        {
            "requestId": "2",
            "type": "Document",
            "request": {"url": "http://x/empty", "method": "GET"},
        }
    )
    fire["Network.responseReceived"](
        {"requestId": "2", "response": {"status": 204, "mimeType": "text/plain"}}
    )

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    out = tmp_path / "web.har"
    backend.har_export("s", out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    entries = {e["request"]["url"]: e for e in doc["log"]["entries"]}

    big = entries["http://x/big"]["response"]
    assert big["content"]["size"] == 5000
    assert big["bodySize"] == 5000
    # A real zero-length body reports 0, not the -1 "unknown" sentinel.
    assert entries["http://x/empty"]["response"]["content"]["size"] == 0
