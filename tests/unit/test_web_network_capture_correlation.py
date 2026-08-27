"""``network.list`` joins two CDP events by requestId, bounds them, and evicts oldest-first.

A captured request is assembled from *two* separate Chrome DevTools Protocol
events wired in ``_wire_events``: ``Network.requestWillBeSent`` creates the row
(url, method, resourceType, and ``status``/``mimeType`` left ``None``), and
``Network.responseReceived`` later fills the status and mime type onto the *same*
row, matched by requestId::

    def on_request(params):
        entry = {"requestId": ..., "url": url, "method": method,
                 "resourceType": ..., "status": None, "mimeType": None}
        with handle.lock:
            handle.requests[str(params.get("requestId"))] = entry
            while len(handle.requests) > _MAX_REQUESTS:
                handle.requests.popitem(last=False)     # oldest first
                handle.requests_dropped += 1

    def on_response(params):
        mime_type, mime_truncated = _bounded_metadata(resp.get("mimeType"), ...)
        with handle.lock:
            entry = handle.requests.get(str(params.get("requestId")))
            if entry is not None:                        # the join, and the miss
                entry["status"] = resp.get("status")
                entry["mimeType"] = mime_type
                ...

Everything the existing tests touch here is set by hand: they assign
``requests_dropped`` directly and reproduce the eviction loop in the test body,
or check that ``network_list`` *reports* a counter -- never that the handlers
actually correlate, bound, or evict. Four behaviours on the real ingestion path
are therefore unpinned, and a homogeneous fixture (one request, its own
response, no overflow) cannot tell any of them from their broken forms:

* **The response fills its own request in place.** ``on_response`` looks the row
  up by requestId and writes status/mimeType onto it; the list then shows a
  complete request. Break the correlation and every row stays ``status: null``
  no matter how many responses arrived.

* **A response for a request that is not buffered is a silent no-op.** The row
  can be gone (evicted after ``_MAX_REQUESTS``) or never have existed;
  ``handle.requests.get`` returns ``None`` and the ``if entry is not None`` guard
  steps over it. Drop the guard and the handler dereferences ``None`` -- the CDP
  listener thread dies mid-capture -- or, worse, a phantom status-only row with
  no url/method appears in the list.

* **The response's mime type is bounded like the request's fields.** A server
  controls the ``Content-Type``; an oversized one must be clipped to
  ``_MAX_METADATA_BYTES`` and flagged, exactly as the request path bounds url and
  method. Nothing pins the bound on the *response* side.

* **The buffer evicts oldest-first and counts honestly through the handler.**
  ``popitem(last=False)`` drops the oldest row and each drop increments
  ``requests_dropped``; a caller reads ``dropped`` to know the list is not the
  whole story. Evict newest-first and the recent, interesting requests vanish
  while stale ones linger; miscount and ``dropped`` lies.

These drive the wired handlers directly through a fake CDP and assert on the
caller-facing ``network_list`` -- no Playwright, no browser, no sockets.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_METADATA_BYTES,
    _MAX_REQUESTS,
    WebBackend,
    _WebSession,
)


class _FakeCdp:
    """Records the handlers ``_wire_events`` registers so a test can fire them."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> None:
        del method, params

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def _wired() -> tuple[WebBackend, _WebSession, _FakeCdp]:
    cdp = _FakeCdp()
    handle = _WebSession(object(), object(), object(), object(), cdp)
    backend = WebBackend()
    backend._wire_events(handle)
    backend._sessions["s"] = handle
    return backend, handle, cdp


def _fire_request(cdp: _FakeCdp, request_id: str, *, url: str = "https://x/a") -> None:
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": request_id, "request": {"url": url, "method": "GET"}, "type": "XHR"}
    )


def _fire_response(
    cdp: _FakeCdp, request_id: str, *, status: int = 200, mime: str = "text/html"
) -> None:
    cdp.handlers["Network.responseReceived"](
        {"requestId": request_id, "response": {"status": status, "mimeType": mime}}
    )


def _only(backend: WebBackend) -> dict[str, Any]:
    listing = backend.network_list("s")
    assert listing["count"] == 1
    return listing["requests"][0]


def test_a_response_fills_status_and_mime_on_its_own_request() -> None:
    """The two events are joined by requestId into one complete row.

    Until the response arrives the row carries ``status: null``; after it, the
    list shows the status and mime the response reported -- on that exact
    request, not a duplicate.
    """
    backend, _handle, cdp = _wired()
    _fire_request(cdp, "r1")
    assert _only(backend)["status"] is None

    _fire_response(cdp, "r1", status=200, mime="application/json")
    row = _only(backend)
    assert row["status"] == 200
    assert row["mimeType"] == "application/json"
    assert row["url"] == "https://x/a"


def test_a_response_for_an_unbuffered_request_is_a_silent_no_op() -> None:
    """A response whose request is absent neither crashes nor invents a row.

    With no prior ``requestWillBeSent`` the lookup misses; the guard makes the
    handler do nothing, so the list stays empty rather than gaining a phantom
    status-only entry with no url or method.
    """
    backend, _handle, cdp = _wired()
    _fire_response(cdp, "ghost", status=500, mime="text/plain")
    listing = backend.network_list("s")
    assert listing["count"] == 0
    assert listing["total"] == 0
    assert listing["requests"] == []


def test_a_late_response_for_an_evicted_request_is_dropped_too() -> None:
    """Once a request is evicted, its later response has nothing to attach to.

    This is the eviction and the join-miss together: the row for ``r0`` is gone
    after the buffer overflowed, so its response is a no-op and cannot resurrect
    it.
    """
    backend, handle, cdp = _wired()
    for index in range(_MAX_REQUESTS + 1):
        _fire_request(cdp, f"r{index}")
    assert "r0" not in handle.requests

    _fire_response(cdp, "r0", status=200, mime="text/html")
    assert "r0" not in handle.requests
    assert backend.network_list("s")["total"] == _MAX_REQUESTS


def test_an_oversized_response_content_type_is_bounded_and_flagged() -> None:
    """A giant server ``Content-Type`` is clipped and marked, like request fields.

    The response path must bound the mime type to ``_MAX_METADATA_BYTES`` the
    same way the request path bounds url and method -- a hostile server does not
    get to store an unbounded string per request.
    """
    backend, _handle, cdp = _wired()
    _fire_request(cdp, "r1")
    _fire_response(cdp, "r1", status=200, mime="m" * (_MAX_METADATA_BYTES + 50))
    row = _only(backend)
    assert len(row["mimeType"]) == _MAX_METADATA_BYTES
    assert row["metadata_truncated"] is True


def test_the_request_buffer_evicts_oldest_first_and_counts_drops() -> None:
    """Overflow drops the oldest rows first and ``dropped`` counts every one.

    Firing five past the cap leaves exactly ``_MAX_REQUESTS`` rows, the five
    oldest gone and the newest kept, with ``dropped == 5`` -- the FIFO order and
    the honest count a caller relies on to know what fell out.
    """
    backend, handle, cdp = _wired()
    overflow = 5
    for index in range(_MAX_REQUESTS + overflow):
        _fire_request(cdp, f"r{index}", url=f"https://x/{index}")

    listing = backend.network_list("s", limit=1000)
    assert listing["total"] == _MAX_REQUESTS
    assert listing["dropped"] == overflow
    assert handle.requests_dropped == overflow
    # The five oldest were evicted; the newest survived.
    for gone in range(overflow):
        assert f"r{gone}" not in handle.requests
    assert f"r{_MAX_REQUESTS + overflow - 1}" in handle.requests


def test_a_request_is_captured_with_status_pending_until_its_response() -> None:
    """A brand-new request is listed immediately with status/mime still null.

    The list does not wait for the response to show the request; it shows it as
    in-flight, which is why the response has to find and update it by id.
    """
    backend, _handle, cdp = _wired()
    _fire_request(cdp, "r1", url="https://x/pending")
    row = _only(backend)
    assert row["status"] is None
    assert row["mimeType"] is None
    assert row["method"] == "GET"
    assert row["resourceType"] == "XHR"


def test_the_fake_cdp_registers_the_expected_capture_events() -> None:
    """Guard the harness: the handlers under test are actually the wired ones."""
    _backend, _handle, cdp = _wired()
    assert "Network.requestWillBeSent" in cdp.handlers
    assert "Network.responseReceived" in cdp.handlers
