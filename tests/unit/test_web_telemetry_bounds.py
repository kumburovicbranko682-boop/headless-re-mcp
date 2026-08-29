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
        "Network.loadingFinished",
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


def test_request_records_started_at_from_a_positive_walltime_only() -> None:
    """requestWillBeSent's wallTime becomes started_at, but a junk clock is dropped.

    HAR's startedDateTime wants the true epoch each request began, not the single
    export instant, so the request handler stamps started_at from CDP's wallTime.
    Only a positive value: a zero or missing wallTime (CDP has not resolved wall
    time for this request) must leave started_at off so the export can fall back,
    rather than dating the request to the 1970 epoch.
    """
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]

    stamped = _request_event("stamped")
    stamped["wallTime"] = 1_700_000_000.5
    on_request(stamped)
    assert handle.requests["stamped"]["started_at"] == 1_700_000_000.5

    bare = _request_event("bare")
    bare["wallTime"] = 0
    on_request(bare)
    assert "started_at" not in handle.requests["bare"]


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


def _response_with_timing(request_id: str, *, request_time: float, headers_end: float) -> dict:
    return {
        "requestId": request_id,
        "response": {
            "status": 200,
            "mimeType": "application/json",
            "timing": {
                "requestTime": request_time,
                "sendStart": 1.0,
                "sendEnd": 2.0,
                "receiveHeadersEnd": headers_end,
            },
        },
    }


def test_loading_finished_adds_the_receive_phase_from_the_stored_anchor() -> None:
    """loadingFinished turns the headers-received anchor into timings.receive.

    The response event stores the monotonic instant headers finished arriving
    (requestTime + receiveHeadersEnd/1000); loadingFinished's timestamp is on
    the same clock, so their difference is the body download -- HAR's receive
    phase, computed the way Chrome DevTools' own HAR export computes it. The
    anchor is consumed: a duplicate finished event must be a no-op, and an
    orphan id (already-evicted row) must never resurrect anything.
    """
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_request_event("r1"))
    # Headers done at 100.0 + 40ms; body finished 60ms after that.
    cdp.handlers["Network.responseReceived"](
        _response_with_timing("r1", request_time=100.0, headers_end=40.0)
    )
    on_finished = cdp.handlers["Network.loadingFinished"]
    on_finished({"requestId": "r1", "timestamp": 100.1})
    entry = handle.requests["r1"]
    assert entry["timings"] == {"send": 1.0, "wait": 38.0, "receive": 60.0}
    assert handle.receive_anchors == {}

    # Consumed anchor: a stray duplicate must not recompute or crash.
    on_finished({"requestId": "r1", "timestamp": 200.0})
    assert entry["timings"]["receive"] == 60.0
    on_finished({"requestId": "ghost", "timestamp": 1.0})
    assert "ghost" not in handle.requests


def test_loading_finished_drops_junk_clocks_instead_of_negative_receive() -> None:
    """A backwards or junk timestamp leaves receive unmeasured, never negative.

    A clock step (finished before the anchor) or a junk timing object must not
    ship a negative duration into the HAR time sum; the anchor is still
    consumed so the map cannot grow.
    """
    handle, cdp = _wired_session()
    on_finished = cdp.handlers["Network.loadingFinished"]

    cdp.handlers["Network.requestWillBeSent"](_request_event("back"))
    cdp.handlers["Network.responseReceived"](
        _response_with_timing("back", request_time=100.0, headers_end=40.0)
    )
    on_finished({"requestId": "back", "timestamp": 99.0})
    assert "receive" not in handle.requests["back"]["timings"]
    assert handle.receive_anchors == {}

    # A -1 "not applicable" receiveHeadersEnd stores no anchor at all, so the
    # later finished event has nothing to measure against.
    cdp.handlers["Network.requestWillBeSent"](_request_event("na"))
    cdp.handlers["Network.responseReceived"](
        _response_with_timing("na", request_time=100.0, headers_end=-1)
    )
    assert handle.receive_anchors == {}
    on_finished({"requestId": "na", "timestamp": 200.0})
    assert "receive" not in handle.requests["na"].get("timings", {})


def test_loading_finished_creates_the_timings_map_when_only_receive_is_measurable() -> None:
    """A response with only a receive anchor still gets timings.receive at finish.

    Some responses (served from cache, early-hints, an odd redirect) carry
    requestTime + receiveHeadersEnd -- enough to anchor the body download -- but
    no sendStart/sendEnd, so _cdp_phase_timings yields nothing and responseReceived
    leaves the row with no timings map at all. loadingFinished must then create
    that map and put receive in it, rather than skipping the phase because the
    map it expected to enrich was never there.
    """
    handle, cdp = _wired_session()
    cdp.handlers["Network.requestWillBeSent"](_request_event("r1"))
    cdp.handlers["Network.responseReceived"](
        {
            "requestId": "r1",
            "response": {
                "status": 200,
                "mimeType": "application/json",
                # Only the receive anchor is derivable: no send/wait phases.
                "timing": {"requestTime": 100.0, "receiveHeadersEnd": 40.0},
            },
        }
    )
    assert "timings" not in handle.requests["r1"]
    assert "r1" in handle.receive_anchors

    cdp.handlers["Network.loadingFinished"]({"requestId": "r1", "timestamp": 100.1})
    # Headers done at 100.04, finished at 100.1 -> a 60ms body download, and it
    # lands in a map created here rather than one the response left behind.
    assert handle.requests["r1"]["timings"] == {"receive": 60.0}
    assert handle.receive_anchors == {}


def test_receive_anchors_are_evicted_and_cleared_with_their_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The anchor map can never outgrow the ring or outlive a failed request.

    Anchors are keyed by request id beside the row (not in it, rows are handed
    to callers verbatim), so they must go when the row is evicted and when
    loadingFailed means no loadingFinished will ever consume them -- otherwise
    a page whose requests never finish grows the map for the session's life.
    """
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 2)
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_response = cdp.handlers["Network.responseReceived"]
    for index in range(3):
        on_request(_request_event(f"r{index}"))
        on_response(_response_with_timing(f"r{index}", request_time=100.0, headers_end=40.0))
    assert list(handle.requests) == ["r1", "r2"]
    assert set(handle.receive_anchors) == {"r1", "r2"}

    cdp.handlers["Network.loadingFailed"](
        {"requestId": "r2", "errorText": "net::ERR_FAILED", "canceled": False}
    )
    assert set(handle.receive_anchors) == {"r1"}


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


def _redirect_event(
    request_id: str, *, url: str, status: int, timing: dict[str, Any] | None = None
) -> dict[str, Any]:
    """A requestWillBeSent for a redirect hop: same id, carrying the 3xx that caused it."""
    event = _request_event(request_id, url=url)
    response: dict[str, Any] = {"status": status, "mimeType": "text/html"}
    if timing is not None:
        response["timing"] = timing
    event["redirectResponse"] = response
    return event


def test_a_redirect_hop_survives_as_its_own_row_before_the_id_is_reused() -> None:
    """CDP reuses one requestId across a redirect chain; each hop must stay visible.

    Without preserving it the 302 -- the actual handoff -- was overwritten by the
    landing request and vanished from network.list and the HAR. The prior hop is
    kept under a synthetic id with its own status and redirect_url, in front of
    the final row, so the chain reads a -> b.
    """
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_response = cdp.handlers["Network.responseReceived"]

    on_request(_request_event("X", url="https://site/a"))
    on_request(_redirect_event("X", url="https://site/b", status=302))
    on_response({"requestId": "X", "response": {"status": 200, "mimeType": "text/html"}})

    rows = list(handle.requests.values())
    assert len(rows) == 2
    hop, final = rows
    assert hop["redirect"] is True
    assert hop["status"] == 302
    assert hop["url"] == "https://site/a"
    assert hop["redirect_url"] == "https://site/b"
    assert hop["requestId"] != "X"
    assert hop["requestId"].startswith("X:redirect:")
    assert final["requestId"] == "X"
    assert final["url"] == "https://site/b"
    assert final["status"] == 200


def test_a_two_hop_redirect_chain_keeps_every_hop() -> None:
    """A -> B -> C leaves three rows: two preserved 3xx hops and the final landing."""
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]

    on_request(_request_event("X", url="https://site/a"))
    on_request(_redirect_event("X", url="https://site/b", status=301))
    on_request(_redirect_event("X", url="https://site/c", status=302))

    rows = list(handle.requests.values())
    assert [r["url"] for r in rows] == ["https://site/a", "https://site/b", "https://site/c"]
    assert [r.get("status") for r in rows] == [301, 302, None]
    assert [r.get("redirect_url") for r in rows] == [
        "https://site/b",
        "https://site/c",
        None,
    ]
    # The two preserved hops get distinct synthetic ids; the live hop keeps X.
    ids = [r["requestId"] for r in rows]
    assert ids[2] == "X"
    assert ids[0] != ids[1]
    assert all(i.startswith("X:redirect:") for i in ids[:2])


def test_a_redirect_hop_carries_its_measured_send_wait_timings() -> None:
    """The redirectResponse's ResourceTiming populates the preserved hop's timings."""
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    timing = {"sendStart": 1.0, "sendEnd": 3.0, "receiveHeadersEnd": 10.0}
    on_request(_request_event("X", url="https://site/a"))
    on_request(_redirect_event("X", url="https://site/b", status=307, timing=timing))
    hop = next(iter(handle.requests.values()))
    assert hop["timings"] == {"send": 2.0, "wait": 7.0}


def test_a_redirect_for_an_unknown_id_does_not_crash_or_fabricate_a_hop() -> None:
    """A redirectResponse whose id was already evicted must be a clean no-op there.

    The new hop is still recorded under the reused id; only the (absent) prior
    hop cannot be preserved, and that must not raise on the handler thread.
    """
    handle, cdp = _wired_session()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_request(_redirect_event("ghost", url="https://site/b", status=302))
    assert list(handle.requests) == ["ghost"]
    assert handle.requests["ghost"]["url"] == "https://site/b"
    # No preserved hop was fabricated for a prior request that was never seen.
    assert not any(k.startswith("ghost:redirect:") for k in handle.requests)
