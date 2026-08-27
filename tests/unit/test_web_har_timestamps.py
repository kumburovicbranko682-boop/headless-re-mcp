"""web.har.export stamps each entry with the request's real start time.

HAR's startedDateTime is meant to be when the request actually went out. The
web capture never kept that, so har_entry fell back to the export instant and
every entry in the file shared one timestamp -- a HAR that reads as though all
traffic happened at once, losing the ordering and spacing that are a main reason
to open a HAR. CDP delivers wallTime on Network.requestWillBeSent; these tests
pin that it is captured, evicted in lockstep with the request summaries, and
surfaced as the entry's startedDateTime, with a safe fallback when it is absent.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import (
    WebBackend,
    _iso_from_wall_time,
    _WebSession,
)


class _Cdp:
    """Records the handlers _wire_events registers so a test can drive them."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> None:
        del method, params

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def test_iso_from_wall_time_converts_epoch_and_rejects_unusable_values() -> None:
    wall = 1_700_000_000.5
    assert _iso_from_wall_time(wall) == datetime.fromtimestamp(wall, tz=UTC).isoformat()
    # A missing, zero, negative, boolean, or absurd value falls back (None) so
    # har_entry uses the export instant rather than fabricating a timestamp.
    assert _iso_from_wall_time(None) is None
    assert _iso_from_wall_time(0) is None
    assert _iso_from_wall_time(-1) is None
    assert _iso_from_wall_time(True) is None
    assert _iso_from_wall_time("2026") is None
    assert _iso_from_wall_time(10**30) is None


def test_har_export_stamps_each_entry_with_its_recorded_wall_time(
    tmp_path: Path,
) -> None:
    """The exported HAR must carry the real per-request start, not export time."""
    backend = WebBackend()
    handle = _WebSession(object(), object(), object(), object(), object())
    times = {"1": 1_700_000_000.0, "2": 1_700_000_123.5}
    for rid, wall in times.items():
        handle.requests[rid] = {
            "requestId": rid,
            "url": f"https://example.com/{rid}",
            "method": "GET",
            "status": 200,
            "mimeType": "text/html",
            "resourceType": "XHR",
        }
        handle.request_times[rid] = wall
    backend._sessions["s"] = handle

    out = tmp_path / "capture.har"
    backend.har_export("s", out)

    doc = json.loads(out.read_text(encoding="utf-8"))
    by_url = {
        entry["request"]["url"]: entry["startedDateTime"]
        for entry in doc["log"]["entries"]
    }
    assert by_url["https://example.com/1"] == _iso_from_wall_time(times["1"])
    assert by_url["https://example.com/2"] == _iso_from_wall_time(times["2"])
    # Distinct requests keep distinct timestamps -- the whole point.
    assert by_url["https://example.com/1"] != by_url["https://example.com/2"]


def test_har_export_falls_back_to_export_time_when_wall_time_is_missing(
    tmp_path: Path,
) -> None:
    """A request with no recorded wallTime still gets a valid, recent instant."""
    backend = WebBackend()
    handle = _WebSession(object(), object(), object(), object(), object())
    handle.requests["1"] = {
        "requestId": "1",
        "url": "https://example.com/1",
        "method": "GET",
        "status": 200,
        "mimeType": "text/html",
    }
    # No entry in request_times for "1".
    backend._sessions["s"] = handle

    before = datetime.now(UTC)
    out = tmp_path / "capture.har"
    backend.har_export("s", out)
    after = datetime.now(UTC)

    doc = json.loads(out.read_text(encoding="utf-8"))
    stamped = datetime.fromisoformat(doc["log"]["entries"][0]["startedDateTime"])
    assert before <= stamped <= after


def test_request_wall_time_is_captured_and_evicted_in_lockstep(
    monkeypatch: Any,
) -> None:
    """request_times must not outgrow the request ring it shadows.

    on_request records wallTime beside each summary; if eviction dropped only
    the summary, request_times would grow for the life of a busy session. Drive
    more requests than the (shrunk) cap and both maps must hold the same newest
    keys, with the overflow counted as dropped.
    """
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 3)
    cdp = _Cdp()
    handle = _WebSession(object(), object(), object(), object(), cdp)
    WebBackend()._wire_events(handle)
    on_request = cdp.handlers["Network.requestWillBeSent"]

    for index in range(5):
        on_request(
            {
                "requestId": str(index),
                "request": {"url": f"https://x/{index}", "method": "GET"},
                "type": "XHR",
                "wallTime": 1_700_000_000.0 + index,
            }
        )

    assert list(handle.requests) == ["2", "3", "4"]
    assert list(handle.request_times) == ["2", "3", "4"]
    assert handle.requests_dropped == 2
    assert handle.request_times["4"] == 1_700_000_004.0


def test_request_without_wall_time_is_still_recorded_without_a_time(
    monkeypatch: Any,
) -> None:
    """A requestWillBeSent lacking wallTime records the summary but no time."""
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 3)
    cdp = _Cdp()
    handle = _WebSession(object(), object(), object(), object(), cdp)
    WebBackend()._wire_events(handle)
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "1", "request": {"url": "https://x/1", "method": "GET"}, "type": "XHR"}
    )
    assert "1" in handle.requests
    assert "1" not in handle.request_times
