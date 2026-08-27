"""The web HAR export must carry the headers/timing/sizes CDP actually reports.

web.har.export used to emit only method/url/status/mimeType. CDP hands the
capture much more for free -- request/response headers, the protocol, status
text, ResourceTiming and the finished byte count -- so the export now records
it. These tests pin that enrichment end to end: drive the real CDP event
handlers with representative params, export, and assert the HAR entry carries
the rich fields, while network.list stays lean (no internal ``_har`` leak).
"""

from __future__ import annotations

import json
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    WebBackend,
    _cdp_entry_to_har,
    _cdp_timings,
)


class _Cdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, *args: Any) -> None:
        del method, args

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class _Handle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.requests_dropped = 0
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts_dropped = 0
        self.console: list[dict[str, Any]] = []
        self.console_dropped = 0
        self.cdp = _Cdp()


def _drive_one_exchange(handle: _Handle) -> None:
    """Feed one full request/response/finished cycle through the wired handlers."""
    handlers = handle.cdp.handlers
    handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "wallTime": 1_700_000_000.0,
            "timestamp": 1000.0,
            "type": "XHR",
            "request": {
                "url": "https://api.test/thing?a=1&b=2",
                "method": "POST",
                "headers": {"Content-Type": "application/json", "X-Trace": "abc"},
                "postData": '{"k":"v"}',
            },
        }
    )
    handlers["Network.responseReceived"](
        {
            "requestId": "r1",
            "response": {
                "status": 201,
                "statusText": "Created",
                "mimeType": "application/json",
                "protocol": "h2",
                "headers": {"Content-Type": "application/json", "Server": "test"},
                "timing": {
                    "requestTime": 1000.0,
                    "dnsStart": 1.0,
                    "dnsEnd": 3.0,
                    "connectStart": 3.0,
                    "connectEnd": 8.0,
                    "sslStart": 4.0,
                    "sslEnd": 8.0,
                    "sendStart": 10.0,
                    "sendEnd": 12.0,
                    "receiveHeadersEnd": 40.0,
                },
            },
        }
    )
    handlers["Network.loadingFinished"](
        {"requestId": "r1", "timestamp": 1000.1, "encodedDataLength": 512}
    )


class TestCdpTimings:
    def test_derives_phases_from_resource_timing(self) -> None:
        meta = {
            "timing": {
                "requestTime": 1000.0,
                "sendStart": 10.0,
                "sendEnd": 12.0,
                "receiveHeadersEnd": 40.0,
                "dnsStart": 1.0,
                "dnsEnd": 3.0,
                "connectStart": 3.0,
                "connectEnd": 8.0,
                "sslStart": 4.0,
                "sslEnd": 8.0,
            },
            "finished_ts": 1000.1,
        }
        time_ms, timings = _cdp_timings(meta)
        assert timings["send"] == 2.0
        assert timings["wait"] == 28.0  # receiveHeadersEnd - sendEnd
        assert timings["dns"] == 2.0
        assert timings["connect"] == 5.0
        assert timings["ssl"] == 4.0
        # receive = (finished - requestTime)*1000 - receiveHeadersEnd = 100 - 40
        assert timings["receive"] == 60.0
        # total = (finished - requestTime) * 1000
        assert time_ms == 100.0

    def test_missing_timing_yields_unknown_phases(self) -> None:
        time_ms, timings = _cdp_timings({})
        assert timings == {"send": -1.0, "wait": -1.0, "receive": -1.0}
        assert time_ms == 0.0

    def test_negative_or_absent_offsets_stay_unknown(self) -> None:
        # A phase whose offsets are -1 (CDP's "not applicable") is not invented.
        _, timings = _cdp_timings({"timing": {"requestTime": 5.0, "sendStart": -1.0}})
        assert timings["send"] == -1.0
        assert "dns" not in timings


class TestCdpEntryToHar:
    def test_rich_entry_carries_headers_query_timings_and_size(self) -> None:
        handle = _Handle()
        WebBackend()._wire_events(handle)  # type: ignore[arg-type]
        _drive_one_exchange(handle)
        entry = handle.requests["r1"]

        har_entry = _cdp_entry_to_har(entry)

        # Request side: method, parsed query, headers, JSON post body.
        assert har_entry["request"]["method"] == "POST"
        qs = {p["name"]: p["value"] for p in har_entry["request"]["queryString"]}
        assert qs == {"a": "1", "b": "2"}
        req_headers = {h["name"] for h in har_entry["request"]["headers"]}
        assert {"Content-Type", "X-Trace"} <= req_headers
        assert har_entry["request"]["httpVersion"] == "h2"
        assert har_entry["request"]["postData"]["text"] == '{"k":"v"}'

        # Response side: status text, headers, transfer size, mime.
        assert har_entry["response"]["status"] == 201
        assert har_entry["response"]["statusText"] == "Created"
        resp_headers = {h["name"] for h in har_entry["response"]["headers"]}
        assert {"Content-Type", "Server"} <= resp_headers
        assert har_entry["response"]["bodySize"] == 512
        assert har_entry["response"]["content"]["mimeType"] == "application/json"

        # startedDateTime comes from wallTime, and timings are real.
        assert datetime.fromisoformat(har_entry["startedDateTime"]).year == 2023
        assert har_entry["timings"]["send"] == 2.0
        assert har_entry["time"] == 100.0
        assert har_entry["_resourceType"] == "XHR"


class TestHarExportIsRichAndListStaysLean:
    def test_export_is_rich_but_network_list_hides_internal_har(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        handle = _Handle()
        backend = WebBackend()
        backend._wire_events(handle)  # type: ignore[arg-type]
        _drive_one_exchange(handle)
        monkeypatch.setattr(backend, "_get", lambda session_id: handle)

        # network.list must never expose the internal _har enrichment payload.
        listed = backend.network_list("s")
        assert listed["requests"], listed
        assert all("_har" not in row for row in listed["requests"]), listed["requests"]

        out = tmp_path / "capture.har"
        result = backend.har_export("s", out)
        assert result["entry_count"] == 1
        doc = json.loads(out.read_text(encoding="utf-8"))
        entry = doc["log"]["entries"][0]
        # The exported entry is the rich one, not a method/url stub.
        assert entry["request"]["headers"], entry["request"]
        assert entry["response"]["headers"], entry["response"]
        assert entry["response"]["bodySize"] == 512
