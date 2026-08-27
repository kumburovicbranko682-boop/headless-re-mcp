"""The shared HAR builder must emit spec-compliant HAR 1.2 documents.

The proxy and web lines both exported a HAR that omitted almost every required
field, so the artifact would not load in a HAR viewer or validate. These tests
pin the contract every consumer relies on: the log envelope, and each entry's
required request/response/timings shape -- so a future edit that drops a field
fails here rather than shipping an unopenable capture.
"""

from __future__ import annotations

import base64
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends import har
from headless_re_mcp.backends.proxy.client import _flow_to_har_entry

# The fields HAR 1.2 requires on each object; a consumer (Chrome import,
# haralyzer, har-validator) rejects an entry missing any of them.
_REQUIRED_ENTRY = {"startedDateTime", "time", "request", "response", "cache", "timings"}
_REQUIRED_REQUEST = {
    "method",
    "url",
    "httpVersion",
    "cookies",
    "headers",
    "queryString",
    "headersSize",
    "bodySize",
}
_REQUIRED_RESPONSE = {
    "status",
    "statusText",
    "httpVersion",
    "cookies",
    "headers",
    "content",
    "redirectURL",
    "headersSize",
    "bodySize",
}
_REQUIRED_TIMINGS = {"send", "wait", "receive"}


def _assert_valid_har(doc: dict[str, Any]) -> None:
    """Assert a whole HAR document carries every field HAR 1.2 mandates."""
    assert set(doc) == {"log"}, doc
    log = doc["log"]
    assert log["version"] == "1.2", log
    assert log["creator"]["name"] == "headless-re-mcp"
    assert log["creator"]["version"], "creator.version is required"
    for entry in log["entries"]:
        assert set(entry) >= _REQUIRED_ENTRY, entry
        # startedDateTime must be a parseable ISO 8601 timestamp with a timezone.
        parsed = datetime.fromisoformat(entry["startedDateTime"])
        assert parsed.tzinfo is not None, entry["startedDateTime"]
        assert isinstance(entry["time"], (int, float))
        assert set(entry["request"]) >= _REQUIRED_REQUEST, entry["request"]
        assert set(entry["response"]) >= _REQUIRED_RESPONSE, entry["response"]
        assert set(entry["timings"]) >= _REQUIRED_TIMINGS, entry["timings"]
        assert "size" in entry["response"]["content"], entry["response"]["content"]
        assert "mimeType" in entry["response"]["content"], entry["response"]["content"]
        for header in entry["request"]["headers"] + entry["response"]["headers"]:
            assert set(header) >= {"name", "value"}, header


class TestHarPrimitives:
    def test_iso8601_of_none_is_a_valid_epoch_timestamp(self) -> None:
        text = har.iso8601(None)
        assert datetime.fromisoformat(text).year == 1970
        assert har.iso8601(1_700_000_000.0).startswith("2023-")

    def test_duration_is_minus_one_when_a_timestamp_is_missing(self) -> None:
        assert har.duration_ms(None, 5.0) == -1.0
        assert har.duration_ms(1.0, None) == -1.0
        assert har.duration_ms(1.0, 1.5) == 500.0
        # A clock that went backwards is unknown, not negative.
        assert har.duration_ms(2.0, 1.0) == -1.0

    def test_total_time_sums_only_known_phases(self) -> None:
        assert har.total_time(10.0, -1.0, 5.0) == 15.0
        assert har.total_time(-1.0, -1.0, -1.0) == 0.0

    def test_query_string_is_parsed_from_the_url(self) -> None:
        pairs = har.query_string("http://h/p?a=1&b=&a=2")
        assert {"name": "a", "value": "1"} in pairs
        assert {"name": "b", "value": ""} in pairs
        assert pairs.count({"name": "a", "value": "2"}) == 1

    def test_header_list_handles_mitmproxy_multidict_and_plain_mapping(self) -> None:
        class _MultiHeaders:
            def items(self, multi: bool = False) -> list[tuple[str, str]]:
                assert multi is True
                return [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]

        multi = har.header_list(_MultiHeaders())
        assert multi == [
            {"name": "Set-Cookie", "value": "a=1"},
            {"name": "Set-Cookie", "value": "b=2"},
        ]
        plain = har.header_list({"Content-Type": "text/html"})
        assert plain == [{"name": "Content-Type", "value": "text/html"}]
        assert har.header_list(None) == []
        assert har.header_list(object()) == []

    def test_content_inlines_utf8_and_base64s_binary(self) -> None:
        text = har.content(b"hello", "text/plain")
        assert text == {"size": 5, "mimeType": "text/plain", "text": "hello"}
        binary = har.content(b"\xff\xfe\x00", "application/octet-stream")
        assert binary["encoding"] == "base64"
        assert base64.b64decode(binary["text"]) == b"\xff\xfe\x00"
        assert binary["size"] == 3

    def test_empty_body_is_valid_content_with_no_text(self) -> None:
        empty = har.content(b"", "text/html")
        assert empty == {"size": 0, "mimeType": "text/html"}


class TestHarDocument:
    def test_document_of_a_minimal_entry_is_valid_har(self) -> None:
        entry = har.entry(
            started=None,
            time_ms=0.0,
            request=har.request_entry(method="GET", url="http://h/p"),
            response=har.response_entry(status=200, mime="text/html"),
        )
        _assert_valid_har(har.document([entry]))

    def test_empty_capture_is_still_a_valid_har(self) -> None:
        _assert_valid_har(har.document([]))


class TestProxyFlowEntry:
    """A recorded mitmproxy flow must map to a rich, valid HAR entry."""

    def _flow(self) -> Any:
        request = SimpleNamespace(
            method="POST",
            pretty_url="http://host/api?x=1",
            http_version="HTTP/2.0",
            headers={"content-type": "application/json", "accept": "*/*"},
            content=b'{"k":"v"}',
            raw_content=b'{"k":"v"}',
            timestamp_start=1000.0,
            timestamp_end=1000.1,
        )
        response = SimpleNamespace(
            status_code=200,
            reason="OK",
            http_version="HTTP/2.0",
            headers={"content-type": "text/plain"},
            content=b"pong",
            raw_content=b"pong",
            timestamp_start=1000.2,
            timestamp_end=1000.35,
        )
        return SimpleNamespace(id="f1", request=request, response=response)

    def _summary(self) -> dict[str, Any]:
        return {
            "id": "f1",
            "method": "POST",
            "url": "http://host/api?x=1",
            "status": 200,
            "content_type": "text/plain",
        }

    def test_rich_flow_fills_headers_query_body_and_timings(self) -> None:
        entry = _flow_to_har_entry(self._summary(), self._flow())
        _assert_valid_har(har.document([entry]))

        assert entry["request"]["method"] == "POST"
        assert entry["request"]["httpVersion"] == "HTTP/2.0"
        assert entry["request"]["queryString"] == [{"name": "x", "value": "1"}]
        assert {"name": "accept", "value": "*/*"} in entry["request"]["headers"]
        # The JSON request body is carried as postData.
        assert entry["request"]["postData"]["text"] == '{"k":"v"}'

        assert entry["response"]["status"] == 200
        assert entry["response"]["statusText"] == "OK"
        assert entry["response"]["content"]["text"] == "pong"
        assert entry["response"]["content"]["size"] == 4

        # Real timestamps yield real, non-negative timings and a positive total.
        timings = entry["timings"]
        assert timings["send"] >= 0
        assert timings["receive"] >= 0
        assert entry["time"] > 0
        # startedDateTime reflects the request's own start time, not "now".
        assert datetime.fromisoformat(entry["startedDateTime"]).timestamp() == 1000.0

    def test_summary_only_flow_still_yields_a_valid_entry(self) -> None:
        """A flow whose body was evicted (no raw object) must not break export."""
        entry = _flow_to_har_entry(self._summary(), None)
        _assert_valid_har(har.document([entry]))
        # Sparse, but honest: method/url/status survive from the summary.
        assert entry["request"]["method"] == "POST"
        assert entry["response"]["status"] == 200
        assert entry["request"]["headers"] == []
        assert entry["timings"] == {"send": -1.0, "wait": -1.0, "receive": -1.0}
