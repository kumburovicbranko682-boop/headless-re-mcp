"""HAR exports must be spec-valid 1.2, not method/url/status stubs.

A HAR whose entries omit startedDateTime, timings, request/response members and
cache is rejected by Chrome DevTools and other viewers, so an export nothing can
open is not an export. These tests pin the required shape for the shared builder
and for both backends that use it.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.common.har import (
    har_document,
    har_entry,
    har_headers,
    iso8601,
    query_string,
)
from headless_re_mcp.backends.proxy.client import ProxyBackend
from headless_re_mcp.backends.web.client import WebBackend


def _assert_entry_is_spec_valid(entry: dict[str, Any]) -> None:
    # startedDateTime must parse as a date, or strict parsers reject the log.
    datetime.fromisoformat(entry["startedDateTime"])
    assert isinstance(entry["time"], (int, float))
    request = entry["request"]
    for field in ("method", "url", "httpVersion"):
        assert isinstance(request[field], str)
    for field in ("cookies", "headers", "queryString"):
        assert isinstance(request[field], list)
    assert isinstance(request["headersSize"], int)
    assert isinstance(request["bodySize"], int)
    response = entry["response"]
    assert isinstance(response["status"], int)
    for field in ("statusText", "httpVersion", "redirectURL"):
        assert isinstance(response[field], str)
    for field in ("cookies", "headers"):
        assert isinstance(response[field], list)
    assert set(response["content"]) >= {"size", "mimeType"}
    assert isinstance(entry["cache"], dict)
    timings = entry["timings"]
    for field in ("send", "wait", "receive"):
        assert isinstance(timings[field], (int, float))
    # The spec ties time to the sum of the phase timings when all are present.
    assert entry["time"] == timings["send"] + timings["wait"] + timings["receive"]


def test_iso8601_degrades_a_missing_timestamp_to_the_epoch() -> None:
    assert iso8601(None).startswith("1970-01-01T00:00:00")
    assert iso8601(0).startswith("1970-01-01T00:00:00")
    # A real epoch round-trips to a parseable date.
    parsed = datetime.fromisoformat(iso8601(1_700_000_000.0))
    assert parsed.year == 2023


def test_har_entry_fills_every_required_member() -> None:
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="POST",
        url="https://api.example/login",
        status=200,
        mime_type="application/json",
        extra={"_resourceType": "XHR"},
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["request"]["method"] == "POST"
    assert entry["response"]["content"]["mimeType"] == "application/json"
    # Custom underscore fields are allowed and preserved.
    assert entry["_resourceType"] == "XHR"


def test_query_string_recovers_request_parameters_from_the_url() -> None:
    """The parameters an analyst opens a HAR to read come off the URL itself."""
    params = query_string("https://api.example/search?q=hello+world&page=2&flag")
    assert params == [
        {"name": "q", "value": "hello world"},
        {"name": "page", "value": "2"},
        # keep_blank_values keeps a bare key with an empty value.
        {"name": "flag", "value": ""},
    ]


def test_query_string_is_empty_without_a_query() -> None:
    assert query_string("https://x/a") == []
    assert query_string("") == []
    assert query_string(None) == []
    # The fragment is not the query and must not leak into the parameters.
    assert query_string("https://x/a#q=notaparam") == []


def test_query_string_is_capped() -> None:
    dense = "https://x/a?" + "&".join(f"k{i}=v{i}" for i in range(1000))
    assert len(query_string(dense)) == 512


def test_har_entry_populates_query_string_from_the_url() -> None:
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="GET",
        url="https://api.example/login?user=alice&next=%2Fhome",
        status=200,
        mime_type="application/json",
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["request"]["queryString"] == [
        {"name": "user", "value": "alice"},
        {"name": "next", "value": "/home"},
    ]


class _MultiHeaders:
    """Stands in for mitmproxy Headers, which can repeat a name."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = pairs

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        if not multi:
            raise TypeError("multi is required for the repeated form")
        return list(self._pairs)


def test_har_headers_converts_a_dict_to_name_value_objects() -> None:
    out = har_headers({"Authorization": "Bearer x", "Accept": "*/*"})
    assert {"name": "Authorization", "value": "Bearer x"} in out
    assert {"name": "Accept", "value": "*/*"} in out


def test_har_headers_prefers_the_repeated_form_and_keeps_duplicates() -> None:
    headers = _MultiHeaders([("set-cookie", "a=1"), ("set-cookie", "b=2")])
    assert har_headers(headers) == [
        {"name": "set-cookie", "value": "a=1"},
        {"name": "set-cookie", "value": "b=2"},
    ]


def test_har_headers_degrades_and_bounds() -> None:
    assert har_headers(None) == []
    assert har_headers(object()) == []
    flood = {f"h{i}": "v" for i in range(1000)}
    assert len(har_headers(flood)) == 200
    long = har_headers({"x": "y" * 100_000})
    assert len(long[0]["value"]) == 8 * 1024


def test_har_entry_populates_headers_when_the_capture_kept_them() -> None:
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="GET",
        url="https://x/a",
        status=200,
        mime_type="text/html",
        request_headers=[{"name": "authorization", "value": "Bearer t"}],
        response_headers=[{"name": "content-type", "value": "text/html"}],
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["request"]["headers"] == [{"name": "authorization", "value": "Bearer t"}]
    assert entry["response"]["headers"] == [{"name": "content-type", "value": "text/html"}]


def test_har_document_wraps_entries_in_the_log_envelope() -> None:
    doc = har_document([har_entry(
        started_at=None, method="GET", url="https://x", status=0, mime_type="",
    )])
    assert doc["log"]["version"] == "1.2"
    assert doc["log"]["creator"]["name"]
    assert len(doc["log"]["entries"]) == 1


def _proxy_flow(started: float) -> SimpleNamespace:
    request = SimpleNamespace(
        method="GET",
        pretty_url="https://x/a?token=abc&id=7",
        host="x",
        headers={"authorization": "Bearer secret", "user-agent": "curl"},
        raw_content=b"",
        timestamp_start=started,
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/html"}, raw_content=b"ok"
    )
    return SimpleNamespace(id="f1", request=request, response=response)


def test_proxy_export_har_is_spec_valid(tmp_path: Path, monkeypatch: Any) -> None:
    from headless_re_mcp.backends.proxy.client import _FlowRecorder

    backend = ProxyBackend()
    rec = _FlowRecorder()
    rec.response(_proxy_flow(1_700_000_000.0))
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=rec))
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["entry_count"] == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["log"]["version"] == "1.2"
    (entry,) = doc["log"]["entries"]
    _assert_entry_is_spec_valid(entry)
    # The captured wire start time reached the export, not the export instant.
    assert datetime.fromisoformat(entry["startedDateTime"]).year == 2023
    assert entry["request"]["url"] == "https://x/a?token=abc&id=7"
    # The query parameters reached the export off the captured URL.
    assert entry["request"]["queryString"] == [
        {"name": "token", "value": "abc"},
        {"name": "id", "value": "7"},
    ]
    # The retained flow's real headers reached the HAR, on both sides.
    assert {"name": "authorization", "value": "Bearer secret"} in entry["request"]["headers"]
    assert {"name": "content-type", "value": "text/html"} in entry["response"]["headers"]


class _WebHandle:
    lock = Lock()
    requests = {
        "1": {
            "method": "GET",
            "url": "https://x",
            "status": 200,
            "mimeType": "text/plain",
            "resourceType": "XHR",
            "started_at": 1_700_000_000.0,
            "response_headers": [{"name": "content-type", "value": "text/plain"}],
        }
    }


def test_web_har_export_is_spec_valid(tmp_path: Path, monkeypatch: Any) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle())
    out = tmp_path / "c.har"
    payload = backend.har_export("s", out)
    assert payload["entry_count"] == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    (entry,) = doc["log"]["entries"]
    _assert_entry_is_spec_valid(entry)
    assert entry["_resourceType"] == "XHR"
    assert datetime.fromisoformat(entry["startedDateTime"]).year == 2023
    # The response headers the web capture kept reached the HAR too.
    assert {"name": "content-type", "value": "text/plain"} in entry["response"]["headers"]
