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
    content_length,
    har_document,
    har_entry,
    har_headers,
    header_value,
    iso8601,
    post_data,
    query_string,
    request_cookies,
    response_cookies,
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


def test_request_cookies_split_the_cookie_header_into_pairs() -> None:
    cookies = request_cookies(
        [
            {"name": "Cookie", "value": "sid=abc; theme=dark; flag"},
            {"name": "content-type", "value": "text/html"},
        ]
    )
    assert cookies == [
        {"name": "sid", "value": "abc"},
        {"name": "theme", "value": "dark"},
        {"name": "flag", "value": ""},
    ]


def test_request_cookies_is_empty_without_a_cookie_header() -> None:
    assert request_cookies(None) == []
    assert request_cookies([{"name": "accept", "value": "*/*"}]) == []


def test_response_cookies_capture_name_value_and_security_flags() -> None:
    """Each Set-Cookie is one cookie; HttpOnly/Secure are the triage signals."""
    cookies = response_cookies(
        [
            {
                "name": "set-cookie",
                "value": "sid=xyz; Path=/; Domain=x.test; HttpOnly; Secure",
            },
            {"name": "set-cookie", "value": "plain=1"},
            {"name": "content-type", "value": "text/html"},
        ]
    )
    assert cookies == [
        {
            "name": "sid",
            "value": "xyz",
            "path": "/",
            "domain": "x.test",
            "httpOnly": True,
            "secure": True,
        },
        {"name": "plain", "value": "1"},
    ]
    # expires is deliberately omitted (HTTP-date vs the ISO 8601 HAR wants).
    assert "expires" not in cookies[0]


def test_response_cookies_skips_a_nameless_set_cookie() -> None:
    assert response_cookies([{"name": "set-cookie", "value": "=orphan; Path=/"}]) == []


def test_har_entry_populates_cookies_from_the_headers() -> None:
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="GET",
        url="https://x",
        status=200,
        mime_type="text/html",
        request_headers=[{"name": "Cookie", "value": "sid=abc"}],
        response_headers=[{"name": "Set-Cookie", "value": "sid=new; HttpOnly"}],
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["request"]["cookies"] == [{"name": "sid", "value": "abc"}]
    assert entry["response"]["cookies"] == [
        {"name": "sid", "value": "new", "httpOnly": True}
    ]


def test_content_length_reads_the_declared_body_size() -> None:
    assert content_length([{"name": "Content-Length", "value": "1024"}]) == 1024
    # Case-insensitive, like every other header lookup.
    assert content_length([{"name": "content-length", "value": "7"}]) == 7


def test_content_length_is_unknown_when_absent_or_not_a_plain_integer() -> None:
    assert content_length(None) == -1
    assert content_length([]) == -1
    assert content_length([{"name": "content-type", "value": "text/html"}]) == -1
    # A comma-folded duplicate is ambiguous, not a size.
    assert content_length([{"name": "content-length", "value": "10, 10"}]) == -1
    assert content_length([{"name": "content-length", "value": "-5"}]) == -1
    assert content_length([{"name": "content-length", "value": "abc"}]) == -1


def test_har_entry_recovers_body_sizes_from_content_length() -> None:
    """bodySize is the sender's own count, honest even past a clipped body copy."""
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="POST",
        url="https://x/api",
        status=200,
        mime_type="application/json",
        request_headers=[{"name": "Content-Length", "value": "31"}],
        response_headers=[{"name": "Content-Length", "value": "4096"}],
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["request"]["bodySize"] == 31
    assert entry["response"]["bodySize"] == 4096
    # Uncompressed body length is not known without decoding, so it stays 0.
    assert entry["response"]["content"]["size"] == 0


def test_har_entry_leaves_body_sizes_unknown_without_content_length() -> None:
    entry = har_entry(
        started_at=None,
        method="GET",
        url="https://x",
        status=200,
        mime_type="text/html",
    )
    assert entry["request"]["bodySize"] == -1
    assert entry["response"]["bodySize"] == -1


def test_har_entry_recovers_redirect_url_from_the_location_header() -> None:
    """A 3xx's Location header is the redirect target; the HAR must show it."""
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="GET",
        url="https://x/login",
        status=302,
        mime_type="text/html",
        response_headers=[
            {"name": "Location", "value": "https://x/dashboard"},
            {"name": "content-type", "value": "text/html"},
        ],
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["response"]["redirectURL"] == "https://x/dashboard"


def test_har_entry_redirect_url_is_empty_without_a_location_header() -> None:
    entry = har_entry(
        started_at=None,
        method="GET",
        url="https://x",
        status=200,
        mime_type="text/html",
        response_headers=[{"name": "content-type", "value": "text/html"}],
    )
    assert entry["response"]["redirectURL"] == ""


def test_har_entry_records_the_server_ip_when_the_capture_kept_it() -> None:
    """serverIPAddress names the host the request actually reached."""
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="GET",
        url="https://x/a",
        status=200,
        mime_type="text/html",
        server_ip="93.184.216.34",
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["serverIPAddress"] == "93.184.216.34"


def test_har_entry_omits_server_ip_when_absent() -> None:
    entry = har_entry(
        started_at=None, method="GET", url="https://x", status=0, mime_type="",
    )
    _assert_entry_is_spec_valid(entry)
    assert "serverIPAddress" not in entry


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


def test_header_value_reads_a_header_case_insensitively() -> None:
    headers = [{"name": "Content-Type", "value": "application/json"}]
    assert header_value(headers, "content-type") == "application/json"
    assert header_value(headers, "missing") == ""
    assert header_value(None, "content-type") == ""


def test_post_data_carries_a_json_body_verbatim() -> None:
    """The POST payload an analyst opens a HAR for reaches request.postData."""
    body = '{"user":"alice","pw":"secret"}'
    assert post_data(body, "application/json") == {
        "mimeType": "application/json",
        "text": body,
    }


def test_post_data_splits_a_form_body_into_params() -> None:
    pd = post_data(
        "user=alice&pw=s%40cret&flag",
        "application/x-www-form-urlencoded; charset=utf-8",
    )
    assert pd is not None
    assert pd["mimeType"].startswith("application/x-www-form-urlencoded")
    assert pd["text"] == "user=alice&pw=s%40cret&flag"
    assert pd["params"] == [
        {"name": "user", "value": "alice"},
        {"name": "pw", "value": "s@cret"},
        {"name": "flag", "value": ""},
    ]


def test_post_data_decodes_bytes_and_degrades_on_empty() -> None:
    assert post_data(b"raw-bytes", "application/octet-stream") == {
        "mimeType": "application/octet-stream",
        "text": "raw-bytes",
    }
    # An absent or empty body yields no postData object at all.
    assert post_data(None, "application/json") is None
    assert post_data("", "application/json") is None
    assert post_data(b"", "application/json") is None


def test_post_data_is_clipped() -> None:
    pd = post_data("a" * (256 * 1024 + 10), "text/plain")
    assert pd is not None
    assert len(pd["text"]) == 256 * 1024


def test_har_entry_includes_post_data_when_the_capture_kept_a_body() -> None:
    entry = har_entry(
        started_at=1_700_000_000.0,
        method="POST",
        url="https://x/login",
        status=200,
        mime_type="application/json",
        request_post_data=post_data('{"a":1}', "application/json"),
    )
    _assert_entry_is_spec_valid(entry)
    assert entry["request"]["postData"] == {
        "mimeType": "application/json",
        "text": '{"a":1}',
    }


def test_har_entry_omits_post_data_when_absent() -> None:
    entry = har_entry(
        started_at=None, method="GET", url="https://x", status=0, mime_type="",
    )
    _assert_entry_is_spec_valid(entry)
    assert "postData" not in entry["request"]


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


def _proxy_post_flow(started: float) -> SimpleNamespace:
    body = b'{"user":"alice"}'
    request = SimpleNamespace(
        method="POST",
        pretty_url="https://x/login",
        host="x",
        headers={"content-type": "application/json"},
        raw_content=body,
        content=body,
        timestamp_start=started,
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "application/json"}, raw_content=b"{}"
    )
    return SimpleNamespace(id="p1", request=request, response=response)


def test_proxy_export_har_includes_the_request_body(tmp_path: Path, monkeypatch: Any) -> None:
    """The retained flow's POST body reaches the HAR as request.postData."""
    from headless_re_mcp.backends.proxy.client import _FlowRecorder

    backend = ProxyBackend()
    rec = _FlowRecorder()
    rec.response(_proxy_post_flow(1_700_000_000.0))
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=rec))
    out = tmp_path / "post.har"
    backend.export_har("s", out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    (entry,) = doc["log"]["entries"]
    _assert_entry_is_spec_valid(entry)
    assert entry["request"]["postData"] == {
        "mimeType": "application/json",
        "text": '{"user":"alice"}',
    }


def _proxy_flow_with_server_ip(started: float) -> SimpleNamespace:
    flow = _proxy_flow(started)
    flow.server_conn = SimpleNamespace(ip_address=("93.184.216.34", 443))
    return flow


def test_proxy_export_har_records_the_server_ip(tmp_path: Path, monkeypatch: Any) -> None:
    """The upstream host mitmproxy connected to reaches serverIPAddress."""
    from headless_re_mcp.backends.proxy.client import _FlowRecorder

    backend = ProxyBackend()
    rec = _FlowRecorder()
    rec.response(_proxy_flow_with_server_ip(1_700_000_000.0))
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=rec))
    out = tmp_path / "ip.har"
    backend.export_har("s", out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    (entry,) = doc["log"]["entries"]
    _assert_entry_is_spec_valid(entry)
    assert entry["serverIPAddress"] == "93.184.216.34"


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
            "remote_ip": "93.184.216.34",
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
    # The server IP CDP reported for the connection reached serverIPAddress.
    assert entry["serverIPAddress"] == "93.184.216.34"


class _WebPostHandle:
    lock = Lock()
    requests = {
        "1": {
            "method": "POST",
            "url": "https://x/login",
            "status": 200,
            "mimeType": "application/json",
            "resourceType": "XHR",
            "started_at": 1_700_000_000.0,
            "request_headers": [{"name": "content-type", "value": "application/json"}],
            # The small body CDP inlined at send time and the ring kept.
            "post_data": '{"user":"alice"}',
        }
    }


def test_web_har_export_includes_the_inline_request_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebPostHandle())
    out = tmp_path / "post.har"
    backend.har_export("s", out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    (entry,) = doc["log"]["entries"]
    _assert_entry_is_spec_valid(entry)
    # The inline body, typed by the request's own content-type, reached the HAR.
    assert entry["request"]["postData"] == {
        "mimeType": "application/json",
        "text": '{"user":"alice"}',
    }
