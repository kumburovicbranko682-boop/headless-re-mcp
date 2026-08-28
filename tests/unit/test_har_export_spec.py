"""Both HAR exporters emit spec-valid HAR 1.2 and stay under the capture cap.

The web and proxy captures used to each hand-roll a ``{"request": {method,
url}, "response": {status, content: {mimeType}}}`` shape that no standard HAR
consumer (Chrome DevTools "Import HAR", Firefox, har-validator) will load,
because the 1.2 spec makes ``startedDateTime``, ``time``, several request and
response members, ``cache`` and ``timings`` mandatory on every entry. And
``proxy.export_har`` wrote whatever the flow ring held with no size ceiling,
unlike ``web.har.export`` and unlike the rest of the byte-bounded proxy
backend. These tests pin both: the file validates against the mandatory HAR 1.2
members, and an oversized capture is truncated to fit the cap rather than
written whole.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from headless_re_mcp.backends.common.har import (
    build_har,
    har_entry,
    iso_from_epoch,
    serialize_har,
)
from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _FlowRecorder
from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import WebBackend, WebError, _cdp_phase_timings

# Mandatory members per the HAR 1.2 spec. A consumer that finds any of these
# missing rejects the whole log, which is exactly the interop break this file
# guards against.
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


def _assert_valid_har(text: str) -> dict[str, Any]:
    doc = json.loads(text)
    log = doc["log"]
    assert log["version"] == "1.2"
    assert log["creator"]["name"] == "headless-re-mcp"
    assert log["creator"]["version"], "creator.version must name the tool build"
    assert isinstance(log["entries"], list)
    for entry in log["entries"]:
        assert _REQUIRED_ENTRY.issubset(entry), f"entry missing members: {entry}"
        assert _REQUIRED_REQUEST.issubset(entry["request"])
        assert _REQUIRED_RESPONSE.issubset(entry["response"])
        assert {"size", "mimeType"}.issubset(entry["response"]["content"])
        assert _REQUIRED_TIMINGS.issubset(entry["timings"])
        # Each queryString member must carry the spec's name/value pair.
        for param in entry["request"]["queryString"]:
            assert {"name", "value"}.issubset(param), f"malformed queryString: {param}"
        # startedDateTime must be a real ISO 8601 instant, not a placeholder.
        datetime.fromisoformat(entry["startedDateTime"])
    return doc


def test_har_entry_is_spec_complete_and_carries_the_summary_fields() -> None:
    entry = har_entry(
        method="POST",
        url="https://example.com/api",
        status=201,
        mime_type="application/json",
        resource_type="XHR",
    )
    _assert_valid_har(json.dumps(build_har([entry])))
    assert entry["request"]["method"] == "POST"
    assert entry["request"]["url"] == "https://example.com/api"
    assert entry["response"]["status"] == 201
    assert entry["response"]["content"]["mimeType"] == "application/json"
    # Chrome's own extension key, so the browser capture keeps the resource hint.
    assert entry["_resourceType"] == "XHR"


def test_har_entry_tolerates_missing_status_and_url() -> None:
    entry = har_entry(method="", url=None, status=None, mime_type="")
    _assert_valid_har(json.dumps(build_har([entry])))
    assert entry["response"]["status"] == 0
    assert entry["request"]["url"] == ""
    assert entry["request"]["queryString"] == []
    assert "_resourceType" not in entry


def test_har_entry_parses_the_query_string_from_the_url() -> None:
    """A HAR viewer reads request params from queryString, not just the URL.

    parse_qsl keeps repeated keys and blank values, so a consumer that does not
    re-split the URL itself still sees every parameter the request carried.
    """
    entry = har_entry(
        method="GET",
        url="https://example.com/search?q=hello+world&tag=a&tag=b&flag=",
        status=200,
        mime_type="text/html",
    )
    _assert_valid_har(json.dumps(build_har([entry])))
    params = [(p["name"], p["value"]) for p in entry["request"]["queryString"]]
    assert params == [("q", "hello world"), ("tag", "a"), ("tag", "b"), ("flag", "")]


def test_a_url_the_parser_rejects_does_not_sink_the_whole_export() -> None:
    """One malformed URL must degrade to an empty queryString, not abort the HAR.

    har_entry parses queryString by handing the URL to urlsplit, which raises
    ValueError on an unmatched IPv6 bracket. A proxy records whatever the client
    sent, malformed URLs included, and har_entry runs inside the comprehension
    that builds *every* entry -- so an unguarded raise there would lose the whole
    capture over one bad row. The guard keeps the raw URL verbatim, empties only
    its parsed query, and leaves the entry spec-valid so the export still writes.
    """
    bad_url = "http://[::1/path?a=b"
    # Ground the premise: this really is a URL urlsplit refuses to parse, so the
    # test exercises the guard rather than a URL that happens to parse cleanly.
    with pytest.raises(ValueError):
        urlsplit(bad_url)

    entry = har_entry(method="GET", url=bad_url, status=200, mime_type="text/html")
    assert entry["request"]["queryString"] == []
    # Only the query parse degraded; the URL itself is still reported verbatim.
    assert entry["request"]["url"] == bad_url

    # A mixed capture -- the bad row beside a good one -- must serialize whole,
    # with the good row's query still parsed. That is the property the guard
    # protects: a hostile URL cannot take the rest of the HAR down with it.
    good = har_entry(
        method="GET", url="https://example.com/s?q=1", status=200, mime_type="text/html"
    )
    result = serialize_har([entry, good], max_bytes=64 * 1024 * 1024)
    assert result.entry_count == 2
    doc = _assert_valid_har(result.text)
    by_url = {e["request"]["url"]: e for e in doc["log"]["entries"]}
    assert by_url[bad_url]["request"]["queryString"] == []
    good_params = [
        (p["name"], p["value"])
        for p in by_url["https://example.com/s?q=1"]["request"]["queryString"]
    ]
    assert good_params == [("q", "1")]


def test_har_entry_reports_a_known_response_body_size() -> None:
    """When the capture knows the decoded body length it must not emit -1."""
    known = har_entry(
        method="GET",
        url="https://x/1",
        status=200,
        mime_type="application/json",
        response_body_size=1234,
    )
    assert known["response"]["content"]["size"] == 1234
    assert known["response"]["bodySize"] == 1234
    # Absent or negative size falls back to the spec's -1 "not available".
    unknown = har_entry(method="GET", url="https://x/1", status=200, mime_type="")
    assert unknown["response"]["content"]["size"] == -1
    assert unknown["response"]["bodySize"] == -1


def test_iso_from_epoch_converts_a_real_time_and_rejects_junk() -> None:
    """A real epoch becomes an ISO instant; unknown or unparseable stays None.

    startedDateTime is mandatory, so har_entry falls back to the export instant
    when this returns None -- but a capture that knows the real time (the proxy's
    request.timestamp_start) must surface it so a viewer's waterfall shows the
    true request order. Pin the round-trip and that junk does not become a bad
    timestamp that would then read as a real (wrong) time.
    """
    from datetime import UTC, datetime

    iso = iso_from_epoch(1_700_000_000.5)
    assert iso is not None
    assert datetime.fromisoformat(iso) == datetime.fromtimestamp(1_700_000_000.5, tz=UTC)
    assert iso_from_epoch(None) is None
    assert iso_from_epoch(float("nan")) is None


def test_proxy_export_har_uses_the_captured_request_time(tmp_path: Path) -> None:
    """A flow's real start time must reach the HAR, not the single export instant.

    mitmproxy stamps request.timestamp_start; the recorder keeps it and the
    export passes it as startedDateTime so a HAR viewer orders the waterfall by
    when each request actually began. Without it every entry carried the one
    export time, reading as if the whole capture happened at a single instant.
    The captured epoch also surfaces on proxy.flows as started_at.
    """
    from datetime import UTC, datetime

    recorder = _FlowRecorder()
    epoch = 1_700_000_000.0
    for index in range(3):
        request = SimpleNamespace(
            method="GET",
            pretty_url=f"http://x/{index}",
            host="x",
            timestamp_start=epoch + index,
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]

    flows = backend.flows("s", offset=0, limit=10)
    by_url = {row["url"]: row for row in flows["flows"]}
    assert by_url["http://x/0"]["started_at"] == epoch
    assert by_url["http://x/2"]["started_at"] == epoch + 2

    out = tmp_path / "capture.har"
    backend.export_har("s", out)
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    stamps = {
        entry["request"]["url"]: entry["startedDateTime"]
        for entry in doc["log"]["entries"]
    }
    assert stamps["http://x/0"] == datetime.fromtimestamp(epoch, tz=UTC).isoformat()
    assert stamps["http://x/2"] == datetime.fromtimestamp(epoch + 2, tz=UTC).isoformat()
    # Three flows, three distinct ordered timestamps -- not one shared export time.
    assert len(set(stamps.values())) == 3


def test_har_entry_reports_measured_phases_and_sums_them_as_time() -> None:
    """Measured send/wait/receive replace the -1 sentinels and time is their sum.

    The spec defines time as the sum of the non-negative timing phases, and a
    viewer draws the waterfall bar from it -- so an entry whose capture measured
    the phases must say so instead of shipping a zero-width bar. The comment
    must also stop claiming timings were not captured once they were.
    """
    entry = har_entry(
        method="GET",
        url="http://x/",
        status=200,
        mime_type="text/plain",
        timings_ms={"send": 0.5, "wait": 12.25, "receive": 3.25},
    )
    _assert_valid_har(json.dumps(build_har([entry])))
    assert entry["timings"] == {"send": 0.5, "wait": 12.25, "receive": 3.25}
    assert entry["time"] == 16.0
    assert "timings" not in entry["comment"]

    # A partial measurement (errored flow: request arrived, no response) keeps
    # the unmeasured phases at -1 and sums only what was measured.
    partial = har_entry(
        method="GET",
        url="http://x/",
        status=None,
        mime_type="",
        timings_ms={"send": 2.0},
    )
    assert partial["timings"] == {"send": 2.0, "wait": -1, "receive": -1}
    assert partial["time"] == 2.0


def test_har_entry_rejects_junk_phase_values_instead_of_corrupting_time() -> None:
    """A negative, NaN, or non-numeric phase stays -1 and never reaches the sum.

    time feeds a viewer's waterfall; one NaN phase would make the whole bar NaN
    (and json.dumps would emit the non-standard NaN literal, which strict JSON
    parsers reject), and a negative would shrink the total below the measured
    phases. The guard keeps the -1 "not measured" sentinel for anything that is
    not a finite non-negative number, so the entry stays spec-valid and honest.
    """
    entry = har_entry(
        method="GET",
        url="http://x/",
        status=200,
        mime_type="text/plain",
        timings_ms={"send": -5.0, "wait": float("nan"), "receive": "fast"},
    )
    _assert_valid_har(json.dumps(build_har([entry])))
    assert entry["timings"] == {"send": -1, "wait": -1, "receive": -1}
    assert entry["time"] == 0
    # Nothing was measured, so the comment keeps the full disclaimer.
    assert "timings" in entry["comment"]


def test_proxy_export_har_carries_real_phase_timings(tmp_path: Path) -> None:
    """mitmproxy's four flow timestamps become HAR send/wait/receive and time.

    request.timestamp_start/_end and response.timestamp_start/_end are how
    mitmproxy's own HAR export derives the phases, so the recorder measures the
    same way: send is the request arriving, wait is upstream think time, receive
    is the response body. The row keeps them (surfaced on proxy.flows as
    timings) because the raw flow can be evicted while the summary lives on. An
    errored flow with no response still reports its send phase; the other
    phases stay the spec's -1.
    """
    recorder = _FlowRecorder()
    epoch = 1_700_000_000.0
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://x/ok",
        host="x",
        timestamp_start=epoch,
        timestamp_end=epoch + 0.010,
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "text/plain"},
        timestamp_start=epoch + 0.050,
        timestamp_end=epoch + 0.075,
    )
    recorder.response(SimpleNamespace(id="ok", request=request, response=response))
    failed_request = SimpleNamespace(
        method="GET",
        pretty_url="http://x/refused",
        host="x",
        timestamp_start=epoch + 1.0,
        timestamp_end=epoch + 1.002,
    )
    recorder.error(
        SimpleNamespace(
            id="refused",
            request=failed_request,
            response=None,
            error=SimpleNamespace(msg="connection refused"),
        )
    )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]

    rows = {row["url"]: row for row in backend.flows("s", offset=0, limit=10)["flows"]}
    assert rows["http://x/ok"]["timings"] == {"send": 10.0, "wait": 40.0, "receive": 25.0}
    assert rows["http://x/refused"]["timings"] == {"send": 2.0}

    out = tmp_path / "capture.har"
    backend.export_har("s", out)
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    entries = {e["request"]["url"]: e for e in doc["log"]["entries"]}
    ok = entries["http://x/ok"]
    assert ok["timings"] == {"send": 10.0, "wait": 40.0, "receive": 25.0}
    assert ok["time"] == 75.0
    refused = entries["http://x/refused"]
    assert refused["timings"] == {"send": 2.0, "wait": -1, "receive": -1}
    assert refused["time"] == 2.0


def test_serialize_har_keeps_the_newest_entries_that_fit_the_cap() -> None:
    """Eviction drops the oldest end, so the surviving entries are the newest.

    Callers pass entries oldest-first; keeping the newest that fit matches the
    capture rings (which evict oldest) and is the subset an analyst wants from a
    HAR taken right after an action. This pins that direction, not just the size.
    """
    entries = [
        har_entry(
            method="GET",
            url=f"https://example.com/{'p' * 200}/{index}",
            status=200,
            mime_type="text/html",
        )
        for index in range(200)
    ]
    result = serialize_har(entries, max_bytes=4096)
    assert result.truncated is True
    assert result.size <= 4096
    assert 0 < result.entry_count < 200
    doc = _assert_valid_har(result.text)
    assert len(doc["log"]["entries"]) == result.entry_count
    kept = [int(entry["request"]["url"].rsplit("/", 1)[1]) for entry in doc["log"]["entries"]]
    # The newest index survives and the kept run is the contiguous newest tail.
    assert kept[-1] == 199
    assert kept == list(range(200 - result.entry_count, 200))


def test_serialize_har_leaves_a_small_capture_intact() -> None:
    entries = [har_entry(method="GET", url="https://x/1", status=200, mime_type="text/html")]
    result = serialize_har(entries, max_bytes=64 * 1024 * 1024)
    assert result.truncated is False
    assert result.entry_count == 1


class _WebHandle:
    def __init__(self, count: int) -> None:
        self.lock = Lock()
        self.requests = {
            str(index): {
                "requestId": str(index),
                "url": f"https://example.com/{index}",
                "method": "GET",
                "resourceType": "Document" if index == 0 else "Script",
                "status": 200,
                "mimeType": "text/html",
            }
            for index in range(count)
        }


def test_web_har_export_writes_a_valid_har_that_carries_every_request(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(3))
    out = tmp_path / "capture.har"
    payload = backend.har_export("s", out)
    assert payload["entry_count"] == 3
    assert payload["truncated"] is False
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    urls = {entry["request"]["url"] for entry in doc["log"]["entries"]}
    assert urls == {"https://example.com/0", "https://example.com/1", "https://example.com/2"}
    resource_types = {entry.get("_resourceType") for entry in doc["log"]["entries"]}
    assert resource_types == {"Document", "Script"}


def test_web_har_export_uses_the_captured_request_time(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """CDP's wallTime must reach the web HAR's startedDateTime, like the proxy's.

    requestWillBeSent carries wallTime -- the real epoch the request began --
    and the web capture keeps it as started_at so the export stamps each entry
    with the true time instead of the one export instant. A request the browser
    reported no wallTime for falls back to the export instant, staying spec-valid.
    """
    from datetime import UTC, datetime

    epoch = 1_700_000_000.0

    class _Handle:
        def __init__(self) -> None:
            self.lock = Lock()
            self.requests = {
                "0": {
                    "requestId": "0",
                    "url": "https://example.com/0",
                    "method": "GET",
                    "resourceType": "Document",
                    "status": 200,
                    "mimeType": "text/html",
                    "started_at": epoch,
                },
                "1": {
                    "requestId": "1",
                    "url": "https://example.com/1",
                    "method": "GET",
                    "resourceType": "Script",
                    "status": 200,
                    "mimeType": "text/javascript",
                    "started_at": epoch + 5,
                },
                # No started_at (browser reported no wallTime): export-time fallback.
                "2": {
                    "requestId": "2",
                    "url": "https://example.com/2",
                    "method": "GET",
                    "resourceType": "Script",
                    "status": 200,
                    "mimeType": "text/javascript",
                },
            }

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    out = tmp_path / "capture.har"
    backend.har_export("s", out)
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    stamps = {e["request"]["url"]: e["startedDateTime"] for e in doc["log"]["entries"]}
    assert stamps["https://example.com/0"] == datetime.fromtimestamp(epoch, tz=UTC).isoformat()
    assert (
        stamps["https://example.com/1"]
        == datetime.fromtimestamp(epoch + 5, tz=UTC).isoformat()
    )
    # The row with no wallTime still produced a valid (fallback) instant.
    datetime.fromisoformat(stamps["https://example.com/2"])


def test_cdp_phase_timings_derives_send_and_wait_and_drops_junk() -> None:
    """CDP ResourceTiming offsets become HAR send/wait; -1 or backwards drop out.

    The offsets are ms ticks relative to requestTime, so a difference is already
    a duration -- send is sendEnd-sendStart, wait is receiveHeadersEnd-sendEnd,
    the two phases responseReceived can measure. receive ends at the separate
    loadingFinished event, so this helper never produces it -- the finished
    handler computes it from the anchor _receive_anchor derives. A -1 "not
    applicable" endpoint or a backwards pair must be dropped, not shipped as a
    negative duration that would corrupt the HAR time sum.
    """
    good = _cdp_phase_timings(
        {"sendStart": 1.0, "sendEnd": 3.5, "receiveHeadersEnd": 40.0}
    )
    assert good == {"send": 2.5, "wait": 36.5}
    assert "receive" not in good

    # sendEnd present but receiveHeadersEnd -1 (not applicable): only send.
    assert _cdp_phase_timings(
        {"sendStart": 0.0, "sendEnd": 2.0, "receiveHeadersEnd": -1}
    ) == {"send": 2.0}
    # Backwards pair (receiveHeadersEnd before sendEnd) drops wait, keeps send.
    assert _cdp_phase_timings(
        {"sendStart": 0.0, "sendEnd": 5.0, "receiveHeadersEnd": 3.0}
    ) == {"send": 5.0}
    # No timing object at all (cached response): nothing measured.
    assert _cdp_phase_timings(None) == {}
    assert _cdp_phase_timings({}) == {}


def test_web_har_export_carries_the_measured_phase_timings(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A row's measured phases must reach the HAR entry's timings and time.

    on_response derives send/wait from CDP's response.timing and on_finished
    adds receive from loadingFinished; the export passes whatever the row
    carries to har_entry, which replaces the -1 sentinels and reports time as
    the sum -- the same pipeline the proxy HAR uses from mitmproxy timestamps.
    A row whose loadingFinished never arrived keeps receive -1, and a row with
    no measured phase keeps the historical all -1 / time 0.
    """

    class _Handle:
        def __init__(self) -> None:
            self.lock = Lock()
            self.requests = {
                "0": {
                    "requestId": "0",
                    "url": "https://example.com/timed",
                    "method": "GET",
                    "resourceType": "Document",
                    "status": 200,
                    "mimeType": "text/html",
                    "timings": {"send": 1.5, "wait": 18.0, "receive": 5.25},
                },
                "1": {
                    "requestId": "1",
                    "url": "https://example.com/untimed",
                    "method": "GET",
                    "resourceType": "Script",
                    "status": 200,
                    "mimeType": "text/javascript",
                },
                "2": {
                    "requestId": "2",
                    "url": "https://example.com/unfinished",
                    "method": "GET",
                    "resourceType": "Fetch",
                    "status": 200,
                    "mimeType": "application/json",
                    "timings": {"send": 1.0, "wait": 2.0},
                },
            }

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    out = tmp_path / "capture.har"
    backend.har_export("s", out)
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    entries = {e["request"]["url"]: e for e in doc["log"]["entries"]}
    timed = entries["https://example.com/timed"]
    assert timed["timings"] == {"send": 1.5, "wait": 18.0, "receive": 5.25}
    assert timed["time"] == 24.75
    untimed = entries["https://example.com/untimed"]
    assert untimed["timings"] == {"send": -1, "wait": -1, "receive": -1}
    assert untimed["time"] == 0
    unfinished = entries["https://example.com/unfinished"]
    assert unfinished["timings"] == {"send": 1.0, "wait": 2.0, "receive": -1}
    assert unfinished["time"] == 3.0


def test_web_har_export_is_bounded_by_the_capture_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4096)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(400))
    out = tmp_path / "capture.har"
    payload = backend.har_export("s", out)
    assert payload["truncated"] is True
    assert payload["entry_count"] < 400
    assert out.stat().st_size <= 4096
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    kept = [int(entry["request"]["url"].rsplit("/", 1)[1]) for entry in doc["log"]["entries"]]
    # The oldest requests are dropped; the newest that fit are kept.
    assert kept[-1] == 399
    assert min(kept) > 0


def test_web_har_export_refuses_when_even_an_empty_har_exceeds_the_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(1))
    with pytest.raises(WebError) as info:
        backend.har_export("s", tmp_path / "capture.har")
    assert info.value.code == "too_large"


def _proxy_backend_with_flows(count: int, *, url_pad: int = 0, body_len: int = 0) -> ProxyBackend:
    recorder = _FlowRecorder()
    for index in range(count):
        request = SimpleNamespace(
            method="GET",
            pretty_url=f"http://x/{'q' * url_pad}/{index}",
            host="x",
        )
        response = SimpleNamespace(
            status_code=200,
            headers={"content-type": "text/plain"},
            raw_content=b"x" * body_len if body_len else None,
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]
    return backend


def test_proxy_export_har_writes_a_valid_har(tmp_path: Path) -> None:
    backend = _proxy_backend_with_flows(4)
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["entry_count"] == 4
    assert payload["truncated"] is False
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    assert len(doc["log"]["entries"]) == 4


def test_proxy_export_har_carries_the_captured_response_body_size(tmp_path: Path) -> None:
    """The proxy knows each decoded body length; the HAR must report it.

    The recorder computes the response body length when the flow arrives, even
    for a flow whose body is later dropped from the retain ring, so the export
    can fill content.size and bodySize with a real number instead of -1. The
    same number surfaces on proxy.flows as response_size.
    """
    backend = _proxy_backend_with_flows(3, body_len=512)
    flows = backend.flows("s", offset=0, limit=10)
    assert all(row["response_size"] == 512 for row in flows["flows"])
    out = tmp_path / "capture.har"
    backend.export_har("s", out)
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    for entry in doc["log"]["entries"]:
        assert entry["response"]["content"]["size"] == 512
        assert entry["response"]["bodySize"] == 512


def test_proxy_export_har_is_now_bounded_by_the_capture_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Regression: proxy.export_har wrote the whole ring with no size ceiling.

    An overnight capture of thousands of flows dropped an unbounded artifact
    into the session directory that retention never budgeted for. It must now
    truncate to fit the cap like web.har.export already did.
    """
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4096)
    backend = _proxy_backend_with_flows(400, url_pad=120)
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["truncated"] is True
    assert payload["entry_count"] < 400
    assert out.stat().st_size <= 4096
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    kept = [int(entry["request"]["url"].rsplit("/", 1)[1]) for entry in doc["log"]["entries"]]
    # The oldest flows are dropped; the newest that fit are kept.
    assert kept[-1] == 399
    assert min(kept) > 0


def test_proxy_export_har_refuses_when_even_an_empty_har_exceeds_the_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    backend = _proxy_backend_with_flows(1)
    with pytest.raises(ProxyError) as info:
        backend.export_har("s", tmp_path / "capture.har")
    assert info.value.code == "too_large"
