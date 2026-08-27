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

import pytest

from headless_re_mcp.backends.common.har import build_har, har_entry, serialize_har
from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _FlowRecorder
from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import WebBackend, WebError

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


def test_har_entry_carries_measured_phase_timings_and_sums_time() -> None:
    """Measured send/wait/receive fill timings and time is their sum.

    HAR's time is defined as the sum of the non-negative timing phases, so a
    consumer draws a waterfall of the right total width from a real capture
    instead of the flat 0 the export used to emit.
    """
    entry = har_entry(
        method="GET",
        url="https://x/1",
        status=200,
        mime_type="application/json",
        started_date_time="2020-01-02T03:04:05+00:00",
        timings={"send": 12.5, "wait": 40.0, "receive": 7.5},
    )
    _assert_valid_har(json.dumps(build_har([entry])))
    assert entry["timings"] == {"send": 12.5, "wait": 40.0, "receive": 7.5}
    assert entry["time"] == pytest.approx(60.0)
    # The caller supplied the instant, so it is used verbatim, not export time.
    assert entry["startedDateTime"] == "2020-01-02T03:04:05+00:00"
    # The comment no longer claims phase timings were absent.
    assert "phase timings" not in entry["comment"]
    assert "headers and bodies were not captured" in entry["comment"]


def test_har_entry_time_excludes_unmeasured_phases() -> None:
    """An errored flow has no response phases; time counts only what was measured.

    A phase the capture could not measure is the spec's -1 sentinel, and time is
    the sum of the non-negative phases only -- here just send. A -1 is never
    added into time (which would understate or corrupt the total), and the entry
    stays spec-valid.
    """
    entry = har_entry(
        method="GET",
        url="https://x/err",
        status=None,
        mime_type="",
        timings={"send": 8.0, "wait": None, "receive": -1},
    )
    _assert_valid_har(json.dumps(build_har([entry])))
    assert entry["timings"] == {"send": 8.0, "wait": -1, "receive": -1}
    assert entry["time"] == pytest.approx(8.0)


def test_har_entry_without_timings_stays_all_unknown() -> None:
    """No measured timings: every phase is -1, time is 0, comment says so.

    This is the web capture's shape (it records which flows happened, not phase
    durations) and any flow whose timestamps were missing. It must not fabricate
    a zero-length phase, which a consumer reads as a real measurement of 0.
    """
    entry = har_entry(method="GET", url="https://x/1", status=200, mime_type="")
    assert entry["timings"] == {"send": -1, "wait": -1, "receive": -1}
    assert entry["time"] == 0
    assert "phase timings were not captured" in entry["comment"]
    # An empty dict is treated the same as no measurement at all.
    empty = har_entry(method="GET", url="https://x/1", status=200, mime_type="", timings={})
    assert empty["timings"] == {"send": -1, "wait": -1, "receive": -1}
    assert empty["time"] == 0


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


def _record_timed_flow(
    recorder: _FlowRecorder,
    flow_id: str,
    *,
    req_start: float | None,
    req_end: float | None,
    resp_start: float | None,
    resp_end: float | None,
    with_response: bool = True,
) -> None:
    """Feed the recorder one flow carrying mitmproxy-style per-end timestamps."""
    request = SimpleNamespace(
        method="GET",
        pretty_url=f"http://x/{flow_id}",
        host="x",
        timestamp_start=req_start,
        timestamp_end=req_end,
    )
    response = (
        SimpleNamespace(
            status_code=200,
            headers={"content-type": "text/plain"},
            raw_content=None,
            timestamp_start=resp_start,
            timestamp_end=resp_end,
        )
        if with_response
        else None
    )
    recorder.response(SimpleNamespace(id=flow_id, request=request, response=response))


def test_proxy_records_real_timing_and_export_stamps_the_request_instant(
    tmp_path: Path,
) -> None:
    """The proxy keeps mitmproxy's timestamps; the HAR carries them, not now().

    mitmproxy stamps each end of the exchange, so the recorder can derive the
    flow's real start and its send/wait/receive phases. proxy.flows surfaces
    started_at and timings, and the HAR entry stamps startedDateTime at the
    request instant with time the sum of the phases -- instead of the old
    behaviour, which stamped every entry at export time with a flat-zero
    waterfall.
    """
    from datetime import UTC, datetime

    recorder = _FlowRecorder()
    # send = 20 ms, wait = 50 ms, receive = 15 ms -> time = 85 ms.
    _record_timed_flow(
        recorder,
        "f0",
        req_start=1000.0,
        req_end=1000.02,
        resp_start=1000.07,
        resp_end=1000.085,
    )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]

    expected_started = datetime.fromtimestamp(1000.0, UTC).isoformat()
    row = backend.flows("s", offset=0, limit=10)["flows"][0]
    assert row["started_at"] == expected_started
    assert row["timings"]["send"] == pytest.approx(20.0, abs=0.001)
    assert row["timings"]["wait"] == pytest.approx(50.0, abs=0.001)
    assert row["timings"]["receive"] == pytest.approx(15.0, abs=0.001)

    out = tmp_path / "capture.har"
    backend.export_har("s", out)
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    entry = doc["log"]["entries"][0]
    assert entry["startedDateTime"] == expected_started
    assert entry["timings"]["send"] == pytest.approx(20.0, abs=0.001)
    assert entry["timings"]["wait"] == pytest.approx(50.0, abs=0.001)
    assert entry["timings"]["receive"] == pytest.approx(15.0, abs=0.001)
    assert entry["time"] == pytest.approx(85.0, abs=0.01)


def test_proxy_errored_flow_keeps_the_start_and_leaves_response_phases_unknown(
    tmp_path: Path,
) -> None:
    """A flow with no response: start and send are known, wait/receive are -1.

    An errored flow (upstream unreachable, reset mid-request) never produced a
    response, so only the request timestamps exist. The export must still stamp
    the real start and the measurable send phase, and report wait/receive as the
    -1 "not measured" sentinel rather than a fabricated zero -- with time the
    sum of just the measured phase.
    """
    from datetime import UTC, datetime

    recorder = _FlowRecorder()
    _record_timed_flow(
        recorder,
        "err",
        req_start=2000.0,
        req_end=2000.03,
        resp_start=None,
        resp_end=None,
        with_response=False,
    )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]

    row = backend.flows("s", offset=0, limit=10)["flows"][0]
    assert row["started_at"] == datetime.fromtimestamp(2000.0, UTC).isoformat()
    assert row["timings"] == {"send": pytest.approx(30.0, abs=0.001), "wait": -1, "receive": -1}

    out = tmp_path / "capture.har"
    backend.export_har("s", out)
    entry = _assert_valid_har(out.read_text(encoding="utf-8"))["log"]["entries"][0]
    assert entry["timings"]["send"] == pytest.approx(30.0, abs=0.001)
    assert entry["timings"]["wait"] == -1
    assert entry["timings"]["receive"] == -1
    assert entry["time"] == pytest.approx(30.0, abs=0.001)


def test_proxy_flow_without_timestamps_omits_timing_and_export_falls_back(
    tmp_path: Path,
) -> None:
    """A flow mitmproxy left untimed carries no started_at/timings on the row.

    Not every flow gets timestamps (some replayed or synthetic flows do not), so
    the summary must not invent them: the row omits started_at and timings, and
    the HAR export falls back to unknown timings and an export-time stamp rather
    than crashing or fabricating a phase.
    """
    recorder = _FlowRecorder()
    _record_timed_flow(
        recorder,
        "bare",
        req_start=None,
        req_end=None,
        resp_start=None,
        resp_end=None,
    )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]
    row = backend.flows("s", offset=0, limit=10)["flows"][0]
    assert "started_at" not in row
    assert "timings" not in row
    out = tmp_path / "capture.har"
    backend.export_har("s", out)
    entry = _assert_valid_har(out.read_text(encoding="utf-8"))["log"]["entries"][0]
    assert entry["timings"] == {"send": -1, "wait": -1, "receive": -1}
    assert entry["time"] == 0


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
