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
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.har import build_har, har_entry, serialize_har
from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    ProxyBackend,
    ProxyError,
    _flow_start_time,
    _FlowRecorder,
    _iso_from_epoch,
)
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


def _flow_with_start(index: int, ts: float | None) -> Any:
    request = SimpleNamespace(method="GET", pretty_url=f"http://x/{index}", host="x")
    if ts is not None:
        request.timestamp_start = ts
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=None
    )
    return SimpleNamespace(id=str(index), request=request, response=response)


def test_iso_from_epoch_converts_and_rejects_unusable_values() -> None:
    epoch = 1_700_000_000.5
    assert _iso_from_epoch(epoch) == datetime.fromtimestamp(epoch, tz=UTC).isoformat()
    assert _iso_from_epoch(None) is None
    assert _iso_from_epoch(0) is None
    assert _iso_from_epoch(-1) is None
    assert _iso_from_epoch(True) is None
    assert _iso_from_epoch("2026") is None
    assert _iso_from_epoch(10**30) is None


def test_flow_start_time_reads_timestamp_start_and_rejects_bad() -> None:
    assert _flow_start_time(SimpleNamespace(timestamp_start=1_700_000_000.0)) == 1_700_000_000.0
    assert _flow_start_time(SimpleNamespace()) is None
    assert _flow_start_time(SimpleNamespace(timestamp_start=0)) is None
    assert _flow_start_time(SimpleNamespace(timestamp_start=True)) is None


def test_proxy_export_har_stamps_entries_with_the_flow_start_time(tmp_path: Path) -> None:
    """The HAR must carry each flow's real request start, not the export time.

    Without it har_entry stamps every entry with the export instant, so an
    overnight capture reads as though all traffic happened at once -- the
    ordering and spacing a HAR exists to show are lost.
    """
    recorder = _FlowRecorder()
    recorder.response(_flow_with_start(0, 1_700_000_000.0))
    recorder.response(_flow_with_start(1, 1_700_000_050.5))
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]

    out = tmp_path / "capture.har"
    backend.export_har("s", out)

    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    by_url = {e["request"]["url"]: e["startedDateTime"] for e in doc["log"]["entries"]}
    assert by_url["http://x/0"] == _iso_from_epoch(1_700_000_000.0)
    assert by_url["http://x/1"] == _iso_from_epoch(1_700_000_050.5)
    assert by_url["http://x/0"] != by_url["http://x/1"]


def test_proxy_export_har_falls_back_to_export_time_without_a_start(
    tmp_path: Path,
) -> None:
    """A flow lacking timestamp_start still gets a valid, recent instant."""
    backend = _proxy_backend_with_flows(2)  # this helper sets no timestamp_start
    before = datetime.now(UTC)
    out = tmp_path / "capture.har"
    backend.export_har("s", out)
    after = datetime.now(UTC)
    doc = _assert_valid_har(out.read_text(encoding="utf-8"))
    for entry in doc["log"]["entries"]:
        stamped = datetime.fromisoformat(entry["startedDateTime"])
        assert before <= stamped <= after


def test_recorder_flow_times_map_is_bounded_to_the_ring_capacity() -> None:
    """The parallel time map must not outgrow the summary ring it shadows."""
    recorder = _FlowRecorder(capacity=3)
    for index in range(6):
        recorder.response(_flow_with_start(index, 1_700_000_000.0 + index))
    times = recorder.flow_times()
    assert len(times) == 3
    assert set(times) == {"3", "4", "5"}
    assert times["5"] == 1_700_000_005.0
    # And the timestamp never leaked into the flow summaries (proxy.flows).
    for row in recorder.snapshot():
        assert "started" not in row
        assert "timestamp_start" not in row
