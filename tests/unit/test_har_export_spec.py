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
    assert "_resourceType" not in entry


def test_serialize_har_drops_newest_entries_until_it_fits_the_cap() -> None:
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
    _assert_valid_har(out.read_text(encoding="utf-8"))


def test_web_har_export_refuses_when_even_an_empty_har_exceeds_the_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(1))
    with pytest.raises(WebError) as info:
        backend.har_export("s", tmp_path / "capture.har")
    assert info.value.code == "too_large"


def _proxy_backend_with_flows(count: int, *, url_pad: int = 0) -> ProxyBackend:
    recorder = _FlowRecorder()
    for index in range(count):
        request = SimpleNamespace(
            method="GET",
            pretty_url=f"http://x/{'q' * url_pad}/{index}",
            host="x",
        )
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
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
    _assert_valid_har(out.read_text(encoding="utf-8"))


def test_proxy_export_har_refuses_when_even_an_empty_har_exceeds_the_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    backend = _proxy_backend_with_flows(1)
    with pytest.raises(ProxyError) as info:
        backend.export_har("s", tmp_path / "capture.har")
    assert info.value.code == "too_large"
