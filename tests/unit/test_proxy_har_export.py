"""proxy.export_har must write a complete HAR 1.2: headers, bodies, timings.

The old export was a request line and a status -- useless to any HAR consumer.
These drive ProxyBackend.export_har with fake retained flows and assert the file
on disk carries the fields that make a HAR a HAR.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import _OMITTED_BODY, ProxyBackend


def _flow(
    *,
    method: str,
    url: str,
    req_headers: dict[str, str],
    req_body: bytes,
    status: int,
    resp_headers: dict[str, str],
    resp_body: bytes,
    t0: float = 1000.0,
    t1: float = 1000.25,
) -> Any:
    request = SimpleNamespace(
        method=method,
        pretty_url=url,
        http_version="HTTP/1.1",
        headers=req_headers,
        raw_content=req_body,
        timestamp_start=t0,
    )
    response = SimpleNamespace(
        status_code=status,
        reason="OK",
        http_version="HTTP/1.1",
        headers=resp_headers,
        raw_content=resp_body,
        timestamp_end=t1,
    )
    return SimpleNamespace(request=request, response=response)


class _Recorder:
    def __init__(self, summaries: list[dict[str, Any]], raws: dict[str, Any]) -> None:
        self._summaries = summaries
        self._raws = raws

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._summaries)

    def raw(self, flow_id: str) -> Any:
        return self._raws.get(flow_id)


def _export(
    recorder: _Recorder, tmp_path: Path, monkeypatch: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    out = tmp_path / "capture.har"
    result = backend.export_har("s", out)
    har = json.loads(out.read_text(encoding="utf-8"))
    return result, har


def test_har_includes_headers_bodies_and_timings(tmp_path: Path, monkeypatch: Any) -> None:
    flow = _flow(
        method="GET",
        url="http://api.test/v1/thing",
        req_headers={"user-agent": "gate/1.0", "accept": "application/json"},
        req_body=b"",
        status=200,
        resp_headers={"content-type": "application/json"},
        resp_body=b'{"ok":true}',
    )
    recorder = _Recorder(
        [{"id": "f1", "method": "GET", "url": "http://api.test/v1/thing", "status": 200}],
        {"f1": flow},
    )
    result, har = _export(recorder, tmp_path, monkeypatch)
    assert result["entry_count"] == 1
    log = har["log"]
    assert log["version"] == "1.2"
    entry = log["entries"][0]
    # Request line + headers survived, keyed the HAR way.
    req = entry["request"]
    assert req["method"] == "GET"
    assert req["httpVersion"] == "HTTP/1.1"
    header_names = {h["name"]: h["value"] for h in req["headers"]}
    assert header_names["user-agent"] == "gate/1.0"
    # Response body inlined as text with its real mime and size.
    resp = entry["response"]
    assert resp["status"] == 200
    assert resp["statusText"] == "OK"
    assert resp["content"]["text"] == '{"ok":true}'
    assert resp["content"]["size"] == len(b'{"ok":true}')
    assert resp["content"]["mimeType"] == "application/json"
    resp_header_names = {h["name"] for h in resp["headers"]}
    assert "content-type" in resp_header_names
    # Timings sum to time, and startedDateTime is a real ISO-8601 instant.
    assert entry["time"] == 250.0
    assert entry["timings"]["receive"] == 250.0
    assert entry["startedDateTime"].startswith("1970-01-01T00:16:40")
    # HAR-required structural fields are present.
    assert entry["cache"] == {}
    assert req["cookies"] == [] and resp["cookies"] == []
    assert req["headersSize"] == -1 and resp["headersSize"] == -1


def test_har_carries_post_body_and_base64s_binary(tmp_path: Path, monkeypatch: Any) -> None:
    png = b"\x89PNG\r\n\x1a\n\x00\x01\x02\x03"
    flow = _flow(
        method="POST",
        url="http://api.test/upload",
        req_headers={"content-type": "application/json"},
        req_body=b'{"user":"admin"}',
        status=200,
        resp_headers={"content-type": "image/png"},
        resp_body=png,
    )
    recorder = _Recorder(
        [{"id": "f1", "method": "POST", "url": "http://api.test/upload"}], {"f1": flow}
    )
    _result, har = _export(recorder, tmp_path, monkeypatch)
    entry = har["log"]["entries"][0]
    post = entry["request"]["postData"]
    assert post["text"] == '{"user":"admin"}'
    assert post["mimeType"] == "application/json"
    assert entry["request"]["bodySize"] == len(b'{"user":"admin"}')
    content = entry["response"]["content"]
    # A binary response body base64s with content.encoding "base64" and decodes back.
    assert content["encoding"] == "base64"
    assert base64.b64decode(content["text"]) == png
    assert content["size"] == len(png)
    assert entry["response"]["bodySize"] == len(png)


def test_har_parses_query_string(tmp_path: Path, monkeypatch: Any) -> None:
    flow = _flow(
        method="GET",
        url="http://api.test/search?q=cat&page=2",
        req_headers={},
        req_body=b"",
        status=200,
        resp_headers={},
        resp_body=b"",
    )
    recorder = _Recorder([{"id": "f1"}], {"f1": flow})
    _result, har = _export(recorder, tmp_path, monkeypatch)
    query = {q["name"]: q["value"] for q in har["log"]["entries"][0]["request"]["queryString"]}
    assert query == {"q": "cat", "page": "2"}


def test_har_lean_entry_when_body_not_retained(tmp_path: Path, monkeypatch: Any) -> None:
    # One flow whose body was evicted (_OMITTED_BODY) and one never retained (None).
    recorder = _Recorder(
        [
            {
                "id": "f1",
                "method": "GET",
                "url": "http://x/a",
                "status": 204,
                "content_type": "text/plain",
            },
            {"id": "f2", "method": "POST", "url": "http://x/b", "status": 500},
        ],
        {"f1": _OMITTED_BODY},
    )
    result, har = _export(recorder, tmp_path, monkeypatch)
    # No captured flow is dropped: both still export as valid, lean entries.
    assert result["entry_count"] == 2
    entries = har["log"]["entries"]
    for entry in entries:
        assert entry["request"]["headers"] == []
        assert entry["request"]["bodySize"] == -1
        assert "not retained" in entry["comment"]
    assert entries[0]["request"]["method"] == "GET"
    assert entries[0]["response"]["status"] == 204
    assert entries[0]["response"]["content"]["mimeType"] == "text/plain"
    assert entries[1]["response"]["status"] == 500
