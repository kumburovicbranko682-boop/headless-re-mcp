"""The HAR export shared by the Web and proxy capture lines must stay bounded.

Both surfaces write their HAR into the session artifact tree, where
``_register_capture`` reads the whole file back to hash it. A capture ring
holds thousands of flows, each summary carrying a URL up to 16 KiB, so an
unbounded export is the overnight OOM the count caps were meant to prevent --
first on write, then again on the hash read. These pin: the serializer stays
at or below the cap, it drops the oldest flows and keeps the newest, and both
backends report ``truncated`` and ``size`` so a partial export is never read
as the whole capture.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.common.har import build_bounded_har


def _entries(count: int) -> list[dict[str, object]]:
    return [
        {
            "request": {"method": "GET", "url": f"http://host/{index:05d}"},
            "response": {"status": 200, "content": {"mimeType": "text/plain"}},
        }
        for index in range(count)
    ]


def test_bounded_har_keeps_everything_under_the_cap() -> None:
    text, count, truncated, size = build_bounded_har(_entries(5), max_bytes=1_000_000)
    assert count == 5
    assert truncated is False
    assert size == len(text.encode("utf-8"))
    doc = json.loads(text)
    assert doc["log"]["version"] == "1.2"
    assert len(doc["log"]["entries"]) == 5


def test_bounded_har_drops_oldest_and_keeps_newest_over_the_cap() -> None:
    text, count, truncated, size = build_bounded_har(_entries(200), max_bytes=2000)
    assert truncated is True
    assert size <= 2000
    assert size == len(text.encode("utf-8"))
    assert 0 < count < 200
    urls = [entry["request"]["url"] for entry in json.loads(text)["log"]["entries"]]
    # The surviving flows are a contiguous newest suffix: oldest gone, newest kept.
    assert urls == [f"http://host/{index:05d}" for index in range(200 - count, 200)]
    assert "http://host/00199" in urls
    assert "http://host/00000" not in urls


def test_bounded_har_empty_log_is_valid_and_not_truncated() -> None:
    text, count, truncated, size = build_bounded_har([], max_bytes=1_000_000)
    assert count == 0
    assert truncated is False
    assert size == len(text.encode("utf-8"))
    assert json.loads(text)["log"]["entries"] == []


def test_proxy_export_har_is_bounded_and_reports_truncation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from headless_re_mcp.backends.proxy import client as proxy_mod
    from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder

    monkeypatch.setattr(proxy_mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 2000)
    recorder = _FlowRecorder()
    for index in range(200):
        request = SimpleNamespace(method="GET", pretty_url=f"http://host/{index:05d}", host="host")
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
        recorder.response(SimpleNamespace(id=str(index), request=request, response=response))
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["truncated"] is True
    assert payload["size"] <= 2000
    assert out.stat().st_size <= 2000
    assert 0 < payload["entry_count"] < 200
    urls = [entry["request"]["url"] for entry in json.loads(out.read_text())["log"]["entries"]]
    assert "http://host/00199" in urls
    assert "http://host/00000" not in urls


def test_web_har_export_is_bounded_and_reports_truncation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from headless_re_mcp.backends.web import client as web_mod
    from headless_re_mcp.backends.web.client import WebBackend

    monkeypatch.setattr(web_mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 2000)
    requests: OrderedDict[str, dict[str, object]] = OrderedDict()
    for index in range(200):
        requests[str(index)] = {
            "method": "GET",
            "url": f"http://host/{index:05d}",
            "status": 200,
            "mimeType": "text/plain",
            "resourceType": "XHR",
        }
    handle = SimpleNamespace(requests=requests, lock=Lock())
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    out = tmp_path / "c.har"
    payload = backend.har_export("s", out)
    assert payload["truncated"] is True
    assert payload["size"] <= 2000
    assert out.stat().st_size <= 2000
    assert 0 < payload["entry_count"] < 200
    urls = [entry["request"]["url"] for entry in json.loads(out.read_text())["log"]["entries"]]
    assert "http://host/00199" in urls
    assert "http://host/00000" not in urls
