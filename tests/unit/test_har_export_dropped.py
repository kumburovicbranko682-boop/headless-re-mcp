"""HAR export must disclose flows/requests the capture ring evicted.

Both proxy.export_har and web.har.export build the HAR from a bounded capture
ring. When the ring has already evicted older rows, the file holds only the tail
of the session. Reported without a count, a HAR with entry_count entries reads
as the whole capture, and a caller replays it believing nothing earlier existed.
``dropped`` says how many rows were lost before the export ran; it is a separate
axis from ``truncated`` (entries dropped to fit the export size cap).
"""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder
from headless_re_mcp.backends.web.client import WebBackend


class _WebHandle:
    def __init__(self, *, dropped: int) -> None:
        self.lock = Lock()
        self.requests_dropped = dropped
        self.requests = {
            "1": {
                "method": "GET",
                "url": "https://x/1",
                "status": 200,
                "mimeType": "text/plain",
                "resourceType": "XHR",
            }
        }


def _record_flows(recorder: _FlowRecorder, count: int) -> None:
    for index in range(count):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )


def test_web_har_export_reports_dropped_and_notes_the_gap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(dropped=7))
    payload = backend.har_export("s", tmp_path / "c.har")
    assert payload["dropped"] == 7
    assert "note" in payload
    assert "evicted" in payload["note"]
    assert (tmp_path / "c.har").is_file()


def test_web_har_export_omits_the_note_when_nothing_was_evicted(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(dropped=0))
    payload = backend.har_export("s", tmp_path / "c.har")
    assert payload["dropped"] == 0
    assert "note" not in payload


def test_proxy_export_har_reports_dropped_and_notes_the_gap(
    tmp_path: Path,
) -> None:
    recorder = _FlowRecorder(capacity=5)
    _record_flows(recorder, 12)
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.export_har("s", tmp_path / "capture.har")
    assert payload["entry_count"] == 5
    assert payload["dropped"] == 7
    assert "note" in payload
    assert "evicted" in payload["note"]
    assert (tmp_path / "capture.har").is_file()


def test_proxy_export_har_omits_the_note_when_ring_never_filled(
    tmp_path: Path,
) -> None:
    recorder = _FlowRecorder(capacity=2000)
    _record_flows(recorder, 4)
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.export_har("s", tmp_path / "capture.har")
    assert payload["entry_count"] == 4
    assert payload["dropped"] == 0
    assert "note" not in payload
