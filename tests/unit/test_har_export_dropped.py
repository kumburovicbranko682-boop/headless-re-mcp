"""Both HAR exporters disclose ring eviction (dropped), not just cap truncation.

The web request ring and the proxy flow ring are count-capped, so a session
busier than the cap loses its earliest rows before an export ever runs -- the
file then holds only the newest tail. web.network.list and proxy.flows already
report that loss as ``dropped``; the HAR exporters used to omit it, so an export
of ``entry_count`` entries read as the whole session and a caller replayed a
truncated capture as if nothing earlier had happened. These pin ``dropped`` (and
its explanatory ``note``) onto both exports, and pin that a lossless capture
still reports ``dropped == 0`` with no note. ``dropped`` (evicted while
capturing) and ``truncated`` (entries shed to fit the export cap) are
independent axes that both surface here.
"""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend
from headless_re_mcp.backends.web.client import WebBackend


class _WebHandle:
    def __init__(self, count: int, *, dropped: int) -> None:
        self.lock = Lock()
        self.requests_dropped = dropped
        self.requests = {
            str(index): {
                "requestId": str(index),
                "url": f"https://example.com/{index}",
                "method": "GET",
                "resourceType": "Script",
                "status": 200,
                "mimeType": "text/html",
            }
            for index in range(count)
        }


class _FakeRecorder:
    """Snapshot of flow summaries with a monotonic seq that outruns len.

    ``seq`` is the recorder's per-response counter; the newest slot's seq minus
    the rows still held is how many earlier flows the count-capped ring evicted,
    which is exactly how proxy.flows derives dropped.
    """

    def __init__(self, count: int, *, first_seq: int) -> None:
        self._entries = [
            {
                "seq": first_seq + index,
                "method": "GET",
                "url": f"http://x/{first_seq + index}",
                "status": 200,
                "content_type": "text/plain",
                "response_size": 0,
            }
            for index in range(count)
        ]

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._entries)


def _proxy_backend(count: int, *, first_seq: int) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = _FakeRecorder(count, first_seq=first_seq)
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]
    return backend


def test_web_har_export_reports_zero_dropped_and_no_note_for_a_lossless_capture(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(3, dropped=0))
    payload = backend.har_export("s", tmp_path / "c.har")
    assert payload["entry_count"] == 3
    assert payload["dropped"] == 0
    assert "note" not in payload


def test_web_har_export_discloses_requests_the_ring_evicted(
    tmp_path: Path, monkeypatch: Any
) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _WebHandle(3, dropped=41))
    payload = backend.har_export("s", tmp_path / "c.har")
    # The file holds the surviving tail; dropped says the earliest are gone.
    assert payload["entry_count"] == 3
    assert payload["dropped"] == 41
    assert "missing the earliest requests" in payload["note"]


def test_proxy_export_har_reports_zero_dropped_and_no_note_for_a_lossless_capture(
    tmp_path: Path,
) -> None:
    # seq starts at 1, so the newest seq equals the row count: nothing evicted.
    backend = _proxy_backend(4, first_seq=1)
    payload = backend.export_har("s", tmp_path / "c.har")
    assert payload["entry_count"] == 4
    assert payload["dropped"] == 0
    assert "note" not in payload


def test_proxy_export_har_discloses_flows_the_ring_evicted(tmp_path: Path) -> None:
    # Three rows whose newest seq is 102 => 99 earlier flows fell out of the ring.
    backend = _proxy_backend(3, first_seq=100)
    payload = backend.export_har("s", tmp_path / "c.har")
    assert payload["entry_count"] == 3
    assert payload["dropped"] == 99
    assert "missing the earliest flows" in payload["note"]


def test_proxy_export_har_on_an_empty_capture_reports_zero_dropped(tmp_path: Path) -> None:
    backend = _proxy_backend(0, first_seq=1)
    payload = backend.export_har("s", tmp_path / "c.har")
    assert payload["entry_count"] == 0
    assert payload["dropped"] == 0
    assert "note" not in payload
