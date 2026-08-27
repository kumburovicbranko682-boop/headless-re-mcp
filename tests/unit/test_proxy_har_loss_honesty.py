"""proxy.export_har must bound the file and own up to what it left out.

The mitmproxy-side HAR export used to write whatever the ring held with no
size cap, and reported only entry_count -- so it could drop tens of megabytes
onto disk before retention ran, and never disclosed the flows the capture ring
had already evicted. These tests pin parity with web.har.export: a bounded file
plus total / truncated / dropped.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import headless_re_mcp.backends.proxy.client as proxy_client
from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder


def _feed(recorder: _FlowRecorder, count: int, *, url_len: int = 8) -> None:
    for index in range(count):
        request = SimpleNamespace(
            method="GET",
            pretty_url="http://x/" + str(index).rjust(url_len, "0"),
            host="x",
        )
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )


def _backend_with(recorder: _FlowRecorder) -> ProxyBackend:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]
    return backend


def test_ring_evictions_surface_as_dropped(tmp_path: Path) -> None:
    """A ring smaller than the traffic evicts flows; the export says how many."""
    recorder = _FlowRecorder(capacity=3)
    _feed(recorder, 5)
    payload = _backend_with(recorder).export_har("s", tmp_path / "c.har")
    assert payload["total"] == 3
    assert payload["entry_count"] == 3
    assert payload["truncated"] is False
    assert payload["dropped"] == 2
    log = json.loads((tmp_path / "c.har").read_text(encoding="utf-8"))
    assert len(log["log"]["entries"]) == 3


def test_over_cap_entries_are_dropped_from_the_tail_and_quantified(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """total stays the retained count; entry_count falls below it; truncated says so."""
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 2000)
    recorder = _FlowRecorder(capacity=64)
    _feed(recorder, 40, url_len=300)
    out = tmp_path / "c.har"
    payload = _backend_with(recorder).export_har("s", out)
    assert payload["truncated"] is True
    assert payload["total"] == 40
    assert 0 < payload["entry_count"] < 40
    assert payload["size"] <= 2000
    log = json.loads(out.read_text(encoding="utf-8"))
    assert len(log["log"]["entries"]) == payload["entry_count"]


def test_a_single_entry_too_big_to_fit_yields_an_empty_but_marked_har(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """One entry that alone blows the cap is dropped, and the export owns up."""
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 200)
    recorder = _FlowRecorder(capacity=8)
    _feed(recorder, 1, url_len=400)
    out = tmp_path / "c.har"
    payload = _backend_with(recorder).export_har("s", out)
    assert payload["total"] == 1
    assert payload["entry_count"] == 0
    assert payload["truncated"] is True
    log = json.loads(out.read_text(encoding="utf-8"))
    assert log["log"]["entries"] == []


def test_flows_and_export_agree_on_dropped(tmp_path: Path) -> None:
    """The two views share one eviction count so they can never contradict."""
    recorder = _FlowRecorder(capacity=3)
    _feed(recorder, 7)
    backend = _backend_with(recorder)
    listed = backend.flows("s")
    exported = backend.export_har("s", tmp_path / "c.har")
    assert listed["dropped"] == exported["dropped"] == 4
