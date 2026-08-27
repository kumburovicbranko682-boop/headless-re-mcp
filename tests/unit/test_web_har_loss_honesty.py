"""web.har.export must own up to both ways entries go missing.

A HAR loses entries two independent ways: the capture ring evicts requests
while the page runs (surfaced by web.network.list as ``dropped``), and the
exporter itself drops entries from the tail when the serialized file would
exceed the capture cap. The pre-fix payload reported only ``entry_count`` and
a ``truncated`` boolean, so an agent could read the file as "the whole capture
minus a nibble" when in truth most of it never made the ring. These tests pin
``total`` (retained and available), ``dropped`` (ring evictions), and the
quantified tail loss.
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any

import headless_re_mcp.backends.web.client as web_client
from headless_re_mcp.backends.web.client import WebBackend


class _Handle:
    def __init__(self, requests: dict[str, dict[str, Any]], *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.requests = requests
        self.requests_dropped = dropped


def _entry(i: int, *, url_len: int = 8) -> dict[str, Any]:
    return {
        "method": "GET",
        "url": "https://x/" + str(i).rjust(url_len, "0"),
        "status": 200,
        "mimeType": "text/plain",
        "resourceType": "XHR",
    }


def _export(backend: WebBackend, handle: _Handle, out: Path) -> dict[str, Any]:
    backend._get = lambda session_id: handle  # type: ignore[assignment,method-assign]
    return backend.har_export("s", out)


def test_a_small_capture_is_reported_as_the_whole_thing(tmp_path: Path) -> None:
    handle = _Handle({str(i): _entry(i) for i in range(3)})
    payload = _export(WebBackend(), handle, tmp_path / "c.har")
    assert payload["entry_count"] == 3
    assert payload["total"] == 3
    assert payload["truncated"] is False
    assert payload["dropped"] == 0
    # The file on disk holds exactly what was reported.
    log = json.loads((tmp_path / "c.har").read_text(encoding="utf-8"))
    assert len(log["log"]["entries"]) == 3


def test_ring_evictions_surface_as_dropped_even_when_nothing_is_truncated(
    tmp_path: Path,
) -> None:
    """dropped is a distinct loss from truncated: the ring shed rows before export."""
    handle = _Handle({str(i): _entry(i) for i in range(2)}, dropped=17)
    payload = _export(WebBackend(), handle, tmp_path / "c.har")
    assert payload["dropped"] == 17
    assert payload["truncated"] is False
    assert payload["entry_count"] == payload["total"] == 2


def test_over_cap_entries_are_dropped_from_the_tail_and_quantified(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """total stays the retained count; entry_count falls below it; truncated says so."""
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 2000)
    handle = _Handle({str(i): _entry(i, url_len=200) for i in range(40)})
    out = tmp_path / "c.har"
    payload = _export(WebBackend(), handle, out)
    assert payload["truncated"] is True
    assert payload["total"] == 40
    assert 0 < payload["entry_count"] < 40
    assert payload["size"] <= 2000
    # The written file matches the reported surviving count exactly, and the
    # magnitude of the tail loss is total - entry_count, not a bare boolean.
    log = json.loads(out.read_text(encoding="utf-8"))
    assert len(log["log"]["entries"]) == payload["entry_count"]


def test_a_single_entry_too_big_to_fit_yields_an_empty_but_marked_har(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """One entry that alone blows the cap is dropped, and the export owns up.

    entry_count 0 with total 1 and truncated True reads as "we had one and
    could not fit it", not as "the capture was empty".
    """
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 2000)
    handle = _Handle({"0": _entry(0, url_len=4000)})
    out = tmp_path / "c.har"
    payload = _export(WebBackend(), handle, out)
    assert payload["total"] == 1
    assert payload["entry_count"] == 0
    assert payload["truncated"] is True
    log = json.loads(out.read_text(encoding="utf-8"))
    assert log["log"]["entries"] == []
