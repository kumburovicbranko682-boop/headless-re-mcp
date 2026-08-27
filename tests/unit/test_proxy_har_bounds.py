"""proxy.export_har must honour the capture byte cap, like web.har_export.

Every other artifact writer bounds what it puts on disk to
``UNREGISTERED_CAPTURE_MAX_BYTES``; the web HAR export drops the newest entries
until it fits and reports ``truncated``/``size``. The proxy HAR export used to
serialise every retained flow and write it unconditionally. Each summary URL is
capped at 16 KiB, but 2000 of them -- doubled again when JSON escaping expands
runs of backslashes or quotes -- can push the file past the cap the rest of the
surface honours. These tests hold the proxy exporter to the same bound.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _FlowRecorder


def _recorder(count: int, *, url: str = "http://x/") -> _FlowRecorder:
    recorder = _FlowRecorder()
    for index in range(count):
        request = SimpleNamespace(method="GET", pretty_url=f"{url}{index}", host="x")
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
        recorder.response(SimpleNamespace(id=str(index), request=request, response=response))
    return recorder


def _backend(recorder: _FlowRecorder) -> ProxyBackend:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    return backend


def test_small_capture_reports_size_and_is_not_truncated(tmp_path: Path) -> None:
    backend = _backend(_recorder(4))
    payload = backend.export_har("s", tmp_path / "capture.har")
    assert payload["entry_count"] == 4
    assert payload["truncated"] is False
    assert payload["size"] > 0
    assert (tmp_path / "capture.har").stat().st_size == payload["size"]


def test_export_drops_newest_entries_until_it_fits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A capture past the cap is trimmed and flagged, not written whole."""
    # A small cap makes the drop loop reachable without a giant fixture.
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 2000)
    backend = _backend(_recorder(200))
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["truncated"] is True
    assert 0 < payload["entry_count"] < 200
    assert payload["size"] <= 2000
    # The bound is on bytes actually written, not merely reported.
    assert out.stat().st_size <= 2000


def test_export_refuses_when_even_an_empty_log_would_exceed_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The drop loop empties the entries; a cap below the skeleton still refuses."""
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 1)
    backend = _backend(_recorder(5))
    out = tmp_path / "capture.har"
    with pytest.raises(ProxyError) as info:
        backend.export_har("s", out)
    assert info.value.code == "too_large"
    # Nothing over the cap is left on disk.
    assert not out.exists()


def test_a_giant_url_capture_stays_under_the_real_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Escaping-heavy URLs are exactly the case the count cap alone misses."""
    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 50_000)
    # Backslash runs double under JSON escaping; the count is tiny but the
    # serialised size is not.
    recorder = _recorder(40, url="http://x/" + ("\\" * 800))
    backend = _backend(recorder)
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["size"] <= 50_000
    assert out.stat().st_size <= 50_000
    assert payload["truncated"] is True


def _dumped_fields(payload: dict[str, Any]) -> set[str]:
    return set(payload)


def test_payload_keeps_path_and_entry_count(tmp_path: Path) -> None:
    """The documented fields survive alongside the new size/truncated ones."""
    backend = _backend(_recorder(2))
    payload = backend.export_har("s", tmp_path / "capture.har")
    assert {"path", "entry_count"} <= _dumped_fields(payload)
    assert payload["path"].endswith("capture.har")
