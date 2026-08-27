"""proxy.export_har must bound its output like web.har_export does.

The flow ring caps entry count and URL length, so a real export fits the
capture cap today. But that cap is a property of the write, not a coincidence
of the recorder's limits: web.har_export already drops oldest-first entries
until the HAR fits and reports ``size``/``truncated``, while proxy.export_har
wrote the whole dump and reported neither -- the one capture-writing export on
the non-PE lines that neither bounded its output nor named its size. These pin
the parity so the two siblings behave the same way.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy import client as mod
from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _FlowRecorder


def _recorder_with(flow_count: int, *, url_len: int = 200) -> _FlowRecorder:
    recorder = _FlowRecorder()
    for index in range(flow_count):
        request = SimpleNamespace(
            method="GET",
            pretty_url="http://x/" + ("a" * url_len) + f"/{index}",
            host="x",
        )
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    return recorder


def _backend_with(recorder: _FlowRecorder) -> ProxyBackend:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)  # type: ignore[assignment]
    return backend


def test_export_reports_size_and_is_not_truncated_when_it_fits(tmp_path: Path) -> None:
    """A small capture reports its byte size and does not claim truncation."""
    backend = _backend_with(_recorder_with(4))
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["entry_count"] == 4
    assert payload["truncated"] is False
    assert payload["size"] == out.stat().st_size


def test_oldest_first_flows_are_dropped_until_the_har_fits(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Over the cap, entries are dropped and truncated is reported, not written whole."""
    monkeypatch.setattr(mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 2000)
    backend = _backend_with(_recorder_with(40))
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["truncated"] is True
    assert 0 < payload["entry_count"] < 40
    assert payload["size"] <= 2000
    assert out.stat().st_size == payload["size"]


def test_a_har_that_cannot_fit_the_cap_is_refused(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """When even the empty skeleton exceeds the cap, refuse rather than overrun."""
    monkeypatch.setattr(mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 10)
    backend = _backend_with(_recorder_with(3))
    out = tmp_path / "capture.har"
    try:
        backend.export_har("s", out)
    except ProxyError as exc:
        assert exc.code == "too_large"
    else:  # pragma: no cover - the assertion above is the contract
        raise AssertionError("expected a too_large refusal")
    assert out.exists() is False
