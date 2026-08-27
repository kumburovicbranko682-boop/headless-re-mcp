"""Ring-buffer bookkeeping and reader guards of the mitmproxy backend.

mitmproxy itself needs a live listener, but the part that keeps an unattended
capture from eating the host -- the bounded ``_FlowRecorder`` and the readers
that page, cap and spill what it holds -- is pure Python fed fake flow objects.
This pins the memory bounds (a body over the per-flow cap is dropped, the retain
ring omits oldest bodies to stay under the byte ceiling, the count ring evicts in
lockstep), the honesty of an errored flow (null status, error flag), and the
degradation replies of the readers, so each stays a structured ``ProxyError``
rather than a bare exception.
"""

from __future__ import annotations

import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _content_len,
    _encoded_len,
    _FlowRecorder,
    _headers_len,
    _port_accepts,
    _port_bindable,
    _raw_body,
)


def _flow(
    *,
    flow_id: str = "f",
    method: str = "GET",
    url: str = "http://x/1",
    host: str = "x",
    req_body: bytes = b"",
    with_response: bool = True,
    status: int = 200,
    resp_body: bytes = b"",
    content_type: str = "text/plain",
    error: str | None = None,
) -> Any:
    request = SimpleNamespace(
        method=method, pretty_url=url, host=host, headers={}, raw_content=req_body
    )
    response = (
        SimpleNamespace(
            status_code=status, headers={"content-type": content_type}, raw_content=resp_body
        )
        if with_response
        else None
    )
    flow = SimpleNamespace(id=flow_id, request=request, response=response)
    if error is not None:
        flow.error = SimpleNamespace(msg=error)
    return flow


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def test_content_len_handles_none_empty_and_unsized() -> None:
    assert _content_len(None) == 0
    assert _content_len(SimpleNamespace(raw_content=None)) == 0
    assert _content_len(SimpleNamespace(raw_content=b"abc")) == 3
    # A raw_content that is truthy but not sizeable reads as zero, not a crash.
    assert _content_len(SimpleNamespace(raw_content=object())) == 0


def test_encoded_len_of_a_value_whose_str_raises_is_over_the_cap() -> None:
    class _Hostile:
        def __str__(self) -> str:
            raise RuntimeError("no repr")

    assert _encoded_len(_Hostile()) > proxy_client._MAX_STORED_BODY


def test_raw_body_of_none_and_non_bytes_is_empty() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content="not-bytes")) == b""

    class _Decoding:
        @property
        def raw_content(self) -> bytes:
            raise RuntimeError("lazy decode failed")

    assert _raw_body(_Decoding()) == b""


def test_headers_len_handles_missing_and_hostile_headers() -> None:
    assert _headers_len(SimpleNamespace()) == 0

    class _BadHeaders:
        def items(self, multi: bool = False) -> Any:
            raise ValueError("cannot iterate")

    assert _headers_len(SimpleNamespace(headers=_BadHeaders())) == 0


def test_bounded_headers_caps_the_total_size_before_the_count() -> None:
    """Values under the per-value cap can still overflow the total budget; the
    map is cut there and flagged rather than returned whole."""
    big = "z" * 4000
    headers = {f"h{index}": big for index in range(30)}
    out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
    assert truncated is True
    assert len(out) < 30


def test_bounded_headers_reports_truncation_when_iteration_fails() -> None:
    class _Unyielding:
        def items(self, multi: bool = False) -> Any:
            raise TypeError("no multi") if multi else (_ for _ in ()).throw(
                RuntimeError("iteration blew up")
            )

    out, truncated = _bounded_headers(SimpleNamespace(headers=_Unyielding()))
    assert out == {}
    assert truncated is True


# ---------------------------------------------------------------------------
# _FlowRecorder ring buffer
# ---------------------------------------------------------------------------
def test_recorder_records_a_completed_flow_and_exposes_it() -> None:
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="a", method="POST", resp_body=b"hi"))
    assert recorder.count() == 1
    snap = recorder.snapshot()
    assert snap[0]["id"] == "a"
    assert snap[0]["status"] == 200
    assert snap[0]["response_size"] == 2
    assert recorder.raw("a") is not None
    assert recorder.retained_bytes() > 0


def test_recorder_records_an_errored_flow_with_null_status() -> None:
    recorder = _FlowRecorder()
    recorder.error(_flow(flow_id="e", with_response=False, error="connection reset"))
    entry = recorder.snapshot()[0]
    assert entry["status"] is None
    assert entry["error"] is True
    assert entry["error_msg"] == "connection reset"


def test_recorder_omits_a_body_over_the_per_flow_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 8)
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="big", resp_body=b"x" * 100))
    entry = recorder.snapshot()[0]
    assert entry["body_omitted"] is True
    # Marked omitted: the raw flow is dropped so it cannot be re-fetched.
    assert recorder.raw("big") is _OMITTED_BODY


def test_recorder_evicts_oldest_bodies_to_stay_under_the_byte_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When retained bytes would exceed the ceiling, the oldest retained body is
    omitted rather than letting the capture grow without bound."""
    monkeypatch.setattr(proxy_client, "_MAX_RETAINED_BYTES", 40)
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="old", resp_body=b"a" * 30))
    assert recorder.raw("old") is not None
    # A second sizeable flow pushes the total past the ceiling, so the first
    # flow's body is omitted and its summary back-annotated.
    recorder.response(_flow(flow_id="new", resp_body=b"b" * 30))
    assert recorder.raw("old") is _OMITTED_BODY
    old_summary = next(s for s in recorder.snapshot() if s["id"] == "old")
    assert old_summary["body_omitted"] is True


def test_recorder_count_ring_evicts_in_lockstep(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _FlowRecorder(capacity=2)
    for i in range(3):
        recorder.response(_flow(flow_id=f"f{i}", resp_body=b"x"))
    assert recorder.count() == 2
    # The oldest flow left both the summary ring and the raw retain map.
    assert recorder.raw("f0") is None
    ids = {s["id"] for s in recorder.snapshot()}
    assert ids == {"f1", "f2"}


def test_recorder_flags_truncated_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_METADATA_BYTES", 3)
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="t", method="DELETE"))
    assert recorder.snapshot()[0]["metadata_truncated"] is True


# ---------------------------------------------------------------------------
# readers driven through an injected recorder
# ---------------------------------------------------------------------------
def _backend_with_recorder(
    monkeypatch: pytest.MonkeyPatch, recorder: Any, **extra: Any
) -> ProxyBackend:
    backend = ProxyBackend()
    inst = SimpleNamespace(recorder=recorder, host="127.0.0.1", port=8080, **extra)
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


def test_flows_on_an_empty_ring_reports_no_drops(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = SimpleNamespace(snapshot=list)
    backend = _backend_with_recorder(monkeypatch, recorder)
    payload = backend.flows("s")
    assert payload["total"] == 0
    assert payload["count"] == 0
    assert payload["dropped"] == 0
    assert payload["has_more"] is False


def test_flows_reports_dropped_from_the_sequence_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    """seq counts every flow ever seen; total counts what the ring still holds,
    so their gap is how many the caller missed to eviction."""
    snapshot = [{"id": str(i), "seq": i} for i in range(51, 61)]  # seq 51..60, ten held
    recorder = SimpleNamespace(snapshot=lambda: snapshot)
    backend = _backend_with_recorder(monkeypatch, recorder)
    payload = backend.flows("s", offset=0, limit=5)
    assert payload["count"] == 5
    assert payload["total"] == 10
    assert payload["has_more"] is True
    assert payload["dropped"] == 50


def test_flow_get_flags_truncated_request_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_METADATA_BYTES", 3)
    flow = _flow(flow_id="f", method="DELETE", resp_body=b"ok")
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    backend = _backend_with_recorder(monkeypatch, recorder)
    payload = backend.flow_get("s", "f", tmp_path)
    assert payload["request"]["metadata_truncated"] is True


def test_flow_get_reports_an_unknown_flow_as_not_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorder = SimpleNamespace(raw=lambda flow_id: None)
    backend = _backend_with_recorder(monkeypatch, recorder)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "gone", tmp_path)
    assert caught.value.code == "not_found"


def test_flow_get_reports_an_omitted_body_as_too_large(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorder = SimpleNamespace(raw=lambda flow_id: _OMITTED_BODY)
    backend = _backend_with_recorder(monkeypatch, recorder)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "big", tmp_path)
    assert caught.value.code == "too_large"


def test_status_of_a_running_proxy_reports_the_bounds() -> None:
    backend = ProxyBackend()
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="a", resp_body=b"hi"))
    backend._instances["s"] = SimpleNamespace(  # type: ignore[assignment]
        host="127.0.0.1", port=8081, recorder=recorder
    )
    payload = backend.status("s")
    assert payload["running"] is True
    assert payload["port"] == 8081
    assert payload["flow_count"] == 1
    assert payload["retained_max"] == proxy_client._MAX_FLOWS
    assert payload["retained_bytes"] > 0


def test_export_har_writes_entries_and_refuses_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="a", url="http://x/api", status=200, resp_body=b"{}"))
    backend = _backend_with_recorder(monkeypatch, recorder)

    out = tmp_path / "cap.har"
    payload = backend.export_har("s", out)
    assert payload["entry_count"] == 1
    assert out.is_file()

    monkeypatch.setattr(proxy_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    with pytest.raises(ProxyError) as caught:
        backend.export_har("s", tmp_path / "toobig.har")
    assert caught.value.code == "too_large"


def test_replay_guards_missing_omitted_and_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # unknown flow id
    missing = _backend_with_recorder(
        monkeypatch, SimpleNamespace(raw=lambda fid: None), _master=object(), _loop=object()
    )
    with pytest.raises(ProxyError) as gone:
        missing.replay("s", "x")
    assert gone.value.code == "not_found"

    # body omitted, cannot replay
    omitted = _backend_with_recorder(
        monkeypatch,
        SimpleNamespace(raw=lambda fid: _OMITTED_BODY),
        _master=object(),
        _loop=object(),
    )
    with pytest.raises(ProxyError) as big:
        omitted.replay("s", "x")
    assert big.value.code == "too_large"

    # a live flow but no running master
    stopped = _backend_with_recorder(
        monkeypatch,
        SimpleNamespace(raw=lambda fid: SimpleNamespace()),
        _master=None,
        _loop=None,
    )
    with pytest.raises(ProxyError) as down:
        stopped.replay("s", "x")
    assert down.value.code == "invalid_state"


# ---------------------------------------------------------------------------
# lifecycle guards
# ---------------------------------------------------------------------------
def test_start_without_mitmproxy_is_capability_unavailable() -> None:
    backend = ProxyBackend()
    backend._available = False
    with pytest.raises(ProxyError) as caught:
        backend.start("s")
    assert caught.value.code == "capability_unavailable"


def test_check_available_caches_a_successful_probe() -> None:
    """mitmproxy is installed in this environment, so the probe resolves to
    available and does not raise; the result is cached for later calls."""
    backend = ProxyBackend()
    assert backend._available is None
    backend._check_available()
    assert backend._available is True
    backend._check_available()


def test_stop_without_a_running_proxy_is_not_an_error() -> None:
    assert ProxyBackend().stop("nope") == {"stopped": False, "note": "no proxy was running"}


def test_get_without_a_running_proxy_reports_invalid_state() -> None:
    with pytest.raises(ProxyError) as caught:
        ProxyBackend().flows("nope")
    assert caught.value.code == "invalid_state"


def test_ca_cert_path_finds_a_certificate_or_reports_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(proxy_client.Path, "home", staticmethod(lambda: tmp_path))
    assert ProxyBackend().ca_cert_path() is None
    mitm = tmp_path / ".mitmproxy"
    mitm.mkdir()
    cert = mitm / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    assert ProxyBackend().ca_cert_path() == cert


# ---------------------------------------------------------------------------
# port probes
# ---------------------------------------------------------------------------
def test_port_probes_agree_with_a_real_listener() -> None:
    listener = socket.socket()
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        # Something is accepting here, so it cannot be bound again.
        assert _port_accepts("127.0.0.1", port) is True
        assert _port_bindable("127.0.0.1", port) is False
    finally:
        listener.close()

    # A free ephemeral port is bindable and nothing is accepting on it.
    free = socket.socket()
    try:
        free.bind(("127.0.0.1", 0))
        free_port = free.getsockname()[1]
    finally:
        free.close()
    assert _port_bindable("127.0.0.1", free_port) is True
