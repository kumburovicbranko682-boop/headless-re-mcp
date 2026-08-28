"""Read-side guards of ProxyBackend that do not need a live mitmproxy.

test_proxy_fields.py pins the happy-path shapes (flows page, a large flow_get
spill, status, HAR export). What is left are the error and guard branches on the
read side: fetching a flow that was evicted or whose body was dropped, replaying
one that cannot be replayed, discovering the generated CA certificate, and the
capability gate. None of these need a running proxy -- a _ProxyInstance does no
network on construction and the recorder is an ordinary ring buffer -- so each
is driven with a fake recorder registered directly on the backend.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _FlowRecorder,
)


class _Recorder:
    """Returns a preset object from raw(); stands in for the ring buffer."""

    def __init__(self, value: Any) -> None:
        self._value = value

    def raw(self, flow_id: str) -> Any:
        del flow_id
        return self._value


def _backend_with_raw(value: Any, **inst_attrs: Any) -> tuple[ProxyBackend, str]:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=_Recorder(value), **inst_attrs)
    return backend, "s"


# --- flow_get -------------------------------------------------------------


def test_flow_get_reports_not_found_for_an_unknown_id(tmp_path: Path) -> None:
    backend, sid = _backend_with_raw(None)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get(sid, "gone", tmp_path)
    assert caught.value.code == "not_found"
    assert caught.value.details["flow_id"] == "gone"


def test_flow_get_reports_too_large_when_the_body_was_dropped(tmp_path: Path) -> None:
    # The ring keeps the summary but marks the body omitted once retained bytes
    # crossed the cap; fetching it must say too_large, not hand back an empty body.
    backend, sid = _backend_with_raw(_OMITTED_BODY)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get(sid, "f1", tmp_path)
    assert caught.value.code == "too_large"


def test_flow_get_inlines_a_small_body(tmp_path: Path) -> None:
    flow = SimpleNamespace(
        request=SimpleNamespace(method="GET", pretty_url="http://x/1", headers={"accept": "*/*"}),
        response=SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}, raw_content=b"hello"
        ),
    )
    backend, sid = _backend_with_raw(flow)
    payload = backend.flow_get(sid, "f1", tmp_path)
    # Small enough to inline: body present, no spill file written.
    assert payload["response"]["body"] == "hello"
    assert payload["response"]["size"] == 5
    assert "body_path" not in payload["response"]
    assert list(tmp_path.iterdir()) == []


def test_flow_get_survives_a_body_that_cannot_be_read(tmp_path: Path) -> None:
    class _Unreadable:
        status_code = 200
        headers = {"content-type": "text/plain"}

        @property
        def raw_content(self) -> bytes:
            raise ValueError("stream already consumed")

    flow = SimpleNamespace(
        request=SimpleNamespace(method="GET", pretty_url="http://x/1", headers={}),
        response=_Unreadable(),
    )
    backend, sid = _backend_with_raw(flow)
    payload = backend.flow_get(sid, "f1", tmp_path)
    # The unreadable body degrades to empty rather than raising out of the tool.
    assert payload["response"]["size"] == 0
    assert payload["response"]["body"] == ""


# --- replay ---------------------------------------------------------------


def test_replay_reports_not_found_for_an_unknown_id() -> None:
    backend, sid = _backend_with_raw(None, _master=object(), _loop=object())
    with pytest.raises(ProxyError) as caught:
        backend.replay(sid, "gone")
    assert caught.value.code == "not_found"


def test_replay_reports_too_large_when_the_body_was_dropped() -> None:
    backend, sid = _backend_with_raw(_OMITTED_BODY, _master=object(), _loop=object())
    with pytest.raises(ProxyError) as caught:
        backend.replay(sid, "f1")
    assert caught.value.code == "too_large"


def test_replay_reports_invalid_state_when_the_proxy_is_not_running() -> None:
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    backend, sid = _backend_with_raw(flow, _master=None, _loop=None)
    with pytest.raises(ProxyError) as caught:
        backend.replay(sid, "f1")
    assert caught.value.code == "invalid_state"


# --- ca_cert_path ---------------------------------------------------------


def test_ca_cert_path_prefers_cer_then_pem_then_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    backend = ProxyBackend()
    mitm = tmp_path / ".mitmproxy"
    mitm.mkdir(parents=True)

    # Nothing generated yet.
    assert backend.ca_cert_path() is None

    # Only the PEM present: it is returned.
    pem = mitm / "mitmproxy-ca-cert.pem"
    pem.write_text("pem", encoding="utf-8")
    assert backend.ca_cert_path() == pem

    # The .cer wins when both exist (Android wants the DER-named file first).
    cer = mitm / "mitmproxy-ca-cert.cer"
    cer.write_text("cer", encoding="utf-8")
    assert backend.ca_cert_path() == cer


# --- capability gate and empty capture ------------------------------------


def test_check_available_raises_when_mitmproxy_is_absent() -> None:
    backend = ProxyBackend()
    backend._available = False  # model a host without mitmproxy
    with pytest.raises(ProxyError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_flows_on_an_empty_capture_reports_nothing_dropped() -> None:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=_FlowRecorder())
    payload = backend.flows("s")
    assert payload["total"] == 0
    assert payload["count"] == 0
    assert payload["has_more"] is False
    assert payload["dropped"] == 0


def test_omit_retained_is_idempotent_and_never_double_subtracts() -> None:
    # Once a body is dropped its bytes are reclaimed exactly once; a second omit
    # of the same id must be a no-op, or retained_bytes would drift negative and
    # the byte cap would stop firing.
    recorder = _FlowRecorder(capacity=8)
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", host="x")
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=b"x" * 1024
    )
    recorder.response(SimpleNamespace(id="f1", request=request, response=response))
    assert recorder.retained_bytes() > 0

    recorder._omit_retained("f1")
    after_first = recorder.retained_bytes()
    recorder._omit_retained("f1")
    assert recorder.retained_bytes() == after_first == 0
    assert recorder.snapshot()[0]["body_omitted"] is True
