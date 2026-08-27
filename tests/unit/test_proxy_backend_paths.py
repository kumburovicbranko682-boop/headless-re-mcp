"""ProxyBackend pure helpers, recorder retention, and read-method contracts.

The flow-recording behaviour and field shapes are pinned elsewhere; what is
covered here is the machinery around them that does not need a live mitmproxy:

* the pure helpers -- port probes, content/header/flow byte accounting, the
  UTF-8-or-spill body emitter, the bounded header map, and the loop/logging
  teardown helpers;
* the ``_FlowRecorder`` memory guard -- a body over the per-flow cap is stored
  as omitted, and retained bytes are evicted in lockstep once the total cap is
  crossed;
* the ``ProxyBackend`` read surface -- capability/state guards, status/flows
  paging, and flow_get/replay refusing an unknown or omitted flow.

A fake ``_ProxyInstance`` with a real recorder stands in for the running proxy.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.proxy.client as proxy
from headless_re_mcp.backends.proxy.client import (
    _MAX_INLINE_BODY,
    _MAX_STORED_BODY,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _bounded_metadata,
    _content_len,
    _emit_body,
    _encoded_len,
    _flow_stored_bytes,
    _FlowRecorder,
    _headers_len,
    _ProxyInstance,
    _raw_body,
    _shutdown_loop,
    _uninstall_master_logging,
)


# --------------------------------------------------------------------------
# byte accounting helpers
# --------------------------------------------------------------------------
def test_content_len_reads_raw_content_or_zero() -> None:
    assert _content_len(None) == 0
    assert _content_len(SimpleNamespace(raw_content=b"abcd")) == 4
    assert _content_len(SimpleNamespace(raw_content=None)) == 0

    class _NoLen:
        raw_content = 5  # truthy but len() raises TypeError

    assert _content_len(_NoLen()) == 0


def test_encoded_len_measures_utf8_and_survives_bad_values() -> None:
    assert _encoded_len("abc") == 3
    assert _encoded_len("é") == 2

    class _Boom:
        def __str__(self) -> str:
            raise RuntimeError("cannot stringify")

    # An unstringifiable value is treated as over the stored-body cap.
    assert _encoded_len(_Boom()) == _MAX_STORED_BODY + 1


def test_headers_len_handles_multi_single_and_missing() -> None:
    assert _headers_len(SimpleNamespace(headers=None)) == 0

    class _Multi:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            return [("a", "1"), ("b", "22")]

    assert _headers_len(SimpleNamespace(headers=_Multi())) == len("a1b22")

    class _SingleOnly:
        def items(self, multi: bool = False) -> Any:
            if multi:
                raise TypeError("no multi kwarg")
            return [("x", "yy")]

    assert _headers_len(SimpleNamespace(headers=_SingleOnly())) == len("xyy")


def test_flow_stored_bytes_sums_bodies_meta_and_headers() -> None:
    request = SimpleNamespace(
        raw_content=b"body",
        method="GET",
        pretty_url="http://x/",
        host="x",
        headers=None,
    )
    response = SimpleNamespace(raw_content=b"resp", headers=None)
    flow = SimpleNamespace(request=request, response=response)
    total = _flow_stored_bytes(flow)
    assert total == len(b"body") + len(b"resp") + len("GET") + len("http://x/") + len("x")


# --------------------------------------------------------------------------
# _bounded_metadata / _raw_body / _emit_body / _bounded_headers
# --------------------------------------------------------------------------
def test_bounded_metadata_truncates_over_the_cap() -> None:
    assert _bounded_metadata(None, 10) == ("", False)
    text, cut = _bounded_metadata("z" * 100, 8)
    assert cut is True and len(text.encode("utf-8")) <= 8


def test_raw_body_reads_bytes_and_swallows_decode_failures() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content=b"data")) == b"data"

    class _Boom:
        @property
        def raw_content(self) -> bytes:
            raise RuntimeError("decode failed")

    assert _raw_body(_Boom()) == b""
    # A non-bytes content is treated as empty.
    assert _raw_body(SimpleNamespace(raw_content="text")) == b""


def test_emit_body_inlines_text_spills_binary_and_large(tmp_path: Path) -> None:
    assert _emit_body(b"", tmp_path) == {"size": 0, "body": ""}

    inline = _emit_body(b"hello", tmp_path)
    assert inline["body"] == "hello" and "body_path" not in inline

    binary = _emit_body(b"\xff\xfe\x00", tmp_path)
    assert binary["spill_reason"] == "binary"
    assert Path(binary["body_path"]).read_bytes() == b"\xff\xfe\x00"

    big = b"a" * (_MAX_INLINE_BODY + 10)
    large = _emit_body(big, tmp_path)
    assert large["spill_reason"] == "too_large"
    assert Path(large["body_path"]).read_bytes() == big


def test_bounded_headers_maps_bounds_and_absence() -> None:
    assert _bounded_headers(SimpleNamespace(headers=None)) == ({}, False)

    class _Multi:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            return [("a", "1"), ("a", "2"), ("b", "3")]

    # Duplicate names collapse to the last value.
    mapping, truncated = _bounded_headers(SimpleNamespace(headers=_Multi()))
    assert mapping == {"a": "2", "b": "3"} and truncated is False

    class _Explode:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("headers unreadable")

    assert _bounded_headers(SimpleNamespace(headers=_Explode())) == ({}, True)


def test_bounded_headers_caps_the_count() -> None:
    class _Many:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            return [(f"h{i}", "v") for i in range(proxy._MAX_FLOW_HEADERS + 5)]

    mapping, truncated = _bounded_headers(SimpleNamespace(headers=_Many()))
    assert truncated is True and len(mapping) == proxy._MAX_FLOW_HEADERS


# --------------------------------------------------------------------------
# loop / logging teardown
# --------------------------------------------------------------------------
def test_shutdown_loop_cancels_pending_and_closes() -> None:
    loop = asyncio.new_event_loop()

    async def _sleeper() -> None:
        await asyncio.sleep(100)

    loop.create_task(_sleeper())
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_uninstall_master_logging_removes_the_handler() -> None:
    root = logging.getLogger()

    class _Handler(logging.Handler):
        def __init__(self, master: Any) -> None:
            super().__init__()
            self.master = master

        def emit(self, record: logging.LogRecord) -> None:
            return None

    loop = asyncio.new_event_loop()
    master = SimpleNamespace(event_loop=loop, _legacy_log_events=None)
    handler = _Handler(master)
    root.addHandler(handler)
    try:
        _uninstall_master_logging(master, loop)
        assert handler not in root.handlers
    finally:
        root.removeHandler(handler)
        loop.close()


def test_uninstall_master_logging_is_a_noop_without_targets() -> None:
    # Neither master nor loop -> returns immediately, touching nothing.
    _uninstall_master_logging(None, None)


# --------------------------------------------------------------------------
# _FlowRecorder retention
# --------------------------------------------------------------------------
def _flow(flow_id: str, body: bytes) -> Any:
    request = SimpleNamespace(
        raw_content=body, method="GET", pretty_url=f"http://x/{flow_id}", host="x", headers=None
    )
    response = SimpleNamespace(raw_content=b"", status_code=200, headers={})
    return SimpleNamespace(id=flow_id, request=request, response=response, error=None)


def test_recorder_omits_a_flow_over_the_per_flow_cap() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_flow("big", b"x" * (_MAX_STORED_BODY + 1)))
    assert recorder.raw("big") is _OMITTED_BODY
    row = recorder.snapshot()[0]
    assert row["body_omitted"] is True


def test_recorder_evicts_retained_bytes_over_the_total_cap(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    # Shrink the caps so a couple of small flows cross the total ceiling; the
    # oldest retained body is omitted to make room for the newest.
    monkeypatch.setattr(proxy, "_MAX_RETAINED_BYTES", 200)
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_flow("first", b"a" * 150))
    recorder.response(_flow("second", b"b" * 150))
    # The first flow's body was dropped to keep the total under the cap; the
    # second is still fully retained.
    assert recorder.raw("first") is _OMITTED_BODY
    assert recorder.raw("second") is not _OMITTED_BODY


def test_recorder_omit_retained_is_idempotent() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_flow("f", b"body"))
    with recorder._lock:
        recorder._omit_retained("f")
        before = recorder._retained_bytes
        recorder._omit_retained("f")  # already omitted -> no double subtraction
        assert recorder._retained_bytes == before
    assert recorder.raw("f") is _OMITTED_BODY


# --------------------------------------------------------------------------
# ProxyBackend guards + read methods
# --------------------------------------------------------------------------
def _backend_with_instance(session_id: str) -> tuple[ProxyBackend, _ProxyInstance]:
    backend = ProxyBackend()
    backend._available = True
    inst = _ProxyInstance("127.0.0.1", 8080)
    backend._instances[session_id] = inst
    return backend, inst


def test_check_available_refuses_without_mitmproxy(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "mitmproxy", None)
    backend = ProxyBackend()
    backend._available = None
    with pytest.raises(ProxyError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_get_refuses_a_session_with_no_proxy() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as caught:
        backend._get("nope")
    assert caught.value.code == "invalid_state"


def test_start_rejects_a_bad_port_and_a_duplicate() -> None:
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as bad_port:
        backend.start("s", port=70000)
    assert bad_port.value.code == "invalid_params"

    backend._instances["s"] = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as dup:
        backend.start("s", port=8081)
    assert dup.value.code == "invalid_state"


def test_start_refuses_a_port_reserved_by_another_session() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["first"] = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as caught:
        backend.start("second", host="127.0.0.1", port=8080)
    assert caught.value.code == "invalid_state"
    assert caught.value.details["owner_session_id"] == "first"


def test_stop_reports_when_nothing_ran() -> None:
    backend = ProxyBackend()
    assert backend.stop("nope") == {"stopped": False, "note": "no proxy was running"}


def test_status_reports_running_and_absent() -> None:
    backend = ProxyBackend()
    assert backend.status("nope") == {"running": False}

    backend, inst = _backend_with_instance("s")
    inst.recorder.response(_flow("f1", b"body"))
    status = backend.status("s")
    assert status["running"] is True and status["flow_count"] == 1
    assert status["port"] == 8080


def test_flows_pages_the_capture() -> None:
    backend, inst = _backend_with_instance("s")
    for index in range(5):
        inst.recorder.response(_flow(f"f{index}", b"b"))
    payload = backend.flows("s", offset=1, limit=2)
    assert payload["count"] == 2 and payload["total"] == 5 and payload["has_more"] is True


def test_flow_get_refuses_unknown_and_omitted(tmp_path: Path) -> None:
    backend, inst = _backend_with_instance("s")
    with pytest.raises(ProxyError) as unknown:
        backend.flow_get("s", "ghost", tmp_path)
    assert unknown.value.code == "not_found"

    inst.recorder.response(_flow("big", b"x" * (_MAX_STORED_BODY + 1)))
    with pytest.raises(ProxyError) as omitted:
        backend.flow_get("s", "big", tmp_path)
    assert omitted.value.code == "too_large"


def test_flow_get_returns_request_and_response_bodies(tmp_path: Path) -> None:
    backend, inst = _backend_with_instance("s")
    request = SimpleNamespace(
        raw_content=b'{"q":1}',
        method="POST",
        pretty_url="http://x/api",
        host="x",
        headers=None,
    )
    response = SimpleNamespace(
        raw_content=b"ok", status_code=201, headers={"content-type": "text/plain"}
    )
    flow = SimpleNamespace(id="f", request=request, response=response, error=None)
    inst.recorder.response(flow)
    result = backend.flow_get("s", "f", tmp_path)
    assert result["request"]["method"] == "POST" and result["request"]["body"] == '{"q":1}'
    assert result["response"]["status"] == 201 and result["response"]["body"] == "ok"


def test_replay_refuses_unknown_omitted_and_stopped(tmp_path: Path) -> None:
    backend, inst = _backend_with_instance("s")
    with pytest.raises(ProxyError) as unknown:
        backend.replay("s", "ghost")
    assert unknown.value.code == "not_found"

    inst.recorder.response(_flow("big", b"x" * (_MAX_STORED_BODY + 1)))
    with pytest.raises(ProxyError) as omitted:
        backend.replay("s", "big")
    assert omitted.value.code == "too_large"

    # A retained flow but no running master -> invalid_state.
    inst.recorder.response(_flow("f", b"small"))
    with pytest.raises(ProxyError) as stopped:
        backend.replay("s", "f")
    assert stopped.value.code == "invalid_state"


def test_export_har_writes_the_capture(tmp_path: Path) -> None:
    backend, inst = _backend_with_instance("s")
    inst.recorder.response(_flow("f", b"small"))
    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["entry_count"] == 1 and out.exists()


def test_ca_cert_path_reports_absence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(proxy.Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() is None
    cert_dir = tmp_path / ".mitmproxy"
    cert_dir.mkdir()
    (cert_dir / "mitmproxy-ca-cert.pem").write_text("x")
    assert ProxyBackend().ca_cert_path() == cert_dir / "mitmproxy-ca-cert.pem"
