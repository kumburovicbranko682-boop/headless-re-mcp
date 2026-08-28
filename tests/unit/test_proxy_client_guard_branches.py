"""Guard, error and eviction branches of the mitmproxy capture backend.

The existing proxy tests pin the error-flow hook, the stop() drain, the port
reservation and the field contracts. This file fills in the branches those
happy-path fakes step over: the pure body/header/metadata bounding helpers, the
retained-bytes eviction that keeps the ring from OOMing overnight, the
availability guard, and the start / stop / status / flows / flow_get / replay /
ca_cert / close_all read-outs that have to hold when the session is wrong, the
body was dropped, or the replay command hangs. Each test pins one branch.

The real mitmproxy start (`_ProxyInstance.start` / `_run`) binds a port and runs
a DumpMaster, so it stays with the integration gate; everything here runs with
fakes and needs no mitmproxy server, no port and no network.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxymod
from headless_re_mcp.backends.proxy.client import (
    _MAX_STORED_BODY,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _bounded_metadata,
    _content_len,
    _drain_proxy_servers,
    _encoded_len,
    _FlowRecorder,
    _headers_len,
    _port_accepts,
    _ProxyInstance,
    _raw_body,
    _shutdown_loop,
    _uninstall_master_logging,
)


def _ok_flow(flow_id: str, body: bytes = b"") -> Any:
    request = SimpleNamespace(
        method="GET", pretty_url=f"http://x/{flow_id}", host="x", raw_content=body
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=b""
    )
    return SimpleNamespace(id=flow_id, request=request, response=response)


def _full_flow(flow_id: str, body: bytes = b"hello") -> Any:
    request = SimpleNamespace(
        method="GET",
        pretty_url=f"http://x/{flow_id}",
        host="x",
        headers={"h": "v"},
        raw_content=b"reqbody",
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=body
    )
    return SimpleNamespace(id=flow_id, request=request, response=response)


@contextlib.contextmanager
def _running_loop() -> Iterator[asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, name="fake-proxy", daemon=True)
    thread.start()
    try:
        yield loop
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=3.0)
        loop.close()


# ---------------------------------------------------------------------------
# _shutdown_loop / _port_accepts.
# ---------------------------------------------------------------------------
def test_shutdown_loop_cancels_pending_tasks_and_closes() -> None:
    """A stalled task is cancelled and awaited so its socket is really freed."""
    loop = asyncio.new_event_loop()

    async def sleeper() -> None:
        await asyncio.sleep(3600)

    task = loop.create_task(sleeper())
    _shutdown_loop(loop)
    assert loop.is_closed()
    assert task.cancelled()


def test_shutdown_loop_closes_a_loop_with_no_pending_tasks() -> None:
    """A loop with nothing outstanding is still asyncgen-drained and closed."""
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_drain_proxy_servers_swallows_a_missing_addon_surface() -> None:
    """A master whose addon lookup raises is a no-op, not a stop() failure.

    The proxyserver addon surface varies across mitmproxy versions; stop() must
    still tear the rest down, so a lookup that blows up here is swallowed.
    """

    class _Addons:
        def get(self, name: str) -> Any:
            raise RuntimeError("addon registry unavailable")

    master = SimpleNamespace(addons=_Addons())
    loop = asyncio.new_event_loop()
    try:
        _drain_proxy_servers(master, loop)
    finally:
        loop.close()


def test_port_accepts_true_for_a_listening_socket() -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert _port_accepts("127.0.0.1", port) is True
    finally:
        server.close()


def test_port_accepts_false_for_a_closed_port() -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert _port_accepts("127.0.0.1", port) is False


def test_port_accepts_false_when_the_probe_raises(monkeypatch: Any) -> None:
    """A socket error during the probe reads as "not accepting", never a crash."""

    class _Boom:
        def settimeout(self, _t: float) -> None:
            return None

        def connect_ex(self, _addr: Any) -> int:
            raise OSError("probe failed")

        def __enter__(self) -> _Boom:
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

    monkeypatch.setattr(proxymod.socket, "socket", lambda *a, **k: _Boom())
    assert _port_accepts("127.0.0.1", 1) is False


# ---------------------------------------------------------------------------
# _uninstall_master_logging.
# ---------------------------------------------------------------------------
def test_uninstall_master_logging_is_a_noop_without_master_or_loop() -> None:
    _uninstall_master_logging(None, None)


def test_uninstall_master_logging_removes_the_installed_handler() -> None:
    calls: list[str] = []

    class _Handler(logging.Handler):
        def __init__(self, master: object) -> None:
            super().__init__()
            self.master = master

        def emit(self, record: logging.LogRecord) -> None:
            return None

    master = SimpleNamespace(
        _legacy_log_events=SimpleNamespace(uninstall=lambda: calls.append("uninstall"))
    )
    handler = _Handler(master)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        _uninstall_master_logging(master)
    finally:
        if handler in root.handlers:
            root.removeHandler(handler)
    assert handler not in root.handlers
    assert calls == ["uninstall"]


def test_uninstall_master_logging_leaves_unrelated_handlers_in_place() -> None:
    """A handler owned by another master (or none) must not be torn down.

    The root logger is shared; removing a handler whose master is not the one
    being cleaned up would silence logging installed by something else.
    """

    class _Handler(logging.Handler):
        def __init__(self, master: object) -> None:
            super().__init__()
            self.master = master

        def emit(self, record: logging.LogRecord) -> None:
            return None

    other = _Handler(SimpleNamespace())
    plain = logging.Handler()
    root = logging.getLogger()
    root.addHandler(other)
    root.addHandler(plain)
    try:
        _uninstall_master_logging(SimpleNamespace(), loop=None)
        assert other in root.handlers
        assert plain in root.handlers
    finally:
        for handler in (other, plain):
            if handler in root.handlers:
                root.removeHandler(handler)


# ---------------------------------------------------------------------------
# Body / header / metadata bounding helpers.
# ---------------------------------------------------------------------------
def test_content_len_reads_raw_content_and_tolerates_a_bad_length() -> None:
    assert _content_len(None) == 0
    assert _content_len(SimpleNamespace(raw_content=None)) == 0
    assert _content_len(SimpleNamespace(raw_content=b"abc")) == 3
    # A value with no len() is treated as zero, not a crash.
    assert _content_len(SimpleNamespace(raw_content=123)) == 0


def test_encoded_len_charges_a_hostile_str_the_max() -> None:
    assert _encoded_len("abc") == 3

    class _Bad:
        def __str__(self) -> str:
            raise RuntimeError("no str")

    assert _encoded_len(_Bad()) == _MAX_STORED_BODY + 1


def test_headers_len_variants() -> None:
    assert _headers_len(SimpleNamespace(headers=None)) == 0
    dict_part = SimpleNamespace(headers={"a": "b"})
    assert _headers_len(dict_part) == _encoded_len("a") + _encoded_len("b")

    class _Raises:
        def items(self, *args: Any, **kwargs: Any) -> Any:
            raise ValueError("boom")

    assert _headers_len(SimpleNamespace(headers=_Raises())) == 0


def test_headers_len_stops_counting_past_the_cap() -> None:
    big = "x" * (_MAX_STORED_BODY + 10)
    total = _headers_len(SimpleNamespace(headers={"k": big}))
    assert total > _MAX_STORED_BODY


def test_raw_body_variants() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content=b"abc")) == b"abc"
    assert _raw_body(SimpleNamespace(raw_content=bytearray(b"xy"))) == b"xy"
    # A non-bytes payload is not text bytes; it reads as an empty body.
    assert _raw_body(SimpleNamespace(raw_content="notbytes")) == b""

    class _Boom:
        @property
        def raw_content(self) -> bytes:
            raise RuntimeError("decode failed")

    assert _raw_body(_Boom()) == b""


def test_bounded_metadata_marks_when_it_truncates() -> None:
    assert _bounded_metadata("hello", 100) == ("hello", False)
    assert _bounded_metadata(None, 10) == ("", False)
    assert _bounded_metadata(123, 10) == ("123", False)
    text, cut = _bounded_metadata("e" * 50, 10)
    assert cut is True
    assert len(text.encode("utf-8")) <= 10


def test_bounded_headers_none_and_normal() -> None:
    assert _bounded_headers(SimpleNamespace(headers=None)) == ({}, False)
    part = SimpleNamespace(headers={"A": "1", "B": "2"})
    out, cut = _bounded_headers(part)
    assert out == {"A": "1", "B": "2"}
    assert cut is False


def test_bounded_headers_reports_an_items_failure() -> None:
    class _Raises:
        def items(self, *args: Any, **kwargs: Any) -> Any:
            raise ValueError("boom")

    out, cut = _bounded_headers(SimpleNamespace(headers=_Raises()))
    assert out == {}
    assert cut is True


def test_bounded_headers_caps_the_header_count(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxymod, "_MAX_FLOW_HEADERS", 1)
    out, cut = _bounded_headers(SimpleNamespace(headers={"a": "1", "b": "2"}))
    assert len(out) == 1
    assert cut is True


def test_bounded_headers_caps_the_total_size(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxymod, "_MAX_FLOW_HEADERS_TOTAL_BYTES", 8)
    out, cut = _bounded_headers(SimpleNamespace(headers={"aaaa": "bbbb", "cccc": "dddd"}))
    assert len(out) == 1
    assert cut is True


# ---------------------------------------------------------------------------
# _FlowRecorder retained-bytes eviction.
# ---------------------------------------------------------------------------
def test_recorder_omits_the_oldest_body_when_over_the_retain_cap(
    monkeypatch: Any,
) -> None:
    """A new flow over the byte cap evicts an older body and marks it omitted.

    The ring is count-capped, but each slot can hold megabytes; without a byte
    ceiling an unattended capture is an overnight OOM. When the cap is reached
    the oldest retained body is dropped (its summary flagged body_omitted) so
    the newest flow can still be retrieved in full.
    """
    monkeypatch.setattr(proxymod, "_MAX_RETAINED_BYTES", 250)
    recorder = _FlowRecorder(capacity=8)
    # Each flow stores ~117 bytes (80 body + method/url/host + response
    # headers), so two fit under the 250-byte cap and every later flow evicts
    # the oldest still-retained body. Four flows walk the eviction loop past an
    # already-omitted entry (skipped) to reach the next one it can drop.
    for name in ("f1", "f2", "f3", "f4"):
        recorder.response(_ok_flow(name, body=b"z" * 80))

    assert recorder.raw("f1") is _OMITTED_BODY
    assert recorder.raw("f2") is _OMITTED_BODY
    assert recorder.raw("f3") is not _OMITTED_BODY
    assert recorder.raw("f4") is not _OMITTED_BODY
    by_id = {row["id"]: row for row in recorder.snapshot()}
    assert by_id["f1"].get("body_omitted") is True
    assert by_id["f2"].get("body_omitted") is True
    assert "body_omitted" not in by_id["f4"]


# ---------------------------------------------------------------------------
# ProxyBackend._check_available / _get.
# ---------------------------------------------------------------------------
def test_check_available_degrades_without_mitmproxy(monkeypatch: Any) -> None:
    import builtins

    real_import = builtins.__import__

    def deny(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "mitmproxy" or name.startswith("mitmproxy."):
            raise ImportError("no mitmproxy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny)
    backend = ProxyBackend()
    backend._available = None
    with pytest.raises(ProxyError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"
    assert backend._available is False


def test_get_reports_when_no_proxy_is_running() -> None:
    with pytest.raises(ProxyError) as caught:
        ProxyBackend()._get("nope")
    assert caught.value.code == "invalid_state"


# ---------------------------------------------------------------------------
# start: reserve / success / cleanup / stopped-while-starting.
# ---------------------------------------------------------------------------
def test_start_reserves_and_reports_running(monkeypatch: Any) -> None:
    """A start on a free port past an unrelated reservation reports running."""
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, *a, **k: None)
    backend = ProxyBackend()
    backend._available = True
    backend._instances["other"] = SimpleNamespace(host="127.0.0.1", port=9999)
    payload = backend.start("s", host="127.0.0.1", port=8080)
    assert payload == {
        "running": True,
        "host": "127.0.0.1",
        "port": 8080,
        "endpoint": "127.0.0.1:8080",
    }
    assert backend._instances["s"].port == 8080


def test_start_rejects_a_bad_port() -> None:
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=99999)
    assert caught.value.code == "invalid_params"


def test_start_releases_the_reservation_on_failure(monkeypatch: Any) -> None:
    """A listen that fails frees the slot so a retry is not blocked."""

    def boom(self: Any, *args: Any, **kwargs: Any) -> None:
        raise ProxyError("backend_error", "could not bind")

    monkeypatch.setattr(_ProxyInstance, "start", boom)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: None)
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as caught:
        backend.start("s")
    assert caught.value.code == "backend_error"
    assert "s" not in backend._instances


def test_start_reports_a_stop_during_startup(monkeypatch: Any) -> None:
    """A concurrent stop that removes the reservation mid-start is reported.

    start() re-checks that its own instance is still the tracked one after
    listen returns; if a stop() dropped it in between, the freshly started proxy
    is torn back down and the caller told, rather than returning running=True
    for a session that no longer owns the port.
    """
    backend = ProxyBackend()
    backend._available = True

    def vanish(self: Any, *args: Any, **kwargs: Any) -> None:
        backend._instances.pop("s", None)

    monkeypatch.setattr(_ProxyInstance, "start", vanish)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: None)
    with pytest.raises(ProxyError) as caught:
        backend.start("s")
    assert caught.value.code == "invalid_state"
    assert "stopped while starting" in caught.value.message


# ---------------------------------------------------------------------------
# stop / status.
# ---------------------------------------------------------------------------
def test_stop_reports_when_nothing_was_running() -> None:
    assert ProxyBackend().stop("nope") == {
        "stopped": False,
        "note": "no proxy was running",
    }


def test_stop_stops_a_running_instance() -> None:
    backend = ProxyBackend()
    stopped: list[bool] = []
    backend._instances["s"] = SimpleNamespace(stop=lambda: stopped.append(True))
    assert backend.stop("s") == {"stopped": True}
    assert stopped == [True]
    assert "s" not in backend._instances


def test_status_reports_not_running_for_an_unknown_session() -> None:
    assert ProxyBackend().status("nope") == {"running": False}


def test_status_reports_the_running_counts() -> None:
    backend = ProxyBackend()
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_ok_flow("a"))
    backend._instances["s"] = SimpleNamespace(
        host="127.0.0.1", port=8080, recorder=recorder
    )
    payload = backend.status("s")
    assert payload["running"] is True
    assert payload["flow_count"] == 1
    assert payload["port"] == 8080


# ---------------------------------------------------------------------------
# flows.
# ---------------------------------------------------------------------------
def test_flows_on_an_empty_capture_reports_zero_dropped() -> None:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=_FlowRecorder(capacity=8))
    assert backend.flows("s") == {
        "flows": [],
        "count": 0,
        "total": 0,
        "offset": 0,
        "has_more": False,
        "dropped": 0,
    }


def test_flows_pages_and_reports_dropped() -> None:
    backend = ProxyBackend()
    recorder = _FlowRecorder(capacity=4)
    for i in range(6):
        recorder.response(_ok_flow(f"f{i}"))
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.flows("s", offset=0, limit=2)
    assert payload["total"] == 4
    assert payload["count"] == 2
    assert payload["has_more"] is True
    assert payload["dropped"] == 2


# ---------------------------------------------------------------------------
# flow_get.
# ---------------------------------------------------------------------------
def test_flow_get_reports_an_unknown_flow(tmp_path: Path) -> None:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=_FlowRecorder(capacity=4))
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "nope", tmp_path)
    assert caught.value.code == "not_found"


def test_flow_get_reports_an_omitted_body(tmp_path: Path) -> None:
    backend = ProxyBackend()
    recorder = _FlowRecorder(capacity=4)
    recorder._raw["omitted"] = _OMITTED_BODY
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "omitted", tmp_path)
    assert caught.value.code == "too_large"


def test_flow_get_returns_request_and_response_bodies(tmp_path: Path) -> None:
    backend = ProxyBackend()
    recorder = _FlowRecorder(capacity=4)
    recorder.response(_full_flow("f1"))
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["id"] == "f1"
    assert payload["request"]["method"] == "GET"
    assert payload["request"]["body"] == "reqbody"
    assert payload["response"]["status"] == 200
    assert payload["response"]["body"] == "hello"


def test_flow_get_marks_truncated_request_metadata(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(proxymod, "_MAX_URL_BYTES", 4)
    backend = ProxyBackend()
    recorder = _FlowRecorder(capacity=4)
    recorder.response(_full_flow("f1"))
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["request"]["metadata_truncated"] is True


# ---------------------------------------------------------------------------
# replay.
# ---------------------------------------------------------------------------
def test_replay_reports_an_unknown_flow() -> None:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(
        recorder=_FlowRecorder(capacity=4), _master=None, _loop=None
    )
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "nope")
    assert caught.value.code == "not_found"


def test_replay_reports_an_omitted_flow() -> None:
    backend = ProxyBackend()
    recorder = _FlowRecorder(capacity=4)
    recorder._raw["omitted"] = _OMITTED_BODY
    backend._instances["s"] = SimpleNamespace(
        recorder=recorder, _master=object(), _loop=object()
    )
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "omitted")
    assert caught.value.code == "too_large"


def test_replay_reports_a_stopped_proxy() -> None:
    backend = ProxyBackend()
    recorder = _FlowRecorder(capacity=4)
    recorder.response(_full_flow("f1"))
    backend._instances["s"] = SimpleNamespace(recorder=recorder, _master=None, _loop=None)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "f1")
    assert caught.value.code == "invalid_state"


def _replay_backend(
    call: Any, loop: asyncio.AbstractEventLoop
) -> tuple[ProxyBackend, list[Any]]:
    flow = SimpleNamespace(id="f1")
    flow.copy = lambda: SimpleNamespace(id="f1-copy")
    recorder = _FlowRecorder(capacity=4)
    recorder._raw["f1"] = flow
    master = SimpleNamespace(commands=SimpleNamespace(call=call))
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(
        recorder=recorder, _master=master, _loop=loop
    )
    return backend, []


def test_replay_completes_when_the_command_succeeds() -> None:
    calls: list[tuple[str, list[str]]] = []

    def call(name: str, args: list[Any]) -> None:
        calls.append((name, [a.id for a in args]))

    with _running_loop() as loop:
        backend, _ = _replay_backend(call, loop)
        payload = backend.replay("s", "f1")
    assert payload == {"replayed": True, "flow_id": "f1"}
    assert calls == [("replay.client", ["f1-copy"])]


def test_replay_times_out_when_the_command_hangs(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxymod, "_REPLAY_WAIT_S", 0.1)

    def call(name: str, args: list[Any]) -> None:
        time.sleep(1.0)

    with _running_loop() as loop:
        backend, _ = _replay_backend(call, loop)
        with pytest.raises(ProxyError) as caught:
            backend.replay("s", "f1")
    assert caught.value.code == "timeout"


def test_replay_wraps_an_unstructured_command_failure() -> None:
    def call(name: str, args: list[Any]) -> None:
        raise RuntimeError("replay boom")

    with _running_loop() as loop:
        backend, _ = _replay_backend(call, loop)
        with pytest.raises(ProxyError) as caught:
            backend.replay("s", "f1")
    assert caught.value.code == "backend_error"


def test_replay_passes_through_a_structured_command_failure() -> None:
    def call(name: str, args: list[Any]) -> None:
        raise ProxyError("invalid_state", "structured")

    with _running_loop() as loop:
        backend, _ = _replay_backend(call, loop)
        with pytest.raises(ProxyError) as caught:
            backend.replay("s", "f1")
    assert caught.value.code == "invalid_state"


# ---------------------------------------------------------------------------
# ca_cert_path / close_all.
# ---------------------------------------------------------------------------
def test_ca_cert_path_finds_a_cert(tmp_path: Path, monkeypatch: Any) -> None:
    (tmp_path / ".mitmproxy").mkdir()
    cert = tmp_path / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    cert.write_text("CERT", encoding="utf-8")
    monkeypatch.setattr(proxymod.Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() == cert


def test_ca_cert_path_is_none_when_absent(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(proxymod.Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() is None


def test_close_all_stops_every_instance() -> None:
    backend = ProxyBackend()
    stopped: list[str] = []
    backend._instances["a"] = SimpleNamespace(stop=lambda: stopped.append("a"))
    backend._instances["b"] = SimpleNamespace(stop=lambda: stopped.append("b"))
    backend.close_all()
    assert sorted(stopped) == ["a", "b"]
    assert backend._instances == {}
