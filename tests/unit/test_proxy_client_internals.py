"""ProxyBackend and _ProxyInstance internals, reached without a real mitmproxy.

The flow-recording behaviour is pinned in the sibling proxy tests; this file
drives the parts that only a defensively written embed exercises: the socket
readiness probes, the retain-ring's byte-eviction and body omission, the master
logging teardown, and the ProxyBackend control surface (capability gate, port
reservation, start rollback, flow_get/replay envelopes, CA lookup). mitmproxy
is not installed here, so start() degrades to capability_unavailable and the
proxy thread fails fast on import -- both are exercised on purpose.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOW_HEADERS_TOTAL_BYTES,
    _MAX_HEADER_VALUE_BYTES,
    _MAX_INLINE_BODY,
    _MAX_RETAINED_BYTES,
    _MAX_STORED_BODY,
    _MAX_URL_BYTES,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _content_len,
    _drain_proxy_servers,
    _encoded_len,
    _FlowRecorder,
    _headers_len,
    _port_accepts,
    _port_bindable,
    _ProxyInstance,
    _raw_body,
    _shutdown_loop,
    _uninstall_master_logging,
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# --------------------------------------------------------------------------
# asyncio / socket helpers
# --------------------------------------------------------------------------
def test_shutdown_loop_cancels_pending_tasks_and_closes() -> None:
    loop = asyncio.new_event_loop()

    async def _forever() -> None:
        await asyncio.sleep(3600)

    loop.create_task(_forever())
    _shutdown_loop(loop)
    assert loop.is_closed() is True


def test_shutdown_loop_closes_an_idle_loop() -> None:
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed() is True


def test_port_probes_track_a_live_listener() -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()
    try:
        assert _port_accepts(host, port) is True
        assert _port_bindable(host, port) is False
    finally:
        srv.close()
    assert _port_accepts(host, port) is False
    assert _port_bindable(host, port) is True


# --------------------------------------------------------------------------
# master logging teardown / server drain
# --------------------------------------------------------------------------
def test_uninstall_master_logging_returns_early_when_nothing_to_do() -> None:
    # Both None: there is nothing to detach and the function must not touch the
    # root logger's handler list.
    _uninstall_master_logging(None, None)


class _FakeLegacy:
    def __init__(self) -> None:
        self.uninstalled = False

    def uninstall(self) -> None:
        self.uninstalled = True


def test_uninstall_master_logging_detaches_the_legacy_and_root_handlers() -> None:
    root = logging.getLogger()
    legacy = _FakeLegacy()
    master = SimpleNamespace(_legacy_log_events=legacy, event_loop=None)
    handler = logging.NullHandler()
    handler.master = master  # type: ignore[attr-defined]
    root.addHandler(handler)
    try:
        _uninstall_master_logging(master)
        assert legacy.uninstalled is True
        assert handler not in root.handlers
    finally:
        if handler in root.handlers:
            root.removeHandler(handler)


def test_uninstall_master_logging_matches_a_handler_by_loop() -> None:
    root = logging.getLogger()
    loop = asyncio.new_event_loop()
    try:
        orphan_master = SimpleNamespace(event_loop=loop)
        handler = logging.NullHandler()
        handler.master = orphan_master  # type: ignore[attr-defined]
        unrelated = logging.NullHandler()  # no .master -> skipped
        root.addHandler(handler)
        root.addHandler(unrelated)
        try:
            _uninstall_master_logging(None, loop)
            assert handler not in root.handlers
            assert unrelated in root.handlers
        finally:
            for candidate in (handler, unrelated):
                if candidate in root.handlers:
                    root.removeHandler(candidate)
    finally:
        loop.close()


def test_drain_proxy_servers_swallows_an_addon_surface_error() -> None:
    def _boom(_name: str) -> Any:
        raise RuntimeError("addon registry unavailable")

    master = SimpleNamespace(addons=SimpleNamespace(get=_boom))
    # Must return, not raise, when the addon surface differs across versions.
    _drain_proxy_servers(master, object())  # type: ignore[arg-type]


def test_drain_proxy_servers_returns_when_no_update_hook() -> None:
    addon = SimpleNamespace(servers=SimpleNamespace())  # no .update
    master = SimpleNamespace(addons=SimpleNamespace(get=lambda _name: addon))
    _drain_proxy_servers(master, object())  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# length / body helpers
# --------------------------------------------------------------------------
def test_content_len_is_zero_when_len_raises() -> None:
    assert _content_len(SimpleNamespace(raw_content=5)) == 0


def test_encoded_len_falls_back_when_str_raises() -> None:
    class _Bad:
        def __str__(self) -> str:
            raise ValueError("no string form")

    assert _encoded_len(_Bad()) == _MAX_STORED_BODY + 1


def test_headers_len_breaks_once_it_passes_the_cap() -> None:
    big = "z" * (_MAX_STORED_BODY + 100)
    part = SimpleNamespace(headers=SimpleNamespace(items=lambda **_kw: [("k", big)]))
    assert _headers_len(part) > _MAX_STORED_BODY


def test_headers_len_is_zero_when_items_raises() -> None:
    def _explode(**_kw: Any) -> Any:
        raise ValueError("headers gone")

    assert _headers_len(SimpleNamespace(headers=SimpleNamespace(items=_explode))) == 0


def test_raw_body_of_a_missing_part_is_empty() -> None:
    assert _raw_body(None) == b""


def test_raw_body_of_a_non_bytes_body_is_empty() -> None:
    assert _raw_body(SimpleNamespace(raw_content="not bytes")) == b""


def test_bounded_headers_returns_truncated_when_items_raises() -> None:
    def _explode(**_kw: Any) -> Any:
        raise ValueError("headers gone")

    out, truncated = _bounded_headers(SimpleNamespace(headers=SimpleNamespace(items=_explode)))
    assert out == {}
    assert truncated is True


def test_bounded_headers_stops_at_the_total_byte_budget() -> None:
    value = "v" * _MAX_HEADER_VALUE_BYTES
    many = {f"h{index}": value for index in range(64)}
    out, truncated = _bounded_headers(SimpleNamespace(headers=many))
    assert truncated is True
    total = sum(len(k.encode()) + len(v.encode()) for k, v in out.items())
    assert total <= _MAX_FLOW_HEADERS_TOTAL_BYTES


# --------------------------------------------------------------------------
# _FlowRecorder retain ring
# --------------------------------------------------------------------------
class _SizedContent:
    """A body that reports a length without allocating it.

    _content_len only calls len(); the retain-ring accounting can be driven to
    its byte cap this way without churning tens of megabytes of real bytes.
    """

    def __init__(self, size: int) -> None:
        self._size = size

    def __len__(self) -> int:
        return self._size

    def __bool__(self) -> bool:
        return self._size > 0


def _sized_flow(flow_id: str, body_size: int) -> Any:
    request = SimpleNamespace(
        method="GET",
        pretty_url=f"http://x/{flow_id}",
        host="x",
        raw_content=_SizedContent(body_size),
        headers={},
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "application/octet-stream"},
        raw_content=_SizedContent(0),
    )
    return SimpleNamespace(id=flow_id, request=request, response=response)


def test_recorder_omits_a_flow_larger_than_the_per_flow_cap() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_sized_flow("huge", _MAX_STORED_BODY + 1))
    row = recorder.snapshot()[0]
    assert row["body_omitted"] is True
    assert recorder.raw("huge") is _OMITTED_BODY


def test_recorder_evicts_retained_bodies_once_the_byte_budget_is_passed() -> None:
    recorder = _FlowRecorder(capacity=2000)
    per_flow = _MAX_STORED_BODY - 50_000  # each retained, none self-omitted
    count = (_MAX_RETAINED_BYTES // per_flow) + 5
    for index in range(count):
        recorder.response(_sized_flow(f"f{index}", per_flow))
    assert recorder.retained_bytes() <= _MAX_RETAINED_BYTES
    # The earliest flow's body was surrendered to make room; its summary says so
    # and its raw slot now reads as omitted, in lockstep.
    assert recorder.raw("f0") is _OMITTED_BODY
    first = next(row for row in recorder.snapshot() if row["id"] == "f0")
    assert first["body_omitted"] is True


def test_recorder_evicts_oldest_when_the_count_cap_is_passed() -> None:
    recorder = _FlowRecorder(capacity=2)
    for index in range(3):
        recorder.response(_sized_flow(f"c{index}", 10))
    ids = {row["id"] for row in recorder.snapshot()}
    assert ids == {"c1", "c2"}
    assert recorder.raw("c0") is None


# --------------------------------------------------------------------------
# ProxyBackend control surface
# --------------------------------------------------------------------------
def test_start_reports_capability_unavailable_without_mitmproxy() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s")
    assert excinfo.value.code == "capability_unavailable"


def test_get_refuses_a_session_with_no_proxy() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as excinfo:
        backend.flows("nope")
    assert excinfo.value.code == "invalid_state"


def test_start_rejects_an_out_of_range_port() -> None:
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s", port=0)
    assert excinfo.value.code == "invalid_params"


def test_start_refuses_a_session_that_already_has_a_proxy() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s")
    assert excinfo.value.code == "invalid_state"
    assert "already running" in excinfo.value.message


def test_start_refuses_a_port_reserved_by_another_session() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["other"] = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s", host="127.0.0.1", port=8080)
    assert excinfo.value.code == "invalid_state"
    assert excinfo.value.details.get("owner_session_id") == "other"


def test_start_rolls_back_the_reservation_when_the_instance_fails(monkeypatch: Any) -> None:
    backend = ProxyBackend()
    backend._available = True

    def _boom(self: Any, timeout: float = 15.0) -> None:
        raise ProxyError("backend_error", "mitmproxy failed to start")

    monkeypatch.setattr(_ProxyInstance, "start", _boom)
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s")
    assert excinfo.value.code == "backend_error"
    assert "s" not in backend._instances


def test_start_reports_the_endpoint_on_success(monkeypatch: Any) -> None:
    backend = ProxyBackend()
    backend._available = True
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    try:
        data = backend.start("s", host="127.0.0.1", port=9091)
        assert data["running"] is True
        assert data["endpoint"] == "127.0.0.1:9091"
    finally:
        backend.close_all()


def test_start_fails_when_the_session_is_dropped_mid_start(monkeypatch: Any) -> None:
    backend = ProxyBackend()
    backend._available = True

    def _drop(self: Any, timeout: float = 15.0) -> None:
        backend._instances.clear()

    monkeypatch.setattr(_ProxyInstance, "start", _drop)
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s")
    assert excinfo.value.code == "invalid_state"
    assert "stopped while starting" in excinfo.value.message


def test_stop_returns_a_no_op_note_when_nothing_runs() -> None:
    assert ProxyBackend().stop("s") == {"stopped": False, "note": "no proxy was running"}


def test_stop_stops_the_instance_it_pops() -> None:
    backend = ProxyBackend()
    stopped: list[bool] = []
    backend._instances["s"] = SimpleNamespace(stop=lambda: stopped.append(True))  # type: ignore[assignment]
    assert backend.stop("s") == {"stopped": True}
    assert stopped == [True]
    assert "s" not in backend._instances


def test_status_without_a_proxy_reports_not_running() -> None:
    assert ProxyBackend().status("s") == {"running": False}


def test_status_reports_recorder_counters() -> None:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(  # type: ignore[assignment]
        host="127.0.0.1",
        port=8080,
        recorder=SimpleNamespace(count=lambda: 3, retained_bytes=lambda: 4096),
    )
    data = backend.status("s")
    assert data["running"] is True
    assert data["flow_count"] == 3
    assert data["retained_bytes"] == 4096


def test_flows_reports_the_dropped_count() -> None:
    backend = ProxyBackend()
    snapshot = [{"seq": 5, "id": "a"}, {"seq": 6, "id": "b"}]
    backend._instances["s"] = SimpleNamespace(  # type: ignore[assignment]
        recorder=SimpleNamespace(snapshot=lambda: snapshot)
    )
    data = backend.flows("s")
    assert data["total"] == 2
    assert data["dropped"] == 4
    assert data["has_more"] is False


def test_flows_on_an_empty_capture_reports_nothing_dropped() -> None:
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(  # type: ignore[assignment]
        recorder=SimpleNamespace(snapshot=list)
    )
    data = backend.flows("s")
    assert data["total"] == 0
    assert data["count"] == 0
    assert data["dropped"] == 0
    assert data["has_more"] is False


def _backend_with_flow(flow: Any, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    inst = SimpleNamespace(recorder=recorder, _master=object(), _loop=object())
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


def test_flow_get_reports_not_found_for_an_unknown_flow(tmp_path: Path, monkeypatch: Any) -> None:
    backend = _backend_with_flow(None, monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.flow_get("s", "gone", tmp_path)
    assert excinfo.value.code == "not_found"


def test_flow_get_reports_too_large_for_an_omitted_body(tmp_path: Path, monkeypatch: Any) -> None:
    backend = _backend_with_flow(_OMITTED_BODY, monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.flow_get("s", "big", tmp_path)
    assert excinfo.value.code == "too_large"


def test_flow_get_flags_a_truncated_request_url(tmp_path: Path, monkeypatch: Any) -> None:
    request = SimpleNamespace(
        method="GET", pretty_url="h" * (_MAX_URL_BYTES + 10), headers={}
    )
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"")
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend_with_flow(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["request"]["metadata_truncated"] is True


def test_flow_get_spills_a_binary_body(tmp_path: Path, monkeypatch: Any) -> None:
    binary = bytes(range(256)) * 4  # small, but not valid UTF-8
    assert len(binary) <= _MAX_INLINE_BODY
    request = SimpleNamespace(method="POST", pretty_url="http://x/1", headers={}, raw_content=b"")
    response = SimpleNamespace(status_code=200, headers={}, raw_content=binary)
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend_with_flow(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["response"]["spill_reason"] == "binary"
    assert Path(payload["response"]["body_path"]).is_file()


# --------------------------------------------------------------------------
# replay
# --------------------------------------------------------------------------
class _SyncLoop:
    def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
        fn(*args)


class _DeadLoop:
    def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
        return None


def _replay_backend(flow: Any, master: Any, loop: Any, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow), _master=master, _loop=loop
    )
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


def test_replay_reports_not_found(monkeypatch: Any) -> None:
    backend = _replay_backend(None, object(), _SyncLoop(), monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.replay("s", "gone")
    assert excinfo.value.code == "not_found"


def test_replay_reports_too_large_for_an_omitted_flow(monkeypatch: Any) -> None:
    backend = _replay_backend(_OMITTED_BODY, object(), _SyncLoop(), monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.replay("s", "big")
    assert excinfo.value.code == "too_large"


def test_replay_reports_invalid_state_when_the_proxy_is_gone(monkeypatch: Any) -> None:
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    backend = _replay_backend(flow, None, None, monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.replay("s", "f1")
    assert excinfo.value.code == "invalid_state"


def test_replay_succeeds_and_names_the_flow(monkeypatch: Any) -> None:
    calls: list[tuple[str, Any]] = []
    master = SimpleNamespace(
        commands=SimpleNamespace(call=lambda name, args: calls.append((name, args)))
    )
    flow = SimpleNamespace(copy=lambda: SimpleNamespace(tag="copied"))
    backend = _replay_backend(flow, master, _SyncLoop(), monkeypatch)
    data = backend.replay("s", "f1")
    assert data == {"replayed": True, "flow_id": "f1"}
    assert calls and calls[0][0] == "replay.client"


def test_replay_maps_a_backend_failure(monkeypatch: Any) -> None:
    def _call(name: str, args: Any) -> None:
        raise RuntimeError("replay refused")

    master = SimpleNamespace(commands=SimpleNamespace(call=_call))
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    backend = _replay_backend(flow, master, _SyncLoop(), monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.replay("s", "f1")
    assert excinfo.value.code == "backend_error"


def test_replay_times_out_when_the_loop_never_runs_it(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_REPLAY_WAIT_S", 0.05)
    master = SimpleNamespace(commands=SimpleNamespace(call=lambda name, args: None))
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    backend = _replay_backend(flow, master, _DeadLoop(), monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.replay("s", "f1")
    assert excinfo.value.code == "timeout"


# --------------------------------------------------------------------------
# ca_cert_path / close_all
# --------------------------------------------------------------------------
def test_ca_cert_path_finds_a_generated_cert(tmp_path: Path, monkeypatch: Any) -> None:
    mitm = tmp_path / ".mitmproxy"
    mitm.mkdir()
    cert = mitm / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() == cert


def test_ca_cert_path_is_none_when_absent(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() is None


def test_close_all_stops_every_instance() -> None:
    backend = ProxyBackend()
    stopped: list[str] = []
    for name in ("a", "b"):
        backend._instances[name] = SimpleNamespace(  # type: ignore[assignment]
            stop=lambda name=name: stopped.append(name)
        )
    backend.close_all()
    assert sorted(stopped) == ["a", "b"]
    assert backend._instances == {}


# --------------------------------------------------------------------------
# _ProxyInstance start/stop
# --------------------------------------------------------------------------
def test_instance_stop_is_a_no_op_before_start() -> None:
    _ProxyInstance("127.0.0.1", 9).stop()  # master/loop/thread all None


def test_instance_start_refuses_a_port_already_in_use() -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()
    try:
        with pytest.raises(ProxyError) as excinfo:
            _ProxyInstance(host, port).start(timeout=1.0)
        assert excinfo.value.code == "invalid_state"
    finally:
        srv.close()


def test_instance_start_reports_backend_error_when_mitmproxy_is_missing() -> None:
    # The proxy thread imports mitmproxy, which is absent here, so it fails fast
    # and start() surfaces that as backend_error rather than hanging.
    inst = _ProxyInstance("127.0.0.1", _free_port())
    with pytest.raises(ProxyError) as excinfo:
        inst.start(timeout=5.0)
    assert excinfo.value.code == "backend_error"


def test_instance_start_reports_backend_error_when_the_thread_exits(monkeypatch: Any) -> None:
    monkeypatch.setattr(_ProxyInstance, "_run", lambda self: None)
    inst = _ProxyInstance("127.0.0.1", _free_port())
    with pytest.raises(ProxyError) as excinfo:
        inst.start(timeout=2.0)
    assert excinfo.value.code == "backend_error"


def test_instance_start_times_out_when_it_never_binds(monkeypatch: Any) -> None:
    def _linger(self: Any) -> None:
        time.sleep(1.3)

    monkeypatch.setattr(_ProxyInstance, "_run", _linger)
    inst = _ProxyInstance("127.0.0.1", _free_port())
    with pytest.raises(ProxyError) as excinfo:
        inst.start(timeout=0.1)
    assert excinfo.value.code == "timeout"
