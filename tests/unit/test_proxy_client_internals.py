"""ProxyBackend must bound every buffer and wrap every mitmproxy failure.

The flow-shape, error-flow, header-bound and port-reservation modules pin the
success payloads and the argument guards; this module drives the machinery they
sit on:

* the asyncio/logging teardown helpers that actually free the listening socket,
* the metadata/body length shims that must degrade a hostile shape to a bounded
  answer rather than raise,
* the ``_FlowRecorder`` retain-ring omission and lockstep eviction,
* ``_ProxyInstance.start`` reporting a thread error / early exit / readiness /
  timeout, and ``_run`` recording a missing mitmproxy import,
* the per-method ``not_found`` / ``too_large`` / ``invalid_state`` / ``timeout``
  envelopes (flow_get, replay), plus close_all and ca_cert_path.

mitmproxy is not installed in CI, so ``_run`` is called directly to exercise the
import-failure path with no real proxy, and ``start`` is driven with a fake
thread body and monkeypatched port probes -- no socket, no DumpMaster.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy
from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOW_HEADERS_TOTAL_BYTES,
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
    _ProxyInstance,
    _raw_body,
    _shutdown_loop,
    _uninstall_master_logging,
)

# --------------------------------------------------------------------------
# asyncio / logging teardown helpers
# --------------------------------------------------------------------------


def test_shutdown_loop_cancels_pending_tasks_then_closes() -> None:
    loop = asyncio.new_event_loop()

    async def sleeper() -> None:
        await asyncio.sleep(100)

    loop.create_task(sleeper())
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_shutdown_loop_closes_an_idle_loop() -> None:
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_port_accepts_is_false_for_an_unresolvable_host() -> None:
    # getaddrinfo raises an OSError subclass, which the probe swallows.
    assert _port_accepts("no.such.host.invalid.", 9) is False


def test_uninstall_master_logging_is_a_noop_without_master_or_loop() -> None:
    _uninstall_master_logging(None, None)


def test_uninstall_master_logging_removes_only_matching_handlers() -> None:
    root = logging.getLogger()

    class _Handler(logging.Handler):
        def __init__(self, owner: object) -> None:
            super().__init__()
            self.master = owner

        def emit(self, record: logging.LogRecord) -> None:
            return None

    uninstalled: list[int] = []
    master = SimpleNamespace(
        _legacy_log_events=SimpleNamespace(uninstall=lambda: uninstalled.append(1))
    )
    matching = _Handler(master)
    foreign = _Handler(object())
    plain = logging.Handler()
    for handler in (matching, foreign, plain):
        root.addHandler(handler)
    try:
        _uninstall_master_logging(master, None)
        assert uninstalled == [1]
        assert matching not in root.handlers
        assert foreign in root.handlers  # a different owner is left alone
        assert plain in root.handlers  # a handler with no master is left alone
    finally:
        for handler in (matching, foreign, plain):
            with contextlib.suppress(Exception):
                root.removeHandler(handler)


def test_drain_proxy_servers_swallows_a_broken_addon_surface() -> None:
    class _Addons:
        def get(self, name: str) -> Any:
            raise RuntimeError("addon surface changed")

    master = SimpleNamespace(addons=_Addons())
    # No exception escapes even though the addon lookup raised.
    _drain_proxy_servers(master, loop=object())  # type: ignore[arg-type]


def test_drain_proxy_servers_returns_when_there_is_no_update() -> None:
    master = SimpleNamespace(addons=SimpleNamespace(get=lambda name: SimpleNamespace(servers=None)))
    _drain_proxy_servers(master, loop=object())  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# length / body shims degrade hostile shapes
# --------------------------------------------------------------------------


def test_content_len_survives_a_sizeless_body() -> None:
    assert _content_len(SimpleNamespace(raw_content=object())) == 0


def test_content_len_is_zero_for_none() -> None:
    assert _content_len(None) == 0


def test_encoded_len_survives_a_raising_str() -> None:
    class _BadStr:
        def __str__(self) -> str:
            raise ValueError("cannot render")

    assert _encoded_len(_BadStr()) > 0


def test_headers_len_survives_a_raising_header_map() -> None:
    class _Headers:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("iteration failed")

    assert _headers_len(SimpleNamespace(headers=_Headers())) == 0


def test_raw_body_is_empty_for_none() -> None:
    assert _raw_body(None) == b""


def test_raw_body_is_empty_for_non_bytes_content() -> None:
    assert _raw_body(SimpleNamespace(raw_content="not bytes")) == b""


def test_bounded_headers_returns_truncated_when_iteration_fails() -> None:
    class _Headers:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("iteration failed")

    out, truncated = _bounded_headers(SimpleNamespace(headers=_Headers()))
    assert out == {}
    assert truncated is True


def test_bounded_headers_caps_the_total_size() -> None:
    # Each value is under the per-value cap, but their sum blows the total cap
    # before the count cap is reached.
    value = "z" * 1024
    headers = {f"h{index}": value for index in range(100)}
    out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
    assert truncated is True
    total = sum(len(k.encode()) + len(v.encode()) for k, v in out.items())
    assert total <= _MAX_FLOW_HEADERS_TOTAL_BYTES


# --------------------------------------------------------------------------
# _FlowRecorder retain-ring omission
# --------------------------------------------------------------------------


def _body_flow(flow_id: str, body_len: int) -> Any:
    body = b"x" * body_len
    request = SimpleNamespace(
        method="GET", pretty_url=f"http://x/{flow_id}", host="x", raw_content=body, headers={}
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=b""
    )
    return SimpleNamespace(id=flow_id, request=request, response=response)


def test_record_omits_a_flow_that_alone_exceeds_the_per_flow_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy, "_MAX_STORED_BODY", 32)
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_body_flow("big", 200))
    assert recorder.snapshot()[0]["body_omitted"] is True
    assert recorder.raw("big") is _OMITTED_BODY


def test_record_evicts_older_bodies_to_stay_under_the_retain_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy, "_MAX_STORED_BODY", 10_000)
    monkeypatch.setattr(proxy, "_MAX_RETAINED_BYTES", 120)
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_body_flow("a", 40))
    recorder.response(_body_flow("b", 40))
    # Adding a third body pushes the total over 120, so the oldest retained
    # body is omitted to make room.
    recorder.response(_body_flow("c", 40))
    assert recorder.raw("a") is _OMITTED_BODY
    by_id = {row["id"]: row for row in recorder.snapshot()}
    assert by_id["a"]["body_omitted"] is True
    assert recorder.retained_bytes() <= 120


def test_omit_retained_ignores_unknown_or_already_omitted_ids() -> None:
    recorder = _FlowRecorder(capacity=8)
    # Neither raises, and nothing changes.
    recorder._omit_retained("never-seen")
    recorder._raw["ghost"] = _OMITTED_BODY
    recorder._omit_retained("ghost")
    assert recorder.raw("ghost") is _OMITTED_BODY


def test_omit_retained_tolerates_a_raw_entry_with_no_summary() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_body_flow("real", 10))
    # A raw entry with no matching summary: the marking loop must simply finish
    # without finding a row to flag.
    flow = _body_flow("orphan", 10)
    recorder._raw["orphan"] = flow
    recorder._raw_sizes["orphan"] = 10
    recorder._retained_bytes += 10
    recorder._omit_retained("orphan")
    assert recorder.raw("orphan") is _OMITTED_BODY


# --------------------------------------------------------------------------
# _ProxyInstance.start and _run
# --------------------------------------------------------------------------


def test_start_reports_a_thread_error_as_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy, "_port_accepts", lambda host, port, timeout=0.25: False)
    monkeypatch.setattr(proxy, "_port_bindable", lambda host, port: True)
    inst = _ProxyInstance("127.0.0.1", 8080)

    def fake_run() -> None:
        inst._error = RuntimeError("mitmproxy blew up")

    inst._run = fake_run  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as caught:
        inst.start(timeout=1.0)
    assert caught.value.code == "backend_error"


def test_start_reports_an_early_thread_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy, "_port_accepts", lambda host, port, timeout=0.25: False)
    monkeypatch.setattr(proxy, "_port_bindable", lambda host, port: True)
    inst = _ProxyInstance("127.0.0.1", 8081)
    inst._run = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as caught:
        inst.start(timeout=1.0)
    assert caught.value.code == "backend_error"
    assert "exited" in caught.value.message


def test_start_returns_once_the_port_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def flaky_accepts(host: str, port: int, timeout: float = 0.25) -> bool:
        calls["n"] += 1
        # The initial in-use guard sees "free", the readiness probe sees "up".
        return calls["n"] > 1

    monkeypatch.setattr(proxy, "_port_accepts", flaky_accepts)
    monkeypatch.setattr(proxy, "_port_bindable", lambda host, port: True)
    inst = _ProxyInstance("127.0.0.1", 8082)
    inst._run = lambda: time.sleep(1.0)  # type: ignore[method-assign]
    inst.start(timeout=2.0)  # returns without raising


def test_start_times_out_when_the_port_never_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy, "_port_accepts", lambda host, port, timeout=0.25: False)
    monkeypatch.setattr(proxy, "_port_bindable", lambda host, port: True)
    inst = _ProxyInstance("127.0.0.1", 8083)
    inst._run = lambda: time.sleep(1.3)  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as caught:
        inst.start(timeout=1.0)
    assert caught.value.code == "timeout"


def test_run_records_a_missing_mitmproxy_import() -> None:
    # mitmproxy is not installed in CI, so _run's import fails and it records the
    # error for the starting thread rather than raising out of the daemon.
    inst = _ProxyInstance("127.0.0.1", 8084)
    inst._run()
    assert inst._error is not None
    assert inst._started.is_set()


# --------------------------------------------------------------------------
# ProxyBackend method envelopes
# --------------------------------------------------------------------------


def test_check_available_raises_when_mitmproxy_is_absent() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"
    assert backend._available is False


def test_start_skips_a_non_matching_reservation(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ProxyBackend()
    backend._available = True
    # A session already holding a different endpoint must not block a new one;
    # the loop scans past it. Stub the instance start so no real proxy launches.
    other = _ProxyInstance("127.0.0.1", 9000)
    backend._instances["other"] = other
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    payload = backend.start("new", "127.0.0.1", 8080)
    assert payload["running"] is True
    assert payload["endpoint"] == "127.0.0.1:8080"


def test_start_unreserves_the_port_when_the_listen_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A failed listen must not leave the reservation behind; otherwise the port
    # looks taken forever and the session can never be retried.
    backend = ProxyBackend()
    backend._available = True
    stopped: list[int] = []

    def boom(self: _ProxyInstance, timeout: float = 15.0) -> None:
        raise ProxyError("backend_error", "listen failed")

    monkeypatch.setattr(_ProxyInstance, "start", boom)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: stopped.append(self.port))
    with pytest.raises(ProxyError) as caught:
        backend.start("sess", "127.0.0.1", 8080)
    assert caught.value.code == "backend_error"
    assert backend._instances == {}
    assert stopped == [8080]


def test_start_reports_a_session_closed_while_it_was_starting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If a concurrent close drops the reservation while start() is still
    # bringing the proxy up, the winner is the close: the just-started proxy is
    # torn back down and the caller is told the start was pre-empted.
    backend = ProxyBackend()
    backend._available = True
    stopped: list[int] = []

    def steal(self: _ProxyInstance, timeout: float = 15.0) -> None:
        backend._instances.clear()

    monkeypatch.setattr(_ProxyInstance, "start", steal)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: stopped.append(self.port))
    with pytest.raises(ProxyError) as caught:
        backend.start("sess", "127.0.0.1", 8080)
    assert caught.value.code == "invalid_state"
    assert "stopped while starting" in caught.value.message
    assert stopped == [8080]


def test_flows_reports_zero_dropped_for_an_empty_ring(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ProxyBackend()
    inst = SimpleNamespace(recorder=_FlowRecorder(capacity=4))
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    payload = backend.flows("s")
    assert payload == {
        "flows": [],
        "count": 0,
        "total": 0,
        "offset": 0,
        "has_more": False,
        "dropped": 0,
    }


def _backend_with_raw(raw: Any, monkeypatch: pytest.MonkeyPatch) -> ProxyBackend:
    backend = ProxyBackend()
    inst = SimpleNamespace(recorder=SimpleNamespace(raw=lambda flow_id: raw))
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


def test_flow_get_rejects_an_unknown_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _backend_with_raw(None, monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "missing", tmp_path)
    assert caught.value.code == "not_found"


def test_flow_get_rejects_an_omitted_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _backend_with_raw(_OMITTED_BODY, monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "big", tmp_path)
    assert caught.value.code == "too_large"


def test_flow_get_flags_truncated_request_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    huge_url = "http://x/" + "u" * (proxy._MAX_URL_BYTES + 10)
    request = SimpleNamespace(method="GET", pretty_url=huge_url, headers={}, raw_content=b"")
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"")
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend_with_raw(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["request"]["metadata_truncated"] is True


def _replay_backend(
    flow: Any, master: Any, loop: Any, monkeypatch: pytest.MonkeyPatch
) -> ProxyBackend:
    backend = ProxyBackend()
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow), _master=master, _loop=loop
    )
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


class _InlineLoop:
    def call_soon_threadsafe(self, fn: Any) -> None:
        fn()


class _DeadLoop:
    def call_soon_threadsafe(self, fn: Any) -> None:
        return None


def test_replay_rejects_an_unknown_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _replay_backend(None, object(), _InlineLoop(), monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "missing")
    assert caught.value.code == "not_found"


def test_replay_rejects_an_omitted_body(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _replay_backend(_OMITTED_BODY, object(), _InlineLoop(), monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "big")
    assert caught.value.code == "too_large"


def test_replay_requires_a_running_master(monkeypatch: pytest.MonkeyPatch) -> None:
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    backend = _replay_backend(flow, None, _InlineLoop(), monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "f1")
    assert caught.value.code == "invalid_state"


def test_replay_succeeds_when_the_command_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    master = SimpleNamespace(commands=SimpleNamespace(call=lambda cmd, args: None))
    backend = _replay_backend(flow, master, _InlineLoop(), monkeypatch)
    payload = backend.replay("s", "f1")
    assert payload == {"replayed": True, "flow_id": "f1"}


def test_replay_maps_a_command_failure_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(cmd: str, args: Any) -> None:
        raise RuntimeError("no such command")

    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    master = SimpleNamespace(commands=SimpleNamespace(call=boom))
    backend = _replay_backend(flow, master, _InlineLoop(), monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "f1")
    assert caught.value.code == "backend_error"


def test_replay_passes_a_proxyerror_through(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_proxy(cmd: str, args: Any) -> None:
        raise ProxyError("invalid_state", "already structured")

    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    master = SimpleNamespace(commands=SimpleNamespace(call=raise_proxy))
    backend = _replay_backend(flow, master, _InlineLoop(), monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "f1")
    assert caught.value.code == "invalid_state"


def test_replay_times_out_when_the_command_never_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy, "_REPLAY_WAIT_S", 0.05)
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    master = SimpleNamespace(commands=SimpleNamespace(call=lambda cmd, args: None))
    backend = _replay_backend(flow, master, _DeadLoop(), monkeypatch)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "f1")
    assert caught.value.code == "timeout"


def test_ca_cert_path_finds_a_generated_cert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_dir = tmp_path / ".mitmproxy"
    cert_dir.mkdir()
    (cert_dir / "mitmproxy-ca-cert.pem").write_text("CERT")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    found = ProxyBackend().ca_cert_path()
    assert found is not None
    assert found.name == "mitmproxy-ca-cert.pem"


def test_ca_cert_path_is_none_without_a_cert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert ProxyBackend().ca_cert_path() is None


def test_close_all_stops_every_instance() -> None:
    backend = ProxyBackend()
    stopped: list[str] = []
    backend._instances["a"] = SimpleNamespace(stop=lambda: stopped.append("a"))  # type: ignore[assignment]
    backend._instances["b"] = SimpleNamespace(stop=lambda: stopped.append("b"))  # type: ignore[assignment]
    backend.close_all()
    assert set(stopped) == {"a", "b"}
    assert backend._instances == {}
