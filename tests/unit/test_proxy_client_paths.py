"""Helper, lifecycle, and method guard paths for the proxy (mitmproxy) backend.

The field contracts, the flow-error hook, the header/body bounds and the
stop() drain wiring already live in the other ``test_proxy_*`` files. This one
covers the layers those skip: the loop/port/logging helpers that run without
mitmproxy, the byte-accounting helpers and their defensive arms, the
``_FlowRecorder`` omit/eviction bookkeeping, the ``ProxyBackend.start`` reserve
and rollback branches (with ``_ProxyInstance.start`` faked so no real proxy is
launched), and the not-found/too-large/replay/export arms of the read tools.

mitmproxy is optional; nothing here needs it installed. The one startup-failure
test that depends on the module being absent is skipped when it is present so a
host with mitmproxy still runs green.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_mod
from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOW_HEADERS_TOTAL_BYTES,
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
    _ProxyInstance,
    _raw_body,
    _shutdown_loop,
    _uninstall_master_logging,
)

try:  # pragma: no cover - trivial import probe
    import mitmproxy  # noqa: F401

    _HAVE_MITMPROXY = True
except Exception:  # noqa: BLE001
    _HAVE_MITMPROXY = False


def _ok_flow(flow_id: str) -> Any:
    request = SimpleNamespace(method="GET", pretty_url=f"http://x/{flow_id}", host="x")
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
    return SimpleNamespace(id=flow_id, request=request, response=response)


# ---------------------------------------------------------------------------
# _shutdown_loop
# ---------------------------------------------------------------------------


def test_shutdown_loop_cancels_pending_tasks_and_closes() -> None:
    """A still-pending task must be cancelled and awaited, not abandoned.

    Abandoning it is what leaves the proxy's listening socket open at the OS
    level, so this pins that the loop is unwound and then closed.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:

        async def _sleep() -> None:
            await asyncio.sleep(100)

        task = asyncio.ensure_future(_sleep(), loop=loop)
        _shutdown_loop(loop)
    finally:
        asyncio.set_event_loop(None)
    assert task.cancelled()
    assert loop.is_closed()


def test_shutdown_loop_closes_a_loop_with_no_pending_tasks() -> None:
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


# ---------------------------------------------------------------------------
# _port_accepts
# ---------------------------------------------------------------------------


def test_port_accepts_is_false_for_a_closed_port() -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    host, port = probe.getsockname()
    probe.close()
    assert _port_accepts(host, port, timeout=0.1) is False


def test_port_accepts_swallows_a_socket_error(monkeypatch: Any) -> None:
    """A resolver/socket failure is not "listening"; it must read as False."""

    class _BadProbe:
        def __enter__(self) -> _BadProbe:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def settimeout(self, _timeout: float) -> None:
            pass

        def connect_ex(self, _addr: object) -> int:
            raise OSError("cannot resolve")

    monkeypatch.setattr(proxy_mod.socket, "socket", lambda *a, **k: _BadProbe())
    assert _port_accepts("host.invalid", 12345) is False


# ---------------------------------------------------------------------------
# _uninstall_master_logging
# ---------------------------------------------------------------------------


def test_uninstall_master_logging_removes_only_the_matching_loops_handler() -> None:
    """Detach by loop identity, leaving unrelated root handlers untouched.

    A constructor that raised after installing the handler leaves a master
    nothing else can reach, so removal has to key on the event loop, not just
    on the master object -- but a handler owned by a *different* loop, or by no
    master at all, must survive.
    """
    root = logging.getLogger()
    sentinel_loop = object()

    class _H(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover
            pass

    h_no_owner = _H()
    h_no_owner.master = None  # type: ignore[attr-defined]
    h_other_loop = _H()
    h_other_loop.master = SimpleNamespace(event_loop=object())  # type: ignore[attr-defined]
    h_match = _H()
    h_match.master = SimpleNamespace(event_loop=sentinel_loop)  # type: ignore[attr-defined]

    for handler in (h_no_owner, h_other_loop, h_match):
        root.addHandler(handler)
    try:
        _uninstall_master_logging(None, sentinel_loop)
        assert h_match not in root.handlers
        assert h_other_loop in root.handlers
        assert h_no_owner in root.handlers
    finally:
        for handler in (h_no_owner, h_other_loop, h_match):
            root.removeHandler(handler)


# ---------------------------------------------------------------------------
# _drain_proxy_servers
# ---------------------------------------------------------------------------


def test_drain_proxy_servers_swallows_a_broken_addon_surface() -> None:
    """The addon surface varies across versions; a failure must not raise."""
    loop = asyncio.new_event_loop()
    try:
        _drain_proxy_servers(object(), loop)  # object().addons -> AttributeError
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# byte-accounting helpers
# ---------------------------------------------------------------------------


def test_content_len_is_zero_when_len_raises_type_error() -> None:
    part = SimpleNamespace(raw_content=object())
    assert _content_len(part) == 0


def test_encoded_len_of_an_unstringable_value_is_over_the_cap() -> None:
    class _BadStr:
        def __str__(self) -> str:
            raise RuntimeError("no str")

    assert _encoded_len(_BadStr()) > proxy_mod._MAX_STORED_BODY


def test_headers_len_is_zero_when_iterating_raises() -> None:
    class _BadHeaders:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("boom")

    assert _headers_len(SimpleNamespace(headers=_BadHeaders())) == 0


def test_raw_body_is_empty_for_none_and_for_non_bytes() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content="not-bytes")) == b""


def test_bounded_headers_is_empty_and_truncated_when_iterating_raises() -> None:
    class _BadHeaders:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("boom")

    out, truncated = _bounded_headers(SimpleNamespace(headers=_BadHeaders()))
    assert out == {}
    assert truncated is True


def test_bounded_headers_stops_at_the_total_size_budget() -> None:
    per_value = "v" * 3000  # under the per-value cap, so nothing is value-clipped
    headers = {f"h{index}": per_value for index in range(40)}
    out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
    assert truncated is True
    total = sum(len(name.encode()) + len(value.encode()) for name, value in out.items())
    assert total <= _MAX_FLOW_HEADERS_TOTAL_BYTES
    assert len(out) < len(headers)


# ---------------------------------------------------------------------------
# _FlowRecorder omit / eviction bookkeeping
# ---------------------------------------------------------------------------


def test_omit_retained_is_a_noop_for_unknown_or_already_omitted_ids() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder._omit_retained("never-seen")  # retained is None -> early return

    recorder._raw["gone"] = _OMITTED_BODY
    recorder._omit_retained("gone")  # already omitted -> early return
    assert recorder._raw["gone"] is _OMITTED_BODY


def test_omit_retained_tolerates_a_raw_flow_with_no_surviving_summary() -> None:
    """The summary ring is shorter than the raw store here; omit must not raise.

    It walks ``reversed(flows)`` looking for the row to flag and simply stops
    when none matches, releasing the retained bytes regardless.
    """
    recorder = _FlowRecorder(capacity=8)
    recorder._raw["orphan"] = SimpleNamespace()
    recorder._raw_sizes["orphan"] = 10
    recorder._retained_bytes = 10
    recorder.flows.append({"id": "some-other-row"})

    recorder._omit_retained("orphan")

    assert recorder._raw["orphan"] is _OMITTED_BODY
    assert recorder._retained_bytes == 0


def test_record_skips_already_omitted_entries_when_reclaiming_bytes(
    monkeypatch: Any,
) -> None:
    """The retained-byte walker must step over entries it already omitted.

    Shrinking the retained-byte ceiling makes each new flow force the oldest
    live flow's body out; a second eviction pass then has to skip the entry it
    omitted last time instead of double-counting it.
    """
    monkeypatch.setattr(proxy_mod, "_MAX_RETAINED_BYTES", 50)
    recorder = _FlowRecorder(capacity=8)

    recorder.response(_ok_flow("a"))
    recorder.response(_ok_flow("b"))
    recorder.response(_ok_flow("c"))

    assert recorder._raw["a"] is _OMITTED_BODY
    assert recorder._raw["b"] is _OMITTED_BODY
    assert recorder._raw["c"] is not _OMITTED_BODY
    by_id = {row["id"]: row for row in recorder.snapshot()}
    assert by_id["a"]["body_omitted"] is True
    assert by_id["b"]["body_omitted"] is True
    assert "body_omitted" not in by_id["c"]


# ---------------------------------------------------------------------------
# _ProxyInstance.start guards
# ---------------------------------------------------------------------------


def test_instance_start_refuses_a_port_that_is_already_accepting() -> None:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    host, port = listener.getsockname()
    try:
        inst = _ProxyInstance(host, port)
        with pytest.raises(ProxyError) as raised:
            inst.start(timeout=1.0)
        assert raised.value.code == "invalid_state"
    finally:
        listener.close()


@pytest.mark.skipif(_HAVE_MITMPROXY, reason="exercises the mitmproxy-missing startup failure")
def test_instance_start_reports_backend_error_when_mitmproxy_is_absent() -> None:
    """With mitmproxy uninstalled, the worker thread dies in import and start()
    surfaces that as a backend_error rather than hanging on the readiness probe."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    host, port = probe.getsockname()
    probe.close()
    inst = _ProxyInstance(host, port)
    with pytest.raises(ProxyError) as raised:
        inst.start(timeout=3.0)
    assert raised.value.code == "backend_error"


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    _host, port = probe.getsockname()
    probe.close()
    return int(port)


def test_instance_start_returns_once_the_worker_is_accepting(monkeypatch: Any) -> None:
    """Readiness is "the port accepts", not "the thread reached run()".

    A fake worker that actually binds and listens lets start() take its success
    arm without a real mitmproxy behind it.
    """
    release = threading.Event()

    def fake_run(self: _ProxyInstance) -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen()
        self._started.set()
        release.wait(2.0)
        server.close()

    monkeypatch.setattr(_ProxyInstance, "_run", fake_run)
    inst = _ProxyInstance("127.0.0.1", _free_port())
    try:
        inst.start(timeout=2.0)  # returns on the readiness probe, no exception
    finally:
        release.set()
        if inst._thread is not None:
            inst._thread.join(timeout=2.0)


def test_instance_start_detects_a_worker_that_exits_during_startup(
    monkeypatch: Any,
) -> None:
    """A worker that returns without binding is a failed start, not a hang."""

    def fake_run(self: _ProxyInstance) -> None:
        return  # exits immediately: no error recorded, nothing ever listens

    monkeypatch.setattr(_ProxyInstance, "_run", fake_run)
    inst = _ProxyInstance("127.0.0.1", _free_port())
    with pytest.raises(ProxyError) as raised:
        inst.start(timeout=2.0)
    assert raised.value.code == "backend_error"
    assert "exited during startup" in str(raised.value)


def test_instance_start_times_out_when_the_port_never_accepts(monkeypatch: Any) -> None:
    """A worker that stays alive but never binds must be stopped and reported."""
    release = threading.Event()
    stopped: list[bool] = []

    def fake_run(self: _ProxyInstance) -> None:
        self._started.set()
        release.wait(3.0)  # alive, but never binds or accepts

    monkeypatch.setattr(_ProxyInstance, "_run", fake_run)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: stopped.append(True))
    inst = _ProxyInstance("127.0.0.1", _free_port())
    try:
        with pytest.raises(ProxyError) as raised:
            inst.start(timeout=1.0)
        assert raised.value.code == "timeout"
        assert stopped == [True]
    finally:
        release.set()
        if inst._thread is not None:
            inst._thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# ProxyBackend._check_available
# ---------------------------------------------------------------------------


def test_check_available_caches_a_successful_import(monkeypatch: Any) -> None:
    monkeypatch.setitem(__import__("sys").modules, "mitmproxy", types.ModuleType("mitmproxy"))
    backend = ProxyBackend()
    backend._check_available()
    assert backend._available is True


# ---------------------------------------------------------------------------
# ProxyBackend.start reserve / rollback branches
# ---------------------------------------------------------------------------


def test_start_rejects_a_port_out_of_range() -> None:
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as raised:
        backend.start("s", port=70000)
    assert raised.value.code == "invalid_params"


def test_start_reserves_and_returns_the_endpoint(monkeypatch: Any) -> None:
    backend = ProxyBackend()
    backend._available = True
    started: list[tuple[str, int]] = []

    def fake_start(self: _ProxyInstance, timeout: float = 15.0) -> None:
        started.append((self.host, self.port))

    monkeypatch.setattr(_ProxyInstance, "start", fake_start)
    # A non-matching reservation exercises the port-conflict loop's skip arm.
    backend._instances["other"] = _ProxyInstance("127.0.0.1", 9999)

    out = backend.start("s", host="127.0.0.1", port=8080)

    assert out == {
        "running": True,
        "host": "127.0.0.1",
        "port": 8080,
        "endpoint": "127.0.0.1:8080",
    }
    assert started == [("127.0.0.1", 8080)]
    assert backend._instances["s"].port == 8080


def test_start_rolls_back_the_reservation_when_the_listener_fails(
    monkeypatch: Any,
) -> None:
    backend = ProxyBackend()
    backend._available = True

    def boom(self: _ProxyInstance, timeout: float = 15.0) -> None:
        raise ProxyError("backend_error", "did not bind")

    monkeypatch.setattr(_ProxyInstance, "start", boom)
    with pytest.raises(ProxyError) as raised:
        backend.start("s")
    assert raised.value.code == "backend_error"
    assert "s" not in backend._instances


def test_start_does_not_pop_a_reservation_replaced_during_launch(
    monkeypatch: Any,
) -> None:
    """If a concurrent stop replaced the slot, rollback must not touch it."""
    backend = ProxyBackend()
    backend._available = True
    survivor = _ProxyInstance("127.0.0.1", 8080)

    def replace_then_fail(self: _ProxyInstance, timeout: float = 15.0) -> None:
        backend._instances["s"] = survivor
        raise ProxyError("backend_error", "did not bind")

    monkeypatch.setattr(_ProxyInstance, "start", replace_then_fail)
    with pytest.raises(ProxyError):
        backend.start("s")
    assert backend._instances["s"] is survivor


def test_start_raises_when_the_session_was_stopped_while_starting(
    monkeypatch: Any,
) -> None:
    backend = ProxyBackend()
    backend._available = True

    def stop_during(self: _ProxyInstance, timeout: float = 15.0) -> None:
        backend._instances.pop("s", None)

    monkeypatch.setattr(_ProxyInstance, "start", stop_during)
    with pytest.raises(ProxyError) as raised:
        backend.start("s")
    assert raised.value.code == "invalid_state"
    assert "stopped while starting" in str(raised.value)


# ---------------------------------------------------------------------------
# ProxyBackend.flows
# ---------------------------------------------------------------------------


def test_flows_reports_no_drop_on_an_empty_capture(monkeypatch: Any) -> None:
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_FlowRecorder(capacity=4))
    )
    out = backend.flows("s")
    assert out["total"] == 0
    assert out["count"] == 0
    assert out["dropped"] == 0
    assert out["has_more"] is False
    assert out["flows"] == []


# ---------------------------------------------------------------------------
# ProxyBackend.flow_get
# ---------------------------------------------------------------------------


def _backend_with_raw(monkeypatch: Any, raw_return: Any) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = SimpleNamespace(raw=lambda flow_id: raw_return)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_flow_get_reports_an_unknown_flow_id(tmp_path: Path, monkeypatch: Any) -> None:
    backend = _backend_with_raw(monkeypatch, None)
    with pytest.raises(ProxyError) as raised:
        backend.flow_get("s", "missing", tmp_path)
    assert raised.value.code == "not_found"


def test_flow_get_reports_an_omitted_body(tmp_path: Path, monkeypatch: Any) -> None:
    backend = _backend_with_raw(monkeypatch, _OMITTED_BODY)
    with pytest.raises(ProxyError) as raised:
        backend.flow_get("s", "big", tmp_path)
    assert raised.value.code == "too_large"


def test_flow_get_flags_a_truncated_request_url(tmp_path: Path, monkeypatch: Any) -> None:
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://x/" + "a" * (_MAX_URL_BYTES + 10),
        headers={},
    )
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"ok")
    backend = _backend_with_raw(monkeypatch, SimpleNamespace(request=request, response=response))
    payload = backend.flow_get("s", "f", tmp_path)
    assert payload["request"]["metadata_truncated"] is True


# ---------------------------------------------------------------------------
# ProxyBackend.replay
# ---------------------------------------------------------------------------


class _ImmediateLoop:
    """A stand-in event loop that runs the queued callable synchronously."""

    def call_soon_threadsafe(self, func: Any, *args: Any) -> None:
        func(*args)


class _DeadLoop:
    """A loop that never runs what it is handed, to force the replay timeout."""

    def call_soon_threadsafe(self, func: Any, *args: Any) -> None:
        pass


def _replay_backend(monkeypatch: Any, inst: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


def test_replay_reports_an_unknown_flow_id(monkeypatch: Any) -> None:
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: None), _master=object(), _loop=object()
    )
    backend = _replay_backend(monkeypatch, inst)
    with pytest.raises(ProxyError) as raised:
        backend.replay("s", "missing")
    assert raised.value.code == "not_found"


def test_replay_reports_an_omitted_body(monkeypatch: Any) -> None:
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: _OMITTED_BODY),
        _master=object(),
        _loop=object(),
    )
    backend = _replay_backend(monkeypatch, inst)
    with pytest.raises(ProxyError) as raised:
        backend.replay("s", "big")
    assert raised.value.code == "too_large"


def test_replay_refuses_when_the_proxy_is_not_running(monkeypatch: Any) -> None:
    flow = SimpleNamespace(copy=lambda: flow)
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow), _master=None, _loop=object()
    )
    backend = _replay_backend(monkeypatch, inst)
    with pytest.raises(ProxyError) as raised:
        backend.replay("s", "f")
    assert raised.value.code == "invalid_state"


def test_replay_dispatches_the_copy_on_the_proxy_loop(monkeypatch: Any) -> None:
    copied = SimpleNamespace(tag="copy")
    flow = SimpleNamespace(copy=lambda: copied)
    calls: list[tuple[str, list[Any]]] = []

    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            calls.append((name, args))

    master = SimpleNamespace(commands=_Commands())
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow),
        _master=master,
        _loop=_ImmediateLoop(),
    )
    backend = _replay_backend(monkeypatch, inst)
    out = backend.replay("s", "f")
    assert out == {"replayed": True, "flow_id": "f"}
    assert calls == [("replay.client", [copied])]


def test_replay_wraps_a_command_failure_as_backend_error(monkeypatch: Any) -> None:
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())

    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            raise RuntimeError("replay blew up")

    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow),
        _master=SimpleNamespace(commands=_Commands()),
        _loop=_ImmediateLoop(),
    )
    backend = _replay_backend(monkeypatch, inst)
    with pytest.raises(ProxyError) as raised:
        backend.replay("s", "f")
    assert raised.value.code == "backend_error"


def test_replay_reraises_a_proxy_error_from_the_command(monkeypatch: Any) -> None:
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())

    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            raise ProxyError("invalid_state", "master refused")

    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow),
        _master=SimpleNamespace(commands=_Commands()),
        _loop=_ImmediateLoop(),
    )
    backend = _replay_backend(monkeypatch, inst)
    with pytest.raises(ProxyError) as raised:
        backend.replay("s", "f")
    assert raised.value.code == "invalid_state"


def test_replay_times_out_when_the_loop_never_runs_it(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_mod, "_REPLAY_WAIT_S", 0.05)
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow),
        _master=SimpleNamespace(commands=SimpleNamespace(call=lambda *a: None)),
        _loop=_DeadLoop(),
    )
    backend = _replay_backend(monkeypatch, inst)
    with pytest.raises(ProxyError) as raised:
        backend.replay("s", "f")
    assert raised.value.code == "timeout"


# ---------------------------------------------------------------------------
# ProxyBackend.ca_cert_path
# ---------------------------------------------------------------------------


def test_ca_cert_path_returns_the_pem_when_present(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_mod.Path, "home", staticmethod(lambda: tmp_path))
    mitm_dir = tmp_path / ".mitmproxy"
    mitm_dir.mkdir()
    pem = mitm_dir / "mitmproxy-ca-cert.pem"
    pem.write_text("cert", encoding="utf-8")
    found = ProxyBackend().ca_cert_path()
    assert found == pem


def test_ca_cert_path_is_none_when_no_cert_exists(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_mod.Path, "home", staticmethod(lambda: tmp_path))
    assert ProxyBackend().ca_cert_path() is None


# ---------------------------------------------------------------------------
# ProxyBackend.close_all
# ---------------------------------------------------------------------------


def test_close_all_stops_every_live_instance() -> None:
    backend = ProxyBackend()
    stopped: list[str] = []
    backend._instances["a"] = SimpleNamespace(stop=lambda: stopped.append("a"))
    backend._instances["b"] = SimpleNamespace(stop=lambda: stopped.append("b"))
    backend.close_all()
    assert sorted(stopped) == ["a", "b"]
    assert backend._instances == {}


# ---------------------------------------------------------------------------
# ProxyError
# ---------------------------------------------------------------------------


def test_proxy_error_is_a_runtime_error_carrying_code_and_details() -> None:
    err = ProxyError("not_found", "gone", flow_id="x")
    assert isinstance(err, RuntimeError)
    assert err.code == "not_found"
    assert err.details["flow_id"] == "x"
