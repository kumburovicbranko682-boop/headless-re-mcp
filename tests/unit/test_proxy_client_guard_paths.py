"""ProxyBackend guard paths off the happy capture/read routes.

The field-shape, bounds, and reservation tests elsewhere drive a proxy through
its recorder; this file drives the edges they do not reach -- the asyncio
teardown helpers (``_shutdown_loop``, ``_drain_proxy_servers``), the socket
probes (``_port_accepts`` name-resolution failure, ``_bind_probe`` on the
Windows path), the leaked-handler sweep (``_uninstall_master_logging``), the
byte-accounting helpers' defensive returns, the ``_FlowRecorder`` omit/eviction
lockstep, the ``_ProxyInstance`` lifecycle (``start`` error/exit/accept/timeout
and ``_run`` with a fake mitmproxy), and every ``ProxyBackend`` method's error
contract. mitmproxy is not installed, so the threaded paths run against a fake
module injected exactly where the real one would be imported.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bind_probe,
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


class _Headers:
    """A header map that can mimic mitmproxy's ``items(multi=True)`` surface."""

    def __init__(
        self,
        mapping: dict[str, str] | None = None,
        *,
        multi: list[tuple[str, str]] | None = None,
        items_error: Exception | None = None,
    ) -> None:
        self._map = dict(mapping or {})
        self._multi = multi
        self._items_error = items_error

    def get(self, key: str, default: str = "") -> str:
        return self._map.get(key, default)

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        if self._items_error is not None:
            raise self._items_error
        if multi and self._multi is not None:
            return list(self._multi)
        return list(self._map.items())


def _mk_flow(
    *,
    flow_id: str | None = None,
    method: str = "GET",
    url: str = "http://x/",
    host: str = "x",
    req_raw: bytes = b"",
    resp_status: int | None = 200,
    resp_raw: bytes = b"",
    content_type: str = "text/plain",
) -> Any:
    request = SimpleNamespace(
        method=method,
        pretty_url=url,
        host=host,
        raw_content=req_raw,
        headers=_Headers({}),
    )
    response = (
        SimpleNamespace(
            status_code=resp_status,
            raw_content=resp_raw,
            headers=_Headers({"content-type": content_type}),
        )
        if resp_status is not None
        else None
    )
    return SimpleNamespace(id=flow_id, request=request, response=response)


def _install_fake_mitmproxy(
    monkeypatch: pytest.MonkeyPatch, *, dumpmaster_typeerror: bool = False
) -> dict[str, int]:
    """Inject a minimal fake mitmproxy so _run/_check_available can execute."""
    calls = {"dumpmaster": 0}

    class _Addons:
        def __init__(self) -> None:
            self._items: dict[str, Any] = {}

        def add(self, addon: Any) -> None:
            self._items[type(addon).__name__] = addon

        def get(self, name: str) -> Any:
            return self._items.get(name)

    class DumpMaster:
        def __init__(
            self,
            opts: Any,
            loop: Any = None,
            with_termlog: Any = None,
            with_dumper: Any = None,
        ) -> None:
            calls["dumpmaster"] += 1
            if dumpmaster_typeerror and (loop is not None or with_termlog is not None):
                raise TypeError("old mitmproxy signature")
            self.opts = opts
            self.addons = _Addons()
            self.event_loop = loop

        async def run(self) -> None:
            return None

        def shutdown(self) -> None:
            return None

    class Options:
        def __init__(self, listen_host: str | None = None, listen_port: int | None = None) -> None:
            self.listen_host = listen_host
            self.listen_port = listen_port

    mitm = types.ModuleType("mitmproxy")
    options_mod = types.ModuleType("mitmproxy.options")
    options_mod.Options = Options  # type: ignore[attr-defined]
    tools_mod = types.ModuleType("mitmproxy.tools")
    dump_mod = types.ModuleType("mitmproxy.tools.dump")
    dump_mod.DumpMaster = DumpMaster  # type: ignore[attr-defined]
    mitm.options = options_mod  # type: ignore[attr-defined]
    mitm.tools = tools_mod  # type: ignore[attr-defined]
    tools_mod.dump = dump_mod  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mitmproxy", mitm)
    monkeypatch.setitem(sys.modules, "mitmproxy.options", options_mod)
    monkeypatch.setitem(sys.modules, "mitmproxy.tools", tools_mod)
    monkeypatch.setitem(sys.modules, "mitmproxy.tools.dump", dump_mod)
    return calls


# --------------------------------------------------------------------------
# _shutdown_loop
# --------------------------------------------------------------------------


def test_shutdown_loop_cancels_pending_tasks() -> None:
    """Pending tasks are cancelled and awaited so their transports close."""
    loop = asyncio.new_event_loop()

    async def _seed() -> None:
        loop.create_task(asyncio.sleep(30))

    loop.run_until_complete(_seed())
    assert any(not task.done() for task in asyncio.all_tasks(loop))
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_shutdown_loop_closes_an_idle_loop() -> None:
    """A loop with no pending tasks is still drained and closed."""
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


# --------------------------------------------------------------------------
# _port_accepts / _bind_probe
# --------------------------------------------------------------------------


def test_port_accepts_is_false_on_a_name_resolution_error() -> None:
    """An unresolvable host is not "accepting"; the OSError is swallowed."""
    assert _port_accepts("proxy-guard-nonexistent.invalid", 9) is False


def test_bind_probe_skips_reuseaddr_on_the_windows_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows the probe binds without SO_REUSEADDR and still answers."""
    monkeypatch.setattr("headless_re_mcp.backends.proxy.client.os.name", "nt")
    assert _bind_probe("127.0.0.1", 0) is None


# --------------------------------------------------------------------------
# _uninstall_master_logging / _drain_proxy_servers
# --------------------------------------------------------------------------


def test_uninstall_master_logging_leaves_unrelated_handlers() -> None:
    """A root handler owned by a different master/loop is not removed."""
    root = logging.getLogger()
    handler = logging.NullHandler()
    handler.master = SimpleNamespace(event_loop=object())  # type: ignore[attr-defined]
    root.addHandler(handler)
    try:
        # A different master and no matching loop: the sweep must leave it alone.
        _uninstall_master_logging(SimpleNamespace())
        assert handler in root.handlers
    finally:
        root.removeHandler(handler)


def test_drain_proxy_servers_swallows_a_varying_addon_surface() -> None:
    """An addon lookup that raises is treated as "nothing to drain"."""

    def boom(name: str) -> Any:
        raise RuntimeError("addon surface differs")

    master = SimpleNamespace(addons=SimpleNamespace(get=boom))
    loop = asyncio.new_event_loop()
    try:
        _drain_proxy_servers(master, loop)
    finally:
        loop.close()


# --------------------------------------------------------------------------
# byte-accounting helpers
# --------------------------------------------------------------------------


def test_content_len_is_zero_when_len_raises() -> None:
    """A raw_content whose length cannot be taken counts as zero bytes."""
    assert _content_len(SimpleNamespace(raw_content=123)) == 0


def test_encoded_len_returns_over_cap_when_str_raises() -> None:
    """A value whose ``str()`` raises is treated as over the stored cap."""

    class _BadStr:
        def __str__(self) -> str:
            raise RuntimeError("no string form")

    assert _encoded_len(_BadStr()) == proxy_client._MAX_STORED_BODY + 1


def test_headers_len_is_zero_when_items_raises() -> None:
    """Header iteration failing (non-TypeError) counts as zero header bytes."""
    part = SimpleNamespace(headers=_Headers(items_error=RuntimeError("boom")))
    assert _headers_len(part) == 0


def test_raw_body_of_none_is_empty() -> None:
    """A missing message part has an empty body."""
    assert _raw_body(None) == b""


def test_raw_body_of_non_bytes_content_is_empty() -> None:
    """A raw_content that is not bytes reads as an empty body."""
    assert _raw_body(SimpleNamespace(raw_content="not-bytes")) == b""


def test_bounded_headers_returns_truncated_when_iteration_raises() -> None:
    """A header map that cannot be iterated returns empty and flags truncation."""
    part = SimpleNamespace(headers=_Headers(items_error=RuntimeError("boom")))
    out, truncated = _bounded_headers(part)
    assert out == {}
    assert truncated is True


def test_bounded_headers_stops_at_the_total_byte_budget() -> None:
    """Header values summing past the total cap stop early and flag truncation."""
    value = "a" * 4000
    mapping = {f"h{index}": value for index in range(20)}
    out, truncated = _bounded_headers(SimpleNamespace(headers=_Headers(mapping)))
    assert truncated is True
    total = sum(len(k.encode()) + len(v.encode()) for k, v in out.items())
    assert total <= proxy_client._MAX_FLOW_HEADERS_TOTAL_BYTES
    assert len(out) < 20


# --------------------------------------------------------------------------
# _FlowRecorder omit / eviction
# --------------------------------------------------------------------------


def test_omit_retained_is_a_noop_for_a_missing_or_already_omitted_flow() -> None:
    """Omitting an unknown or already-omitted flow does nothing and does not raise."""
    recorder = _FlowRecorder()
    recorder._omit_retained("nope")
    recorder._raw["already"] = _OMITTED_BODY
    recorder._omit_retained("already")
    assert recorder._raw["already"] is _OMITTED_BODY


def test_omit_retained_skips_non_matching_summaries() -> None:
    """The summary scan steps past ids that do not match before flagging one."""
    recorder = _FlowRecorder()
    recorder._raw["target"] = object()
    recorder._raw_sizes["target"] = 10
    recorder._retained_bytes = 10
    recorder.flows.append({"id": "target"})
    recorder.flows.append({"id": "other"})
    recorder._omit_retained("target")
    assert recorder._raw["target"] is _OMITTED_BODY
    flagged = next(entry for entry in recorder.flows if entry["id"] == "target")
    assert flagged["body_omitted"] is True


def test_omit_retained_tolerates_no_matching_summary() -> None:
    """A retained flow with no summary row is still omitted without error."""
    recorder = _FlowRecorder()
    recorder._raw["ghost"] = object()
    recorder._raw_sizes["ghost"] = 10
    recorder._retained_bytes = 10
    recorder.flows.append({"id": "unrelated"})
    recorder._omit_retained("ghost")
    assert recorder._raw["ghost"] is _OMITTED_BODY


def test_record_eviction_skips_already_omitted_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retain walker steps past an already-omitted slot to free a live one."""
    monkeypatch.setattr(proxy_client, "_MAX_RETAINED_BYTES", 100)
    recorder = _FlowRecorder()
    live = _mk_flow(flow_id="b", resp_raw=b"x" * 50)
    recorder._raw["a"] = _OMITTED_BODY
    recorder._raw["b"] = live
    recorder._raw_sizes["b"] = 200
    recorder._retained_bytes = 200
    recorder._record(_mk_flow(flow_id="c"))
    # 'a' was skipped (already omitted); 'b' was evicted to make room for 'c'.
    assert recorder._raw["a"] is _OMITTED_BODY
    assert recorder._raw["b"] is _OMITTED_BODY
    assert recorder._raw["c"] is not _OMITTED_BODY


# --------------------------------------------------------------------------
# _ProxyInstance.start lifecycle
# --------------------------------------------------------------------------


def _absent_mitmproxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every ``import mitmproxy`` fail regardless of what is installed.

    A ``None`` entry in ``sys.modules`` is the import system's negative cache, so
    ``_check_available``'s ``import mitmproxy`` and ``_run``'s ``from mitmproxy
    import ...`` both raise ImportError -- the same state a bare install has.
    Without it these tests assumed the environment simply lacked the ``proxy``
    extra and failed the moment mitmproxy was installed (e.g. on a machine that
    also runs the proxy integration gate).
    """
    monkeypatch.setitem(sys.modules, "mitmproxy", None)


def _free_instance() -> _ProxyInstance:
    return _ProxyInstance("127.0.0.1", 8080)


def test_instance_start_reports_a_thread_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run thread that records an error surfaces as backend_error."""
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda *a, **k: False)
    monkeypatch.setattr(proxy_client, "_bind_probe", lambda *a, **k: None)
    inst = _free_instance()
    inst._run = lambda: setattr(inst, "_error", RuntimeError("mitmproxy blew up"))  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as excinfo:
        inst.start(timeout=2.0)
    assert excinfo.value.code == "backend_error"


def test_instance_start_reports_a_thread_that_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run thread that exits without listening is reported as an exit."""
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda *a, **k: False)
    monkeypatch.setattr(proxy_client, "_bind_probe", lambda *a, **k: None)
    inst = _free_instance()
    inst._run = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as excinfo:
        inst.start(timeout=2.0)
    assert excinfo.value.code == "backend_error"
    assert "exited" in excinfo.value.message


def test_instance_start_returns_once_the_port_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start returns as soon as the readiness probe sees the port accepting."""
    release = threading.Event()
    seen = {"n": 0}

    def accepts(*args: Any, **kwargs: Any) -> bool:
        seen["n"] += 1
        return seen["n"] > 1

    monkeypatch.setattr(proxy_client, "_port_accepts", accepts)
    monkeypatch.setattr(proxy_client, "_bind_probe", lambda *a, **k: None)
    inst = _free_instance()
    inst._run = lambda: release.wait(5.0)  # type: ignore[method-assign, assignment]
    try:
        # Success is a normal return; a failure would raise ProxyError instead.
        inst.start(timeout=2.0)
    finally:
        release.set()
        if inst._thread is not None:
            inst._thread.join(timeout=2.0)


def test_instance_start_times_out_when_the_port_never_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A port that never accepts within the deadline is a timeout, and stop runs."""
    release = threading.Event()
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda *a, **k: False)
    monkeypatch.setattr(proxy_client, "_bind_probe", lambda *a, **k: None)
    inst = _free_instance()
    inst._run = lambda: release.wait(10.0)  # type: ignore[method-assign, assignment]
    inst.stop = release.set  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as excinfo:
        inst.start(timeout=0.2)
    assert excinfo.value.code == "timeout"


# --------------------------------------------------------------------------
# _ProxyInstance._run
# --------------------------------------------------------------------------


def _run_in_thread(inst: _ProxyInstance) -> None:
    # daemon=True so a hung _run cannot block interpreter shutdown (a
    # non-daemon worker left alive froze the whole suite on Windows CI
    # before), and the aliveness assert turns that hang into a clear
    # failure here instead.
    thread = threading.Thread(target=inst._run, daemon=True)
    thread.start()
    thread.join(timeout=5.0)
    assert not thread.is_alive(), "_ProxyInstance._run did not return within 5s"


def test_instance_run_starts_and_tears_down_a_fake_master(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A working mitmproxy is constructed, run, and drained without error."""
    _install_fake_mitmproxy(monkeypatch)
    inst = _free_instance()
    _run_in_thread(inst)
    assert inst._error is None
    assert inst._master is not None


def test_instance_run_falls_back_when_the_constructor_signature_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DumpMaster rejecting the modern kwargs is retried positionally."""
    calls = _install_fake_mitmproxy(monkeypatch, dumpmaster_typeerror=True)
    inst = _free_instance()
    _run_in_thread(inst)
    assert inst._error is None
    assert inst._master is not None
    assert calls["dumpmaster"] == 2


def test_instance_run_records_an_import_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """With mitmproxy absent, the run thread records the import error.

    Absence is simulated (see _absent_mitmproxy) rather than assumed of the
    environment, so _run's `from mitmproxy import ...` raises ImportError whether
    or not the proxy extra is installed and the thread records it in _error.
    """
    _absent_mitmproxy(monkeypatch)
    inst = _free_instance()
    _run_in_thread(inst)
    assert inst._error is not None


# --------------------------------------------------------------------------
# ProxyBackend availability / start
# --------------------------------------------------------------------------


def test_check_available_true_when_mitmproxy_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present mitmproxy flips availability to true without raising."""
    _install_fake_mitmproxy(monkeypatch)
    backend = ProxyBackend()
    backend._check_available()
    assert backend._available is True


def test_start_rejects_a_port_out_of_range(monkeypatch: pytest.MonkeyPatch) -> None:
    """A port outside 1..65535 is refused once the capability is available."""
    _install_fake_mitmproxy(monkeypatch)
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s", port=99999)
    assert excinfo.value.code == "invalid_params"


def test_start_iterates_past_a_nonmatching_reservation(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reservation for a different port does not block a new endpoint."""
    _install_fake_mitmproxy(monkeypatch)
    monkeypatch.setattr(proxy_client._ProxyInstance, "start", lambda self, timeout=15.0: None)
    backend = ProxyBackend()
    backend._instances["other"] = _ProxyInstance("127.0.0.1", 9999)
    payload = backend.start("s", host="127.0.0.1", port=8080)
    assert payload["running"] is True
    assert payload["port"] == 8080


def test_start_cleans_up_when_the_session_was_already_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A start failure whose session vanished mid-flight still re-raises cleanly."""
    _install_fake_mitmproxy(monkeypatch)
    backend = ProxyBackend()

    def fake_start(self: Any, timeout: float = 15.0) -> None:
        backend._instances.pop("s", None)
        raise ProxyError("backend_error", "boom during listen")

    monkeypatch.setattr(proxy_client._ProxyInstance, "start", fake_start)
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s")
    assert excinfo.value.code == "backend_error"


def test_start_reports_a_session_stopped_while_starting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A start that succeeds but whose session was dropped is invalid_state."""
    _install_fake_mitmproxy(monkeypatch)
    backend = ProxyBackend()

    def fake_start(self: Any, timeout: float = 15.0) -> None:
        backend._instances.pop("s", None)

    monkeypatch.setattr(proxy_client._ProxyInstance, "start", fake_start)
    with pytest.raises(ProxyError) as excinfo:
        backend.start("s")
    assert excinfo.value.code == "invalid_state"
    assert "stopped while starting" in excinfo.value.message


# --------------------------------------------------------------------------
# ProxyBackend read methods
# --------------------------------------------------------------------------


def _backend_get_returning(monkeypatch: pytest.MonkeyPatch, inst: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


def test_flows_reports_zero_dropped_for_an_empty_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty flow ring reports no drops rather than a negative sentinel."""
    inst = SimpleNamespace(recorder=SimpleNamespace(snapshot=lambda: []))
    payload = _backend_get_returning(monkeypatch, inst).flows("s")
    assert payload == {
        "flows": [],
        "count": 0,
        "total": 0,
        "offset": 0,
        "has_more": False,
        "dropped": 0,
    }


def test_flow_get_rejects_an_unknown_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An id the recorder never saw is not_found."""
    inst = SimpleNamespace(recorder=SimpleNamespace(raw=lambda flow_id: None))
    with pytest.raises(ProxyError) as excinfo:
        _backend_get_returning(monkeypatch, inst).flow_get("s", "missing", tmp_path)
    assert excinfo.value.code == "not_found"


def test_flow_get_reports_a_dropped_body(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A flow whose body was evicted from the retain ring is too_large."""
    inst = SimpleNamespace(recorder=SimpleNamespace(raw=lambda flow_id: _OMITTED_BODY))
    with pytest.raises(ProxyError) as excinfo:
        _backend_get_returning(monkeypatch, inst).flow_get("s", "gone", tmp_path)
    assert excinfo.value.code == "too_large"


def test_flow_get_flags_truncated_request_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A request URL past the cap sets the request's metadata_truncated flag."""
    flow = _mk_flow(url="http://x/" + "a" * 20000, resp_status=None)
    inst = SimpleNamespace(recorder=SimpleNamespace(raw=lambda flow_id: flow))
    payload = _backend_get_returning(monkeypatch, inst).flow_get("s", "f1", tmp_path)
    assert payload["request"]["metadata_truncated"] is True
    assert payload["response"]["status"] is None


# --------------------------------------------------------------------------
# ProxyBackend replay
# --------------------------------------------------------------------------


class _SyncLoop:
    """A stand-in event loop that runs the scheduled callback inline."""

    def __init__(self, times: int = 1) -> None:
        self._times = times

    def call_soon_threadsafe(self, func: Any, *args: Any) -> None:
        for _ in range(self._times):
            func(*args)


class _Commands:
    def __init__(self, errors: list[Exception | None]) -> None:
        self._errors = errors
        self._index = 0

    def call(self, name: str, args: Any) -> str:
        exc = self._errors[self._index] if self._index < len(self._errors) else None
        self._index += 1
        if exc is not None:
            raise exc
        return "ok"


def _replay_instance(flow: Any, *, times: int, errors: list[Exception | None]) -> Any:
    return SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow),
        _master=SimpleNamespace(commands=_Commands(errors)),
        _loop=_SyncLoop(times),
    )


def test_replay_rejects_an_unknown_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replaying an id the recorder never saw is not_found."""
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: None), _master=None, _loop=None
    )
    with pytest.raises(ProxyError) as excinfo:
        _backend_get_returning(monkeypatch, inst).replay("s", "missing")
    assert excinfo.value.code == "not_found"


def test_replay_rejects_a_dropped_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """A flow whose body was not retained cannot be replayed (too_large)."""
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: _OMITTED_BODY), _master=None, _loop=None
    )
    with pytest.raises(ProxyError) as excinfo:
        _backend_get_returning(monkeypatch, inst).replay("s", "gone")
    assert excinfo.value.code == "too_large"


def test_replay_rejects_a_stopped_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replaying with no live master/loop is invalid_state."""
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow), _master=None, _loop=_SyncLoop()
    )
    with pytest.raises(ProxyError) as excinfo:
        _backend_get_returning(monkeypatch, inst).replay("s", "f1")
    assert excinfo.value.code == "invalid_state"


def test_replay_succeeds_and_is_idempotent_on_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A completed replay reports replayed; a second completion is ignored.

    The scheduled runner is invoked twice: the first completes the future, and
    the second -- whose command call raises -- finds the future already done and
    returns without clobbering the result, so replay still reports success.
    """
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst = _replay_instance(flow, times=2, errors=[None, RuntimeError("late error")])
    payload = _backend_get_returning(monkeypatch, inst).replay("s", "f1")
    assert payload == {"replayed": True, "flow_id": "f1"}


def test_replay_ignores_a_second_successful_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A runner that completes twice does not overwrite the first result.

    The second successful command call finds the future already resolved and
    leaves it alone, so replay still reports a single success.
    """
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst = _replay_instance(flow, times=2, errors=[None, None])
    payload = _backend_get_returning(monkeypatch, inst).replay("s", "f1")
    assert payload == {"replayed": True, "flow_id": "f1"}


def test_replay_maps_a_command_failure_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replay command that raises surfaces as backend_error."""
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst = _replay_instance(flow, times=1, errors=[RuntimeError("replay refused")])
    with pytest.raises(ProxyError) as excinfo:
        _backend_get_returning(monkeypatch, inst).replay("s", "f1")
    assert excinfo.value.code == "backend_error"


def test_replay_passes_a_proxyerror_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ProxyError raised by the command call is re-raised unchanged."""
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst = _replay_instance(
        flow, times=1, errors=[ProxyError("invalid_state", "already structured")]
    )
    with pytest.raises(ProxyError) as excinfo:
        _backend_get_returning(monkeypatch, inst).replay("s", "f1")
    assert excinfo.value.code == "invalid_state"


# --------------------------------------------------------------------------
# ProxyBackend ca_cert_path / close_all
# --------------------------------------------------------------------------


def test_ca_cert_path_returns_the_first_existing_certificate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The mitmproxy CA is returned when it is present in the home directory."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    ca_dir = tmp_path / ".mitmproxy"
    ca_dir.mkdir()
    cert = ca_dir / "mitmproxy-ca-cert.cer"
    cert.write_text("cert", encoding="utf-8")
    assert ProxyBackend().ca_cert_path() == cert


def test_ca_cert_path_is_none_when_no_certificate_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No CA on disk yields None rather than a phantom path."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() is None


def test_close_all_stops_every_tracked_instance() -> None:
    """close_all stops and forgets every instance it was tracking."""
    stopped: list[str] = []
    backend = ProxyBackend()
    backend._instances["s1"] = SimpleNamespace(stop=lambda: stopped.append("s1"))  # type: ignore[assignment]
    backend._instances["s2"] = SimpleNamespace(stop=lambda: stopped.append("s2"))  # type: ignore[assignment]
    backend.close_all()
    assert sorted(stopped) == ["s1", "s2"]
    assert backend._instances == {}
