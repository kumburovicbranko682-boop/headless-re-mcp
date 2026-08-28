"""Branch coverage for the mitmproxy interception backend.

The proxy backend runs mitmproxy on a dedicated thread and keeps a bounded ring
of captured flows. The honesty-critical parts -- readiness that refuses a busy
port, a retain ring that omits rather than lies about oversized bodies, header
maps bounded in count/size, spilled bodies that never masquerade as text, and a
stop path that actually frees the port -- have guard branches a live proxy
rarely exercises. These fakes drive those branches without binding a socket, so
a CI host with no mitmproxy still guards them; the live gate
(tests/integration/test_proxy_lifecycle_gate.py) pins the real wiring.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client
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

MP = pytest.MonkeyPatch


def _flow(
    flow_id: str,
    *,
    body: bytes = b"",
    resp: bool = False,
    method: str = "GET",
    url: str = "http://x/a",
    host: str = "x",
) -> Any:
    request = SimpleNamespace(
        method=method, pretty_url=url, host=host, headers={}, raw_content=body
    )
    response = (
        SimpleNamespace(status_code=200, headers={"content-type": "text/plain"}, raw_content=b"ok")
        if resp
        else None
    )
    return SimpleNamespace(id=flow_id, request=request, response=response, error=None)


class TestPureHelpers:
    def test_shutdown_loop_cancels_pending_and_closes(self) -> None:
        loop = asyncio.new_event_loop()

        async def _forever() -> None:
            await asyncio.sleep(1000)

        loop.create_task(_forever())
        _shutdown_loop(loop)
        assert loop.is_closed()

    def test_port_accepts_returns_false_when_socket_construction_raises(
        self, monkeypatch: MP
    ) -> None:
        def _boom(*_a: object, **_k: object) -> Any:
            raise OSError("no sockets today")

        monkeypatch.setattr(client.socket, "socket", _boom)
        assert _port_accepts("127.0.0.1", 1) is False

    def test_content_len_swallows_a_len_that_raises(self) -> None:
        assert _content_len(SimpleNamespace(raw_content=object())) == 0
        assert _content_len(None) == 0
        assert _content_len(SimpleNamespace(raw_content=b"")) == 0

    def test_encoded_len_falls_back_when_str_raises(self) -> None:
        class _Hostile:
            def __str__(self) -> str:
                raise RuntimeError("no str")

        assert _encoded_len(_Hostile()) == client._MAX_STORED_BODY + 1

    def test_headers_len_returns_zero_when_items_raises(self) -> None:
        class _Headers:
            def items(self, *_a: object, **_k: object) -> Any:
                raise RuntimeError("hostile headers")

        assert _headers_len(SimpleNamespace(headers=_Headers())) == 0
        assert _headers_len(SimpleNamespace(headers=None)) == 0

    def test_raw_body_is_empty_for_none_and_non_bytes(self) -> None:
        assert _raw_body(None) == b""
        assert _raw_body(SimpleNamespace(raw_content="not bytes")) == b""
        assert _raw_body(SimpleNamespace(raw_content=b"real")) == b"real"

    def test_raw_body_is_empty_when_decode_raises(self) -> None:
        class _Part:
            @property
            def raw_content(self) -> bytes:
                raise ValueError("lazy decode blew up")

        assert _raw_body(_Part()) == b""

    def test_bounded_headers_returns_truncated_when_items_raises(self) -> None:
        class _Headers:
            def items(self, *_a: object, **_k: object) -> Any:
                raise RuntimeError("hostile")

        out, truncated = _bounded_headers(SimpleNamespace(headers=_Headers()))
        assert out == {}
        assert truncated is True

    def test_bounded_headers_stops_on_total_budget(self) -> None:
        value = "v" * 4000
        headers = {f"h{i}": value for i in range(40)}
        out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
        assert truncated is True
        total = sum(len(k) + len(v) for k, v in out.items())
        assert total <= _MAX_FLOW_HEADERS_TOTAL_BYTES
        assert len(out) < 40

    def test_bounded_headers_none_is_empty(self) -> None:
        assert _bounded_headers(SimpleNamespace(headers=None)) == ({}, False)


class TestDrainAndLogging:
    def test_drain_returns_quietly_when_addon_lookup_raises(self) -> None:
        class _Addons:
            def get(self, _name: str) -> Any:
                raise RuntimeError("addon surface changed")

        master = SimpleNamespace(addons=_Addons())
        # Must not raise; simply returns.
        _drain_proxy_servers(master, asyncio.new_event_loop())

    def test_drain_returns_when_servers_api_is_absent(self) -> None:
        addon = SimpleNamespace(servers=SimpleNamespace())  # no .update
        master = SimpleNamespace(addons=SimpleNamespace(get=lambda _n: addon))
        _drain_proxy_servers(master, asyncio.new_event_loop())

    def test_uninstall_logging_skips_foreign_root_handlers(self) -> None:
        root = logging.getLogger()
        other_master = SimpleNamespace(event_loop=None)
        foreign = logging.NullHandler()
        foreign.master = SimpleNamespace(event_loop=object())  # type: ignore[attr-defined]
        root.addHandler(foreign)
        try:
            # Neither identity nor loop matches, so the foreign handler stays.
            _uninstall_master_logging(other_master, loop=None)
            assert foreign in root.handlers
        finally:
            root.removeHandler(foreign)

    def test_uninstall_logging_is_a_noop_without_master_or_loop(self) -> None:
        _uninstall_master_logging(None, None)


class TestFlowRecorderEviction:
    def test_single_oversized_flow_is_omitted_not_stored(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(client, "_MAX_STORED_BODY", 10)
        rec = _FlowRecorder(capacity=8)
        rec.response(_flow("big", body=b"x" * 100, resp=True))

        row = rec.snapshot()[0]
        assert row["body_omitted"] is True
        assert rec.raw("big") is _OMITTED_BODY

    def test_retain_budget_evicts_the_oldest_body(self, monkeypatch: MP) -> None:
        # Large per-flow cap so no single flow is dropped on its own; a small
        # retain budget so the second arrival must omit the first.
        monkeypatch.setattr(client, "_MAX_STORED_BODY", 10_000_000)
        monkeypatch.setattr(client, "_MAX_RETAINED_BYTES", 2000)
        rec = _FlowRecorder(capacity=8)
        rec.response(_flow("a", body=b"x" * 1500))
        rec.response(_flow("b", body=b"y" * 1500))

        assert rec.raw("a") is _OMITTED_BODY
        assert rec.raw("b") is not _OMITTED_BODY
        by_id = {row["id"]: row for row in rec.snapshot()}
        assert by_id["a"].get("body_omitted") is True
        assert "body_omitted" not in by_id["b"]

        # A third arrival must skip the already-omitted 'a' and omit 'b'.
        rec.response(_flow("c", body=b"z" * 1500))
        assert rec.raw("b") is _OMITTED_BODY
        assert rec.raw("c") is not _OMITTED_BODY

    def test_omit_retained_is_a_noop_for_unknown_or_already_omitted(
        self, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(client, "_MAX_STORED_BODY", 10)
        rec = _FlowRecorder(capacity=8)
        rec._omit_retained("nonexistent")  # early return, no key
        rec.response(_flow("big", body=b"x" * 100))
        # 'big' is already _OMITTED_BODY; a second omit is a clean no-op.
        rec._omit_retained("big")
        assert rec.raw("big") is _OMITTED_BODY

    def test_eviction_scans_past_newer_summaries_to_flag_the_evicted_one(
        self, monkeypatch: MP
    ) -> None:
        # Budget holds two bodies; the third forces the oldest ('a') to be
        # omitted while its summary is no longer the most recent, so the
        # body_omitted flag walk must skip past 'b' to reach 'a'.
        monkeypatch.setattr(client, "_MAX_STORED_BODY", 10_000_000)
        monkeypatch.setattr(client, "_MAX_RETAINED_BYTES", 3500)
        rec = _FlowRecorder(capacity=8)
        rec.response(_flow("a", body=b"x" * 1500))
        rec.response(_flow("b", body=b"y" * 1500))
        rec.response(_flow("c", body=b"z" * 1500))

        by_id = {row["id"]: row for row in rec.snapshot()}
        assert by_id["a"].get("body_omitted") is True
        assert "body_omitted" not in by_id["b"]
        assert "body_omitted" not in by_id["c"]


class TestInstanceStart:
    def test_start_refuses_a_port_already_in_use(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(client, "_port_accepts", lambda *_a, **_k: True)
        inst = _ProxyInstance("127.0.0.1", 18080)
        with pytest.raises(ProxyError) as excinfo:
            inst.start(timeout=1.0)
        assert excinfo.value.code == "invalid_state"

    def test_start_refuses_a_port_it_cannot_bind(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(client, "_port_accepts", lambda *_a, **_k: False)
        monkeypatch.setattr(client, "_port_bindable", lambda *_a, **_k: False)
        inst = _ProxyInstance("127.0.0.1", 18081)
        with pytest.raises(ProxyError) as excinfo:
            inst.start(timeout=1.0)
        assert excinfo.value.code == "invalid_state"

    def test_start_returns_once_the_port_accepts(self, monkeypatch: MP) -> None:
        seen = {"n": 0}

        def _accepts(*_a: object, **_k: object) -> bool:
            # First call is the up-front busy check (must be free); later calls
            # are the readiness probe (server is now listening).
            seen["n"] += 1
            return seen["n"] > 1

        monkeypatch.setattr(client, "_port_accepts", _accepts)
        monkeypatch.setattr(client, "_port_bindable", lambda *_a, **_k: True)
        inst = _ProxyInstance("127.0.0.1", 18082)

        def _fake_run() -> None:
            time.sleep(0.5)

        monkeypatch.setattr(inst, "_run", _fake_run)
        inst.start(timeout=2.0)  # returns without raising

    def test_start_reports_a_thread_error(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(client, "_port_accepts", lambda *_a, **_k: False)
        monkeypatch.setattr(client, "_port_bindable", lambda *_a, **_k: True)
        inst = _ProxyInstance("127.0.0.1", 18083)

        def _fake_run() -> None:
            inst._error = RuntimeError("startup blew up")

        monkeypatch.setattr(inst, "_run", _fake_run)
        with pytest.raises(ProxyError) as excinfo:
            inst.start(timeout=2.0)
        assert excinfo.value.code == "backend_error"
        assert "startup blew up" in str(excinfo.value)

    def test_start_reports_a_thread_that_exits_early(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(client, "_port_accepts", lambda *_a, **_k: False)
        monkeypatch.setattr(client, "_port_bindable", lambda *_a, **_k: True)
        inst = _ProxyInstance("127.0.0.1", 18084)
        monkeypatch.setattr(inst, "_run", lambda: None)  # exits at once, no error
        with pytest.raises(ProxyError) as excinfo:
            inst.start(timeout=2.0)
        assert excinfo.value.code == "backend_error"
        assert "exited during startup" in str(excinfo.value)

    def test_start_times_out_when_the_port_never_accepts(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(client, "_port_accepts", lambda *_a, **_k: False)
        monkeypatch.setattr(client, "_port_bindable", lambda *_a, **_k: True)
        inst = _ProxyInstance("127.0.0.1", 18085)

        def _fake_run() -> None:
            time.sleep(3.0)

        monkeypatch.setattr(inst, "_run", _fake_run)
        with pytest.raises(ProxyError) as excinfo:
            inst.start(timeout=1.0)
        assert excinfo.value.code == "timeout"


def _install_fake_mitmproxy(monkeypatch: MP, dumpmaster: type) -> None:
    mitm = types.ModuleType("mitmproxy")
    options_mod = types.ModuleType("mitmproxy.options")
    tools_mod = types.ModuleType("mitmproxy.tools")
    dump_mod = types.ModuleType("mitmproxy.tools.dump")

    class _Options:
        def __init__(self, **kw: object) -> None:
            self.kw = kw

    options_mod.Options = _Options  # type: ignore[attr-defined]
    dump_mod.DumpMaster = dumpmaster  # type: ignore[attr-defined]
    mitm.options = options_mod  # type: ignore[attr-defined]
    mitm.tools = tools_mod  # type: ignore[attr-defined]
    tools_mod.dump = dump_mod  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mitmproxy", mitm)
    monkeypatch.setitem(sys.modules, "mitmproxy.options", options_mod)
    monkeypatch.setitem(sys.modules, "mitmproxy.tools", tools_mod)
    monkeypatch.setitem(sys.modules, "mitmproxy.tools.dump", dump_mod)


class _FakeAddons:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, addon: object) -> None:
        self.added.append(addon)


class TestInstanceRun:
    def _restore_loop(self) -> None:
        asyncio.set_event_loop(asyncio.new_event_loop())

    def test_run_wires_the_recorder_addon_and_finishes(self, monkeypatch: MP) -> None:
        class _Master:
            def __init__(self, *_a: object, **_k: object) -> None:
                self.addons = _FakeAddons()

            async def run(self) -> None:
                return None

        _install_fake_mitmproxy(monkeypatch, _Master)
        inst = _ProxyInstance("127.0.0.1", 18086)
        try:
            inst._run()
        finally:
            self._restore_loop()
        assert inst._error is None
        assert inst._started.is_set()
        assert inst.recorder in inst._master.addons.added  # type: ignore[union-attr]

    def test_run_falls_back_when_kwargs_are_rejected(self, monkeypatch: MP) -> None:
        seen: dict[str, int] = {"kw": 0, "pos": 0}

        class _Master:
            def __init__(self, opts: object, **kw: object) -> None:
                if kw:
                    seen["kw"] += 1
                    raise TypeError("older mitmproxy signature")
                seen["pos"] += 1
                self.addons = _FakeAddons()

            async def run(self) -> None:
                return None

        _install_fake_mitmproxy(monkeypatch, _Master)
        inst = _ProxyInstance("127.0.0.1", 18087)
        try:
            inst._run()
        finally:
            self._restore_loop()
        assert seen == {"kw": 1, "pos": 1}
        assert inst._error is None

    def test_run_records_a_run_failure_for_the_starter(self, monkeypatch: MP) -> None:
        class _Master:
            def __init__(self, *_a: object, **_k: object) -> None:
                self.addons = _FakeAddons()

            async def run(self) -> None:
                raise RuntimeError("proxy crashed mid-run")

        _install_fake_mitmproxy(monkeypatch, _Master)
        inst = _ProxyInstance("127.0.0.1", 18088)
        try:
            inst._run()
        finally:
            self._restore_loop()
        assert isinstance(inst._error, RuntimeError)
        assert inst._started.is_set()


class _FakeInst:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.host = host
        self.port = port
        self.stopped = 0

    def stop(self) -> None:
        self.stopped += 1


class TestBackendAvailability:
    def test_check_available_raises_when_import_fails(self, monkeypatch: MP) -> None:
        monkeypatch.setitem(sys.modules, "mitmproxy", None)
        backend = ProxyBackend()
        with pytest.raises(ProxyError) as excinfo:
            backend._check_available()
        assert excinfo.value.code == "capability_unavailable"
        assert backend._available is False

    def test_check_available_raises_when_flagged_unavailable(self) -> None:
        backend = ProxyBackend()
        backend._available = False
        with pytest.raises(ProxyError) as excinfo:
            backend._check_available()
        assert excinfo.value.code == "capability_unavailable"


class TestBackendStart:
    def test_start_rejects_a_bad_port(self) -> None:
        backend = ProxyBackend()
        backend._available = True
        with pytest.raises(ProxyError) as excinfo:
            backend.start("s", port=70000)
        assert excinfo.value.code == "invalid_params"

    def test_start_rejects_a_second_proxy_for_the_session(self) -> None:
        backend = ProxyBackend()
        backend._available = True
        backend._instances["s"] = _FakeInst()  # type: ignore[assignment]
        with pytest.raises(ProxyError) as excinfo:
            backend.start("s")
        assert excinfo.value.code == "invalid_state"

    def test_start_rejects_a_port_reserved_by_another_session(self) -> None:
        backend = ProxyBackend()
        backend._available = True
        backend._instances["other"] = _FakeInst(port=8080)  # type: ignore[assignment]
        with pytest.raises(ProxyError) as excinfo:
            backend.start("s", port=8080)
        assert excinfo.value.code == "invalid_state"
        assert excinfo.value.details.get("owner_session_id") == "other"

    def test_start_skips_a_nonmatching_reservation_and_launches(self, monkeypatch: MP) -> None:
        backend = ProxyBackend()
        backend._available = True
        backend._instances["other"] = _FakeInst(port=9999)  # type: ignore[assignment]
        monkeypatch.setattr(client._ProxyInstance, "start", lambda self, *a, **k: None)
        out = backend.start("s", port=8080)
        assert out == {
            "running": True,
            "host": "127.0.0.1",
            "port": 8080,
            "endpoint": "127.0.0.1:8080",
        }
        assert "s" in backend._instances

    def test_start_reclaims_the_reservation_when_launch_fails(self, monkeypatch: MP) -> None:
        backend = ProxyBackend()
        backend._available = True
        stops: list[int] = []

        def _boom(self: Any, *_a: object, **_k: object) -> None:
            stops.append(id(self))
            raise ProxyError("backend_error", "no listen")

        monkeypatch.setattr(client._ProxyInstance, "start", _boom)
        monkeypatch.setattr(client._ProxyInstance, "stop", lambda self: None)
        with pytest.raises(ProxyError):
            backend.start("s", port=8080)
        assert "s" not in backend._instances

    def test_start_reports_a_race_that_dropped_the_reservation(self, monkeypatch: MP) -> None:
        backend = ProxyBackend()
        backend._available = True

        def _drop(self: Any, *_a: object, **_k: object) -> None:
            backend._instances.pop("s", None)  # someone stopped us mid-start

        monkeypatch.setattr(client._ProxyInstance, "start", _drop)
        monkeypatch.setattr(client._ProxyInstance, "stop", lambda self: None)
        with pytest.raises(ProxyError) as excinfo:
            backend.start("s", port=8080)
        assert excinfo.value.code == "invalid_state"
        assert "stopped while starting" in str(excinfo.value)


class TestBackendStopStatus:
    def test_stop_is_a_noop_when_nothing_is_running(self) -> None:
        backend = ProxyBackend()
        out = backend.stop("missing")
        assert out == {"stopped": False, "note": "no proxy was running"}

    def test_stop_tears_down_a_live_instance(self) -> None:
        backend = ProxyBackend()
        inst = _FakeInst()
        backend._instances["s"] = inst  # type: ignore[assignment]
        out = backend.stop("s")
        assert out == {"stopped": True}
        assert inst.stopped == 1
        assert "s" not in backend._instances

    def test_status_reports_not_running_when_absent(self) -> None:
        backend = ProxyBackend()
        assert backend.status("missing") == {"running": False}

    def test_status_reports_ring_metrics_for_a_live_proxy(self) -> None:
        backend = ProxyBackend()
        inst = _ProxyInstance("127.0.0.1", 8080)
        inst.recorder.response(_flow("a", resp=True))
        backend._instances["s"] = inst
        out = backend.status("s")
        assert out["running"] is True
        assert out["flow_count"] == 1
        assert out["host"] == "127.0.0.1"
        assert out["retained_bytes"] >= 0

    def test_get_raises_for_an_unknown_session(self) -> None:
        backend = ProxyBackend()
        with pytest.raises(ProxyError) as excinfo:
            backend._get("nope")
        assert excinfo.value.code == "invalid_state"


def _backend_with_recorder(monkeypatch: MP, recorder: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda _sid: SimpleNamespace(recorder=recorder, _master=None, _loop=None)
    )
    return backend


class TestBackendFlows:
    def test_flows_paginates_and_reports_drops(self) -> None:
        backend = ProxyBackend()
        inst = _ProxyInstance("127.0.0.1", 8080)
        for i in range(5):
            inst.recorder.response(_flow(f"f{i}", resp=True))
        backend._instances["s"] = inst
        out = backend.flows("s", offset=1, limit=2)
        assert out["count"] == 2
        assert out["offset"] == 1
        assert out["total"] == 5
        assert out["has_more"] is True
        assert out["dropped"] == 0

    def test_flows_on_an_empty_capture(self) -> None:
        backend = ProxyBackend()
        backend._instances["s"] = _ProxyInstance("127.0.0.1", 8080)
        out = backend.flows("s")
        assert out["total"] == 0
        assert out["dropped"] == 0
        assert out["has_more"] is False

    def test_flows_has_more_is_false_when_the_last_page_exactly_fills(self) -> None:
        """The off-by-one boundary of ``start + len(window) < total``.

        A final page whose window exactly reaches the end (``start + count ==
        total``) must report ``has_more`` False, and a page one row short of the
        end must report True. This is the ``<`` vs ``<=`` slip the whole
        offset-paginated non-PE surface (proxy.flows, web.network/scripts,
        apk.classes/methods/strings, jsre files) shares the same formula for, so
        pinning it here guards the exact edge the mid-list cases leave open.
        """
        backend = ProxyBackend()
        inst = _ProxyInstance("127.0.0.1", 8080)
        for i in range(6):
            inst.recorder.response(_flow(f"f{i}", resp=True))
        backend._instances["s"] = inst
        # Last page perfectly filled: items[3:6] is 3 rows, 3 + 3 == 6.
        exact = backend.flows("s", offset=3, limit=3)
        assert exact["count"] == 3
        assert exact["total"] == 6
        assert exact["has_more"] is False
        # One row short of the end: items[2:5] is 3 rows, 2 + 3 == 5 < 6.
        short = backend.flows("s", offset=2, limit=3)
        assert short["count"] == 3
        assert short["has_more"] is True


class TestBackendFlowGet:
    def test_flow_get_raises_not_found(self, monkeypatch: MP, tmp_path: Path) -> None:
        backend = _backend_with_recorder(monkeypatch, SimpleNamespace(raw=lambda _f: None))
        with pytest.raises(ProxyError) as excinfo:
            backend.flow_get("s", "gone", tmp_path)
        assert excinfo.value.code == "not_found"

    def test_flow_get_raises_too_large_for_omitted(self, monkeypatch: MP, tmp_path: Path) -> None:
        backend = _backend_with_recorder(
            monkeypatch, SimpleNamespace(raw=lambda _f: _OMITTED_BODY)
        )
        with pytest.raises(ProxyError) as excinfo:
            backend.flow_get("s", "big", tmp_path)
        assert excinfo.value.code == "too_large"

    def test_flow_get_returns_null_status_for_a_bodyless_response(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        flow = _flow("f", method="POST", url="http://x/login", body=b"payload")
        backend = _backend_with_recorder(monkeypatch, SimpleNamespace(raw=lambda _f: flow))
        out = backend.flow_get("s", "f", tmp_path)
        assert out["response"]["status"] is None
        assert out["request"]["body"] == "payload"

    def test_flow_get_flags_truncated_request_metadata(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        flow = _flow("f", url="http://x/" + "q" * (client._MAX_URL_BYTES + 10))
        backend = _backend_with_recorder(monkeypatch, SimpleNamespace(raw=lambda _f: flow))
        out = backend.flow_get("s", "f", tmp_path)
        assert out["request"]["metadata_truncated"] is True
        assert len(out["request"]["url"].encode()) <= client._MAX_URL_BYTES


class TestBackendReplay:
    def _inst_with(self, flow: Any, *, master: Any, loop: Any) -> Any:
        return SimpleNamespace(
            recorder=SimpleNamespace(raw=lambda _f: flow), _master=master, _loop=loop
        )

    def test_replay_raises_not_found(self, monkeypatch: MP) -> None:
        backend = ProxyBackend()
        inst = self._inst_with(None, master=object(), loop=object())
        monkeypatch.setattr(backend, "_get", lambda _s: inst)
        with pytest.raises(ProxyError) as excinfo:
            backend.replay("s", "gone")
        assert excinfo.value.code == "not_found"

    def test_replay_raises_too_large_for_omitted(self, monkeypatch: MP) -> None:
        backend = ProxyBackend()
        inst = self._inst_with(_OMITTED_BODY, master=object(), loop=object())
        monkeypatch.setattr(backend, "_get", lambda _s: inst)
        with pytest.raises(ProxyError) as excinfo:
            backend.replay("s", "big")
        assert excinfo.value.code == "too_large"

    def test_replay_raises_invalid_state_without_a_master(self, monkeypatch: MP) -> None:
        backend = ProxyBackend()
        inst = self._inst_with(SimpleNamespace(copy=lambda: object()), master=None, loop=None)
        monkeypatch.setattr(backend, "_get", lambda _s: inst)
        with pytest.raises(ProxyError) as excinfo:
            backend.replay("s", "f")
        assert excinfo.value.code == "invalid_state"

    def test_replay_succeeds_when_the_command_runs(self, monkeypatch: MP) -> None:
        calls: list[Any] = []

        class _Commands:
            def call(self, name: str, args: list[Any]) -> None:
                calls.append((name, args))

        class _Loop:
            def call_soon_threadsafe(self, fn: Any) -> None:
                fn()

        new_flow = object()
        flow = SimpleNamespace(copy=lambda: new_flow)
        master = SimpleNamespace(commands=_Commands())
        inst = self._inst_with(flow, master=master, loop=_Loop())
        backend = ProxyBackend()
        monkeypatch.setattr(backend, "_get", lambda _s: inst)
        out = backend.replay("s", "f")
        assert out == {"replayed": True, "flow_id": "f"}
        assert calls == [("replay.client", [new_flow])]

    def test_replay_wraps_a_command_failure(self, monkeypatch: MP) -> None:
        class _Commands:
            def call(self, *_a: object) -> None:
                raise RuntimeError("replay backend said no")

        class _Loop:
            def call_soon_threadsafe(self, fn: Any) -> None:
                fn()

        flow = SimpleNamespace(copy=lambda: object())
        master = SimpleNamespace(commands=_Commands())
        inst = self._inst_with(flow, master=master, loop=_Loop())
        backend = ProxyBackend()
        monkeypatch.setattr(backend, "_get", lambda _s: inst)
        with pytest.raises(ProxyError) as excinfo:
            backend.replay("s", "f")
        assert excinfo.value.code == "backend_error"

    def test_replay_reraises_a_proxy_error_unchanged(self, monkeypatch: MP) -> None:
        def _copy() -> Any:
            raise ProxyError("invalid_state", "flow is not replayable")

        flow = SimpleNamespace(copy=_copy)
        inst = self._inst_with(flow, master=object(), loop=object())
        backend = ProxyBackend()
        monkeypatch.setattr(backend, "_get", lambda _s: inst)
        with pytest.raises(ProxyError) as excinfo:
            backend.replay("s", "f")
        assert excinfo.value.code == "invalid_state"

    def test_replay_times_out_when_the_command_never_runs(self, monkeypatch: MP) -> None:
        class _Loop:
            def call_soon_threadsafe(self, _fn: Any) -> None:
                return None  # never schedules the work

        monkeypatch.setattr(client, "_REPLAY_WAIT_S", 0.1)
        flow = SimpleNamespace(copy=lambda: object())
        master = SimpleNamespace(commands=SimpleNamespace(call=lambda *_a: None))
        inst = self._inst_with(flow, master=master, loop=_Loop())
        backend = ProxyBackend()
        monkeypatch.setattr(backend, "_get", lambda _s: inst)
        with pytest.raises(ProxyError) as excinfo:
            backend.replay("s", "f")
        assert excinfo.value.code == "timeout"


class TestCaCertAndCloseAll:
    def test_ca_cert_path_returns_the_first_existing_file(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        (tmp_path / ".mitmproxy").mkdir()
        cert = tmp_path / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        cert.write_text("cert")
        monkeypatch.setattr(client.Path, "home", classmethod(lambda cls: tmp_path))
        backend = ProxyBackend()
        assert backend.ca_cert_path() == cert

    def test_ca_cert_path_returns_none_when_absent(self, monkeypatch: MP, tmp_path: Path) -> None:
        monkeypatch.setattr(client.Path, "home", classmethod(lambda cls: tmp_path))
        backend = ProxyBackend()
        assert backend.ca_cert_path() is None

    def test_close_all_stops_every_instance(self) -> None:
        backend = ProxyBackend()
        a, b = _FakeInst(), _FakeInst()
        backend._instances["a"] = a  # type: ignore[assignment]
        backend._instances["b"] = b  # type: ignore[assignment]
        backend.close_all()
        assert a.stopped == 1
        assert b.stopped == 1
        assert backend._instances == {}


def test_stop_signals_shutdown_and_joins(monkeypatch: MP) -> None:
    """stop() drains, signals shutdown, joins, and clears the handles."""
    calls: list[str] = []
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._loop = loop

    class _Master:
        def shutdown(self) -> None:
            calls.append("shutdown")
            loop.call_soon_threadsafe(loop.stop)

    inst._master = _Master()
    inst._thread = thread
    monkeypatch.setattr(client, "_drain_proxy_servers", lambda *_a: calls.append("drain"))
    try:
        inst.stop()
    finally:
        if not loop.is_closed():
            loop.close()
    assert "drain" in calls and "shutdown" in calls
    assert inst._master is None
    assert inst._loop is None
