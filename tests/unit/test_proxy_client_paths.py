"""Runtime arms of the mitmproxy backend, driven by injected fakes.

mitmproxy is optional and not installed in CI, so the existing suite pins a
few field shapes but leaves most of the backend unrun: the socket/loop/logging
teardown helpers, the byte-measuring helpers, the flow-recording ring buffer
with its omission and eviction logic, the instance start/stop error arms, and
the backend's per-method translation (start reservation races, flow_get,
replay, export_har, ca_cert_path). These drive those arms with fake flows,
masters, loops and a fake mitmproxy import -- no proxy, no sockets to a real
server -- where the real handling lives.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _MAX_INLINE_BODY,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _bounded_metadata,
    _content_len,
    _drain_proxy_servers,
    _emit_body,
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

# --------------------------------------------------------------------------- #
# byte-measuring helpers
# --------------------------------------------------------------------------- #


def test_content_len_reads_bytes_or_zero() -> None:
    assert _content_len(None) == 0
    assert _content_len(SimpleNamespace(raw_content=None)) == 0
    assert _content_len(SimpleNamespace(raw_content=b"abcd")) == 4

    class _Weird:
        raw_content = SimpleNamespace()  # truthy but len() raises TypeError

    assert _content_len(_Weird()) == 0


def test_encoded_len_falls_back_when_str_raises() -> None:
    assert _encoded_len("hello") == 5

    class _Bad:
        def __str__(self) -> str:
            raise RuntimeError("no str")

    assert _encoded_len(_Bad()) == proxy_client._MAX_STORED_BODY + 1


class _MultiHeaders:
    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = pairs

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        del multi
        return list(self._pairs)

    def get(self, key: str, default: str = "") -> str:
        for k, v in self._pairs:
            if k == key:
                return v
        return default


def test_headers_len_handles_multi_dict_none_and_errors() -> None:
    assert _headers_len(SimpleNamespace(headers=None)) == 0
    # multi=True path
    multi = _MultiHeaders([("a", "1"), ("b", "22")])
    assert _headers_len(SimpleNamespace(headers=multi)) == len("a1") + len("b22")
    # plain dict: .items(multi=) raises TypeError -> fallback to .items()
    assert _headers_len(SimpleNamespace(headers={"a": "1"})) == 2

    class _BoomHeaders:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("broken header map")

    assert _headers_len(SimpleNamespace(headers=_BoomHeaders())) == 0


def test_headers_len_stops_at_the_stored_body_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 4)
    big = _MultiHeaders([("k", "v" * 100), ("k2", "v" * 100)])
    # The running total passes the ceiling on the first pair and breaks.
    assert _headers_len(SimpleNamespace(headers=big)) > 4


def test_bounded_metadata_truncates() -> None:
    assert _bounded_metadata("abc", 8) == ("abc", False)
    assert _bounded_metadata(None, 8) == ("", False)
    text, cut = _bounded_metadata("x" * 50, 10)
    assert cut is True and len(text.encode("utf-8")) <= 10


def test_raw_body_reads_bytes_or_empty() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content=b"abc")) == b"abc"
    assert _raw_body(SimpleNamespace(raw_content="not-bytes")) == b""

    class _Boom:
        @property
        def raw_content(self) -> bytes:
            raise RuntimeError("decode failed")

    assert _raw_body(_Boom()) == b""


def test_emit_body_inlines_spills_binary_and_too_large(tmp_path: Path) -> None:
    assert _emit_body(b"", tmp_path) == {"size": 0, "body": ""}

    inline = _emit_body(b"hello", tmp_path)
    assert inline == {"size": 5, "body": "hello"}

    binary = _emit_body(b"\xff\xfe\x00", tmp_path)
    assert binary["spill_reason"] == "binary"
    assert Path(binary["body_path"]).read_bytes() == b"\xff\xfe\x00"

    big = b"a" * (_MAX_INLINE_BODY + 10)
    spilled = _emit_body(big, tmp_path)
    assert spilled["spill_reason"] == "too_large"
    assert Path(spilled["body_path"]).read_bytes() == big


def test_bounded_headers_reports_total_and_read_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BoomHeaders:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("cannot enumerate")

    out, truncated = _bounded_headers(SimpleNamespace(headers=_BoomHeaders()))
    assert out == {} and truncated is True

    # Total-size cap: two moderate headers whose sum passes the total ceiling.
    monkeypatch.setattr(proxy_client, "_MAX_FLOW_HEADERS_TOTAL_BYTES", 8)
    headers = _MultiHeaders([("aaaa", "bbbb"), ("cccc", "dddd")])
    out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
    assert truncated is True
    assert len(out) <= 1


# --------------------------------------------------------------------------- #
# socket / loop / logging teardown helpers
# --------------------------------------------------------------------------- #


def test_port_bindable_and_accepts_agree_with_a_real_listener() -> None:
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        assert _port_accepts(host, port) is True
        # A live listener holds the port, so a second bind must fail.
        assert _port_bindable(host, port) is False
    finally:
        listener.close()
    # Once closed, nothing accepts and the port is bindable again.
    assert _port_accepts(host, port) is False
    assert _port_bindable(host, port) is True


def test_port_accepts_swallows_resolution_failures() -> None:
    assert _port_accepts("host.that.does.not.resolve.invalid", 80) is False


def test_shutdown_loop_cancels_pending_tasks_and_closes() -> None:
    loop = asyncio.new_event_loop()

    async def sleeper() -> None:
        await asyncio.sleep(100)

    loop.create_task(sleeper())
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_shutdown_loop_with_nothing_pending_just_closes() -> None:
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_uninstall_master_logging_is_a_noop_without_targets() -> None:
    # Both None: early return, no scan.
    _uninstall_master_logging(None, None)


def test_uninstall_master_logging_removes_the_handler_and_root_entry() -> None:
    uninstalled: list[str] = []
    handler = SimpleNamespace(uninstall=lambda: uninstalled.append("gone"))
    master = SimpleNamespace(_legacy_log_events=handler, event_loop=None)

    root = logging.getLogger()
    stray = logging.NullHandler()
    stray.master = master  # type: ignore[attr-defined]
    root.addHandler(stray)
    try:
        _uninstall_master_logging(master)
        assert uninstalled == ["gone"]
        assert stray not in root.handlers
    finally:
        if stray in root.handlers:
            root.removeHandler(stray)


def test_uninstall_master_logging_matches_by_loop() -> None:
    loop = asyncio.new_event_loop()
    root = logging.getLogger()
    stray = logging.NullHandler()
    stray.master = SimpleNamespace(event_loop=loop)  # type: ignore[attr-defined]
    unrelated = logging.NullHandler()
    unrelated.master = SimpleNamespace(event_loop=None)  # type: ignore[attr-defined]
    root.addHandler(stray)
    root.addHandler(unrelated)
    try:
        _uninstall_master_logging(None, loop)
        assert stray not in root.handlers
        # A handler owned by some other master stays installed.
        assert unrelated in root.handlers
    finally:
        for handler in (stray, unrelated):
            if handler in root.handlers:
                root.removeHandler(handler)
        loop.close()


def test_drain_proxy_servers_returns_early_and_swallows_errors() -> None:
    # Addon without a servers.update: return without scheduling.
    master = SimpleNamespace(addons=SimpleNamespace(get=lambda name: SimpleNamespace()))
    _drain_proxy_servers(master, asyncio.new_event_loop())

    # addons.get raising: swallowed.
    def boom(name: str) -> Any:
        raise RuntimeError("addon surface changed")

    broken = SimpleNamespace(addons=SimpleNamespace(get=boom))
    _drain_proxy_servers(broken, asyncio.new_event_loop())


def test_drain_proxy_servers_awaits_the_update_on_a_live_loop() -> None:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    seen: list[Any] = []

    async def update(servers: Any) -> None:
        seen.append(servers)

    addon = SimpleNamespace(servers=SimpleNamespace(update=update))
    master = SimpleNamespace(addons=SimpleNamespace(get=lambda name: addon))
    try:
        _drain_proxy_servers(master, loop)
        assert seen == [[]]
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=2.0)
        loop.close()


# --------------------------------------------------------------------------- #
# _FlowRecorder
# --------------------------------------------------------------------------- #


def _flow(
    *,
    flow_id: str = "f1",
    method: str = "GET",
    url: str = "http://x/1",
    host: str = "x",
    status: int | None = 200,
    body: bytes = b"body",
    content_type: str = "text/plain",
    error: Any = None,
) -> Any:
    request = SimpleNamespace(method=method, pretty_url=url, host=host, headers={}, raw_content=b"")
    response = (
        SimpleNamespace(
            status_code=status, headers={"content-type": content_type}, raw_content=body
        )
        if status is not None or body
        else None
    )
    return SimpleNamespace(id=flow_id, request=request, response=response, error=error)


def test_recorder_records_response_and_error_flows() -> None:
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="ok", status=200, body=b"hello world"))
    recorder.error(_flow(flow_id="bad", status=None, body=b"", error=SimpleNamespace(msg="reset")))
    snap = recorder.snapshot()
    assert recorder.count() == 2
    ok = next(e for e in snap if e["id"] == "ok")
    bad = next(e for e in snap if e["id"] == "bad")
    assert ok["status"] == 200
    assert ok["response_size"] == len(b"hello world")
    assert bad["error"] is True
    assert bad["error_msg"] == "reset"
    assert bad["status"] is None
    assert recorder.raw("ok") is not None


def test_recorder_omits_a_body_over_the_store_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 4)
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="big", body=b"a much longer body than four bytes"))
    entry = recorder.snapshot()[0]
    assert entry["body_omitted"] is True
    assert recorder.raw("big") is _OMITTED_BODY


def test_recorder_evicts_to_stay_under_the_retained_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Each flow stores ~49 bytes, so one fits under 60 but two do not: the
    # second record must omit the FIRST flow's retained body, not its own.
    monkeypatch.setattr(proxy_client, "_MAX_RETAINED_BYTES", 60)
    recorder = _FlowRecorder()
    recorder.response(_flow(flow_id="f0", url="http://x/0", body=b"payload-bytes"))
    assert recorder.raw("f0") is not _OMITTED_BODY
    recorder.response(_flow(flow_id="f1", url="http://x/1", body=b"payload-bytes"))
    assert recorder.raw("f0") is _OMITTED_BODY
    assert recorder.raw("f1") is not _OMITTED_BODY
    first = next(e for e in recorder.snapshot() if e["id"] == "f0")
    assert first["body_omitted"] is True
    assert recorder.retained_bytes() <= 60
    # A third record walks past the already-omitted f0 and evicts f1's body.
    recorder.response(_flow(flow_id="f2", url="http://x/2", body=b"payload-bytes"))
    assert recorder.raw("f1") is _OMITTED_BODY
    assert recorder.raw("f2") is not _OMITTED_BODY


def test_recorder_flags_truncated_metadata_in_the_summary() -> None:
    recorder = _FlowRecorder()
    recorder.response(
        _flow(flow_id="long", url="http://x/" + "a" * (proxy_client._MAX_URL_BYTES * 2))
    )
    entry = recorder.snapshot()[0]
    assert entry["metadata_truncated"] is True
    assert len(entry["url"].encode("utf-8")) <= proxy_client._MAX_URL_BYTES


def test_omit_retained_ignores_unknown_and_already_omitted_ids() -> None:
    recorder = _FlowRecorder()
    recorder._omit_retained("missing")  # no such flow: early return
    assert recorder.retained_bytes() == 0


def test_recorder_lockstep_eviction_at_capacity() -> None:
    recorder = _FlowRecorder(capacity=2)
    for i in range(4):
        recorder.response(_flow(flow_id=f"f{i}", url=f"http://x/{i}", body=b"x"))
    assert recorder.count() == 2
    # The raw store never exceeds the ring capacity.
    assert recorder.raw("f0") is None
    assert recorder.raw("f3") is not None


# --------------------------------------------------------------------------- #
# _ProxyInstance start/stop
# --------------------------------------------------------------------------- #


def test_instance_start_refuses_a_taken_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda host, port, timeout=0.25: True)
    inst = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as exc:
        inst.start()
    assert exc.value.code == "invalid_state"


def test_instance_start_refuses_an_unbindable_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda host, port, timeout=0.25: False)
    monkeypatch.setattr(proxy_client, "_port_bindable", lambda host, port: False)
    inst = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as exc:
        inst.start()
    assert exc.value.code == "invalid_state"


def test_instance_start_reports_a_thread_that_fails_to_launch_mitmproxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # mitmproxy is absent, so the real _run raises ImportError, sets _error, and
    # start() surfaces it as backend_error -- exercising _run's except/finally.
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda host, port, timeout=0.25: False)
    monkeypatch.setattr(proxy_client, "_port_bindable", lambda host, port: True)
    inst = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as exc:
        inst.start(timeout=1.0)
    assert exc.value.code == "backend_error"


def test_instance_start_returns_once_the_port_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes = {"n": 0}

    def fake_accepts(host: str, port: int, timeout: float = 0.25) -> bool:
        probes["n"] += 1
        return probes["n"] > 1  # the up-front guard sees a free port; the loop sees it bound

    monkeypatch.setattr(proxy_client, "_port_accepts", fake_accepts)
    monkeypatch.setattr(proxy_client, "_port_bindable", lambda host, port: True)
    release = threading.Event()
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._run = lambda: release.wait(5.0)  # type: ignore[method-assign, assignment]
    try:
        inst.start(timeout=2.0)
    finally:
        release.set()


def test_instance_start_reports_a_thread_that_exits_before_listening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda host, port, timeout=0.25: False)
    monkeypatch.setattr(proxy_client, "_port_bindable", lambda host, port: True)
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._run = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as exc:
        inst.start(timeout=2.0)
    assert exc.value.code == "backend_error"
    assert "exited" in exc.value.message


def test_instance_start_times_out_when_the_port_never_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_client, "_port_accepts", lambda host, port, timeout=0.25: False)
    monkeypatch.setattr(proxy_client, "_port_bindable", lambda host, port: True)
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._run = lambda: time.sleep(1.4)  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as exc:
        inst.start(timeout=1.0)
    assert exc.value.code == "timeout"


class _FakeOptions:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def _install_fake_mitmproxy(monkeypatch: pytest.MonkeyPatch, dump_master: type) -> None:
    import types

    root = types.ModuleType("mitmproxy")
    options_mod = types.ModuleType("mitmproxy.options")
    options_mod.Options = _FakeOptions  # type: ignore[attr-defined]
    root.options = options_mod  # type: ignore[attr-defined]
    tools = types.ModuleType("mitmproxy.tools")
    dump = types.ModuleType("mitmproxy.tools.dump")
    dump.DumpMaster = dump_master  # type: ignore[attr-defined]
    tools.dump = dump  # type: ignore[attr-defined]
    root.tools = tools  # type: ignore[attr-defined]
    for name, module in (
        ("mitmproxy", root),
        ("mitmproxy.options", options_mod),
        ("mitmproxy.tools", tools),
        ("mitmproxy.tools.dump", dump),
    ):
        monkeypatch.setitem(sys.modules, name, module)


class _FakeDumpMaster:
    def __init__(self, opts: Any, **kwargs: Any) -> None:
        self.opts = opts
        self.kwargs = kwargs
        self.added: list[Any] = []
        self.addons = SimpleNamespace(add=self.added.append)
        self._legacy_log_events = None

    async def run(self) -> None:
        return None


class _LegacyDumpMaster(_FakeDumpMaster):
    def __init__(self, opts: Any, **kwargs: Any) -> None:
        if kwargs:
            raise TypeError("unexpected keyword arguments")
        super().__init__(opts)


def test_instance_run_drives_a_master_to_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_mitmproxy(monkeypatch, _FakeDumpMaster)
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._run()
    assert inst._error is None
    assert inst._started.is_set()
    master = inst._master
    assert isinstance(master, _FakeDumpMaster)
    assert master.added == [inst.recorder]
    assert master.kwargs == {"loop": inst._loop, "with_termlog": False, "with_dumper": False}
    assert inst._loop is not None and inst._loop.is_closed()


def test_instance_run_falls_back_for_an_older_master_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_mitmproxy(monkeypatch, _LegacyDumpMaster)
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._run()
    assert inst._error is None
    master = inst._master
    assert isinstance(master, _LegacyDumpMaster)
    assert master.kwargs == {}


def test_instance_stop_is_safe_without_a_master() -> None:
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst.stop()  # no thread, no master: a no-op that clears state
    assert inst._master is None and inst._loop is None


def test_instance_stop_shuts_down_a_live_master() -> None:
    calls: list[str] = []

    class _FakeLoop:
        def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
            calls.append("shutdown-scheduled")
            fn(*args)

    master = SimpleNamespace(shutdown=lambda: calls.append("shutdown"), _legacy_log_events=None)
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._master = master
    inst._loop = _FakeLoop()  # type: ignore[assignment]
    inst._thread = None  # dead/absent thread: skip drain, still schedule shutdown
    inst.stop()
    assert "shutdown" in calls
    assert inst._master is None


def test_instance_stop_drains_while_the_proxy_thread_is_alive() -> None:
    done = threading.Event()
    thread = threading.Thread(target=done.wait, args=(5.0,), daemon=True)
    thread.start()

    class _InlineLoop:
        def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
            fn(*args)

    # The addon surface exposes no servers.update, so the drain returns early
    # -- but only a live thread reaches it at all.
    master = SimpleNamespace(
        addons=SimpleNamespace(get=lambda name: SimpleNamespace()),
        shutdown=done.set,
        _legacy_log_events=None,
    )
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._master = master
    inst._loop = _InlineLoop()  # type: ignore[assignment]
    inst._thread = thread
    inst.stop()
    assert not thread.is_alive()
    assert inst._master is None


# --------------------------------------------------------------------------- #
# ProxyBackend
# --------------------------------------------------------------------------- #


def test_backend_check_available_reports_and_caches() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as exc:
        backend.start("s")  # mitmproxy absent -> capability_unavailable
    assert exc.value.code == "capability_unavailable"

    backend._available = True
    backend._check_available()  # cached True: returns without re-import
    backend._available = False
    with pytest.raises(ProxyError):
        backend._check_available()


def test_backend_check_available_detects_an_installed_mitmproxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_mitmproxy(monkeypatch, _FakeDumpMaster)
    backend = ProxyBackend()
    backend._check_available()
    assert backend._available is True


def test_backend_start_rejects_bad_port_and_double_start() -> None:
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as exc:
        backend.start("s", port=99999)
    assert exc.value.code == "invalid_params"

    existing = _ProxyInstance("127.0.0.1", 8080)
    backend._instances["s"] = existing
    with pytest.raises(ProxyError) as exc:
        backend.start("s", port=8080)
    assert exc.value.code == "invalid_state"


def test_backend_start_rejects_a_port_reserved_by_another_session() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["owner"] = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as exc:
        backend.start("new", host="127.0.0.1", port=8080)
    assert exc.value.code == "invalid_state"
    assert exc.value.details.get("owner_session_id") == "owner"


def test_backend_start_cleans_up_when_the_listener_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._available = True

    def boom_start(self: _ProxyInstance, timeout: float = 15.0) -> None:
        raise ProxyError("backend_error", "listener died")

    monkeypatch.setattr(_ProxyInstance, "start", boom_start)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: None)
    with pytest.raises(ProxyError) as exc:
        backend.start("s", port=8080)
    assert exc.value.code == "backend_error"
    assert "s" not in backend._instances  # reservation released


def test_backend_start_releases_nothing_when_a_racing_stop_already_did(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._available = True

    def vanish_then_boom(self: _ProxyInstance, timeout: float = 15.0) -> None:
        backend._instances.pop("s", None)  # a concurrent stop dropped the slot
        raise ProxyError("backend_error", "listener died")

    monkeypatch.setattr(_ProxyInstance, "start", vanish_then_boom)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: None)
    with pytest.raises(ProxyError):
        backend.start("s", port=8080)
    assert "s" not in backend._instances


def test_backend_start_succeeds_when_the_listener_binds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._available = True
    # Another session on a different port must not block this one.
    backend._instances["other"] = _ProxyInstance("127.0.0.1", 9090)
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    payload = backend.start("s", host="127.0.0.1", port=8080)
    assert payload == {
        "running": True,
        "host": "127.0.0.1",
        "port": 8080,
        "endpoint": "127.0.0.1:8080",
    }


def test_backend_start_detects_a_stop_during_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._available = True

    def start_then_vanish(self: _ProxyInstance, timeout: float = 15.0) -> None:
        # Simulate a concurrent stop() dropping the reservation mid-launch.
        backend._instances.pop("s", None)

    monkeypatch.setattr(_ProxyInstance, "start", start_then_vanish)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: None)
    with pytest.raises(ProxyError) as exc:
        backend.start("s", port=8080)
    assert exc.value.code == "invalid_state"


def test_backend_stop_and_status_report_a_live_instance() -> None:
    stopped: list[str] = []
    recorder = SimpleNamespace(count=lambda: 3, retained_bytes=lambda: 4096)
    inst = SimpleNamespace(
        host="127.0.0.1", port=8080, recorder=recorder, stop=lambda: stopped.append("stopped")
    )
    backend = ProxyBackend()
    backend._instances["s"] = inst  # type: ignore[assignment]

    status = backend.status("s")
    assert status["running"] is True
    assert status["flow_count"] == 3
    assert status["retained_bytes"] == 4096

    payload = backend.stop("s")
    assert payload == {"stopped": True}
    assert stopped == ["stopped"]


def test_backend_flows_paginates_and_reports_dropped() -> None:
    entries = [{"id": f"f{i}", "seq": i + 10} for i in range(5)]
    recorder = SimpleNamespace(snapshot=lambda: entries)
    backend = ProxyBackend()
    backend._get = cast(Any, lambda session_id: SimpleNamespace(recorder=recorder))
    payload = backend.flows("s", offset=1, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["offset"] == 1
    assert payload["has_more"] is True
    # last seq 14, len 5 -> 9 dropped before the ring window.
    assert payload["dropped"] == 9


def test_backend_flows_on_an_empty_capture() -> None:
    recorder = SimpleNamespace(snapshot=lambda: [])
    backend = ProxyBackend()
    backend._get = cast(Any, lambda session_id: SimpleNamespace(recorder=recorder))
    payload = backend.flows("s")
    assert payload == {
        "flows": [],
        "count": 0,
        "total": 0,
        "offset": 0,
        "has_more": False,
        "dropped": 0,
    }


def _backend_with_flow(flow: Any) -> ProxyBackend:
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    backend = ProxyBackend()
    backend._get = lambda session_id: SimpleNamespace(  # type: ignore[method-assign]
        recorder=recorder, _master=None, _loop=None
    )
    return backend


def test_flow_get_reports_unknown_and_omitted(tmp_path: Path) -> None:
    with pytest.raises(ProxyError) as exc:
        _backend_with_flow(None).flow_get("s", "gone", tmp_path)
    assert exc.value.code == "not_found"

    with pytest.raises(ProxyError) as exc:
        _backend_with_flow(_OMITTED_BODY).flow_get("s", "big", tmp_path)
    assert exc.value.code == "too_large"


def test_flow_get_returns_request_and_response_bodies(tmp_path: Path) -> None:
    request = SimpleNamespace(
        method="POST", pretty_url="http://x/api", headers={"a": "1"}, raw_content=b"payload"
    )
    response = SimpleNamespace(status_code=201, headers={"b": "2"}, raw_content=b"ok")
    flow = SimpleNamespace(request=request, response=response)
    payload = _backend_with_flow(flow).flow_get("s", "f1", tmp_path)
    assert payload["request"]["body"] == "payload"
    assert payload["response"]["status"] == 201
    assert payload["response"]["body"] == "ok"


def test_flow_get_flags_a_truncated_request_side(tmp_path: Path) -> None:
    many = {f"h{i}": "v" for i in range(proxy_client._MAX_FLOW_HEADERS + 10)}
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers=many, raw_content=b"")
    flow = SimpleNamespace(request=request, response=None)
    payload = _backend_with_flow(flow).flow_get("s", "f1", tmp_path)
    assert payload["request"]["metadata_truncated"] is True
    assert payload["response"]["status"] is None


def test_replay_reports_missing_omitted_and_stopped(tmp_path: Path) -> None:
    with pytest.raises(ProxyError) as exc:
        _backend_with_flow(None).replay("s", "gone")
    assert exc.value.code == "not_found"

    with pytest.raises(ProxyError) as exc:
        _backend_with_flow(_OMITTED_BODY).replay("s", "big")
    assert exc.value.code == "too_large"

    # A real flow but no running master/loop.
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    with pytest.raises(ProxyError) as exc:
        _backend_with_flow(flow).replay("s", "f1")
    assert exc.value.code == "invalid_state"


class _FakeLoop:
    def __init__(self, *, run: bool = True) -> None:
        self._run = run

    def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
        if self._run:
            fn(*args)


def _replay_backend(flow: Any, master: Any, loop: Any) -> ProxyBackend:
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    backend = ProxyBackend()
    backend._get = lambda session_id: SimpleNamespace(  # type: ignore[method-assign]
        recorder=recorder, _master=master, _loop=loop
    )
    return backend


def test_replay_succeeds_when_the_command_runs() -> None:
    calls: list[Any] = []
    master = SimpleNamespace(
        commands=SimpleNamespace(call=lambda name, args: calls.append((name, args)))
    )
    flow = SimpleNamespace(copy=lambda: SimpleNamespace(name="copy"))
    backend = _replay_backend(flow, master, _FakeLoop())
    payload = backend.replay("s", "f1")
    assert payload == {"replayed": True, "flow_id": "f1"}
    assert calls[0][0] == "replay.client"


def test_replay_passes_a_proxy_error_through_unwrapped() -> None:
    def refuse(name: str, args: Any) -> None:
        raise ProxyError("invalid_state", "flow is not replayable")

    master = SimpleNamespace(commands=SimpleNamespace(call=refuse))
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    backend = _replay_backend(flow, master, _FakeLoop())
    with pytest.raises(ProxyError) as exc:
        backend.replay("s", "f1")
    assert exc.value.code == "invalid_state"


def test_replay_maps_a_command_failure_to_backend_error() -> None:
    def boom(name: str, args: Any) -> None:
        raise RuntimeError("replay engine off")

    master = SimpleNamespace(commands=SimpleNamespace(call=boom))
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    backend = _replay_backend(flow, master, _FakeLoop())
    with pytest.raises(ProxyError) as exc:
        backend.replay("s", "f1")
    assert exc.value.code == "backend_error"


def test_replay_times_out_when_the_command_never_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_client, "_REPLAY_WAIT_S", 0.1)
    master = SimpleNamespace(commands=SimpleNamespace(call=lambda name, args: None))
    flow = SimpleNamespace(copy=lambda: SimpleNamespace())
    # The loop never runs the scheduled callback, so the future never resolves.
    backend = _replay_backend(flow, master, _FakeLoop(run=False))
    with pytest.raises(ProxyError) as exc:
        backend.replay("s", "f1")
    assert exc.value.code == "timeout"


def test_export_har_refuses_over_the_cap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    huge = proxy_client.UNREGISTERED_CAPTURE_MAX_BYTES + 1
    monkeypatch.setattr(
        proxy_client,
        "serialize_har",
        lambda entries, max_bytes: SimpleNamespace(
            text="{}", size=huge, entry_count=0, truncated=True
        ),
    )
    recorder = SimpleNamespace(snapshot=lambda: [{"method": "GET", "url": "http://x"}])
    backend = ProxyBackend()
    backend._get = cast(Any, lambda session_id: SimpleNamespace(recorder=recorder))
    with pytest.raises(ProxyError) as exc:
        backend.export_har("s", tmp_path / "out.har")
    assert exc.value.code == "too_large"


def test_export_har_writes_a_bounded_file(tmp_path: Path) -> None:
    recorder = SimpleNamespace(
        snapshot=lambda: [
            {
                "method": "GET",
                "url": "http://x/1",
                "status": 200,
                "content_type": "text/html",
                "response_size": 10,
            }
        ]
    )
    backend = ProxyBackend()
    backend._get = cast(Any, lambda session_id: SimpleNamespace(recorder=recorder))
    out = tmp_path / "cap.har"
    payload = backend.export_har("s", out)
    assert out.is_file()
    assert payload["entry_count"] == 1


def test_ca_cert_path_finds_a_cert_or_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(proxy_client.Path, "home", lambda: tmp_path)
    assert ProxyBackend().ca_cert_path() is None
    certdir = tmp_path / ".mitmproxy"
    certdir.mkdir()
    (certdir / "mitmproxy-ca-cert.pem").write_text("CERT", encoding="utf-8")
    found = ProxyBackend().ca_cert_path()
    assert found is not None and found.name == "mitmproxy-ca-cert.pem"


def test_close_all_stops_every_instance() -> None:
    stopped: list[str] = []
    backend = ProxyBackend()
    backend._instances["a"] = SimpleNamespace(stop=lambda: stopped.append("a"))  # type: ignore[assignment]
    backend._instances["b"] = SimpleNamespace(stop=lambda: stopped.append("b"))  # type: ignore[assignment]
    backend.close_all()
    assert sorted(stopped) == ["a", "b"]
    assert backend._instances == {}
