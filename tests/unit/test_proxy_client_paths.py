"""Proxy backend paths the field/lifecycle suites do not reach.

These cover the pure helpers (loop teardown, port probes, body/header bounding),
the ``_FlowRecorder`` ring buffer with its byte-budget eviction and error-flow
capture, and the ``ProxyBackend`` read/replay/export contracts. Real mitmproxy
startup is exercised by the lifecycle gate; here the master, loop and flows are
fakes so the bookkeeping and honesty branches run without binding a port.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _bounded_metadata,
    _content_len,
    _drain_proxy_servers,
    _emit_body,
    _encoded_len,
    _flow_stored_bytes,
    _FlowRecorder,
    _headers_len,
    _port_accepts,
    _port_bindable,
    _ProxyInstance,
    _raw_body,
    _shutdown_loop,
    _uninstall_master_logging,
)

_CLIENT = "headless_re_mcp.backends.proxy.client"


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------
class _Headers:
    def __init__(self, pairs: list[tuple[str, str]], *, no_multi: bool = False) -> None:
        self._pairs = pairs
        self._no_multi = no_multi

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        if multi and self._no_multi:
            raise TypeError("multi not supported")
        return list(self._pairs)

    def get(self, key: str, default: str = "") -> str:
        for name, value in self._pairs:
            if name.lower() == key.lower():
                return value
        return default


class _Part:
    def __init__(
        self,
        *,
        method: str = "GET",
        pretty_url: str = "http://x/",
        host: str = "x",
        status_code: int | None = 200,
        raw_content: Any = b"",
        headers: _Headers | None = None,
    ) -> None:
        self.method = method
        self.pretty_url = pretty_url
        self.host = host
        self.status_code = status_code
        self.raw_content = raw_content
        self.headers = headers if headers is not None else _Headers([])


class _Flow:
    def __init__(
        self,
        *,
        flow_id: str = "f1",
        request: _Part | None = None,
        response: _Part | None = None,
        error: Any = None,
    ) -> None:
        self.id = flow_id
        self.request = request if request is not None else _Part()
        self.response = response
        self.error = error

    def copy(self) -> _Flow:
        return _Flow(flow_id=self.id + "-copy", request=self.request, response=self.response)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------
def test_shutdown_loop_cancels_pending_and_closes() -> None:
    loop = asyncio.new_event_loop()

    async def seed() -> None:
        asyncio.ensure_future(asyncio.sleep(100))  # noqa: RUF006 - intentionally pending

    loop.run_until_complete(seed())
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_port_accepts_and_bindable() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    try:
        assert _port_accepts(host, port) is True
        # A port with a live listener is not bindable.
        assert _port_bindable(host, port) is False
    finally:
        listener.close()
    # After close nothing accepts and the port is bindable again.
    assert _port_accepts(host, port) is False


def test_content_and_encoded_and_headers_len() -> None:
    assert _content_len(None) == 0
    assert _content_len(_Part(raw_content=b"abcd")) == 4
    assert _content_len(_Part(raw_content=b"")) == 0
    # raw_content that has no len() reads as zero, not a crash.
    assert _content_len(SimpleNamespace(raw_content=object())) == 0

    assert _encoded_len("héllo") == len("héllo".encode())

    part = _Part(headers=_Headers([("A", "1"), ("B", "22")]))
    assert _headers_len(part) == _encoded_len("A") + _encoded_len("1") + _encoded_len(
        "B"
    ) + _encoded_len("22")
    assert _headers_len(SimpleNamespace(headers=None)) == 0


def test_headers_len_falls_back_when_multi_unsupported() -> None:
    part = _Part(headers=_Headers([("A", "1")], no_multi=True))
    assert _headers_len(part) == _encoded_len("A") + _encoded_len("1")


def test_flow_stored_bytes_sums_bodies_and_metadata() -> None:
    req = _Part(raw_content=b"12345", headers=_Headers([("H", "v")]))
    resp = _Part(raw_content=b"678", headers=_Headers([]))
    total = _flow_stored_bytes(_Flow(request=req, response=resp))
    assert total >= 5 + 3  # both bodies counted, plus method/url/host/headers


def test_bounded_metadata_truncates() -> None:
    text, cut = _bounded_metadata("abcdef", 3)
    assert text == "abc" and cut is True
    assert _bounded_metadata(None, 10) == ("", False)


def test_raw_body_reads_bytes_and_tolerates_failures() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(_Part(raw_content=b"data")) == b"data"
    # Non-bytes content reads as an empty body.
    assert _raw_body(_Part(raw_content="a string")) == b""

    class _Boom:
        @property
        def raw_content(self) -> bytes:
            raise RuntimeError("decode failed")

    assert _raw_body(_Boom()) == b""


def test_emit_body_inlines_spills_and_marks_reason(tmp_path: Path) -> None:
    assert _emit_body(b"", tmp_path) == {"size": 0, "body": ""}
    assert _emit_body(b"hello", tmp_path)["body"] == "hello"

    binary = _emit_body(b"\xff\xfe\x00", tmp_path)
    assert binary["spill_reason"] == "binary"
    assert Path(binary["body_path"]).read_bytes() == b"\xff\xfe\x00"


def test_emit_body_spills_when_too_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_INLINE_BODY", 4)
    out = _emit_body(b"abcdefgh", tmp_path)
    assert out["spill_reason"] == "too_large"
    assert Path(out["body_path"]).read_bytes() == b"abcdefgh"


def test_bounded_headers_normal_and_failure() -> None:
    part = _Part(headers=_Headers([("A", "1"), ("A", "2"), ("B", "3")]))
    mapping, truncated = _bounded_headers(part)
    # Duplicate names collapse to the last value.
    assert mapping == {"A": "2", "B": "3"}
    assert truncated is False
    assert _bounded_headers(SimpleNamespace(headers=None)) == ({}, False)

    class _BoomHeaders:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            raise RuntimeError("iteration failed")

    mapping2, truncated2 = _bounded_headers(SimpleNamespace(headers=_BoomHeaders()))
    assert mapping2 == {} and truncated2 is True


def test_bounded_headers_stops_at_the_total_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_FLOW_HEADERS_TOTAL_BYTES", 4)
    part = _Part(headers=_Headers([("AAAA", "1"), ("BBBB", "2")]))
    mapping, truncated = _bounded_headers(part)
    assert truncated is True
    assert len(mapping) <= 1


def test_bounded_headers_stops_at_the_count_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_FLOW_HEADERS", 1)
    part = _Part(headers=_Headers([("A", "1"), ("B", "2")]))
    mapping, truncated = _bounded_headers(part)
    assert truncated is True
    assert len(mapping) == 1


# ---------------------------------------------------------------------------
# _uninstall_master_logging / _drain_proxy_servers
# ---------------------------------------------------------------------------
def test_uninstall_master_logging_removes_by_identity_and_by_loop() -> None:
    root = logging.getLogger()
    loop = asyncio.new_event_loop()
    master = SimpleNamespace(_legacy_log_events=None, event_loop=loop)
    other = SimpleNamespace(_legacy_log_events=None, event_loop=loop)

    by_identity = logging.Handler()
    by_identity.master = master  # type: ignore[attr-defined]
    by_loop = logging.Handler()
    by_loop.master = other  # type: ignore[attr-defined]
    unrelated = logging.Handler()  # no master -> skipped

    for handler in (by_identity, by_loop, unrelated):
        root.addHandler(handler)
    try:
        _uninstall_master_logging(master, loop)
        assert by_identity not in root.handlers
        assert by_loop not in root.handlers
        assert unrelated in root.handlers
    finally:
        for handler in (by_identity, by_loop, unrelated):
            root.removeHandler(handler)
        loop.close()


def test_drain_proxy_servers_returns_when_no_addon() -> None:
    # No servers.update -> quiet return.
    master = SimpleNamespace(addons=SimpleNamespace(get=lambda name: SimpleNamespace(servers=None)))
    _drain_proxy_servers(master, asyncio.new_event_loop())

    class _Boom:
        def get(self, name: str) -> Any:
            raise RuntimeError("addons unavailable")

    # An addon surface that raises is swallowed rather than propagated.
    _drain_proxy_servers(SimpleNamespace(addons=_Boom()), asyncio.new_event_loop())


# ---------------------------------------------------------------------------
# _FlowRecorder
# ---------------------------------------------------------------------------
def test_flow_recorder_records_response_and_error() -> None:
    recorder = _FlowRecorder()
    recorder.response(_Flow(flow_id="ok", response=_Part(status_code=200, raw_content=b"hi")))
    recorder.error(_Flow(flow_id="bad", response=None, error=SimpleNamespace(msg="reset")))
    snap = recorder.snapshot()
    assert recorder.count() == 2
    ok = next(e for e in snap if e["id"] == "ok")
    bad = next(e for e in snap if e["id"] == "bad")
    assert ok["status"] == 200
    # An errored flow carries the message and a null status.
    assert bad["status"] is None
    assert bad["error"] is True
    assert bad["error_msg"] == "reset"
    stored = recorder.raw("ok")
    assert stored is not None and stored.id == "ok"
    assert recorder.raw("missing") is None


def test_flow_recorder_omits_a_body_over_the_stored_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_STORED_BODY", 4)
    recorder = _FlowRecorder()
    recorder.response(_Flow(flow_id="big", response=_Part(raw_content=b"way too many bytes")))
    entry = recorder.snapshot()[0]
    assert entry["body_omitted"] is True
    # The oversized flow is not retained for retrieval.
    assert recorder.raw("big") is _OMITTED_BODY


def test_flow_recorder_evicts_older_bodies_to_stay_under_the_byte_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Small retained budget so the second flow forces the first to be omitted.
    monkeypatch.setattr(f"{_CLIENT}._MAX_RETAINED_BYTES", 40)
    recorder = _FlowRecorder()
    recorder.response(_Flow(flow_id="first", response=_Part(raw_content=b"a" * 30)))
    recorder.response(_Flow(flow_id="second", response=_Part(raw_content=b"b" * 30)))
    # The first flow's body is dropped to make room; its summary says so.
    assert recorder.raw("first") is _OMITTED_BODY
    first = next(e for e in recorder.snapshot() if e["id"] == "first")
    assert first["body_omitted"] is True


# ---------------------------------------------------------------------------
# ProxyBackend orchestration
# ---------------------------------------------------------------------------
def _instance_with_flow(
    flow: _Flow | Any, *, master: Any = None, loop: Any = None
) -> _ProxyInstance:
    inst = _ProxyInstance("127.0.0.1", 8080)
    if flow is not None:
        inst.recorder._raw[flow.id if hasattr(flow, "id") else "f"] = flow
    inst._master = master
    inst._loop = loop
    return inst


def test_check_available_raises_when_unavailable() -> None:
    backend = ProxyBackend()
    backend._available = False
    with pytest.raises(ProxyError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_check_available_detects_a_missing_mitmproxy(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "mitmproxy":
            raise ImportError("no mitmproxy here")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    backend = ProxyBackend()
    # _available starts unknown, so the guard probes the import and caches False.
    with pytest.raises(ProxyError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"
    assert backend._available is False


def test_get_and_stop_and_status_without_a_running_proxy() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as caught:
        backend._get("nope")
    assert caught.value.code == "invalid_state"
    assert backend.stop("nope") == {"stopped": False, "note": "no proxy was running"}
    assert backend.status("nope") == {"running": False}


def test_status_reports_a_running_proxy() -> None:
    backend = ProxyBackend()
    inst = _ProxyInstance("127.0.0.1", 8080)
    backend._instances["s"] = inst
    status = backend.status("s")
    assert status["running"] is True
    assert status["host"] == "127.0.0.1"
    assert status["flow_count"] == 0


def test_flows_pages_and_reports_dropped() -> None:
    backend = ProxyBackend()
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst.recorder = _FlowRecorder(capacity=2)
    for i in range(4):
        inst.recorder.response(_Flow(flow_id=f"f{i}", response=_Part()))
    backend._instances["s"] = inst
    payload = backend.flows("s", offset=0, limit=10)
    assert payload["total"] == 2  # ring holds 2
    assert payload["dropped"] == 2  # 4 seen, 2 retained


def test_flow_get_not_found_too_large_and_success(tmp_path: Path) -> None:
    backend = ProxyBackend()

    empty = _ProxyInstance("127.0.0.1", 8080)
    backend._instances["s"] = empty
    with pytest.raises(ProxyError) as missing:
        backend.flow_get("s", "ghost", tmp_path)
    assert missing.value.code == "not_found"

    omitted = _ProxyInstance("127.0.0.1", 8081)
    omitted.recorder._raw["big"] = _OMITTED_BODY
    backend._instances["s2"] = omitted
    with pytest.raises(ProxyError) as too_large:
        backend.flow_get("s2", "big", tmp_path)
    assert too_large.value.code == "too_large"

    flow = _Flow(
        flow_id="ok",
        request=_Part(method="POST", raw_content=b"payload", headers=_Headers([("X", "1")])),
        response=_Part(status_code=201, raw_content=b"created", headers=_Headers([("Y", "2")])),
    )
    live = _ProxyInstance("127.0.0.1", 8082)
    live.recorder._raw["ok"] = flow
    backend._instances["s3"] = live
    result = backend.flow_get("s3", "ok", tmp_path)
    assert result["request"]["method"] == "POST"
    assert result["request"]["body"] == "payload"
    assert result["response"]["status"] == 201
    assert result["response"]["body"] == "created"


def test_replay_guards_and_success(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ProxyBackend()

    empty = _ProxyInstance("127.0.0.1", 8080)
    backend._instances["s"] = empty
    with pytest.raises(ProxyError) as missing:
        backend.replay("s", "ghost")
    assert missing.value.code == "not_found"

    omitted = _ProxyInstance("127.0.0.1", 8081)
    omitted.recorder._raw["big"] = _OMITTED_BODY
    backend._instances["s2"] = omitted
    with pytest.raises(ProxyError) as too_large:
        backend.replay("s2", "big")
    assert too_large.value.code == "too_large"

    # A flow present but no live master/loop is invalid_state.
    no_master = _instance_with_flow(_Flow(flow_id="ok"), master=None, loop=None)
    backend._instances["s3"] = no_master
    with pytest.raises(ProxyError) as not_running:
        backend.replay("s3", "ok")
    assert not_running.value.code == "invalid_state"


class _InlineLoop:
    """A loop stand-in that runs the scheduled callback immediately."""

    def call_soon_threadsafe(self, fn: Any) -> None:
        fn()


def test_replay_success_and_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ProxyBackend()

    calls: list[Any] = []
    master = SimpleNamespace(
        commands=SimpleNamespace(call=lambda name, args: calls.append((name, args)))
    )
    inst = _instance_with_flow(_Flow(flow_id="ok"), master=master, loop=_InlineLoop())
    backend._instances["s"] = inst
    result = backend.replay("s", "ok")
    assert result == {"replayed": True, "flow_id": "ok"}
    assert calls and calls[0][0] == "replay.client"

    def boom(name: str, args: Any) -> None:
        raise RuntimeError("replay engine offline")

    failing = _instance_with_flow(
        _Flow(flow_id="bad"),
        master=SimpleNamespace(commands=SimpleNamespace(call=boom)),
        loop=_InlineLoop(),
    )
    backend._instances["s2"] = failing
    with pytest.raises(ProxyError) as caught:
        backend.replay("s2", "bad")
    assert caught.value.code == "backend_error"


def test_replay_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{_CLIENT}._REPLAY_WAIT_S", 0.1)

    class _NeverLoop:
        def call_soon_threadsafe(self, fn: Any) -> None:
            pass  # the work never runs, so the future never resolves

    inst = _instance_with_flow(
        _Flow(flow_id="ok"),
        master=SimpleNamespace(commands=SimpleNamespace(call=lambda n, a: None)),
        loop=_NeverLoop(),
    )
    backend = ProxyBackend()
    backend._instances["s"] = inst
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "ok")
    assert caught.value.code == "timeout"


def test_export_har_writes_and_refuses_over_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = ProxyBackend()
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst.recorder.response(
        _Flow(flow_id="f1", response=_Part(status_code=200, raw_content=b"x"))
    )
    backend._instances["s"] = inst
    out = tmp_path / "cap.har"
    payload = backend.export_har("s", out)
    assert payload["entry_count"] == 1
    assert out.is_file()

    monkeypatch.setattr(f"{_CLIENT}.UNREGISTERED_CAPTURE_MAX_BYTES", 1)
    with pytest.raises(ProxyError) as caught:
        backend.export_har("s", tmp_path / "big.har")
    assert caught.value.code == "too_large"


def test_ca_cert_path_finds_and_misses(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() is None
    cert_dir = tmp_path / ".mitmproxy"
    cert_dir.mkdir()
    (cert_dir / "mitmproxy-ca-cert.pem").write_text("cert", encoding="utf-8")
    assert ProxyBackend().ca_cert_path() == cert_dir / "mitmproxy-ca-cert.pem"


def test_close_all_stops_every_instance() -> None:
    backend = ProxyBackend()
    stopped: list[str] = []

    class _Inst:
        def __init__(self, name: str) -> None:
            self._name = name

        def stop(self) -> None:
            stopped.append(self._name)

    backend._instances = {"a": _Inst("a"), "b": _Inst("b")}  # type: ignore[dict-item]
    backend.close_all()
    assert sorted(stopped) == ["a", "b"]
    assert backend._instances == {}


# ---------------------------------------------------------------------------
# start orchestration (without a real mitmproxy)
# ---------------------------------------------------------------------------
def test_start_rejects_a_bad_port() -> None:
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=70000)
    assert caught.value.code == "invalid_params"


def test_start_returns_running_and_reserves_the_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ProxyBackend()
    backend._available = True
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    payload = backend.start("s", port=18080)
    assert payload == {
        "running": True,
        "host": "127.0.0.1",
        "port": 18080,
        "endpoint": "127.0.0.1:18080",
    }
    assert "s" in backend._instances


def test_start_releases_the_slot_when_startup_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ProxyBackend()
    backend._available = True

    def boom(self: _ProxyInstance, timeout: float = 15.0) -> None:
        raise ProxyError("timeout", "did not begin listening")

    monkeypatch.setattr(_ProxyInstance, "start", boom)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: None)
    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=18081)
    assert caught.value.code == "timeout"
    # A failed start must not leave the reservation behind.
    assert "s" not in backend._instances


def test_start_refuses_a_duplicate_session_and_a_taken_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._available = True
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    backend.start("s", host="127.0.0.1", port=18082)
    with pytest.raises(ProxyError) as dup_session:
        backend.start("s", port=18083)
    assert dup_session.value.code == "invalid_state"
    with pytest.raises(ProxyError) as dup_port:
        backend.start("other", host="127.0.0.1", port=18082)
    assert dup_port.value.code == "invalid_state"
    assert dup_port.value.details["owner_session_id"] == "s"


def test_proxy_instance_start_refuses_a_bound_port() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    try:
        inst = _ProxyInstance(host, port)
        with pytest.raises(ProxyError) as caught:
            inst.start(timeout=1.0)
        assert caught.value.code == "invalid_state"
    finally:
        listener.close()


# ---------------------------------------------------------------------------
# remaining reachable honesty branches
# ---------------------------------------------------------------------------
def test_shutdown_loop_closes_a_loop_with_no_pending_tasks() -> None:
    # The gather step is skipped when nothing is pending, but the loop is still
    # drained and closed.
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_encoded_len_falls_back_when_stringify_fails() -> None:
    class _Unstringable:
        def __str__(self) -> str:
            raise RuntimeError("no repr")

    # A value we cannot measure is treated as over the cap rather than zero, so
    # it can never sneak past the byte budget as "free".
    assert _encoded_len(_Unstringable()) > 0


def test_headers_len_returns_zero_when_iteration_fails() -> None:
    class _BoomHeaders:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            raise RuntimeError("iteration failed")

    assert _headers_len(SimpleNamespace(headers=_BoomHeaders())) == 0


def test_flow_recorder_reomitting_an_omitted_body_is_a_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_STORED_BODY", 4)
    recorder = _FlowRecorder()
    recorder.response(_Flow(flow_id="big", response=_Part(raw_content=b"way too many")))
    assert recorder.raw("big") is _OMITTED_BODY
    before = recorder.retained_bytes()
    # Asking to omit an already-omitted flow neither double-counts nor raises.
    recorder._omit_retained("big")
    recorder._omit_retained("never-seen")
    assert recorder.retained_bytes() == before
    assert recorder.raw("big") is _OMITTED_BODY


def test_flows_on_an_empty_recorder_reports_no_dropped() -> None:
    backend = ProxyBackend()
    backend._instances["s"] = _ProxyInstance("127.0.0.1", 8080)
    payload = backend.flows("s")
    assert payload["total"] == 0
    assert payload["dropped"] == 0
    assert payload["has_more"] is False


def test_flow_get_marks_metadata_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_URL_BYTES", 4)
    backend = ProxyBackend()
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst.recorder._raw["ok"] = _Flow(
        flow_id="ok",
        request=_Part(method="GET", pretty_url="http://example/very/long/path"),
        response=_Part(status_code=200, raw_content=b""),
    )
    backend._instances["s"] = inst
    result = backend.flow_get("s", "ok", tmp_path)
    assert result["request"]["metadata_truncated"] is True


def test_start_skips_non_matching_instances_before_reserving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._available = True
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    backend.start("first", host="127.0.0.1", port=18090)
    # A second, unique port must pass the reservation scan even though another
    # instance is already held on a different port.
    payload = backend.start("second", host="127.0.0.1", port=18091)
    assert payload["port"] == 18091
    assert set(backend._instances) == {"first", "second"}


def test_uninstall_master_logging_leaves_an_unrelated_master_handler() -> None:
    root = logging.getLogger()
    loop = asyncio.new_event_loop()
    other_loop = asyncio.new_event_loop()
    master = SimpleNamespace(_legacy_log_events=None, event_loop=loop)
    stranger = SimpleNamespace(_legacy_log_events=None, event_loop=other_loop)

    unrelated = logging.Handler()
    unrelated.master = stranger  # type: ignore[attr-defined]
    root.addHandler(unrelated)
    try:
        _uninstall_master_logging(master, loop)
        # A handler owned by a different master on a different loop is left alone.
        assert unrelated in root.handlers
    finally:
        root.removeHandler(unrelated)
        loop.close()
        other_loop.close()
