"""Helper and method branches of the mitmproxy backend client.

The live proxy lifecycle (``_ProxyInstance.start``/``_run``) is pinned by
tests/integration/test_proxy_lifecycle_gate.py, so it is left to that gate.
Everything around it is unit-testable without binding a port: the loop and
logging teardown helpers, the size/metadata/body accessors that tolerate a
version-varying mitmproxy surface, the flow recorder's retain-and-omit budget,
and every ProxyBackend read/replay/export branch (unknown or dropped flows, a
stopped proxy, a replay that runs, re-raises, times out, or fails, and the CA
lookup). Fakes stand in for flows and the master, matching the sibling suites.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_mod
from headless_re_mcp.backends.proxy.client import (
    _MAX_STORED_BODY,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _content_len,
    _drain_proxy_servers,
    _encoded_len,
    _FlowRecorder,
    _headers_len,
    _ProxyInstance,
    _raw_body,
    _shutdown_loop,
    _uninstall_master_logging,
)


class _Headers(dict):
    """A header map that answers ``items(multi=...)`` like mitmproxy's."""

    def items(self, multi: bool = False) -> list[tuple[Any, Any]]:  # type: ignore[override]
        del multi
        return list(dict.items(self))


# ============================================================================
# _shutdown_loop / _uninstall_master_logging / _drain_proxy_servers.
# ============================================================================
def test_shutdown_loop_cancels_pending_tasks_and_closes() -> None:
    loop = asyncio.new_event_loop()

    async def _sleep_forever() -> None:
        await asyncio.sleep(60)

    loop.create_task(_sleep_forever())
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_shutdown_loop_closes_a_loop_with_no_pending_tasks() -> None:
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


def test_uninstall_master_logging_leaves_unrelated_handlers() -> None:
    class _Handler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.master = SimpleNamespace(event_loop=None)  # a foreign master

        def emit(self, record: logging.LogRecord) -> None:
            del record

    root = logging.getLogger()
    other = _Handler()
    root.addHandler(other)
    try:
        _uninstall_master_logging(SimpleNamespace(_legacy_log_events=None), loop=None)
        assert other in root.handlers
    finally:
        root.removeHandler(other)


def test_drain_proxy_servers_swallows_an_addon_error() -> None:
    class _Master:
        @property
        def addons(self) -> Any:
            raise RuntimeError("addons unavailable")

    loop = asyncio.new_event_loop()
    try:
        _drain_proxy_servers(_Master(), loop)  # must return, not raise
    finally:
        loop.close()


# ============================================================================
# Size / metadata / body accessors.
# ============================================================================
def test_content_len_is_zero_when_length_is_untyped() -> None:
    class _WeirdContent:
        def __bool__(self) -> bool:
            return True

        def __len__(self) -> int:
            raise TypeError("no length")

    assert _content_len(SimpleNamespace(raw_content=_WeirdContent())) == 0


def test_encoded_len_returns_over_cap_when_str_raises() -> None:
    class _BadStr:
        def __str__(self) -> str:
            raise ValueError("cannot render")

    assert _encoded_len(_BadStr()) == _MAX_STORED_BODY + 1


def test_headers_len_is_zero_when_items_raise() -> None:
    class _Broken:
        def items(self, multi: bool = False) -> Any:
            del multi
            raise ValueError("iteration failed")

    assert _headers_len(SimpleNamespace(headers=_Broken())) == 0


def test_raw_body_handles_a_missing_part_and_non_bytes_content() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content="not-bytes")) == b""


def test_bounded_headers_is_empty_and_flagged_when_items_raise() -> None:
    class _Broken:
        def items(self, multi: bool = False) -> Any:
            del multi
            raise ValueError("iteration failed")

    out, truncated = _bounded_headers(SimpleNamespace(headers=_Broken()))
    assert out == {}
    assert truncated is True


def test_bounded_headers_stops_at_the_total_byte_ceiling() -> None:
    # Each value is clamped to 4 KiB; 30 of them blow past the 64 KiB total.
    items = [(f"h{index}", "v" * 5000) for index in range(30)]
    out, truncated = _bounded_headers(SimpleNamespace(headers=_Headers(items)))
    assert truncated is True
    assert len(out) < 30


# ============================================================================
# _FlowRecorder retain-and-omit budget.
# ============================================================================
class _BigContent:
    def __init__(self, size: int) -> None:
        self._size = size

    def __bool__(self) -> bool:
        return True

    def __len__(self) -> int:
        return self._size


def _flow(flow_id: str, *, nbytes: int = 0) -> Any:
    content: Any = _BigContent(nbytes) if nbytes else b""
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://example/",
        host="example",
        headers=_Headers(),
        raw_content=content,
    )
    response = SimpleNamespace(
        status_code=200,
        headers=_Headers({"content-type": "text/plain"}),
        raw_content=b"",
    )
    return SimpleNamespace(id=flow_id, request=request, response=response, error=None)


def test_omit_retained_ignores_an_absent_flow() -> None:
    recorder = _FlowRecorder()
    recorder._omit_retained("never-recorded")  # early return, no error


def test_omit_retained_tolerates_a_missing_summary() -> None:
    recorder = _FlowRecorder()
    recorder._raw["ghost"] = object()
    recorder._raw_sizes["ghost"] = 10
    recorder._retained_bytes = 10
    recorder._omit_retained("ghost")
    assert recorder._raw["ghost"] is _OMITTED_BODY
    assert recorder._retained_bytes == 0


def test_recorder_omits_old_bodies_when_the_retain_budget_is_exceeded() -> None:
    recorder = _FlowRecorder()
    # ~1.8 MiB each: individually retained, but together over the 64 MiB budget.
    for index in range(40):
        recorder.response(_flow(f"f{index}", nbytes=1_800_000))
    assert recorder.raw("f39") is not _OMITTED_BODY
    assert recorder.raw("f0") is _OMITTED_BODY
    summaries = [row for row in recorder.snapshot() if row["id"] == "f0"]
    assert summaries and summaries[0].get("body_omitted") is True


def test_recorder_omits_a_single_oversized_body() -> None:
    recorder = _FlowRecorder()
    recorder.response(_flow("big", nbytes=_MAX_STORED_BODY + 1))
    assert recorder.raw("big") is _OMITTED_BODY
    summary = recorder.snapshot()[0]
    assert summary.get("body_omitted") is True


# ============================================================================
# ProxyBackend._check_available.
# ============================================================================
def test_check_available_raises_when_marked_unavailable() -> None:
    backend = ProxyBackend()
    backend._available = False
    with pytest.raises(ProxyError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"


def test_check_available_marks_unavailable_when_the_import_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "mitmproxy", None)
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"
    assert backend._available is False


# ============================================================================
# ProxyBackend.start reservation edges (the listener itself is stubbed).
# ============================================================================
def test_start_reserves_past_a_non_conflicting_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    backend = ProxyBackend()
    backend._available = True
    backend._instances["other"] = SimpleNamespace(host="127.0.0.1", port=9999)
    result = backend.start("s", host="127.0.0.1", port=8080)
    assert result["running"] is True
    assert result["endpoint"] == "127.0.0.1:8080"
    assert "s" in backend._instances


def test_start_cleans_up_when_the_listener_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(self: _ProxyInstance, timeout: float = 15.0) -> None:
        del self, timeout
        raise ProxyError("backend_error", "could not bind")

    monkeypatch.setattr(_ProxyInstance, "start", boom)
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as info:
        backend.start("s", port=8080)
    assert info.value.code == "backend_error"
    assert "s" not in backend._instances


def test_start_reports_a_stop_during_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ProxyBackend()
    backend._available = True

    def start_then_vanish(self: _ProxyInstance, timeout: float = 15.0) -> None:
        del timeout
        backend._instances.pop("s", None)  # a concurrent stop won the race

    monkeypatch.setattr(_ProxyInstance, "start", start_then_vanish)
    with pytest.raises(ProxyError) as info:
        backend.start("s", port=8080)
    assert info.value.code == "invalid_state"
    assert "stopped while starting" in info.value.message


# ============================================================================
# ProxyBackend.flows / flow_get / replay / ca_cert_path / close_all.
# ============================================================================
def test_flows_reports_nothing_dropped_for_an_empty_capture() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = _ProxyInstance("127.0.0.1", 8080)
    payload = backend.flows("s")
    assert payload["total"] == 0
    assert payload["dropped"] == 0


def _flow_get_backend(monkeypatch: pytest.MonkeyPatch, flow: Any) -> ProxyBackend:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            del flow_id
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    return backend


def test_flow_get_reports_an_unknown_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _flow_get_backend(monkeypatch, None)
    with pytest.raises(ProxyError) as info:
        backend.flow_get("s", "f", tmp_path)
    assert info.value.code == "not_found"


def test_flow_get_reports_a_dropped_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _flow_get_backend(monkeypatch, _OMITTED_BODY)
    with pytest.raises(ProxyError) as info:
        backend.flow_get("s", "f", tmp_path)
    assert info.value.code == "too_large"


def test_flow_get_flags_truncated_request_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://x/" + "a" * 20000,  # past the 16 KiB URL cap
        headers={},
        raw_content=b"",
    )
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"")
    backend = _flow_get_backend(
        monkeypatch, SimpleNamespace(request=request, response=response)
    )
    payload = backend.flow_get("s", "f", tmp_path)
    assert payload["request"]["metadata_truncated"] is True


class _Flow:
    def copy(self) -> _Flow:
        return self


def _instance_with_flow(flow: Any, *, master: Any = None) -> _ProxyInstance:
    inst = _ProxyInstance("127.0.0.1", 8080)
    if flow is not None:
        inst.recorder._raw["f"] = flow
    inst._master = master
    return inst


def test_replay_reports_an_unknown_flow() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = _instance_with_flow(None)
    with pytest.raises(ProxyError) as info:
        backend.replay("s", "f")
    assert info.value.code == "not_found"


def test_replay_reports_a_dropped_body() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = _instance_with_flow(_OMITTED_BODY)
    with pytest.raises(ProxyError) as info:
        backend.replay("s", "f")
    assert info.value.code == "too_large"


def test_replay_reports_a_stopped_proxy() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = _instance_with_flow(_Flow(), master=None)
    with pytest.raises(ProxyError) as info:
        backend.replay("s", "f")
    assert info.value.code == "invalid_state"


def _running_instance(
    master: Any, flow: Any
) -> tuple[_ProxyInstance, asyncio.AbstractEventLoop, threading.Thread]:
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst.recorder._raw["f"] = flow
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    inst._loop = loop
    inst._thread = thread
    inst._master = master
    return inst, loop, thread


def _teardown(loop: asyncio.AbstractEventLoop, thread: threading.Thread) -> None:
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=2.0)
    loop.close()


def test_replay_runs_on_the_proxy_loop() -> None:
    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            del name, args

    master = SimpleNamespace(commands=_Commands())
    inst, loop, thread = _running_instance(master, _Flow())
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = inst
    try:
        result = backend.replay("s", "f")
        assert result["replayed"] is True
    finally:
        _teardown(loop, thread)


def test_replay_reraises_a_proxy_error() -> None:
    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            del name, args
            raise ProxyError("invalid_state", "replay refused")

    inst, loop, thread = _running_instance(SimpleNamespace(commands=_Commands()), _Flow())
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = inst
    try:
        with pytest.raises(ProxyError) as info:
            backend.replay("s", "f")
        assert info.value.code == "invalid_state"
    finally:
        _teardown(loop, thread)


def test_replay_maps_a_backend_error() -> None:
    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            del name, args
            raise RuntimeError("mitmproxy blew up")

    inst, loop, thread = _running_instance(SimpleNamespace(commands=_Commands()), _Flow())
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = inst
    try:
        with pytest.raises(ProxyError) as info:
            backend.replay("s", "f")
        assert info.value.code == "backend_error"
    finally:
        _teardown(loop, thread)


def test_replay_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy_mod, "_REPLAY_WAIT_S", 0.1)

    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            del name, args

    # A loop that is never started: the queued replay never runs, so the
    # future never resolves and the bounded wait must fire.
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst.recorder._raw["f"] = _Flow()
    loop = asyncio.new_event_loop()
    inst._loop = loop
    inst._master = SimpleNamespace(commands=_Commands())
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = inst
    try:
        with pytest.raises(ProxyError) as info:
            backend.replay("s", "f")
        assert info.value.code == "timeout"
    finally:
        loop.close()


def test_ca_cert_path_finds_the_generated_cert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    cert_dir = tmp_path / ".mitmproxy"
    cert_dir.mkdir()
    cert = cert_dir / "mitmproxy-ca-cert.cer"
    cert.write_bytes(b"CERT")
    assert ProxyBackend().ca_cert_path() == cert


def test_ca_cert_path_is_none_when_no_cert_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert ProxyBackend().ca_cert_path() is None


def test_close_all_stops_every_instance() -> None:
    stopped: list[bool] = []
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = SimpleNamespace(stop=lambda: stopped.append(True))
    backend.close_all()
    assert stopped == [True]
    assert backend._instances == {}
