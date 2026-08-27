"""ProxyBackend lifecycle, replay and helper branches without a live proxy.

The mitmproxy interception surface is shared by Web and Android. Its live gate
needs a running DumpMaster and skips where mitmproxy cannot bind, so the parts
that do not need a server -- port probes, loop teardown, body/header bounding,
the reservation and rollback logic, flow_get / replay error contracts, HAR cap
and CA lookup -- were thin under unit coverage. These drive those directly.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
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
)


# ----------------------------------------------------------------------
# Event-loop teardown and port probes.
# ----------------------------------------------------------------------
def test_shutdown_loop_cancels_pending_tasks_and_closes() -> None:
    """A leftover accept task is what keeps the listening socket open.

    _shutdown_loop is what actually frees the port: it cancels and awaits every
    pending task before closing, rather than dropping the loop's reference and
    leaving the OS socket bound.
    """
    loop = asyncio.new_event_loop()

    async def _forever() -> None:  # pragma: no cover - cancelled before it runs
        await asyncio.sleep(100)

    loop.create_task(_forever())
    _shutdown_loop(loop)
    assert loop.is_closed() is True


def test_shutdown_loop_handles_a_loop_with_no_pending_tasks() -> None:
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed() is True


def test_port_accepts_is_true_only_while_something_is_listening() -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        assert _port_accepts("127.0.0.1", port) is True
    finally:
        srv.close()
    # Once the listener is gone the same probe must report free, not stale True.
    assert _port_accepts("127.0.0.1", port) is False


# ----------------------------------------------------------------------
# Metadata / body sizing helpers tolerate hostile shapes.
# ----------------------------------------------------------------------
def test_content_len_treats_an_unsized_body_as_zero() -> None:
    assert _content_len(None) == 0
    assert _content_len(SimpleNamespace()) == 0
    # raw_content present but len() raises -> counted as zero, not a crash.
    assert _content_len(SimpleNamespace(raw_content=12345)) == 0
    assert _content_len(SimpleNamespace(raw_content=b"abc")) == 3


def test_encoded_len_of_a_value_whose_str_raises_is_over_the_cap() -> None:
    class _Hostile:
        def __str__(self) -> str:
            raise RuntimeError("no str")

    # A value that cannot be measured is treated as over the retain cap so it is
    # never mistaken for a small body worth keeping.
    assert _encoded_len(_Hostile()) > proxy_client._MAX_STORED_BODY


def test_headers_len_tolerates_missing_and_broken_header_maps() -> None:
    assert _headers_len(SimpleNamespace()) == 0

    class _MultiOnly:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            if multi:
                raise TypeError("multi unsupported")
            return [("a", "1"), ("b", "2")]

    assert _headers_len(SimpleNamespace(headers=_MultiOnly())) > 0

    class _Broken:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            raise RuntimeError("headers exploded")

    assert _headers_len(SimpleNamespace(headers=_Broken())) == 0


def test_raw_body_reads_empty_on_a_decode_failure_or_non_bytes() -> None:
    class _Raises:
        @property
        def raw_content(self) -> bytes:
            raise RuntimeError("decode failed")

    assert _raw_body(_Raises()) == b""
    # A str content (not bytes) is not silently re-encoded; it reads empty.
    assert _raw_body(SimpleNamespace(raw_content="not bytes")) == b""
    assert _raw_body(SimpleNamespace(raw_content=b"ok")) == b"ok"


def test_bounded_headers_reports_truncation_when_items_cannot_be_read() -> None:
    class _Broken:
        def items(self, multi: bool = False) -> list[tuple[str, str]]:
            raise RuntimeError("cannot enumerate")

    out, truncated = _bounded_headers(SimpleNamespace(headers=_Broken()))
    assert out == {}
    assert truncated is True


def test_drain_proxy_servers_swallows_an_unexpected_addon_surface() -> None:
    """The addon layout varies across mitmproxy versions; a surprise is not fatal."""
    loop = asyncio.new_event_loop()
    try:
        # A master with no addons attribute must not raise out of the drain.
        _drain_proxy_servers(object(), loop)
    finally:
        loop.close()


def test_flow_recorder_omit_is_a_noop_for_an_unknown_flow() -> None:
    recorder = _FlowRecorder(capacity=4)
    recorder._omit_retained("never-seen")
    assert recorder.count() == 0


# ----------------------------------------------------------------------
# ProxyBackend availability, start reservation and rollback.
# ----------------------------------------------------------------------
def test_start_reports_capability_unavailable_when_mitmproxy_is_absent() -> None:
    backend = ProxyBackend()
    backend._available = False
    with pytest.raises(ProxyError) as caught:
        backend.start("s")
    assert caught.value.code == "capability_unavailable"


def test_start_rejects_an_out_of_range_port() -> None:
    backend = ProxyBackend()
    backend._available = True
    for bad in (0, 70000, "8080"):
        with pytest.raises(ProxyError) as caught:
            backend.start("s", port=bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_start_refuses_a_second_proxy_for_the_same_session() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["s"] = _ProxyInstance("127.0.0.1", 8080)
    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=9090)
    assert caught.value.code == "invalid_state"
    assert "already running" in caught.value.message


class _FakeInstance:
    instances: list[_FakeInstance] = []

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.started = False
        self.stopped = False
        _FakeInstance.instances.append(self)

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


def test_start_returns_the_endpoint_after_the_instance_binds(monkeypatch: Any) -> None:
    _FakeInstance.instances = []
    monkeypatch.setattr(proxy_client, "_ProxyInstance", _FakeInstance)
    backend = ProxyBackend()
    backend._available = True
    payload = backend.start("s", host="127.0.0.1", port=9091)
    assert payload == {
        "running": True,
        "host": "127.0.0.1",
        "port": 9091,
        "endpoint": "127.0.0.1:9091",
    }
    assert _FakeInstance.instances[-1].started is True


def test_start_unreserves_the_session_when_the_bind_fails(monkeypatch: Any) -> None:
    """A failed listen must free the reservation, or the port leaks forever."""

    class _FailingInstance(_FakeInstance):
        def start(self) -> None:
            raise ProxyError("invalid_state", "port is already in use")

    monkeypatch.setattr(proxy_client, "_ProxyInstance", _FailingInstance)
    backend = ProxyBackend()
    backend._available = True
    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=9092)
    assert caught.value.code == "invalid_state"
    assert "s" not in backend._instances


def test_stop_on_a_session_with_no_proxy_says_nothing_was_running() -> None:
    backend = ProxyBackend()
    payload = backend.stop("never-started")
    assert payload == {"stopped": False, "note": "no proxy was running"}


def test_status_of_an_unknown_session_is_not_running() -> None:
    assert ProxyBackend().status("nope") == {"running": False}


def test_read_tools_require_a_running_proxy() -> None:
    """flows / flow_get / replay / export_har all fail closed without a proxy."""
    backend = ProxyBackend()
    for call in (
        lambda: backend.flows("nope"),
        lambda: backend.flow_get("nope", "f1", Path(".")),
        lambda: backend.replay("nope", "f1"),
        lambda: backend.export_har("nope", Path("x.har")),
    ):
        with pytest.raises(ProxyError) as caught:
            call()
        assert caught.value.code == "invalid_state"


# ----------------------------------------------------------------------
# flow_get / replay error contracts on a running proxy.
# ----------------------------------------------------------------------
def _backend_with_instance() -> tuple[ProxyBackend, _ProxyInstance]:
    backend = ProxyBackend()
    inst = _ProxyInstance("127.0.0.1", 8080)
    backend._instances["s"] = inst
    return backend, inst


def test_flow_get_reports_an_unknown_flow_id_as_not_found() -> None:
    backend, _ = _backend_with_instance()
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "missing", Path("."))
    assert caught.value.code == "not_found"


def test_flow_get_reports_an_omitted_body_as_too_large() -> None:
    backend, inst = _backend_with_instance()
    inst.recorder._raw["f1"] = _OMITTED_BODY
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "f1", Path("."))
    assert caught.value.code == "too_large"


def test_replay_reports_missing_and_omitted_and_stopped() -> None:
    backend, inst = _backend_with_instance()
    with pytest.raises(ProxyError) as missing:
        backend.replay("s", "gone")
    assert missing.value.code == "not_found"

    inst.recorder._raw["omit"] = _OMITTED_BODY
    with pytest.raises(ProxyError) as omitted:
        backend.replay("s", "omit")
    assert omitted.value.code == "too_large"

    inst.recorder._raw["live"] = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst._master = None
    with pytest.raises(ProxyError) as stopped:
        backend.replay("s", "live")
    assert stopped.value.code == "invalid_state"


class _ImmediateLoop:
    def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
        fn(*args)


def test_replay_drives_the_master_command_and_reports_replayed() -> None:
    backend, inst = _backend_with_instance()
    called: list[Any] = []

    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            called.append((name, args))

    inst.recorder._raw["live"] = SimpleNamespace(copy=lambda: SimpleNamespace(tag="clone"))
    inst._master = SimpleNamespace(commands=_Commands())
    inst._loop = _ImmediateLoop()  # type: ignore[assignment]
    payload = backend.replay("s", "live")
    assert payload == {"replayed": True, "flow_id": "live"}
    assert called and called[0][0] == "replay.client"


def test_replay_wraps_a_command_failure_as_backend_error() -> None:
    backend, inst = _backend_with_instance()

    class _Commands:
        def call(self, name: str, args: list[Any]) -> None:
            raise RuntimeError("replay rejected")

    inst.recorder._raw["live"] = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst._master = SimpleNamespace(commands=_Commands())
    inst._loop = _ImmediateLoop()  # type: ignore[assignment]
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "live")
    assert caught.value.code == "backend_error"


def test_replay_times_out_when_the_command_never_completes(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_REPLAY_WAIT_S", 0.1)
    backend, inst = _backend_with_instance()

    class _NeverLoop:
        def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
            del fn, args  # the command is scheduled but never runs

    inst.recorder._raw["live"] = SimpleNamespace(copy=lambda: SimpleNamespace())
    inst._master = SimpleNamespace(commands=SimpleNamespace(call=lambda *a: None))
    inst._loop = _NeverLoop()  # type: ignore[assignment]
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "live")
    assert caught.value.code == "timeout"


# ----------------------------------------------------------------------
# HAR cap and CA lookup.
# ----------------------------------------------------------------------
def test_export_har_refuses_a_capture_over_the_cap(monkeypatch: Any, tmp_path: Path) -> None:
    backend, _ = _backend_with_instance()
    cap = proxy_client.UNREGISTERED_CAPTURE_MAX_BYTES
    monkeypatch.setattr(
        proxy_client,
        "serialize_har",
        lambda entries, max_bytes: SimpleNamespace(
            size=cap + 1, text="x", entry_count=0, truncated=True
        ),
    )
    with pytest.raises(ProxyError) as caught:
        backend.export_har("s", tmp_path / "out.har")
    assert caught.value.code == "too_large"


def test_ca_cert_path_finds_the_generated_cert_or_none(
    monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setattr(proxy_client.Path, "home", classmethod(lambda cls: tmp_path))
    backend = ProxyBackend()
    assert backend.ca_cert_path() is None
    mitm = tmp_path / ".mitmproxy"
    mitm.mkdir()
    (mitm / "mitmproxy-ca-cert.pem").write_text("cert")
    assert backend.ca_cert_path() == mitm / "mitmproxy-ca-cert.pem"


def test_close_all_stops_every_instance_and_clears_the_registry() -> None:
    backend = ProxyBackend()
    a = _FakeInstance("127.0.0.1", 1)
    b = _FakeInstance("127.0.0.1", 2)
    backend._instances["a"] = a  # type: ignore[assignment]
    backend._instances["b"] = b  # type: ignore[assignment]
    backend.close_all()
    assert a.stopped is True
    assert b.stopped is True
    assert backend._instances == {}
