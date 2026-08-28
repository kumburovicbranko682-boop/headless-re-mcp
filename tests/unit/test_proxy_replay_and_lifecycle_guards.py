"""proxy.replay outcomes, the start/stop race, and the teardown helpers.

replay hands a captured flow back to mitmproxy's event loop. Three things keep
that honest: the flow submitted is a *copy* (replaying the retained object would
let mitmproxy mutate the capture in place), a failure inside the loop comes back
as a classified backend_error naming the flow, and a loop that never answers is
a timeout rather than a worker parked forever. Around it: start() must roll back
an instance whose session was stopped mid-launch, a missing mitmproxy degrades
to capability_unavailable, and the loop/body/header helpers that stop() and
flow reads rely on must tolerate a hostile or version-drifted mitmproxy.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.proxy.client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _MAX_STORED_BODY,
    ProxyBackend,
    ProxyError,
    _bounded_headers,
    _drain_proxy_servers,
    _encoded_len,
    _raw_body,
    _shutdown_loop,
)


@pytest.fixture
def running_loop() -> Any:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        yield loop
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5.0)
        loop.close()


class _ReplayableFlow:
    def __init__(self) -> None:
        self.copies: list[object] = []

    def copy(self) -> object:
        copied = object()
        self.copies.append(copied)
        return copied


def _instance_with(flow: Any, master: Any, loop: Any) -> Any:
    return SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: flow),
        _master=master,
        _loop=loop,
    )


def test_replay_submits_a_copy_of_the_flow_not_the_retained_original(
    running_loop: Any,
) -> None:
    """mitmproxy mutates what it replays; the capture ring must not change.

    replay.client rewrites the flow it is handed (new ids, response replaced),
    so submitting the retained object would corrupt the recorded capture. The
    call must receive flow.copy() and report replayed:True with the flow id.
    """
    calls: list[tuple[str, list[Any]]] = []
    master = SimpleNamespace(
        commands=SimpleNamespace(call=lambda name, args: calls.append((name, args)))
    )
    flow = _ReplayableFlow()
    backend = ProxyBackend()
    backend._instances["s"] = _instance_with(flow, master, running_loop)
    result = backend.replay("s", "f1")
    assert result == {"replayed": True, "flow_id": "f1"}
    assert len(calls) == 1
    name, args = calls[0]
    assert name == "replay.client"
    assert args == [flow.copies[0]]
    assert args[0] is not flow


def test_replay_failure_inside_the_loop_is_backend_error_naming_the_flow(
    running_loop: Any,
) -> None:
    """An exception from replay.client is classified, not lost on the loop thread.

    The command runs on mitmproxy's event loop; without the future handoff its
    exception would die on that thread and the caller would wait out the full
    timeout for a failure that already happened.
    """
    def refuse(name: str, args: list[Any]) -> None:
        raise RuntimeError("client replay is disabled in this mode")

    master = SimpleNamespace(commands=SimpleNamespace(call=refuse))
    backend = ProxyBackend()
    backend._instances["s"] = _instance_with(_ReplayableFlow(), master, running_loop)
    with pytest.raises(ProxyError) as info:
        backend.replay("s", "f1")
    assert info.value.code == "backend_error"
    assert "replay failed" in info.value.message
    assert info.value.details.get("flow_id") == "f1"


def test_replay_that_never_answers_is_a_timeout(
    running_loop: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A loop that does not answer within the budget is a timeout, not a hang."""
    monkeypatch.setattr(proxy_client, "_REPLAY_WAIT_S", 0.05)

    def stall(name: str, args: list[Any]) -> None:
        time.sleep(0.5)

    master = SimpleNamespace(commands=SimpleNamespace(call=stall))
    backend = ProxyBackend()
    backend._instances["s"] = _instance_with(_ReplayableFlow(), master, running_loop)
    with pytest.raises(ProxyError) as info:
        backend.replay("s", "f1")
    assert info.value.code == "timeout"
    assert "replay did not complete" in info.value.message


def test_start_rolls_back_an_instance_whose_session_was_stopped_mid_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy that finishes starting into a stopped session is shut down again.

    Between reserving the slot and the listener coming up, a concurrent
    proxy.stop (or session close) can remove the reservation. Returning
    running:True then would leak a listener nothing tracks; start() must stop
    the instance it just started and report the race as invalid_state.
    """
    created: list[Any] = []

    class _FakeInstance:
        def __init__(self, host: str, port: int) -> None:
            self.host, self.port = host, port
            self.stopped = 0
            created.append(self)

        def start(self) -> None:
            backend._instances.pop("s")

        def stop(self) -> None:
            self.stopped += 1

    monkeypatch.setattr(proxy_client, "_ProxyInstance", _FakeInstance)
    backend = ProxyBackend()
    # This test is about the reserve/rollback race, not backend availability, and
    # _ProxyInstance is faked -- so no real mitmproxy is needed. But start() calls
    # _check_available() first, which raises capability_unavailable on the
    # every-commit quality job (it installs .[test,dev,web], no proxy extra),
    # masking the invalid_state path under test. Mark it available so the race is
    # what gets exercised; the absence path is covered by
    # test_missing_mitmproxy_degrades_to_capability_unavailable.
    backend._available = True
    with pytest.raises(ProxyError) as info:
        backend.start("s", port=18099)
    assert info.value.code == "invalid_state"
    assert "stopped while starting" in info.value.message
    assert created[0].stopped >= 1
    assert backend._instances == {}


def test_missing_mitmproxy_degrades_to_capability_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without mitmproxy, start degrades instead of raising ImportError."""
    monkeypatch.setitem(sys.modules, "mitmproxy", None)
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as info:
        backend.start("s", port=18100)
    assert info.value.code == "capability_unavailable"
    assert "mitmproxy is not installed" in info.value.message


def test_ca_cert_path_prefers_the_cer_and_reports_absence_as_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CA discovery: None when mitmproxy never ran, .cer preferred over .pem."""
    monkeypatch.setattr(proxy_client.Path, "home", staticmethod(lambda: tmp_path))
    backend = ProxyBackend()
    assert backend.ca_cert_path() is None
    certs = tmp_path / ".mitmproxy"
    certs.mkdir()
    (certs / "mitmproxy-ca-cert.pem").write_text("pem", encoding="utf-8")
    assert backend.ca_cert_path() == certs / "mitmproxy-ca-cert.pem"
    (certs / "mitmproxy-ca-cert.cer").write_text("cer", encoding="utf-8")
    assert backend.ca_cert_path() == certs / "mitmproxy-ca-cert.cer"


def test_shutdown_loop_cancels_pending_tasks_and_closes_the_loop() -> None:
    """Teardown unwinds the tasks that own the transports, then closes the loop.

    The listening socket is only released when the task owning it is allowed to
    unwind; dropping the loop reference leaves the port bound until process
    exit. The helper must cancel what is pending and leave the loop closed.
    """
    loop = asyncio.new_event_loop()
    task = loop.create_task(asyncio.sleep(3600))
    _shutdown_loop(loop)
    assert task.cancelled()
    assert loop.is_closed()


def test_drain_proxy_servers_tolerates_an_addon_surface_that_raises() -> None:
    """A mitmproxy whose addon registry raises does not break stop().

    The proxyserver addon surface has changed across mitmproxy majors; stop()
    must still complete its teardown when the lookup itself explodes.
    """
    class _Addons:
        def get(self, name: str) -> Any:
            raise RuntimeError("addon registry replaced in this mitmproxy")

    _drain_proxy_servers(SimpleNamespace(addons=_Addons()), loop=None)  # type: ignore[arg-type]


def test_raw_body_reads_missing_or_undecodable_content_as_empty() -> None:
    """No part, non-bytes content, or a raising decode all read as no body."""
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content=42)) == b""

    class _RaisingContent:
        @property
        def raw_content(self) -> bytes:
            raise ValueError("invalid content-encoding")

    assert _raw_body(_RaisingContent()) == b""


def test_encoded_len_counts_an_unrenderable_value_as_oversized() -> None:
    """A value whose str() raises counts against the cap, not as free.

    The retention accountant uses this length to decide when to omit bodies;
    failing toward zero would let a hostile flow dodge the memory cap.
    """
    class _Unrenderable:
        def __str__(self) -> str:
            raise ValueError("will not render")

    assert _encoded_len(_Unrenderable()) > _MAX_STORED_BODY


def test_bounded_headers_reports_an_unreadable_header_set_as_truncated() -> None:
    """Headers that cannot be iterated read as empty *and flagged*.

    The flag is the contract: a reader must be able to tell "no headers" from
    "headers were dropped", so the failure arm returns ({}, True).
    """
    class _BadHeaders:
        def items(self, multi: bool = False) -> Any:
            raise RuntimeError("corrupt header block")

    assert _bounded_headers(SimpleNamespace(headers=_BadHeaders())) == ({}, True)
