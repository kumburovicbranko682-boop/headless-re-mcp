"""Device-free coverage for the proxy backend's teardown and lifecycle edges.

The heavy machinery -- ``_ProxyInstance._run`` building a real DumpMaster on a
dedicated thread -- only runs when mitmproxy is installed and is proved by the
live integration gate. What this file pins are the surrounding pure branches
that keep a long-lived, multi-session service honest without needing a proxy up:

- ``_FlowRecorder`` eviction residuals: dropping a body when no summary matches,
  scanning past newer summaries to the target, and skipping an already-omitted
  slot while making room. These are the OOM guard's book-keeping; a drift here
  is exactly the overnight memory leak the ring was built to prevent.
- ``_shutdown_loop`` cancelling pending tasks (not just closing an idle loop),
  which is what actually frees the listening socket rather than leaking the port.
- ``_uninstall_master_logging`` leaving a handler that belongs to a *different*
  master and loop alone -- the branch the "unrelated handler" test misses.
- ``_ProxyInstance.start``'s readiness contract: a thread that records an error,
  one that exits early, and one that never begins listening each fail loudly
  instead of reporting a proxy that is about to die as running.
- ``ProxyBackend`` guards: reading a session with no proxy, a bad port, a port
  another session already reserved, and the two "stopped mid-start" rollbacks.
- ``replay`` driven all the way through the loop callback: the success return and
  a backend ``ProxyError`` re-raised unchanged rather than wrapped.

Every test drives fakes directly; nothing binds a real proxy port except the
ephemeral probe used to hand ``start`` a genuinely free port.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _FlowRecorder,
    _ProxyInstance,
    _shutdown_loop,
    _uninstall_master_logging,
)

# --- helpers --------------------------------------------------------------


def _fake_flow(
    flow_id: str,
    *,
    body: bytes = b"",
    method: str = "G",
    url: str = "h",
    host: str = "h",
    status: int = 200,
    content_type: str = "text/plain",
) -> SimpleNamespace:
    """A minimal stand-in for a finished mitmproxy flow.

    Carries just what ``_FlowRecorder.response`` and ``_flow_stored_bytes``
    read: a request with method/url/host/headers and a response whose
    ``raw_content`` is the only sizeable part, so a test controls the stored
    byte count purely through ``body``.
    """
    req = SimpleNamespace(
        raw_content=b"", method=method, pretty_url=url, host=host, headers={}
    )
    resp = SimpleNamespace(
        raw_content=body, status_code=status, headers={"content-type": content_type}
    )
    return SimpleNamespace(id=flow_id, request=req, response=resp)


def _free_port() -> int:
    """A port nothing is listening on right now, so ``start`` gets past its
    up-front bindability check and into the readiness loop under test."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _Recorder:
    """Returns a preset object from raw(); stands in for the ring buffer."""

    def __init__(self, value: Any) -> None:
        self._value = value

    def raw(self, flow_id: str) -> Any:
        del flow_id
        return self._value


class _InlineLoop:
    """Runs a scheduled callback in the caller's thread, like the bounds tests.

    replay() posts its work with ``call_soon_threadsafe`` and then blocks on the
    Future; running it inline makes the whole path deterministic without a real
    event loop, so the success and re-raise branches are exercised in-process.
    """

    def call_soon_threadsafe(self, callback: Any, *args: Any) -> None:
        callback(*args)


# --- _FlowRecorder eviction residuals -------------------------------------


def test_omit_retained_reclaims_bytes_even_with_no_matching_summary() -> None:
    # A raw slot can outlive its summary in principle; omitting it must still
    # reclaim the bytes and mark it omitted rather than walk off the end.
    recorder = _FlowRecorder(capacity=4)
    recorder._raw["ghost"] = object()
    recorder._raw_sizes["ghost"] = 100
    recorder._retained_bytes = 100

    recorder._omit_retained("ghost")

    assert recorder.raw("ghost") is _OMITTED_BODY
    assert recorder.retained_bytes() == 0
    assert recorder.snapshot() == []


def test_omit_retained_scans_past_newer_summaries_to_its_target() -> None:
    # The summary search runs newest-first; omitting the older flow has to step
    # over the newer summary before it reaches the one it must flag.
    recorder = _FlowRecorder(capacity=4)
    recorder.response(_fake_flow("old", body=b"x" * 10))
    recorder.response(_fake_flow("new", body=b"y" * 10))

    recorder._omit_retained("old")

    by_id = {summary["id"]: summary for summary in recorder.snapshot()}
    assert by_id["old"].get("body_omitted") is True
    assert "body_omitted" not in by_id["new"]


def test_eviction_skips_a_slot_that_is_already_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Tight caps so a third flow has to make room. The oldest slot is already an
    # omitted placeholder, so the eviction loop must skip it (not double-omit or
    # crash) and reclaim the next real body instead.
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 200)
    monkeypatch.setattr(proxy_client, "_MAX_RETAINED_BYTES", 200)
    recorder = _FlowRecorder(capacity=8)

    # A: 300B body -> over the per-body cap -> stored as an omitted placeholder.
    recorder.response(_fake_flow("A", body=b"a" * 300))
    # C: 150B body -> ~175B stored, retained under the 200B ring cap.
    recorder.response(_fake_flow("C", body=b"c" * 150))
    # D: another ~175B -> the ring is over budget; the loop meets A (already
    # omitted -> skip) then omits C to fit D.
    recorder.response(_fake_flow("D", body=b"d" * 150))

    assert recorder.raw("A") is _OMITTED_BODY
    assert recorder.raw("C") is _OMITTED_BODY
    assert recorder.raw("D") is not _OMITTED_BODY
    by_id = {summary["id"]: summary for summary in recorder.snapshot()}
    assert by_id["A"].get("body_omitted") is True
    assert by_id["C"].get("body_omitted") is True
    assert "body_omitted" not in by_id["D"]
    # Only D's body is still charged against the retained budget.
    assert recorder.retained_bytes() == recorder._raw_sizes["D"]


# --- _shutdown_loop -------------------------------------------------------


def test_shutdown_loop_cancels_pending_tasks_then_closes() -> None:
    # An idle loop is the easy case; the one that matters is a loop still holding
    # tasks (the proxy's accept task among them). They must be cancelled and
    # awaited, or closing the loop abandons the socket they own.
    loop = asyncio.new_event_loop()

    async def _seed() -> None:
        loop.create_task(asyncio.sleep(30))
        loop.create_task(asyncio.sleep(30))

    loop.run_until_complete(_seed())
    assert len([t for t in asyncio.all_tasks(loop) if not t.done()]) == 2

    _shutdown_loop(loop)

    assert loop.is_closed()


def test_shutdown_loop_closes_an_idle_loop() -> None:
    loop = asyncio.new_event_loop()
    _shutdown_loop(loop)
    assert loop.is_closed()


# --- _uninstall_master_logging --------------------------------------------


def test_uninstall_leaves_a_handler_from_a_different_master_and_loop() -> None:
    # A handler that belongs to *some* master, but not this one and not this
    # loop, is another live proxy's -- removing it would silence that proxy.
    root = logging.getLogger()
    handler = logging.NullHandler()
    handler.master = object()  # type: ignore[attr-defined]
    root.addHandler(handler)
    try:
        _uninstall_master_logging(master=object(), loop=object())
        assert handler in root.handlers
    finally:
        root.removeHandler(handler)


def test_uninstall_with_no_master_and_no_loop_is_a_noop() -> None:
    _uninstall_master_logging(None, None)


# --- _ProxyInstance.start readiness ---------------------------------------


def test_start_raises_backend_error_when_the_thread_records_one() -> None:
    inst = _ProxyInstance("127.0.0.1", _free_port())

    def fake_run() -> None:
        inst._error = RuntimeError("mitmproxy blew up")
        inst._started.set()

    inst._run = fake_run  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as caught:
        inst.start(timeout=2.0)
    assert caught.value.code == "backend_error"
    assert "mitmproxy blew up" in caught.value.message


def test_start_raises_backend_error_when_the_thread_exits_early() -> None:
    inst = _ProxyInstance("127.0.0.1", _free_port())
    inst._run = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as caught:
        inst.start(timeout=2.0)
    assert caught.value.code == "backend_error"
    assert "exited during startup" in caught.value.message


def test_start_times_out_when_the_thread_never_begins_listening() -> None:
    inst = _ProxyInstance("127.0.0.1", _free_port())

    def slow_run() -> None:
        inst._started.set()
        # Outlive the readiness deadline, then exit so stop()'s join returns
        # promptly rather than waiting out its own ten-second ceiling.
        time.sleep(1.3)

    inst._run = slow_run  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as caught:
        inst.start(timeout=0.1)
    assert caught.value.code == "timeout"
    assert caught.value.details["port"] == inst.port


# --- ProxyBackend guards --------------------------------------------------


def test_reading_a_session_with_no_proxy_is_invalid_state() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as caught:
        backend.flows("nope")
    assert caught.value.code == "invalid_state"
    assert "call proxy.start" in caught.value.message


@pytest.mark.parametrize("bad_port", [0, -1, 70000, "8080", 8080.0])
def test_start_refuses_a_port_outside_the_valid_range(bad_port: Any) -> None:
    backend = ProxyBackend()
    backend._check_available = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=bad_port)
    assert caught.value.code == "invalid_params"
    assert backend._instances == {}


def test_start_refuses_a_port_another_session_reserved() -> None:
    backend = ProxyBackend()
    backend._check_available = lambda: None  # type: ignore[method-assign]
    # A non-matching reservation first (the loop must step past it), then the
    # colliding one that must be reported with its owning session.
    backend._instances["other-port"] = SimpleNamespace(host="127.0.0.1", port=9999)
    backend._instances["owner"] = SimpleNamespace(host="127.0.0.1", port=8080)
    with pytest.raises(ProxyError) as caught:
        backend.start("mine", host="127.0.0.1", port=8080)
    assert caught.value.code == "invalid_state"
    assert caught.value.details["owner_session_id"] == "owner"
    # No instance was created for the refused session.
    assert set(backend._instances) == {"other-port", "owner"}


def test_start_rolls_back_when_the_session_vanishes_after_a_clean_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._check_available = lambda: None  # type: ignore[method-assign]
    stopped: list[Any] = []

    def evil_start(self: Any, timeout: float = 15.0) -> None:
        del timeout
        # A concurrent stop dropped the reservation while we were starting.
        backend._instances.pop("s", None)

    monkeypatch.setattr(_ProxyInstance, "start", evil_start)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: stopped.append(self))

    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=_free_port())
    assert caught.value.code == "invalid_state"
    assert "stopped while starting" in caught.value.message
    assert len(stopped) == 1
    assert backend._instances == {}


def test_failed_start_whose_reservation_vanished_still_stops_the_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProxyBackend()
    backend._check_available = lambda: None  # type: ignore[method-assign]
    stopped: list[Any] = []

    def evil_start(self: Any, timeout: float = 15.0) -> None:
        del timeout
        backend._instances.pop("s", None)
        raise ProxyError("timeout", "did not listen")

    monkeypatch.setattr(_ProxyInstance, "start", evil_start)
    monkeypatch.setattr(_ProxyInstance, "stop", lambda self: stopped.append(self))

    with pytest.raises(ProxyError) as caught:
        backend.start("s", port=_free_port())
    # The original failure is re-raised, not masked by the rollback.
    assert caught.value.code == "timeout"
    assert len(stopped) == 1
    assert backend._instances == {}


# --- replay driven through the loop callback ------------------------------


def test_replay_runs_the_command_and_reports_success() -> None:
    calls: list[tuple[str, Any]] = []

    class _Commands:
        def call(self, name: str, args: Any) -> None:
            calls.append((name, args))

    replayed = object()
    flow = SimpleNamespace(copy=lambda: replayed)
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(
        recorder=_Recorder(flow),
        _master=SimpleNamespace(commands=_Commands()),
        _loop=_InlineLoop(),
    )

    result = backend.replay("s", "f1")

    assert result == {"replayed": True, "flow_id": "f1"}
    assert calls == [("replay.client", [replayed])]


def test_replay_reraises_a_proxy_error_from_the_command_unchanged() -> None:
    class _Commands:
        def call(self, name: str, args: Any) -> None:
            del name, args
            raise ProxyError("permission_denied", "replay is blocked here")

    flow = SimpleNamespace(copy=lambda: object())
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(
        recorder=_Recorder(flow),
        _master=SimpleNamespace(commands=_Commands()),
        _loop=_InlineLoop(),
    )

    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "f1")
    # A ProxyError from the command is surfaced as-is, not wrapped as backend_error.
    assert caught.value.code == "permission_denied"
