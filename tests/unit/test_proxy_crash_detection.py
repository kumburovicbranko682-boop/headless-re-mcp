"""A proxy whose mitmproxy thread died must be reported honestly and recoverable.

The instance only reaches ``_instances`` after start() saw the port accept, so a
registered instance whose thread is no longer alive is one whose run() returned
or raised after startup -- an internal mitmproxy error, or the loop dying under
an overnight capture. Membership in the map alone used to keep status reporting
running=True while start refused to rebind ("already running") and replay
dispatched onto a closed loop. These tests pin the liveness-gated behavior; the
recorder buffer (the captured evidence) must survive the death either way.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.proxy.client import _ProxyInstance


class _Recorder:
    def __init__(self, count: int = 0) -> None:
        self._count = count

    def count(self) -> int:
        return self._count

    def retained_bytes(self) -> int:
        return 0

    def snapshot(self) -> list[dict[str, Any]]:
        return []

    def raw(self, flow_id: str) -> Any:
        return None


def _dead_instance(*, error: BaseException | None = None, count: int = 0) -> _ProxyInstance:
    """A _ProxyInstance whose thread has already run and exited."""
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst.recorder = _Recorder(count)  # type: ignore[assignment]
    inst._ever_started = True
    if error is not None:
        inst._error = error
    # A thread that has already finished reports is_alive() False, which is
    # exactly the post-crash state -- no need to actually crash mitmproxy.
    thread = threading.Thread(target=lambda: None)
    thread.start()
    thread.join()
    inst._thread = thread
    return inst


class TestStatusReportsAnExitedProxy:
    def test_a_dead_thread_reports_exited_not_running(self) -> None:
        backend = ProxyBackend()
        backend._instances["s"] = _dead_instance(count=7)
        payload = backend.status("s")
        assert payload["running"] is False
        assert payload["exited"] is True
        assert payload["flow_count"] == 7
        assert payload["port"] == 8080

    def test_the_stored_exit_reason_is_surfaced_and_bounded(self) -> None:
        backend = ProxyBackend()
        backend._instances["s"] = _dead_instance(error=RuntimeError("loop blew up " + "x" * 900))
        payload = backend.status("s")
        assert payload["exited"] is True
        assert payload["error"].startswith("loop blew up ")
        assert len(payload["error"]) <= 500

    def test_a_clean_exit_reports_exited_without_an_error(self) -> None:
        backend = ProxyBackend()
        backend._instances["s"] = _dead_instance(error=None)
        payload = backend.status("s")
        assert payload["exited"] is True
        assert "error" not in payload


class TestStartRecoversFromACrash:
    def test_start_refuses_only_a_live_proxy(self, monkeypatch: Any) -> None:
        backend = ProxyBackend()
        backend._instances["s"] = SimpleNamespace(  # type: ignore[assignment]
            host="127.0.0.1", port=8080, crashed_after_start=lambda: False
        )
        monkeypatch.setattr(backend, "_check_available", lambda: None)
        with pytest.raises(ProxyError) as info:
            backend.start("s", "127.0.0.1", 8080)
        assert info.value.code == "invalid_state"
        assert "already running" in info.value.message

    def test_start_replaces_a_dead_instance_and_rebinds(self, monkeypatch: Any) -> None:
        backend = ProxyBackend()
        dead = _dead_instance()
        stopped: list[bool] = []
        dead.stop = lambda: stopped.append(True)  # type: ignore[method-assign]
        backend._instances["s"] = dead
        monkeypatch.setattr(backend, "_check_available", lambda: None)

        started: list[_ProxyInstance] = []

        def fake_start(self: _ProxyInstance, timeout: float = 15.0) -> None:
            started.append(self)

        monkeypatch.setattr(_ProxyInstance, "start", fake_start)
        payload = backend.start("s", "127.0.0.1", 8080)
        assert payload["running"] is True
        assert payload["port"] == 8080
        # The dead one was dropped and torn down; a fresh instance took the slot.
        assert stopped == [True]
        assert backend._instances["s"] is not dead
        assert started and started[0] is backend._instances["s"]


class TestReplayFailsClosedOnADeadProxy:
    def test_replay_says_the_proxy_exited_instead_of_a_closed_loop_error(self) -> None:
        backend = ProxyBackend()
        dead = _dead_instance()
        # A crashed proxy keeps its stale master and closed loop, which is the
        # shape that produced the misleading "Event loop is closed" backend_error.
        dead._master = object()
        dead._loop = SimpleNamespace(call_soon_threadsafe=lambda *_: None)  # type: ignore[assignment]
        dead.recorder = SimpleNamespace(raw=lambda flow_id: SimpleNamespace(copy=lambda: object()))  # type: ignore[assignment]
        backend._instances["s"] = dead
        with pytest.raises(ProxyError) as info:
            backend.replay(session_id="s", flow_id="1")
        assert info.value.code == "invalid_state"
        assert "proxy is not running" in info.value.message


class TestLiveThreadDeathIsDetected:
    def test_status_flips_to_exited_when_the_loop_stops_under_the_capture(self) -> None:
        """End to end: stop the loop out from under a real running proxy (not
        via backend.stop, so the instance stays registered) and confirm status
        stops claiming it is running."""
        import socket

        pytest.importorskip("mitmproxy")
        backend = ProxyBackend()

        # Pick a free port so the bind is deterministic on a shared runner.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        started = backend.start("s", "127.0.0.1", port)
        assert started["running"] is True
        inst = backend._instances["s"]
        assert backend.status("s")["running"] is True

        # Kill the loop the way an internal failure would end run(), leaving the
        # instance registered -- the exact state the liveness check is for.
        inst._loop.call_soon_threadsafe(inst._loop.stop)
        deadline = time.monotonic() + 10.0
        while inst.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        try:
            payload = backend.status("s")
            assert payload["running"] is False
            assert payload["exited"] is True
        finally:
            backend.stop("s")
