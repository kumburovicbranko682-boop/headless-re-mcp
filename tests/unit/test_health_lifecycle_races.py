"""Races between the health monitor's stop and a concurrent start/open.

Two windows around BackendHealthMonitor.stop():

* stop() joins for up to its timeout while a sweep sits inside a reconnect.
  A start() arriving inside that join used to find _thread and _previous both
  empty, launch a second sweeper and clear the stop flag -- un-cancelling the
  old thread, which had not yet observed it: two sweepers forever.
* close_session evaluates "no runtimes left -> stop the monitor" outside the
  service lock while opens register under it, so a backend can finish opening
  between the emptiness check and the stop. That backend then ran with the
  monitor silently off until some later open called start() again.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from threading import RLock
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.health import BackendHealthMonitor
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService


class BlockingRuntimes:
    """snapshot() parks the sweep until released -- a reconnect outliving the join."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def snapshot(self) -> list[tuple[str, BackendKind, object]]:
        self.entered.set()
        self.release.wait(timeout=10.0)
        return []

    def is_current(self, session_id: str, kind: BackendKind, runtime: object) -> bool:
        return False


def test_a_start_during_stops_join_window_does_not_leave_two_sweepers() -> None:
    source = BlockingRuntimes()
    monitor = BackendHealthMonitor(source, interval_s=0.01)
    monitor.start()
    old = monitor._thread
    assert old is not None
    assert source.entered.wait(timeout=5.0), "sweep never reached the runtime source"

    stopper = threading.Thread(target=lambda: monitor.stop(timeout=1.0))
    stopper.start()
    try:
        # Wait for stop() to publish its intent (stop flag set, _thread handed
        # off); the join it is now sitting in lasts as long as the wedged sweep.
        deadline = time.monotonic() + 5.0
        while monitor._thread is not None and time.monotonic() < deadline:
            time.sleep(0.005)
        assert monitor._thread is None

        monitor.start()
    finally:
        source.release.set()
        stopper.join(timeout=5.0)
    assert not stopper.is_alive()

    # The requested restart must resolve to a single fresh sweeper: the old
    # thread observes the stop flag, exits, and its finally launches the
    # replacement. With the flag cleared by the racing start(), the old
    # thread instead kept sweeping alongside the new one forever.
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        current = monitor._thread
        if not old.is_alive() and current is not None and current.is_alive():
            break
        time.sleep(0.01)
    try:
        assert not old.is_alive(), "the cancelled sweeper kept running"
        current = monitor._thread
        assert current is not None and current.is_alive()
        assert current is not old
    finally:
        monitor.stop()


def _write_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    image[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    image[optional + 56 : optional + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(image)


class _FakeWorker:
    pid = 4242
    capabilities: tuple[str, ...] = ()

    def close(self) -> None: ...

    def terminate(self) -> None: ...


class _FakeRuntime:
    def __init__(self) -> None:
        self.lock = RLock()
        self.worker = _FakeWorker()
        self.event_drain_pump = None
        self.event_log = None


def _fake_runtime() -> Any:
    return _FakeRuntime()


def test_close_restarts_the_monitor_when_a_backend_opened_mid_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "target.exe"
    _write_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        first = service.create_session(str(binary))
        assert first.ok and first.data is not None, first.error
        session_a = first.data["session"]["id"]
        second = service.create_session(str(binary))
        assert second.ok and second.data is not None, second.error
        session_b = second.data["session"]["id"]

        service._runtime_owner.begin_open(session_a, BackendKind.X64DBG)
        service._runtime_owner.put(session_a, BackendKind.X64DBG, _fake_runtime())

        real_stop = service._health.stop
        fired = {"done": False}

        def stop_with_a_concurrent_open(
            self: BackendHealthMonitor, *, timeout: float = 2.0
        ) -> None:
            # Session B's open completes exactly inside the race window: after
            # close's emptiness check, while the stop is tearing the sweep down.
            if not fired["done"]:
                fired["done"] = True
                service._runtime_owner.begin_open(session_b, BackendKind.X64DBG)
                service._runtime_owner.put(session_b, BackendKind.X64DBG, _fake_runtime())
                service._health.start()
            real_stop(timeout=timeout)

        monkeypatch.setattr(BackendHealthMonitor, "stop", stop_with_a_concurrent_open)

        closed = service.close_session(session_a)
        assert closed.ok, closed.error

        # B's backend is live, so its monitor must be too.
        assert service._runtime_owner.snapshot()
        assert service._health._thread is not None
    finally:
        service.close_all()
