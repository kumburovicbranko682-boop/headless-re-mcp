"""Proxy bring-up is serialised and waits for the running() phase.

mitmproxy keeps ctx.master/ctx.options in module globals that every DumpMaster
overwrites in its constructor, so two captures coming up at once share one
half-built context and a running() hook reads an option the next master has
not registered yet. The fix holds a module lock across the whole bring-up and
only reports ready once a marker addon's running() hook has fired. These tests
pin that contract with fakes, so they run in the unit job with no mitmproxy;
the live proof is tests/integration/test_proxy_lifecycle_gate.py.
"""

from __future__ import annotations

import threading
import time

import pytest

import headless_re_mcp.backends.proxy.client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    ProxyError,
    _ProxyInstance,
    _ReadyMarker,
)


def test_ready_marker_sets_its_event_on_running() -> None:
    event = threading.Event()
    marker = _ReadyMarker(event)
    assert not event.is_set()
    marker.running()
    assert event.is_set()


def _fake_transport(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """Make the port probes deterministic: bindable, and not accepting until up."""
    state = {"up": False}
    monkeypatch.setattr(proxy_client, "_port_bindable", lambda *a, **k: True)
    monkeypatch.setattr(
        proxy_client, "_port_accepts", lambda *a, **k: state["up"]
    )
    return state


def test_start_waits_for_the_marker_not_just_the_open_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A port that accepts is not enough: running() must have fired too."""
    state = _fake_transport(monkeypatch)
    inst = _ProxyInstance("127.0.0.1", 12345)

    def fake_run() -> None:
        # Port comes up, but the running() marker never fires -- exactly the
        # window where mitmproxy's hooks could still be racing.
        state["up"] = True
        inst._started.set()
        time.sleep(1.0)

    monkeypatch.setattr(inst, "_run", fake_run)
    with pytest.raises(ProxyError, match="did not begin listening"):
        inst.start(timeout=0.4)


def test_start_returns_once_the_marker_and_port_agree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _fake_transport(monkeypatch)
    inst = _ProxyInstance("127.0.0.1", 12346)

    def fake_run() -> None:
        state["up"] = True
        inst._started.set()
        inst._ready.set()
        time.sleep(1.0)

    monkeypatch.setattr(inst, "_run", fake_run)
    inst.start(timeout=2.0)  # returns None; a raise would fail the test


def test_start_blocks_while_the_module_lock_is_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two bring-ups cannot overlap: start() must take the shared startup lock."""
    state = _fake_transport(monkeypatch)
    inst = _ProxyInstance("127.0.0.1", 12347)

    def fake_run() -> None:
        state["up"] = True
        inst._started.set()
        inst._ready.set()
        time.sleep(0.5)

    monkeypatch.setattr(inst, "_run", fake_run)

    outcome: list[str] = []

    def call_start() -> None:
        try:
            inst.start(timeout=2.0)
            outcome.append("returned")
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            outcome.append(f"raised:{exc}")

    proxy_client._STARTUP_LOCK.acquire()
    worker = threading.Thread(target=call_start, name="start-under-lock")
    worker.start()
    try:
        # Held: start() cannot get past the lock, so it neither returns nor raises.
        time.sleep(0.3)
        assert outcome == [], "start() ran while the startup lock was held"
    finally:
        proxy_client._STARTUP_LOCK.release()
    worker.join(timeout=3.0)
    assert outcome == ["returned"]
