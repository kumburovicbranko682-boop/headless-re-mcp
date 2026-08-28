"""Device-free coverage for the proxy backend's port probes and shutdown.

``test_proxy_teardown_and_lifecycle`` pins the ring buffer, ``_shutdown_loop``,
the start-failure readiness paths and the replay callback. What is left, and what
this file closes, are the surrounding pure branches that never need a real
DumpMaster on a thread:

- ``_port_accepts`` answering "not accepting" when the probe itself raises (an
  unresolvable host, a filtered address), the readiness check the whole start
  contract rests on.
- ``_ProxyInstance.start`` returning the moment the port begins accepting -- the
  success exit of the readiness loop, driven with a probe that flips to live.
- ``_ProxyInstance.stop`` signalling shutdown onto the loop and joining the
  worker thread, then clearing its handles so a restart is clean.
- ``ProxyBackend._check_available`` degrading to ``capability_unavailable`` when
  mitmproxy cannot be imported, instead of an uncaught ImportError.
- ``ProxyBackend.close_all`` stopping every live instance and emptying the map.

The heavy ``_run`` (building a DumpMaster and driving mitmproxy's loop) still
belongs to the live integration gate; nothing here binds a real proxy.
"""

from __future__ import annotations

import builtins
import time
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    ProxyBackend,
    ProxyError,
    _port_accepts,
    _ProxyInstance,
)


class _RaisingProbe:
    """A socket whose connect_ex raises, to drive the suppressed-error path."""

    def __enter__(self) -> _RaisingProbe:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def settimeout(self, timeout: float) -> None:
        return None

    def connect_ex(self, address: object) -> int:
        raise OSError("connect blew up")


def test_port_accepts_answers_false_when_the_probe_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A probe that raises (bad host, filtered port) is 'not accepting', not a crash."""
    monkeypatch.setattr(proxy_client.socket, "socket", lambda *a, **k: _RaisingProbe())
    assert _port_accepts("127.0.0.1", 1) is False


def test_start_returns_once_the_port_begins_accepting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The readiness loop exits the instant the port starts accepting.

    The up-front check must see the port free (nothing listening yet) and
    bindable; the loop then sees it come alive. A probe that answers 'not
    accepting' first and 'accepting' afterwards models exactly that handoff
    without a real listener.
    """
    inst = _ProxyInstance("127.0.0.1", 8080)
    seen = {"n": 0}

    def _flipping_accepts(host: str, port: int, timeout: float = 0.25) -> bool:
        seen["n"] += 1
        return seen["n"] > 1  # free at the up-front check, live in the loop

    monkeypatch.setattr(proxy_client, "_port_accepts", _flipping_accepts)
    monkeypatch.setattr(proxy_client, "_port_bindable", lambda host, port: True)

    def _fake_run() -> None:
        inst._started.set()
        time.sleep(0.3)  # stay alive past the first readiness iteration

    inst._run = _fake_run  # type: ignore[method-assign]
    try:
        inst.start(timeout=2.0)  # returns cleanly rather than timing out
    finally:
        inst.stop()
    assert seen["n"] >= 2


def test_stop_signals_shutdown_onto_the_loop_and_clears_handles() -> None:
    """A running instance is shut down through its own loop, then reset."""
    inst = _ProxyInstance("127.0.0.1", 8080)
    scheduled: list[Any] = []

    class _Loop:
        def call_soon_threadsafe(self, callback: Any, *args: Any) -> None:
            scheduled.append((callback, args))

    inst._master = SimpleNamespace(shutdown=lambda: None)
    inst._loop = _Loop()  # type: ignore[assignment]

    inst.stop()

    assert len(scheduled) == 1  # master.shutdown was posted to the loop
    assert inst._master is None
    assert inst._loop is None


def test_stop_joins_the_worker_thread() -> None:
    """A stopped instance waits on its worker thread with the bounded timeout."""
    inst = _ProxyInstance("127.0.0.1", 8080)
    joined: list[float | None] = []
    inst._thread = SimpleNamespace(  # type: ignore[assignment]
        join=lambda timeout=None: joined.append(timeout)
    )

    inst.stop()

    assert joined == [10.0]


def test_check_available_degrades_when_mitmproxy_cannot_be_imported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing mitmproxy is a clean capability_unavailable, not an ImportError."""
    real_import = builtins.__import__

    def _no_mitmproxy(name: str, *args: object, **kwargs: object) -> Any:
        if name == "mitmproxy":
            raise ImportError("mitmproxy is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_mitmproxy)
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"
    assert backend._available is False


def test_close_all_stops_every_instance_and_empties_the_registry() -> None:
    """Shutting the backend down stops each live proxy and forgets it."""
    backend = ProxyBackend()
    stopped: list[str] = []
    backend._instances["a"] = SimpleNamespace(stop=lambda: stopped.append("a"))  # type: ignore[assignment]
    backend._instances["b"] = SimpleNamespace(stop=lambda: stopped.append("b"))  # type: ignore[assignment]

    backend.close_all()

    assert sorted(stopped) == ["a", "b"]
    assert backend._instances == {}
