"""proxy.stop must release the listeners, not merely signal shutdown.

mitmproxy's ``Master.done()`` stopped closing the proxyserver's listening
servers on the road to 12.x; mitmdump never noticed because the whole process
exits right after ``run()`` returns. Embedded in this long-lived service,
stop() joined a cleanly-exiting thread while the OS socket kept accepting
until process death, so the port could never be rebound. The live gate
(tests/integration/test_proxy_lifecycle_gate.py) pins the real behaviour when
mitmproxy is installed; these tests pin the drain wiring with fakes so a CI
host without mitmproxy still guards it.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

from headless_re_mcp.backends.proxy.client import _SERVER_STOP_WAIT_S, _ProxyInstance


class _FakeServers:
    def __init__(self, calls: list[object]) -> None:
        self._calls = calls

    async def update(self, modes: list[object]) -> bool:
        self._calls.append(("update", list(modes)))
        return True


class _FakeAddons:
    def __init__(self, proxyserver: object | None) -> None:
        self._proxyserver = proxyserver

    def get(self, name: str) -> object | None:
        return self._proxyserver if name == "proxyserver" else None


class _FakeMaster:
    """Records the shutdown call and lets the loop thread exit, like run()."""

    def __init__(self, calls: list[object], loop: asyncio.AbstractEventLoop) -> None:
        self._calls = calls
        self._loop = loop
        self.addons = _FakeAddons(SimpleNamespace(servers=_FakeServers(calls)))

    def shutdown(self) -> None:
        self._calls.append("shutdown")
        self._loop.stop()


def _running_instance(calls: list[object]) -> tuple[_ProxyInstance, asyncio.AbstractEventLoop]:
    inst = _ProxyInstance("127.0.0.1", 18080)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, name="fake-mitmproxy", daemon=True)
    thread.start()
    inst._loop = loop
    inst._thread = thread
    inst._master = _FakeMaster(calls, loop)
    return inst, loop


def test_stop_drains_the_listening_servers_before_signalling_shutdown() -> None:
    calls: list[object] = []
    inst, loop = _running_instance(calls)
    try:
        inst.stop()
    finally:
        loop.close()

    # The drain must come first: shutdown only makes run() return, and once
    # the loop is gone nothing can close the servers any more.
    assert calls == [("update", []), "shutdown"]


def test_stop_still_signals_shutdown_when_the_servers_api_is_missing() -> None:
    """Older mitmproxy exposes no Servers.update; stop() must not regress."""
    calls: list[object] = []
    inst, loop = _running_instance(calls)
    inst._master.addons = _FakeAddons(SimpleNamespace())  # type: ignore[union-attr]
    try:
        inst.stop()
    finally:
        loop.close()

    assert calls == ["shutdown"]


def test_stop_does_not_wait_on_a_dead_proxy_thread() -> None:
    """A crashed proxy has no loop to drain on; stop() must return promptly."""
    calls: list[object] = []
    inst = _ProxyInstance("127.0.0.1", 18080)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=lambda: None, daemon=True)
    thread.start()
    thread.join()
    inst._loop = loop
    inst._thread = thread
    inst._master = _FakeMaster(calls, loop)

    began = time.monotonic()
    try:
        inst.stop()
    finally:
        loop.close()

    assert time.monotonic() - began < _SERVER_STOP_WAIT_S
    # Neither the drain nor the shutdown ever ran: the loop was never serving.
    assert ("update", []) not in calls
