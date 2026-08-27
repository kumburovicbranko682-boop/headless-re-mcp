"""proxy.stop must free the listening socket, not merely ask the master to exit.

From mitmproxy 10 the proxyserver addon releases its listening sockets when its
server list is emptied, not on the Done hook that a plain ``master.shutdown()``
fires. ``mitmdump`` never noticed because the process exits and the OS reclaims
the port, but this backend runs mitmproxy on a thread inside a long-lived
service, so a stop that only sets ``should_exit`` leaves the port bound and the
next capture on it is refused. The live gate proves the real behaviour, but it
skips wherever mitmproxy is absent (every default CI runner), so this drives
``stop()`` against a fake master on a real event loop and asserts each server
was actually stopped -- catching the regression where the gate cannot run.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

from headless_re_mcp.backends.proxy.client import _ProxyInstance


class _FakeServer:
    def __init__(self) -> None:
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


class _FakeAddons:
    def __init__(self, proxyserver: object) -> None:
        self._proxyserver = proxyserver

    def get(self, name: str) -> object | None:
        return self._proxyserver if name == "proxyserver" else None


def test_stop_stops_every_running_server_and_then_shuts_down() -> None:
    servers = [_FakeServer(), _FakeServer()]
    loop = asyncio.new_event_loop()
    shutdown_called = threading.Event()

    def fake_shutdown() -> None:
        shutdown_called.set()
        loop.call_soon_threadsafe(loop.stop)

    master = SimpleNamespace(
        addons=_FakeAddons(SimpleNamespace(servers=servers)),
        shutdown=fake_shutdown,
    )

    ready = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.call_soon(ready.set)
        loop.run_forever()
        loop.close()

    thread = threading.Thread(target=run, name="fake-mitmproxy", daemon=True)
    thread.start()
    assert ready.wait(5.0), "event loop did not start"

    inst = _ProxyInstance("127.0.0.1", 0)
    inst._master = master
    inst._loop = loop
    inst._thread = thread

    inst.stop()

    # Every server was torn down (this is what frees the OS socket), and only
    # then did the master shut down.
    assert all(server.stopped for server in servers)
    assert shutdown_called.is_set()
    # stop() clears its references so a second stop is a no-op rather than a
    # use-after-shutdown against a closed loop.
    assert inst._master is None
    assert inst._loop is None


def test_stop_is_a_noop_when_the_master_never_started() -> None:
    """A session refused before start() must still stop cleanly."""
    inst = _ProxyInstance("127.0.0.1", 0)
    inst.stop()  # no master, no loop, no thread
    assert inst._master is None
    assert inst._loop is None
