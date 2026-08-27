"""Stopping a capture must release the listening socket, not just the loop.

Reaching the end of ``master.run()`` (via ``master.shutdown()``) stops
mitmproxy's event loop but, from mitmproxy 12.x on, does not close the proxy's
listening sockets: they belong to the Proxyserver addon's ``ServerInstance``
objects rather than to the accept *task* the loop teardown cancels. Closing the
loop then abandons the bound socket at the OS level, so ``stop()`` reports
success while the port stays taken and the next capture cannot rebind.

``_close_proxy_servers`` stops each server explicitly. These tests pin that
contract with fakes so they run without mitmproxy installed; the live
``test_proxy_lifecycle_gate`` proves the same thing against the real process.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import _close_proxy_servers


class _FakeServer:
    def __init__(self, *, raises: bool = False) -> None:
        self.stopped = 0
        self._raises = raises

    async def stop(self) -> None:
        self.stopped += 1
        if self._raises:
            raise RuntimeError("teardown blew up")


class _FakeProxyserver:
    def __init__(self, servers: Any) -> None:
        self.servers = servers


class _FakeAddons:
    def __init__(self, addon: Any) -> None:
        self._addon = addon

    def get(self, name: str) -> Any:
        return self._addon if name == "proxyserver" else None


class _FakeMaster:
    def __init__(self, servers: Any) -> None:
        self.addons = _FakeAddons(_FakeProxyserver(servers))


def _fresh_loop() -> asyncio.AbstractEventLoop:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


def test_close_proxy_servers_stops_every_listener() -> None:
    loop = _fresh_loop()
    try:
        servers = [_FakeServer(), _FakeServer()]
        _close_proxy_servers(_FakeMaster(servers), loop)
    finally:
        loop.close()
    assert [server.stopped for server in servers] == [1, 1]


def test_one_server_failing_to_stop_does_not_strand_the_others() -> None:
    """A best-effort teardown still has to reach every listener."""
    loop = _fresh_loop()
    try:
        servers = [_FakeServer(raises=True), _FakeServer()]
        _close_proxy_servers(_FakeMaster(servers), loop)
    finally:
        loop.close()
    assert [server.stopped for server in servers] == [1, 1]


def test_a_mitmproxy_without_the_proxyserver_addon_is_a_no_op() -> None:
    """Defensive across versions: nothing to stop, no exception raised."""
    loop = _fresh_loop()
    try:
        _close_proxy_servers(_FakeMaster(None), loop)

        class _NoAddon:
            class addons:  # noqa: N801 - mimics mitmproxy's attribute shape
                @staticmethod
                def get(_name: str) -> Any:
                    return None

        _close_proxy_servers(_NoAddon(), loop)
    finally:
        loop.close()


def test_no_master_or_closed_loop_is_a_no_op() -> None:
    loop = _fresh_loop()
    loop.close()
    # A closed loop must not be driven, and a missing master has nothing to do.
    _close_proxy_servers(None, loop)
    _close_proxy_servers(_FakeMaster([_FakeServer()]), None)


def test_run_teardown_stops_servers_before_unwinding_the_loop() -> None:
    """Order matters: cancelling loop tasks first still leaves the socket bound.

    Guards against a refactor that drops the explicit server stop or moves it
    after ``_shutdown_loop`` (which was the insufficient mitigation on its own).
    """
    source = inspect.getsource(proxy_client._ProxyInstance._run)
    assert "_close_proxy_servers(" in source
    close_call = source.index("_close_proxy_servers(")
    shutdown_call = source.index("_shutdown_loop(")
    assert close_call < shutdown_call
