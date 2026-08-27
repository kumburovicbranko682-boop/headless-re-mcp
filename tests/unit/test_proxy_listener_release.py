"""Stopping a proxy must actually free its listening port.

mitmproxy's ``Master.shutdown()`` only makes ``run()`` return; the
``Proxyserver`` addon has no ``done`` hook, so its server instances are never
stopped -- the mitmdump CLI frees ports by exiting the process. Embedded in
this long-lived service the listener survived ``stop()``: status said the
capture was gone while the OS socket kept completing TCP handshakes, and the
port could never be bound again. These tests pin the explicit listener
teardown with fakes so they run on every CI box, with or without mitmproxy
installed; the live bind/release contract is proved by
tests/integration/test_proxy_lifecycle_gate.py.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

import headless_re_mcp.backends.proxy.client as proxy_client
from headless_re_mcp.backends.proxy.client import _stop_proxy_listeners


class _FakeServers:
    def __init__(self) -> None:
        self.updates: list[list[Any]] = []

    async def update(self, modes: list[Any]) -> bool:
        self.updates.append(modes)
        return True


class _FakeProxyserver:
    def __init__(self, servers: Any) -> None:
        self.servers = servers


class _FakeAddons:
    def __init__(self, proxyserver: Any) -> None:
        self._proxyserver = proxyserver

    def get(self, name: str) -> Any:
        return self._proxyserver if name == "proxyserver" else None


class _FakeMaster:
    def __init__(self, proxyserver: Any) -> None:
        self.addons = _FakeAddons(proxyserver)


def test_the_unwind_stops_every_mode_server() -> None:
    """update([]) is the same teardown a mode change performs."""
    servers = _FakeServers()
    loop = asyncio.new_event_loop()
    try:
        _stop_proxy_listeners(_FakeMaster(_FakeProxyserver(servers)), loop)
    finally:
        loop.close()
    assert servers.updates == [[]]


def test_a_master_without_the_addon_is_tolerated() -> None:
    """A startup that failed before addons existed must still unwind."""
    loop = asyncio.new_event_loop()
    try:
        _stop_proxy_listeners(_FakeMaster(None), loop)
        _stop_proxy_listeners(None, loop)
    finally:
        loop.close()


def test_a_closed_loop_is_not_asked_to_run() -> None:
    servers = _FakeServers()
    loop = asyncio.new_event_loop()
    loop.close()
    _stop_proxy_listeners(_FakeMaster(_FakeProxyserver(servers)), loop)
    assert servers.updates == []


def test_a_wedged_server_stop_cannot_hang_the_unwind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The close is best effort: a stuck server must not wedge stop() itself."""
    monkeypatch.setattr(proxy_client, "_LISTENER_CLOSE_WAIT_S", 0.05)

    class _WedgedServers:
        async def update(self, modes: list[Any]) -> bool:
            await asyncio.Event().wait()
            return True

    loop = asyncio.new_event_loop()
    try:
        _stop_proxy_listeners(_FakeMaster(_FakeProxyserver(_WedgedServers())), loop)
    finally:
        loop.close()


def test_the_run_unwind_calls_the_listener_stop_before_the_loop_dies() -> None:
    """_run's finally must stop listeners while the loop can still run them.

    Task unwinding alone does not close asyncio servers, so ordering is the
    contract: listeners first, then _shutdown_loop.
    """
    import inspect

    source = inspect.getsource(proxy_client._ProxyInstance._run)
    stop_at = source.index("_stop_proxy_listeners")
    shutdown_at = source.index("_shutdown_loop(loop)")
    assert stop_at < shutdown_at
