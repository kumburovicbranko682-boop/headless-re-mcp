"""Teardown must close every mitmproxy listener, or the port leaks.

mitmproxy 12's embedded shutdown path (``Master.run``'s ``finally`` -> ``done()``)
has no ``proxyserver`` teardown, so an in-process capture leaves its listening
socket bound until the whole process exits -- ``stop()`` reads as success while
the next capture can never rebind the port. ``_close_proxy_servers`` closes the
servers itself; these pin that behaviour with fakes so the guard runs even on
the CI matrix that installs no proxy extra (skip != pass).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from headless_re_mcp.backends.proxy.client import _close_proxy_servers


class _FakeServer:
    def __init__(self) -> None:
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


def _master_with_servers(servers: list[object]) -> SimpleNamespace:
    proxyserver = SimpleNamespace(servers=servers)
    addons = SimpleNamespace(
        get=lambda name: proxyserver if name == "proxyserver" else None
    )
    return SimpleNamespace(addons=addons)


def test_close_proxy_servers_stops_every_listener() -> None:
    loop = asyncio.new_event_loop()
    try:
        servers = [_FakeServer(), _FakeServer()]
        _close_proxy_servers(loop, _master_with_servers(list(servers)))
        assert all(server.stopped for server in servers)
    finally:
        loop.close()


def test_close_proxy_servers_continues_after_one_listener_raises() -> None:
    class _Boom(_FakeServer):
        async def stop(self) -> None:
            raise RuntimeError("boom")

    loop = asyncio.new_event_loop()
    try:
        healthy = _FakeServer()
        _close_proxy_servers(loop, _master_with_servers([_Boom(), healthy]))
        # A single listener that refuses to stop must not strand the others.
        assert healthy.stopped is True
    finally:
        loop.close()


def test_close_proxy_servers_tolerates_a_missing_proxyserver_addon() -> None:
    loop = asyncio.new_event_loop()
    try:
        master = SimpleNamespace(addons=SimpleNamespace(get=lambda name: None))
        _close_proxy_servers(loop, master)
    finally:
        loop.close()


def test_close_proxy_servers_is_a_noop_without_a_master() -> None:
    loop = asyncio.new_event_loop()
    try:
        _close_proxy_servers(loop, None)
    finally:
        loop.close()
