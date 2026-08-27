"""Proxy shutdown must close every mitmproxy listener, not just end run().

mitmproxy's ``Proxyserver`` addon has no ``done()`` hook: setting
``should_exit`` returns from ``Master.run()`` while the server instances --
and their listening sockets -- stay up. mitmproxy's CLI tools never notice
because process exit closes the sockets; embedded in a long-lived MCP process
nothing exits, so stop() reported success while the OS kept the port bound
and the next capture on that port could never start. ``_stop_server_instances``
is the piece that actually frees the port, so its contract is pinned here
without needing mitmproxy installed: it stops every instance, one failing
instance does not shield the rest, and a master shaped unlike what it expects
degrades to a no-op instead of masking shutdown with a fresh crash.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import _stop_server_instances


class _Instance:
    def __init__(self, fail: bool = False) -> None:
        self.stopped = False
        self._fail = fail

    async def stop(self) -> None:
        if self._fail:
            raise RuntimeError("listener already gone")
        self.stopped = True


def _master_with(instances: list[_Instance]) -> Any:
    proxyserver = SimpleNamespace(servers=instances)
    addons = SimpleNamespace(
        get=lambda name: proxyserver if name == "proxyserver" else None
    )
    return SimpleNamespace(addons=addons)


def test_every_server_instance_is_stopped() -> None:
    instances = [_Instance(), _Instance(), _Instance()]
    asyncio.run(_stop_server_instances(_master_with(instances)))
    assert all(inst.stopped for inst in instances)


def test_one_failing_instance_does_not_shield_the_others() -> None:
    failing = _Instance(fail=True)
    healthy = _Instance()
    # The failing listener is gathered, not raised: shutdown must keep going.
    asyncio.run(_stop_server_instances(_master_with([failing, healthy])))
    assert healthy.stopped is True


def test_unexpected_master_shapes_degrade_to_a_noop() -> None:
    # No addons attribute at all (master never finished constructing).
    asyncio.run(_stop_server_instances(SimpleNamespace()))
    # Addon manager without a proxyserver addon.
    asyncio.run(
        _stop_server_instances(SimpleNamespace(addons=SimpleNamespace(get=lambda _: None)))
    )
    # Proxyserver addon without a servers attribute (future API drift).
    proxyless = SimpleNamespace(
        addons=SimpleNamespace(get=lambda _: SimpleNamespace())
    )
    asyncio.run(_stop_server_instances(proxyless))


def test_zero_instances_is_a_noop() -> None:
    asyncio.run(_stop_server_instances(_master_with([])))
