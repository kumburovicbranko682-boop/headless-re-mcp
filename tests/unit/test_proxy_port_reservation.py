"""Cross-session proxy.start must not treat another listener as success."""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError


def test_proxy_start_refuses_a_port_already_reserved_by_another_session() -> None:
    backend = ProxyBackend()
    backend._available = True
    backend._instances["first"] = SimpleNamespace(host="127.0.0.1", port=8080)

    with pytest.raises(ProxyError, match="already reserved") as raised:
        backend.start("second", host="127.0.0.1", port=8080)

    assert raised.value.code == "invalid_state"
    assert raised.value.details["port"] == 8080
    assert raised.value.details["owner_session_id"] == "first"
    assert "second" not in backend._instances


def test_proxy_start_refuses_a_port_held_by_a_foreign_listener() -> None:
    """A port bound outside this backend fails closed as invalid_state, and the
    refused start leaves no phantom reservation behind.

    This is the other half of the pair the test above pins. "Already reserved" is
    this backend's own bookkeeping -- another session owns the port; this is a
    listener the backend knows nothing about, typically a proxy it leaked on a
    previous run. Both must read as ``invalid_state`` so an agent stops the holder
    rather than retrying (a transient fault) or reinstalling mitmproxy
    (capability_unavailable), and the ``_ProxyInstance.start()`` guard that raises
    it fires before any mitmproxy thread starts, so forcing ``_available`` past
    the capability gate lets the contract be pinned with no backend installed.

    The crucial fail-closed property is the rollback: ``start()`` reserves the
    session in ``_instances`` *before* binding, so a raise from the port guard
    must pop it again -- otherwise the dead session would shadow the port forever
    and every later start on it would hit the "already reserved" arm above. A
    leak-focused sibling drives this same path but only asserts that *some*
    ProxyError is raised; this pins the code, the host/port details and that the
    reservation is gone.
    """
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen()
    port = holder.getsockname()[1]

    backend = ProxyBackend()
    backend._available = True  # the port guard is earlier than the capability gate
    try:
        with pytest.raises(ProxyError, match="already in use") as raised:
            backend.start("s", host="127.0.0.1", port=port)

        assert raised.value.code == "invalid_state"
        assert raised.value.details["port"] == port
        assert raised.value.details["host"] == "127.0.0.1"
        assert backend._instances == {}, "a refused start must leave no reservation"
    finally:
        holder.close()
        backend.close_all()


@pytest.mark.parametrize("bad_port", [0, -1, 65536, 999999])
def test_proxy_start_rejects_a_bad_port_before_the_capability_check(bad_port: int) -> None:
    """A port outside 1..65535 must fail as invalid_params even without mitmproxy.

    start() used to run _check_available() first, so a bad port on a host where
    mitmproxy is not installed surfaced as capability_unavailable -- masking the
    parameter mistake behind a missing-backend error, unlike frida.spawn /
    jadx.decompile / apk.methods, which reject malformed caller input before the
    capability gate. With _available forced False (so the capability check would
    fire if reached), a bad port now still fails precisely as invalid_params, and
    no instance is reserved.
    """
    backend = ProxyBackend()
    backend._available = False

    with pytest.raises(ProxyError) as raised:
        backend.start("s", host="127.0.0.1", port=bad_port)

    assert raised.value.code == "invalid_params"
    assert raised.value.details["port"] == bad_port
    assert backend._instances == {}
