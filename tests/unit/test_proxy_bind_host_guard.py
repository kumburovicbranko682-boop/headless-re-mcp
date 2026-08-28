"""proxy.start binds loopback only, so it can never become an open relay.

The proxy listens on the analysis host. ``start`` validated the port but passed
``host`` straight to mitmproxy's ``listen_host``, so ``host="0.0.0.0"`` (or a LAN
address) would have opened an HTTP(S) relay any machine on the network could push
traffic through -- the same posture the web console already refuses for its own
bind. The guard turns a non-loopback host into ``invalid_params`` before any
listener is created, and it must fire in ``start`` itself (both the MCP schema and
the agent transport reach the backend through it). Loopback names/addresses stay
accepted because that is how the Android workflow reaches the proxy: adb reverse
or the emulator host alias, not a wide bind.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _is_loopback_host

LOOPBACK_HOSTS = ["127.0.0.1", "127.0.0.2", "::1", "localhost", "LocalHost", "  127.0.0.1  "]

NON_LOOPBACK_HOSTS = [
    "0.0.0.0",
    "::",
    "192.168.1.10",
    "10.0.2.2",
    "8.8.8.8",
    "example.com",
    "",
    "not-an-ip",
]


@pytest.mark.parametrize("host", LOOPBACK_HOSTS)
def test_a_loopback_host_is_accepted(host: str) -> None:
    assert _is_loopback_host(host) is True


@pytest.mark.parametrize("host", NON_LOOPBACK_HOSTS)
def test_a_non_loopback_host_is_rejected(host: str) -> None:
    assert _is_loopback_host(host) is False


def test_a_non_string_host_is_rejected_without_crashing() -> None:
    # The agent transport bypasses the str-typed schema, so None/int can arrive;
    # the guard must answer False rather than raise on host.strip().
    assert _is_loopback_host(None) is False  # type: ignore[arg-type]
    assert _is_loopback_host(1234) is False  # type: ignore[arg-type]


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com"])
def test_start_refuses_a_non_loopback_bind_before_launching_anything(host: str) -> None:
    """The refusal is wired into start and lands before any instance exists.

    _available is forced True so the check is not short-circuited by a missing
    mitmproxy, and the assertion that _instances stays empty proves the guard
    fires before _ProxyInstance is created and its listener thread spawned --
    i.e. nothing ever bound the wide address.
    """
    backend = ProxyBackend()
    backend._available = True

    with pytest.raises(ProxyError) as caught:
        backend.start("sess-1", host=host, port=8080)

    assert caught.value.code == "invalid_params"
    assert caught.value.details["host"] == host
    assert backend._instances == {}


def test_start_still_reaches_the_port_check_for_a_loopback_host() -> None:
    """A loopback host passes the bind guard, proving it did not over-refuse.

    The port is validated after the host, so an out-of-range port on a loopback
    host must surface the port error -- if the host guard had wrongly rejected
    127.0.0.1 the message would name the host instead.
    """
    backend = ProxyBackend()
    backend._available = True
    # A loopback host with a valid port would proceed to a real launch; instead
    # confirm the sibling reservation guard (also after the host check) is the
    # one that trips, which can only happen if the host was accepted.
    backend._instances["owner"] = SimpleNamespace(host="127.0.0.1", port=8080)

    with pytest.raises(ProxyError) as caught:
        backend.start("sess-2", host="127.0.0.1", port=8080)

    assert caught.value.code == "invalid_state"
    assert "reserved" in caught.value.message
