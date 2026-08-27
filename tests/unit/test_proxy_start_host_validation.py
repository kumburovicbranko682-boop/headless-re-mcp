"""proxy.start must validate the bind host at the boundary.

host is a tool parameter (agent/OpenAI transports call the handler straight
from model arguments, with no schema validation), and it was passed to
mitmproxy unchecked. Two consequences this pins:

* An unresolvable host tripped the bind probe -- socket.bind raises, the probe
  suppresses it and returns "not bindable" -- so start() blamed a port that was
  never in use ("port is already in use; stop the existing listener first").
* The empty string binds every interface in asyncio, the same silent network
  exposure as 0.0.0.0, but read as an unset default.

Both are now a precise invalid_params before any listener is touched. These run
without mitmproxy: validation happens after the availability check (faked here)
and before the port is reserved.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError


def _backend() -> ProxyBackend:
    backend = ProxyBackend()
    # Skip the real mitmproxy import; the host guard runs before any use of it.
    backend._available = True
    return backend


@pytest.mark.parametrize("host", ["not-a-host!!", "", "10.0.0.1;rm -rf", "1.2.3.4:8080", "::1"])
def test_start_rejects_an_invalid_bind_host_as_invalid_params(host: str) -> None:
    backend = _backend()
    with pytest.raises(ProxyError) as raised:
        backend.start("s", host=host, port=9099)
    assert raised.value.code == "invalid_params"
    assert raised.value.message == "invalid host"
    assert raised.value.details["host"] == host
    # It is no longer 9099 nor "already running" is reserved.
    assert "s" not in backend._instances


def test_an_unresolvable_host_is_not_misreported_as_a_port_conflict() -> None:
    """The bug this fixes: a bad host used to read as a busy port."""
    backend = _backend()
    with pytest.raises(ProxyError) as raised:
        backend.start("s", host="totally.bogus.invalid!!", port=9098)
    assert raised.value.code == "invalid_params"
    assert "port is already in use" not in raised.value.message


def test_a_well_formed_but_non_local_address_is_a_bad_host_not_a_busy_port() -> None:
    """A regex-valid IP that is not on any interface must not read as busy.

    192.0.2.1 is TEST-NET-1 (RFC 5737): syntactically fine, so it clears the
    host regex, but binding it raises EADDRNOTAVAIL because it is on no local
    interface. Before, that tripped _port_bindable and start() blamed the port;
    now it is a precise invalid_params about the host. Uses a real bind, so it
    is deterministic and needs no DNS or mitmproxy.
    """
    backend = _backend()
    with pytest.raises(ProxyError) as raised:
        backend.start("s", host="192.0.2.1", port=9096)
    assert raised.value.code == "invalid_params"
    assert "port is already in use" not in raised.value.message
    assert raised.value.details["host"] == "192.0.2.1"
    assert "s" not in backend._instances


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "localhost", "192.168.1.10"])
def test_start_accepts_well_formed_hosts_past_validation(
    host: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A well-formed host must clear the guard and reach the real listener.

    The instance start is stubbed so the test neither needs nor launches
    mitmproxy: reaching it at all proves the host was accepted, and an invalid
    host would have raised invalid_params before this point.
    """
    import headless_re_mcp.backends.proxy.client as proxy_client

    reached: list[tuple[str, int]] = []

    def fake_start(self: proxy_client._ProxyInstance, timeout: float = 15.0) -> None:
        reached.append((self.host, self.port))
        raise proxy_client.ProxyError("backend_error", "stubbed: did not really bind")

    monkeypatch.setattr(proxy_client._ProxyInstance, "start", fake_start)

    backend = _backend()
    with pytest.raises(ProxyError) as raised:
        backend.start("s", host=host, port=9097)
    assert reached == [(host, 9097)]
    assert raised.value.message == "stubbed: did not really bind"
    assert "s" not in backend._instances
