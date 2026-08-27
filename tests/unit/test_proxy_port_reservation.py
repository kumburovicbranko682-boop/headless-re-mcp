"""Cross-session proxy.start must not treat another listener as success."""

from __future__ import annotations

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
