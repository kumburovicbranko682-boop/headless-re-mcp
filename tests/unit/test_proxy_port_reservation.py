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
