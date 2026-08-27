"""A blank proxy.start host must bind loopback, never every interface.

mitmproxy reads ``listen_host=""`` as bind-all (``0.0.0.0`` + ``::``), so a
missing or whitespace host would put an active HTTPS MITM -- and the CA it can
install onto a device -- on every routable interface. The tool documents a
loopback default; these pin that a blank value falls back to that default while
an explicit address (including a deliberate routable bind for a physical
device) is preserved. The instance is faked so the assertion is the host handed
to the listener, not a real bound socket.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import ProxyBackend


class _FakeInstance:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.started = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:  # pragma: no cover - defensive, unused on success
        self.started = False


@pytest.fixture
def _no_real_listener(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_ProxyInstance", _FakeInstance)


@pytest.mark.parametrize("blank", ["", "   ", "\t", None])
def test_a_blank_host_binds_loopback_not_every_interface(
    blank: Any, _no_real_listener: None
) -> None:
    backend = ProxyBackend()
    backend._available = True

    data = backend.start("s", host=blank, port=8080)

    assert data["host"] == "127.0.0.1"
    assert data["endpoint"] == "127.0.0.1:8080"
    inst = backend._instances["s"]
    assert isinstance(inst, _FakeInstance)
    # The listener itself was handed loopback, not just the reported field.
    assert inst.host == "127.0.0.1"
    assert inst.started is True


def test_an_explicit_address_is_left_as_the_callers_choice(_no_real_listener: None) -> None:
    """Binding a routable interface is how a physical device reaches the proxy,
    so an explicit host is a deliberate choice the fallback must not rewrite.
    """
    backend = ProxyBackend()
    backend._available = True

    data = backend.start("s", host="0.0.0.0", port=9090)

    assert data["host"] == "0.0.0.0"
    assert backend._instances["s"].host == "0.0.0.0"


def test_a_surrounding_whitespace_host_is_trimmed_before_binding(_no_real_listener: None) -> None:
    backend = ProxyBackend()
    backend._available = True

    data = backend.start("s", host="  127.0.0.1  ", port=8081)

    assert data["host"] == "127.0.0.1"
    assert backend._instances["s"].host == "127.0.0.1"
