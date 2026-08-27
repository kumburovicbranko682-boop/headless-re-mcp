"""proxy.start must disclose an open (non-loopback) TLS-intercepting bind.

The default is loopback and a deliberate remote bind is allowed (a physical
device that reaches this host by IP), but binding a TLS MITM to every
interface is never a plain success -- the result carries a warning so an
unattended caller is not left running an open proxy it never notices.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.proxy.client import (
    ProxyBackend,
    _is_loopback_host,
    _ProxyInstance,
)


def _no_bind_backend(monkeypatch: Any) -> ProxyBackend:
    # Neither actually bind a port nor require mitmproxy be importable: the
    # subject here is which host the success envelope flags, not the listener.
    monkeypatch.setattr(_ProxyInstance, "start", lambda self, timeout=15.0: None)
    monkeypatch.setattr(ProxyBackend, "_check_available", lambda self: None)
    return ProxyBackend()


def test_non_loopback_bind_carries_a_warning(monkeypatch: Any) -> None:
    backend = _no_bind_backend(monkeypatch)
    result = backend.start("s", host="0.0.0.0", port=18080)
    assert result["running"] is True
    assert result["host"] == "0.0.0.0"
    assert "warning" in result
    assert "loopback" in result["warning"]


def test_loopback_bind_has_no_warning(monkeypatch: Any) -> None:
    backend = _no_bind_backend(monkeypatch)
    result = backend.start("s", host="127.0.0.1", port=18081)
    assert result["running"] is True
    assert "warning" not in result


def test_is_loopback_host_classification() -> None:
    assert _is_loopback_host("127.0.0.1")
    assert _is_loopback_host("127.5.6.7")
    assert _is_loopback_host("::1")
    assert _is_loopback_host("localhost")
    assert _is_loopback_host("LOCALHOST")
    assert not _is_loopback_host("0.0.0.0")
    assert not _is_loopback_host("")
    assert not _is_loopback_host("   ")
    assert not _is_loopback_host("192.168.1.5")
    assert not _is_loopback_host("example.com")
