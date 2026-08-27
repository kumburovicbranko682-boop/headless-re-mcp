"""Service-level fail-closed guards on the proxy line.

proxy.start binds a real port and proxy.ca.install_android pushes the
mitmproxy CA onto a device; both must refuse a session that is already (or
becomes) terminal, or a closed session leaves a listener bound to a port
nothing can stop, or a CA lands on a device for a session that no longer
exists.

The pre-start refusal on an already-closed session is covered in
test_web_backends. Two adjacent guards were not:

- the *mid-start* reclaim: the session going terminal between the pre-check
  and the moment start() returns. proxy_start re-checks and rolls the proxy
  back (stop) so no bound port is orphaned -- the proxy twin of
  test_web_open_reclaims_if_the_session_closes_during_launch.
- ca.install_android refusing a closed session *before* it reaches adb, so
  nothing is pushed to the device.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _StubProxy:
    """A proxy backend that records start/stop and can close mid-start."""

    def __init__(self, service: AnalysisService | None = None) -> None:
        self.live: set[str] = set()
        self.starts: list[str] = []
        self.stops: list[str] = []
        self._service = service
        self.close_during_start = False

    def start(
        self,
        session_id: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        ssl_insecure: bool = False,
    ) -> JsonObject:
        self.starts.append(session_id)
        self.live.add(session_id)
        if self.close_during_start and self._service is not None:
            # Simulate a concurrent close landing while the listener comes up.
            self._service.close_session(session_id)
        return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

    def stop(self, session_id: str) -> JsonObject:
        self.stops.append(session_id)
        self.live.discard(session_id)
        return {"stopped": True}

    def ca_cert_path(self) -> Path:
        return Path("/tmp/fake-mitmproxy-ca.pem")

    def close_all(self) -> None:
        self.live.clear()


class _StubAdb:
    def __init__(self) -> None:
        self.pushes: list[tuple[str, str, str]] = []

    def push(self, serial: str, local: str, remote: str) -> JsonObject:
        self.pushes.append((serial, local, remote))
        return {"pushed": True}


def test_proxy_start_reclaims_if_the_session_closes_during_start() -> None:
    service = AnalysisService()
    proxy = _StubProxy(service)
    proxy.close_during_start = True
    service._proxy_backend = proxy  # type: ignore[assignment]
    try:
        created = service.create_session("https://example.com/app", target="web")
        assert created.data is not None
        session_id = created.data["session"]["id"]

        result = service.proxy_start(session_id, port=18081)

        assert result.ok is False
        assert result.error is not None
        # The listener came up, the close was noticed, and the proxy was rolled
        # back so no bound port is left orphaned for a dead session.
        assert proxy.starts == [session_id]
        assert session_id in proxy.stops
        assert proxy.live == set()
    finally:
        service.close_all()


def test_proxy_ca_install_on_a_closed_session_does_not_push() -> None:
    service = AnalysisService()
    proxy = _StubProxy(service)
    adb = _StubAdb()
    service._proxy_backend = proxy  # type: ignore[assignment]
    service._adb_backend = adb  # type: ignore[assignment]
    try:
        created = service.create_session("https://example.com/app", target="web")
        assert created.data is not None
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.proxy_ca_install_android(session_id, "emulator-5554")

        assert result.ok is False
        assert result.error is not None
        assert "closed" in result.error.message
        # The guard fires before adb is touched: nothing reaches the device.
        assert adb.pushes == []
    finally:
        service.close_all()
