"""Proxy shutdown must not lose a listener that is still alive."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _ProxyInstance
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _StillAliveThread:
    def __init__(self) -> None:
        self.join_timeout: float | None = None

    def join(self, timeout: float | None = None) -> None:
        self.join_timeout = timeout

    def is_alive(self) -> bool:
        return True


def test_proxy_stop_reports_a_wedged_thread_and_keeps_it_tracked() -> None:
    """A ten-second join used to become success even when the thread survived.

    Measured with one wedged thread: stop returned ``stopped=True`` and the
    tracked instance count fell from one to zero, while one listener thread
    remained alive. The next start then had no handle with which to free the
    occupied port.
    """
    backend = ProxyBackend()
    instance = _ProxyInstance("127.0.0.1", 18080)
    thread = _StillAliveThread()
    instance._thread = thread  # type: ignore[assignment]
    backend._instances["session"] = instance

    with pytest.raises(ProxyError, match="did not stop") as raised:
        backend.stop("session")

    assert raised.value.code == "timeout"
    assert raised.value.details["host"] == "127.0.0.1"
    assert raised.value.details["port"] == 18080
    assert thread.join_timeout == 10.0
    assert backend._instances == {"session": instance}


def test_session_close_reports_a_proxy_that_remains_alive(tmp_path: Path) -> None:
    """Closing the owning session must not turn a proxy timeout into success.

    Measured: one proxy ``timeout`` exception was suppressed, the result had
    ``ok=True``, and the session was reported cleanly closed despite the one
    listener known to remain alive.
    """

    class _WedgedProxy:
        def stop(self, session_id: str) -> None:
            raise ProxyError(
                "timeout",
                "proxy thread did not stop within 10 seconds",
                session_id=session_id,
            )

        def close_all(self) -> None:
            return None

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._proxy_backend = _WedgedProxy()  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    closed = service.close_session(session_id)

    assert closed.ok is False
    assert closed.error is not None
    assert closed.error.code == "timeout"
    assert closed.error.details["backend"] == "proxy"
    assert closed.error.details["state"] == "closed"
    assert closed.error.details["close_error_count"] == 1
    assert service.registry.get(session_id).state.value == "closed"
