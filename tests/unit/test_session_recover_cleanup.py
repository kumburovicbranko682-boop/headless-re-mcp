"""Session recovery must not replace a session whose resources survived close."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


def test_failed_session_recovery_stops_when_old_cleanup_fails(tmp_path: Path) -> None:
    """A retained old listener must prevent creation of a conflicting replacement."""

    class _WedgedProxy:
        def stop(self, session_id: str) -> None:
            raise ProxyError(
                "timeout",
                "old proxy listener remains alive",
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
    service.registry.transition(session_id, SessionState.FAILED)

    recovered = service.session_recover(session_id)

    assert recovered.ok is False
    assert recovered.error is not None
    assert recovered.error.code == "timeout"
    live = [
        session
        for session in service.registry.list()
        if session.state not in {SessionState.CLOSED, SessionState.FAILED}
    ]
    assert live == []
