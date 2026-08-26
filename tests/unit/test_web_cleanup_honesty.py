"""Session teardown must disclose a Playwright runner that remains wedged."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def test_session_close_reports_incomplete_browser_thread_cleanup(
    tmp_path: Path,
) -> None:
    """The driver can be reaped while its Python call remains blocked forever.

    Measured: ``web.close`` returned ``closed=True, clean=False`` for one wedged
    runner, but ``session.close`` discarded the flag and returned ``ok=True``.
    """

    class _WedgedWeb:
        def close(self, session_id: str) -> dict[str, bool]:
            del session_id
            return {"closed": True, "clean": False}

        def close_all(self) -> None:
            return None

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._web_backend = _WedgedWeb()  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    result = service.close_session(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "web_cleanup_incomplete"
    assert result.error.retryable is False
    assert result.error.details["backend"] == "web"
    assert result.error.details["state"] == "closed"
    assert result.error.details["close_error_count"] == 1
    assert service.registry.get(session_id).state.value == "closed"
