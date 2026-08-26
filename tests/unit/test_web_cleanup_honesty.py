"""Session teardown must disclose a Playwright runner that remains wedged."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import MethodType

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
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


def test_web_bulk_close_reports_one_wedged_runner_and_continues() -> None:
    """Bulk shutdown must not erase an incomplete close or skip later sessions."""
    backend = WebBackend()
    backend._sessions = {"wedged": object(), "healthy": object()}  # type: ignore[dict-item]
    attempted: list[str] = []

    def close(self: WebBackend, session_id: str) -> dict[str, bool]:
        del self
        attempted.append(session_id)
        return {"closed": True, "clean": session_id != "wedged"}

    backend.close = MethodType(close, backend)  # type: ignore[method-assign]

    with pytest.raises(WebError) as caught:
        backend.close_all()

    assert caught.value.code == "web_cleanup_incomplete"
    assert caught.value.details["session_id"] == "wedged"
    assert attempted == ["wedged", "healthy"]


def test_web_bulk_close_continues_after_an_unexpected_error() -> None:
    """One broken browser cleanup must not skip every later browser."""
    backend = WebBackend()
    backend._sessions = {"broken": object(), "healthy": object()}  # type: ignore[dict-item]
    attempted: list[str] = []

    def close(self: WebBackend, session_id: str) -> dict[str, bool]:
        del self
        attempted.append(session_id)
        if session_id == "broken":
            raise RuntimeError("unexpected browser teardown failure")
        return {"closed": True, "clean": True}

    backend.close = MethodType(close, backend)  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="unexpected browser teardown failure"):
        backend.close_all()

    assert attempted == ["broken", "healthy"]
