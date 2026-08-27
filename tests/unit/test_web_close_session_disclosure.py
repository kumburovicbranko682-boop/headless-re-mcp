"""Session close must disclose a browser that only closed partially."""

from __future__ import annotations

from headless_re_mcp.core.service import AnalysisService


def test_session_close_reports_incomplete_browser_thread_cleanup() -> None:
    """The driver can be reaped while its Python call stays blocked forever.

    web.close returns closed=True, clean=False for a wedged runner, but
    close_session used to discard the flag under a blanket suppress and report
    the session closed with ok=True.
    """
    service = AnalysisService()

    class _WedgedWeb:
        def close(self, session_id: str) -> dict[str, bool]:
            del session_id
            return {"closed": True, "clean": False}

        def close_all(self) -> None:
            return None

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


def test_session_close_reports_a_hard_browser_cleanup_failure() -> None:
    """An exception from web teardown must not read as a clean close."""
    service = AnalysisService()

    class _BrokenWeb:
        def close(self, session_id: str) -> dict[str, bool]:
            del session_id
            raise RuntimeError("playwright stop crashed")

        def close_all(self) -> None:
            return None

    service._web_backend = _BrokenWeb()  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    result = service.close_session(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "web_cleanup_failed"
    assert result.error.retryable is True
    assert result.error.details["backend"] == "web"
    assert service.registry.get(session_id).state.value == "closed"


def test_session_close_stays_clean_when_the_browser_closes_fully() -> None:
    """A clean=True close must still report ok and leave no error behind."""
    service = AnalysisService()

    class _CleanWeb:
        def close(self, session_id: str) -> dict[str, bool]:
            del session_id
            return {"closed": True, "clean": True}

        def close_all(self) -> None:
            return None

    service._web_backend = _CleanWeb()  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    result = service.close_session(session_id)

    assert result.ok is True
    assert service.registry.get(session_id).state.value == "closed"
