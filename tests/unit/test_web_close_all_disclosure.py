"""Bulk browser shutdown must disclose an incomplete or failed close."""

from __future__ import annotations

from types import MethodType

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.core.service import AnalysisService


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


def test_service_close_all_threads_a_web_cleanup_failure_into_the_result() -> None:
    """A wedged browser at shutdown must reach the aggregate close_all result.

    close_all used to call web_backend.close_all() unguarded, so the throw it
    now raises would skip the proxy and adb cleanup after it and discard every
    per-session count already collected.
    """
    service = AnalysisService()

    class _WedgedWeb:
        def close_all(self) -> None:
            raise WebError(
                "web_cleanup_incomplete",
                "browser driver stopped but its runner thread remains wedged",
                session_id="s1",
            )

    service._web_backend = _WedgedWeb()  # type: ignore[assignment]

    result = service.close_all()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "close_all_failed"
    web_errors = [
        entry
        for entry in result.error.details["errors"]
        if entry.get("backend") == "web"
    ]
    assert len(web_errors) == 1
    assert web_errors[0]["error"]["code"] == "web_cleanup_incomplete"
    assert web_errors[0]["error"]["retryable"] is False
