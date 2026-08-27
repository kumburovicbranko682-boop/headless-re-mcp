"""Proxy teardown must disclose a listener it could not actually stop."""

from __future__ import annotations

from types import MethodType

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.core.service import AnalysisService


def test_proxy_stop_keeps_the_handle_when_the_thread_is_wedged() -> None:
    """A stop that times out must retain the instance for a retry."""

    class _WedgedInstance:
        host = "127.0.0.1"
        port = 8080

        def __init__(self) -> None:
            self.calls = 0

        def stop(self) -> None:
            self.calls += 1
            raise ProxyError("timeout", "proxy thread did not stop within 10 seconds")

    backend = ProxyBackend()
    inst = _WedgedInstance()
    backend._instances["session"] = inst  # type: ignore[assignment]

    with pytest.raises(ProxyError) as caught:
        backend.stop("session")

    assert caught.value.code == "timeout"
    assert backend._instances == {"session": inst}
    assert inst.calls == 1


def test_proxy_bulk_close_reports_one_wedged_listener_and_continues() -> None:
    """Bulk shutdown must attempt every proxy and surface the first failure."""
    backend = ProxyBackend()
    backend._instances = {"wedged": object(), "healthy": object()}  # type: ignore[dict-item]
    attempted: list[str] = []

    def stop(self: ProxyBackend, session_id: str) -> dict[str, bool]:
        attempted.append(session_id)
        if session_id == "wedged":
            raise ProxyError("timeout", "proxy thread did not stop within 10 seconds")
        self._instances.pop(session_id, None)
        return {"stopped": True}

    backend.stop = MethodType(stop, backend)  # type: ignore[method-assign]

    with pytest.raises(ProxyError) as caught:
        backend.close_all()

    assert caught.value.code == "timeout"
    assert attempted == ["wedged", "healthy"]


def test_session_close_reports_a_proxy_stop_that_timed_out() -> None:
    """close_session must not report a clean close while a listener is wedged."""
    service = AnalysisService()

    class _WedgedProxy:
        def stop(self, session_id: str) -> dict[str, bool]:
            del session_id
            raise ProxyError(
                "timeout",
                "proxy thread did not stop within 10 seconds",
                port=8080,
            )

        def close_all(self) -> None:
            return None

    service._proxy_backend = _WedgedProxy()  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    result = service.close_session(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True
    assert result.error.details["backend"] == "proxy"
    assert result.error.details["state"] == "closed"
    assert service.registry.get(session_id).state.value == "closed"


def test_service_close_all_threads_a_proxy_cleanup_failure_into_the_result() -> None:
    """A wedged proxy at shutdown must reach the aggregate close_all result."""
    service = AnalysisService()

    class _WedgedProxy:
        def close_all(self) -> None:
            raise ProxyError(
                "timeout",
                "proxy thread did not stop within 10 seconds",
                port=8080,
            )

    service._proxy_backend = _WedgedProxy()  # type: ignore[assignment]

    result = service.close_all()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "close_all_failed"
    proxy_errors = [
        entry
        for entry in result.error.details["errors"]
        if entry.get("backend") == "proxy"
    ]
    assert len(proxy_errors) == 1
    assert proxy_errors[0]["error"]["code"] == "timeout"
    assert proxy_errors[0]["error"]["retryable"] is True
