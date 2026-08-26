"""Proxy shutdown must not lose a listener that is still alive."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.backends.proxy.client as proxy_module
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


class _ExitedThread:
    def is_alive(self) -> bool:
        return False


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


def test_proxy_status_reports_a_tracked_worker_that_exited() -> None:
    """A retained dictionary entry is not proof that capture is still running."""
    backend = ProxyBackend()
    instance = _ProxyInstance("127.0.0.1", 18080)
    instance._thread = _ExitedThread()  # type: ignore[assignment]
    instance._error = RuntimeError("event loop crashed")
    backend._instances["session"] = instance

    status = backend.status("session")

    assert status["running"] is False
    assert status["host"] == "127.0.0.1"
    assert status["port"] == 18080
    assert status["error"] == "RuntimeError: event loop crashed"
    assert backend._instances == {"session": instance}


def test_failed_proxy_start_keeps_a_listener_that_cannot_stop_tracked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startup rollback must retain the only handle to a surviving listener."""

    class _FailedStart:
        host = "127.0.0.1"
        port = 18080

        def __init__(self) -> None:
            self.stops = 0

        def start(self) -> None:
            raise ProxyError("backend_error", "proxy failed during startup")

        def stop(self) -> None:
            self.stops += 1
            raise ProxyError("timeout", "startup listener thread remains alive")

    instance = _FailedStart()
    monkeypatch.setattr(proxy_module, "_ProxyInstance", lambda host, port: instance)
    backend = ProxyBackend()
    backend._available = True

    with pytest.raises(ProxyError) as caught:
        backend.start("session", port=18080)

    assert caught.value.code == "timeout"
    assert instance.stops == 1
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


def test_session_close_reports_an_unexpected_proxy_cleanup_failure(tmp_path: Path) -> None:
    """An untyped teardown exception must not become a clean session close."""

    class _ExplodingProxy:
        def stop(self, session_id: str) -> None:
            del session_id
            raise RuntimeError("proxy event loop corrupted")

        def close_all(self) -> None:
            return None

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._proxy_backend = _ExplodingProxy()  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    closed = service.close_session(session_id)

    assert closed.ok is False
    assert closed.error is not None
    assert closed.error.code == "proxy_cleanup_failed"
    assert closed.error.details["backend"] == "proxy"
    assert closed.error.details["state"] == "closed"


def test_close_all_returns_a_failure_when_proxy_bulk_shutdown_times_out(
    tmp_path: Path,
) -> None:
    """Process shutdown must return its envelope even when proxy cleanup fails.

    Measured: one ``ProxyError(timeout)`` escaped ``close_all`` as an exception,
    so the caller received no count and no machine-readable shutdown result.
    """

    class _WedgedProxy:
        def close_all(self) -> None:
            raise ProxyError("timeout", "one proxy listener is still alive", active=1)

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._proxy_backend = _WedgedProxy()  # type: ignore[assignment]

    result = service.close_all()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "close_all_failed"
    assert result.error.details["closed"] == 0
    assert result.error.details["errors"] == [
        {
            "backend": "proxy",
            "error": {
                "code": "timeout",
                "message": "one proxy listener is still alive",
                "details": {"backend": "proxy", "active": 1},
                "retryable": True,
            },
        }
    ]


def test_proxy_close_all_continues_after_an_unexpected_stop_error() -> None:
    """One broken instance must not prevent later listeners from stopping.

    Measured with two tracked instances: the first raised ``RuntimeError`` and
    the second received zero stop attempts, leaving both entries tracked.
    """

    class _Broken:
        def stop(self) -> None:
            raise RuntimeError("unexpected teardown failure")

    class _Healthy:
        def __init__(self) -> None:
            self.stops = 0

        def stop(self) -> None:
            self.stops += 1

    broken = _Broken()
    healthy = _Healthy()
    backend = ProxyBackend()
    backend._instances = {  # type: ignore[assignment]
        "broken": broken,
        "healthy": healthy,
    }

    with pytest.raises(RuntimeError, match="unexpected teardown failure"):
        backend.close_all()

    assert healthy.stops == 1
    assert backend._instances == {"broken": broken}


def test_retrying_closed_session_retries_retained_proxy_cleanup(
    tmp_path: Path,
) -> None:
    """A retryable close error must have a cleanup action on retry.

    Measured: the first proxy timeout closed the session and returned failure;
    the second ``session.close`` returned ``ok=True, already_closed=True``
    without making a second stop attempt, so the retained listener stayed live.
    """

    class _EventuallyStops:
        def __init__(self) -> None:
            self.calls = 0

        def stop(self, session_id: str) -> dict[str, bool]:
            del session_id
            self.calls += 1
            if self.calls == 1:
                raise ProxyError("timeout", "proxy listener is still alive")
            return {"stopped": True}

        def close_all(self) -> None:
            return None

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    proxy = _EventuallyStops()
    service._proxy_backend = proxy  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    first = service.close_session(session_id)
    second = service.close_session(session_id)

    assert first.ok is False
    assert first.error is not None and first.error.retryable is True
    assert second.ok is True
    assert second.data is not None and second.data["already_closed"] is True
    assert proxy.calls == 2
