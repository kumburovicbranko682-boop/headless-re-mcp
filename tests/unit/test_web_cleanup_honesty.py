"""Browser teardown must disclose a cleanup failure instead of faking success."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.backends.web.client import _WebSession


def test_web_close_keeps_handle_when_cleanup_throws() -> None:
    """A failed close must retain the only handle available for a retry."""

    class _BrokenHandle:
        runner = None

        def close(self) -> None:
            raise RuntimeError("playwright cleanup failed")

    backend = WebBackend()
    handle = _BrokenHandle()
    backend._sessions["session"] = handle  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="playwright cleanup failed"):
        backend.close("session")

    assert backend._sessions == {"session": handle}


def test_web_close_reports_all_failed_playwright_closers() -> None:
    """Context, browser, and driver failures must not become clean=true."""

    class _Closer:
        def __init__(self, name: str) -> None:
            self.name = name
            self.calls = 0

        def close(self) -> None:
            self.calls += 1
            raise RuntimeError(f"{self.name} close failed")

        def stop(self) -> None:
            self.close()

    class _Runner:
        wedged = False

        def __init__(self) -> None:
            self.shutdown_called = False

        def call(self, work: Callable[[], object], *, timeout: float) -> None:
            del timeout
            work()

        def shutdown(self) -> None:
            self.shutdown_called = True

    context = _Closer("context")
    browser = _Closer("browser")
    playwright = _Closer("playwright")
    handle = _WebSession(playwright, browser, context, object(), object())
    runner = _Runner()
    handle.runner = runner  # type: ignore[assignment]
    backend = WebBackend()
    backend._sessions["session"] = handle

    with pytest.raises(WebError) as caught:
        backend.close("session")

    assert caught.value.code == "web_cleanup_failed"
    assert caught.value.details["failed_count"] == 3
    assert [context.calls, browser.calls, playwright.calls] == [1, 1, 1]
    assert runner.shutdown_called is False
    assert backend._sessions == {"session": handle}


def test_web_close_can_retry_a_transient_playwright_cleanup_failure() -> None:
    """Retained state must keep a live runner so the next close can succeed."""

    class _TransientContext:
        def __init__(self) -> None:
            self.calls = 0

        def close(self) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("context was temporarily busy")

    class _Closer:
        def close(self) -> None:
            return None

        def stop(self) -> None:
            return None

    class _Runner:
        wedged = False

        def __init__(self) -> None:
            self.closed = False

        def call(self, work: Callable[[], object], *, timeout: float) -> None:
            del timeout
            if self.closed:
                raise WebError("invalid_state", "runner is already closed")
            work()

        def shutdown(self) -> None:
            self.closed = True

    context = _TransientContext()
    handle = _WebSession(_Closer(), _Closer(), context, object(), object())
    runner = _Runner()
    handle.runner = runner  # type: ignore[assignment]
    backend = WebBackend()
    backend._sessions["session"] = handle

    with pytest.raises(WebError) as first:
        backend.close("session")

    assert first.value.code == "web_cleanup_failed"
    assert runner.closed is False
    assert backend._sessions == {"session": handle}
    assert backend.close("session") == {"closed": True, "clean": True}
    assert runner.closed is True
    assert backend._sessions == {}
