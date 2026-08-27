"""Live gate: web.open's proxy option fails cleanly when the proxy is dead.

The happy path (browser through mitmproxy) has its own gate; this pins the error
contract of the new option. Pointing the browser at a proxy that nothing is
listening on must surface a structured backend_error quickly -- not hang until
the timeout and not leak a half-open session -- and the session id must be free
to reuse afterwards. An analyst who mistypes a proxy should get a clean failure,
not a wedged browser. skip != pass when playwright/chromium is missing.
"""

from __future__ import annotations

import socket
import time
from contextlib import suppress

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _chromium_launchable() -> bool:
    """The module import is not enough for this gate: it drives a real browser.

    ``_check_available`` only proves the playwright package imports, so a
    checkout that has the package but not the chromium binary would pass that
    check and then this test would misread the "executable doesn't exist"
    failure as its own dead-proxy assertion. Probe a trivial data: URL launch
    (no network, no proxy) and skip honestly when the browser cannot come up --
    the "skip != pass when chromium is missing" contract this file promises.
    """
    backend = WebBackend()
    try:
        backend.open(
            "chromium-probe",
            "data:text/html,<title>probe</title>",
            headless=True,
            timeout=30.0,
        )
        return True
    except WebError:
        return False
    finally:
        with suppress(BaseException):
            backend.close_all()


@pytest.mark.integration
def test_web_open_with_dead_proxy_fails_cleanly_and_frees_the_session() -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — proxy error Gate not run (skip != pass)")
    if not _chromium_launchable():
        pytest.skip("chromium binary not installed — proxy error Gate not run (skip != pass)")

    backend = WebBackend()
    dead_proxy_port = _free_port()  # bound then released: nothing is listening
    open_timeout = 30.0
    try:
        # A safe target port (8080) so the only thing that can fail is reaching
        # the dead proxy, not the URL itself.
        started = time.monotonic()
        error: WebError | None = None
        try:
            backend.open(
                "s",
                "http://localhost:8080/",
                headless=True,
                timeout=open_timeout,
                proxy=f"http://127.0.0.1:{dead_proxy_port}",
            )
        except WebError as exc:
            error = exc
        elapsed = time.monotonic() - started

        # Structured failure, not a leaked raw exception, and named as such.
        assert error is not None, "expected web.open to fail against a dead proxy"
        assert error.code == "backend_error", error.code
        assert "proxy" in str(error).lower(), str(error)
        # Fails fast: it did not burn the whole navigation budget waiting.
        assert elapsed < open_timeout - 5.0, elapsed

        # The failed open released the session slot: the same id reopens directly
        # (proxy back to None), proving no half-open session was left behind.
        reopened = backend.open(
            "s", "data:text/html,<title>free</title>", headless=True, timeout=30.0
        )
        assert reopened["opened"] is True
        assert reopened["title"] == "free"
        assert reopened.get("proxy") is None
    finally:
        backend.close_all()
