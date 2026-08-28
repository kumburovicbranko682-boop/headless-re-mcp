"""Live browser lifecycle gate: close must actually close.

A capture backend that reports "closed" while the browser keeps running is the
same failure as a proxy that never frees its port -- it only shows up after a
few hundred sessions, as memory the operator cannot account for.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.core.service import AnalysisService

_BLANK = "data:text/html,<html><head><title>lifecycle</title></head><body>x</body></html>"


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _this_process() -> Any:
    """psutil if it happens to be installed; it is not a project dependency."""
    try:
        import psutil
    except ImportError:
        return None
    process = psutil.Process()
    # num_handles is Windows-only; num_fds is its POSIX counterpart. Accepting
    # either lets the per-navigation growth check run on the hosted Linux runner
    # too, so the browser handle/fd leak is guarded on both platforms rather
    # than only where Windows OS handles happen to be countable.
    if hasattr(process, "num_handles") or hasattr(process, "num_fds"):
        return process
    return None


def _open_handle_count(process: Any) -> int:
    """OS handles on Windows, open file descriptors on POSIX."""
    if hasattr(process, "num_handles"):
        return int(process.num_handles())
    return int(process.num_fds())


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _port_is_open(port: int, *, timeout: float = 0.4) -> bool:
    deadline = time.monotonic() + 2.0
    while True:
        with socket.socket() as probe:
            probe.settimeout(timeout)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _open_or_skip(backend: WebBackend, session_id: str) -> None:
    try:
        backend.open(session_id, _BLANK, headless=True, timeout=30.0)
    except WebError as exc:
        pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")


@pytest.mark.integration
def test_close_disconnects_the_browser_and_frees_the_slot() -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — browser lifecycle Gate not run (skip != pass)")
    backend = WebBackend()
    _open_or_skip(backend, "life-1")
    handle = backend._sessions["life-1"]
    browser = handle.browser
    assert browser.is_connected() is True

    assert backend.close("life-1")["closed"] is True

    # The browser must really be gone, not merely forgotten by the registry.
    assert browser.is_connected() is False
    assert "life-1" not in backend._sessions
    # A second close is a no-op rather than an error, so teardown is idempotent.
    assert backend.close("life-1")["closed"] is False


@pytest.mark.integration
def test_reopening_the_same_session_id_after_close_works() -> None:
    """Otherwise a long run leaks one browser per restarted session."""
    if not _playwright_available():
        pytest.skip("playwright not installed — browser lifecycle Gate not run (skip != pass)")
    backend = WebBackend()
    _open_or_skip(backend, "life-2")
    first = backend._sessions["life-2"].browser
    backend.close("life-2")

    _open_or_skip(backend, "life-2")
    second = backend._sessions["life-2"].browser
    try:
        assert second is not first
        assert second.is_connected() is True
        # Opening twice without closing must be refused, not silently leaked.
        with pytest.raises(WebError) as info:
            backend.open("life-2", _BLANK, headless=True, timeout=30.0)
        assert info.value.code == "invalid_state"
    finally:
        backend.close_all()
    assert second.is_connected() is False


@pytest.mark.integration
def test_a_browser_survives_being_driven_from_other_threads() -> None:
    """Tool calls arrive on a worker pool, not on the thread that opened it.

    Playwright's sync API is thread-affine, so before every call was funnelled
    onto the session's own thread this raised "Cannot switch to a different
    thread" -- intermittently, depending on which worker the pool handed the
    call to.
    """
    if not _playwright_available():
        pytest.skip("playwright not installed — browser lifecycle Gate not run (skip != pass)")
    backend = WebBackend()
    with ThreadPoolExecutor(max_workers=4) as pool:
        try:
            pool.submit(_open_or_skip, backend, "life-3").result()
            if "life-3" not in backend._sessions:
                pytest.skip("chromium could not launch — Gate not run (skip != pass)")

            # Same thread as the caller, then three pool threads, then back.
            assert backend.dom_snapshot("life-3")["title"] == "lifecycle"
            for _ in range(3):
                snapshot = pool.submit(backend.dom_snapshot, "life-3").result()
                assert snapshot["title"] == "lifecycle"
                assert pool.submit(backend.navigate, "life-3", _BLANK).result()["url"]
            assert pool.submit(backend.close, "life-3").result()["closed"] is True
        finally:
            backend.close_all()


_LOUD = (
    "data:text/html,<html><head><title>loud</title></head><body>"
    "<script>for (var i = 0; i < 40; i++) { console.log('line ' + i); }</script>"
    "</body></html>"
)


@pytest.mark.integration
def test_a_talkative_page_does_not_grow_the_process_handle_by_handle() -> None:
    """Console capture used to arrive as remote objects nobody disposed.

    Measured before the fix on a page logging 60 lines: 120 OS handles per
    navigation, still climbing linearly at sixty navigations, released only when
    the browser closed -- so an overnight capture accumulated them for as long
    as it ran. Nothing else in this wiring behaves that way, because everything
    else takes plain CDP data.
    """
    if not _playwright_available():
        pytest.skip("playwright not installed — browser lifecycle Gate not run (skip != pass)")
    process = _this_process()
    if process is None:
        pytest.skip("psutil not installed — handle/fd growth check not run (skip != pass)")

    backend = WebBackend()
    try:
        try:
            backend.open("loud", _LOUD, headless=True, timeout=30.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")

        for _ in range(5):
            backend.navigate("loud", _LOUD)
        settled = _open_handle_count(process)
        for _ in range(20):
            backend.navigate("loud", _LOUD)
        after = _open_handle_count(process)

        captured = backend.console("loud", limit=500)
        assert captured["count"] > 0, "the console must still be captured"
        assert any("line " in str(item.get("text")) for item in captured["console"])
        # A few handles of ordinary churn are fine; per-navigation growth is not.
        growth = after - settled
        assert growth < 100, f"open handles/fds grew by {growth} over 20 navigations"
    finally:
        backend.close_all()


@pytest.mark.integration
def test_closing_a_session_reclaims_the_browser_and_the_proxy_together() -> None:
    """Both backends hang off one session, and only close_session reclaims them.

    Soaked at ten cycles with the mitmproxy import already paid: +4 MB of RSS,
    no handles, no threads and no orphaned browser processes. This is the single
    cycle that keeps it that way.
    """
    if not _playwright_available():
        pytest.skip("playwright not installed — browser lifecycle Gate not run (skip != pass)")
    service = AnalysisService()
    port = _free_port()
    try:
        created = service.create_session(_BLANK, target="web")
        session_id = created.data["session"]["id"]
        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip("chromium could not launch — Gate not run (skip != pass)")
        started = service.proxy_start(session_id, port=port)
        if not started.ok:
            pytest.skip("mitmproxy could not start — Gate not run (skip != pass)")
        browser = service._web._sessions[session_id].browser
        assert browser.is_connected() is True
        assert _port_is_open(port) is True

        service.close_session(session_id)

        assert browser.is_connected() is False
        assert session_id not in service._web._sessions
        assert service.proxy_status(session_id).data == {"running": False}
        assert _port_is_open(port) is False, "the capture port must come back"
    finally:
        service.close_all()


@pytest.mark.integration
def test_closing_the_analysis_session_tears_down_its_browser() -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — browser lifecycle Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_BLANK, target="web")
        session_id = created.data["session"]["id"]
        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip("chromium could not launch — Gate not run (skip != pass)")
        browser = service._web._sessions[session_id].browser
        assert browser.is_connected() is True

        # Closing the analysis session must reclaim the browser too; nothing
        # else will, because the session id is gone afterwards.
        service.close_session(session_id)
        assert browser.is_connected() is False
        assert session_id not in service._web._sessions
    finally:
        service.close_all()
