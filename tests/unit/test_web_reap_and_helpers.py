"""Web teardown safety and the read helpers that tolerate a half-dead page.

A wedged browser cannot be closed through Playwright from any other thread, so
the recovery path kills the node driver by PID instead. Two things make that
safe rather than reckless: the PID is discovered by walking Playwright's private
object chain (which returns nothing rather than crash when the chain is absent),
and the kill only fires when the PID still names a driver process -- a bare
number can have been recycled to something unrelated by the time close runs.
These pin both, plus the small read helpers (title/status) that must answer for
a page mid-navigation without raising, and the navigate/close bodies that route
a failure into a classified error instead of an incident.
"""

from __future__ import annotations

import sys
import threading
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web_client
from headless_re_mcp.backends.web.client import (
    WebBackend,
    WebError,
    _playwright_driver_pid,
    _reap_driver_pid,
    _response_status,
    _Runner,
    _safe_title,
)


class _TitleRaises:
    def title(self) -> str:
        raise RuntimeError("execution context was destroyed (page navigated)")


def test_safe_title_is_empty_when_the_page_title_raises() -> None:
    """A page navigating out from under a status read must not crash the read.

    page.title() raises while a navigation tears down the execution context;
    status/navigate call it only to enrich the reply, so it degrades to an empty
    title rather than turning a routine read into a backend error.
    """
    assert _safe_title(_TitleRaises()) == ""


def test_response_status_is_none_without_a_response() -> None:
    """goto returns None for about:blank / same-document navigations.

    That is an absent status, not a failure, so the helper reports None rather
    than inventing a code or raising.
    """
    assert _response_status(None) is None


def test_response_status_is_none_when_status_cannot_be_read() -> None:
    """A response object whose status attribute raises yields None, not a crash."""
    class _StatusRaises:
        @property
        def status(self) -> int:
            raise RuntimeError("response consumed")

    assert _response_status(_StatusRaises()) is None


def test_response_status_ignores_a_non_integer_status() -> None:
    """A non-int status is treated as absent rather than passed through.

    Downstream reads expect an int or None; a string status would otherwise
    leak into the reply as a type the caller cannot compare numerically.
    """
    assert _response_status(SimpleNamespace(status="200")) is None
    assert _response_status(SimpleNamespace(status=404)) == 404


def test_driver_pid_walks_playwright_private_chain_to_the_proc() -> None:
    """The node driver PID is read from Playwright's private object chain.

    Playwright does not publish the PID, so the wedged-session reaper reads it
    from ``_impl_obj._connection._transport._proc.pid``. When the chain is whole
    and names a real pid, that pid is returned.
    """
    proc = SimpleNamespace(pid=4321)
    transport = SimpleNamespace(_proc=proc)
    connection = SimpleNamespace(_transport=transport)
    playwright = SimpleNamespace(_impl_obj=SimpleNamespace(_connection=connection))
    assert _playwright_driver_pid(playwright) == 4321


def test_driver_pid_is_none_when_the_private_chain_is_broken() -> None:
    """A missing link in the private chain yields None, not an AttributeError.

    Playwright's internals differ across versions; if any expected attribute is
    absent the walk stops and reports no pid, so the reaper simply has nothing to
    kill rather than crashing the recovery path.
    """
    playwright = SimpleNamespace(_impl_obj=SimpleNamespace(_connection=None))
    assert _playwright_driver_pid(playwright) is None


def test_driver_pid_rejects_a_bogus_pid_value() -> None:
    """A non-positive or non-int pid at the end of the chain is refused."""
    for bad in (0, -1, "1234", None):
        proc = SimpleNamespace(pid=bad)
        transport = SimpleNamespace(_proc=proc)
        connection = SimpleNamespace(_transport=transport)
        playwright = SimpleNamespace(_impl_obj=SimpleNamespace(_connection=connection))
        assert _playwright_driver_pid(playwright) is None


def test_reap_ignores_a_missing_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    """A None or non-positive pid is refused up front, even if the image looks right.

    The image marker is made to match so the *only* thing standing between the
    reaper and a kill is the pid guard -- a None (no driver ever recorded) or a 0
    / negative pid must never be signalled, which on POSIX would target the whole
    process group.
    """
    killed: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "node")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(None)
    _reap_driver_pid(0)
    _reap_driver_pid(-1)
    assert killed == []


def test_reap_refuses_to_kill_a_pid_that_is_not_a_driver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recycled PID that now names an unrelated process must never be killed.

    Between a session wedging and close running, the OS can reuse the driver's
    PID for something else entirely. The reaper confirms the PID still names a
    node/chromium/playwright image before signalling it -- without this guard
    the recovery path could terminate an innocent process that happened to
    inherit the number.
    """
    killed: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/usr/bin/postgres")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(4321)
    assert killed == []


def test_reap_does_not_kill_when_the_image_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the PID's image cannot be read, err toward not killing it."""
    killed: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: None)
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(4321)
    assert killed == []


def test_reap_kills_a_confirmed_driver_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """A PID that still names the node driver is terminated, tree and all."""
    killed: list[int] = []
    monkeypatch.setattr(
        web_client, "process_image_path", lambda pid: "/opt/hostedtoolcache/node/bin/node"
    )
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(4321)
    assert killed == [4321]


def test_close_tears_down_a_session_that_has_no_runner() -> None:
    """A handle without a browser thread is closed directly, reported clean.

    Not every stored handle reached the point of owning a runner; close must
    still tear such a handle down (best-effort) and report it closed rather than
    leaking it.
    """
    closed: list[bool] = []
    handle = SimpleNamespace(runner=None, close=lambda: closed.append(True))
    backend = WebBackend()
    backend._sessions["s"] = handle  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True}
    assert closed == [True]


def test_close_reaps_the_driver_when_the_runner_is_wedged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wedged session is reclaimed by killing the driver, and reported unclean.

    When the runner is wedged, handle.close can never run (its thread is stuck in
    Playwright), so close skips it, kills the node driver by PID, still shuts the
    runner down, and reports clean:False so the caller knows the teardown was
    forced rather than graceful.
    """
    killed: list[int] = []
    shutdown: list[bool] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "node")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    runner = SimpleNamespace(wedged=True, shutdown=lambda: shutdown.append(True))
    handle = SimpleNamespace(runner=runner, driver_pid=4321, close=lambda: None)
    backend = WebBackend()
    backend._sessions["s"] = handle  # type: ignore[assignment]
    result = backend.close("s")
    assert result == {"closed": True, "clean": False}
    assert killed == [4321]
    assert shutdown == [True]


class _GotoRaises:
    url = "https://old/"

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> Any:
        raise RuntimeError("net::ERR_CONNECTION_REFUSED")

    def title(self) -> str:
        return "unused"


def test_navigate_failure_is_a_backend_error_naming_the_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hard transport failure from goto is a backend_error, not a wedge.

    goto raises for DNS/refused/protocol failures (a deadline is classified
    separately as code=timeout); navigate must report the hard failure as
    backend_error carrying the url, and -- because the runner did answer -- must
    leave the session usable rather than flipping it to wedged.
    """
    backend = WebBackend()
    runner = _Runner("test-nav-fail-runner")
    try:
        handle = SimpleNamespace(page=_GotoRaises(), runner=runner)
        monkeypatch.setattr(backend, "_get", lambda session_id: handle)
        with pytest.raises(WebError) as info:
            backend.navigate("s", "https://example/app", timeout=5.0)
        assert info.value.code == "backend_error"
        assert "navigation failed" in info.value.message
        assert info.value.details.get("url") == "https://example/app"
        assert runner.wedged is False
    finally:
        runner.shutdown()


def test_a_hung_call_times_out_and_wedges_the_runner_against_further_work() -> None:
    """A browser call that never returns is bounded, and poisons only its session.

    Playwright's own timeouts live in the driver process, so a driver that hangs
    blocks the worker thread with no ceiling of its own. The runner's outer
    deadline is the ceiling: the call raises timeout, the runner marks itself
    wedged, and every later call is refused up front (backend_error, never
    queued) rather than stacking behind a call that will never complete. The
    blocked worker is a daemon; releasing it lets shutdown finish cleanly.
    """
    runner = _Runner("test-wedged-runner")
    release = threading.Event()
    try:
        with pytest.raises(WebError) as first:
            runner.call(lambda: release.wait(5.0), timeout=0.05)
        assert first.value.code == "timeout"
        assert runner.wedged is True

        # A wedged runner refuses further work without queueing it behind the
        # stuck call -- otherwise the whole session would hang on the dead one.
        with pytest.raises(WebError) as second:
            runner.call(lambda: "unreachable", timeout=0.05)
        assert second.value.code == "backend_error"
        assert "unresponsive" in second.value.message
    finally:
        release.set()
        runner.shutdown()


def test_check_available_reports_capability_unavailable_without_playwright(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No Playwright import means the web tools degrade, not crash.

    Setting the module to None in sys.modules makes ``import playwright.sync_api``
    raise the way an absent install does; _check_available must catch that, cache
    the negative, and raise capability_unavailable so the doctor and caller see
    "install Playwright" rather than an ImportError surfacing as an incident.
    """
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    backend = WebBackend()
    assert backend._available is None
    with pytest.raises(WebError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"
    assert backend._available is False


def test_close_all_closes_every_session_and_swallows_a_close_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shutting the backend down must attempt every session and tolerate a failure.

    close_all runs at service teardown; one session whose close raises a WebError
    (a wedged browser, say) must not strand the others still open. Every id is
    attempted and the WebError is suppressed.
    """
    backend = WebBackend()
    attempted: list[str] = []

    def fake_close(session_id: str) -> Any:
        attempted.append(session_id)
        if session_id == "bad":
            raise WebError("backend_error", "close blew up")
        return {"closed": True}

    monkeypatch.setattr(backend, "close", fake_close)
    backend._sessions["good"] = object()  # type: ignore[assignment]
    backend._sessions["bad"] = object()  # type: ignore[assignment]

    backend.close_all()

    assert set(attempted) == {"good", "bad"}
