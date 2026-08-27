"""web.status / web.close: the session-slot states between closed and open.

A web session slot holds one of three things: nothing (closed), a bare
``object()`` token while a browser is launching, or a live ``_WebSession``. Both
status and close dispatch on which -- and the only existing coverage is the
"nothing" case for each. That leaves the in-between and the live states inert:

* ``status`` must report ``opening: True`` for the launch token (``type(handle)
  is object``), and open with url/title only for a real ``_WebSession``;
* ``close`` must drop the launch token as "open was aborted" without touching a
  browser, tear a runner-less handle down directly, run a healthy handle's
  teardown on its browser thread and report it clean, and -- when the runner is
  wedged -- skip the call that would hang, reap the node driver, and flag the
  close unclean rather than pretend it was orderly.

close is the recovery path, so a wedged session that it cannot reclaim is a
leaked Chromium tree for the life of the process.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import WebBackend, _WebSession


class _Runner:
    def __init__(self, *, wedged: bool) -> None:
        self.wedged = wedged
        self.calls = 0
        self.shutdown_called = False

    def call(self, work: Any, timeout: float | None = None) -> Any:
        self.calls += 1
        return work()

    def shutdown(self) -> None:
        self.shutdown_called = True


def _live_session(runner: Any) -> _WebSession:
    page = SimpleNamespace(url="https://target/app", title=lambda: "Target")
    session = _WebSession(object(), object(), object(), page, object())
    session.runner = runner
    return session


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------


def test_status_of_an_opening_reservation_reports_opening_not_open() -> None:
    """The launch token is a bare object(); status must call it opening, not
    conflate it with a closed slot (open False alone) or a live one.
    """
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]

    assert backend.status("s") == {"open": False, "opening": True}


def test_status_of_a_live_session_reports_open_with_url_and_title() -> None:
    """Only a real _WebSession is open, and status surfaces its page identity."""
    backend = WebBackend()
    backend._sessions["s"] = _live_session(_Runner(wedged=False))

    payload = backend.status("s")

    assert payload["open"] is True
    assert payload["url"] == "https://target/app"
    assert payload["title"] == "Target"
    assert "opening" not in payload


# --------------------------------------------------------------------------
# close
# --------------------------------------------------------------------------


def test_close_of_an_opening_reservation_is_aborted_without_touching_a_browser() -> None:
    """Closing during launch drops the reservation and says the open was aborted.
    There is no browser yet, so nothing is torn down and no clean flag applies.
    """
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]

    assert backend.close("s") == {"closed": True, "note": "open was aborted"}
    assert "s" not in backend._sessions


def test_close_of_a_runnerless_handle_tears_it_down_directly() -> None:
    """A handle whose browser thread never came up is closed inline (no runner to
    hand the teardown to), and the result carries no clean flag.
    """
    closed = {"n": 0}

    class _Handle:
        runner = None

        def close(self) -> None:
            closed["n"] += 1

    backend = WebBackend()
    backend._sessions["s"] = _Handle()  # type: ignore[assignment]

    result = backend.close("s")

    assert result == {"closed": True}
    assert closed["n"] == 1


def test_close_of_a_healthy_session_runs_teardown_on_the_browser_thread() -> None:
    """A live, responsive session hands handle.close to its runner (the browser
    thread) and reports the close clean.
    """
    runner = _Runner(wedged=False)
    closed = {"n": 0}

    class _Handle:
        def __init__(self) -> None:
            self.runner = runner

        def close(self) -> None:
            closed["n"] += 1

    backend = WebBackend()
    backend._sessions["s"] = _Handle()  # type: ignore[assignment]

    result = backend.close("s")

    assert result == {"closed": True, "clean": True}
    assert runner.calls == 1
    assert closed["n"] == 1
    assert runner.shutdown_called is True


def test_close_of_a_wedged_session_reaps_the_driver_and_flags_unclean(
    monkeypatch: Any,
) -> None:
    """A wedged runner will never run handle.close, so close must not wait on it:
    it skips the call, reaps the node driver directly, and reports clean False --
    the honest signal that the browser was killed, not shut down.
    """
    reaped: list[Any] = []
    monkeypatch.setattr(web_client, "_reap_web_session", lambda handle: reaped.append(handle))

    runner = _Runner(wedged=True)
    closed = {"n": 0}

    class _Handle:
        def __init__(self) -> None:
            self.runner = runner
            self.driver_pid = 4321

        def close(self) -> None:  # pragma: no cover - must never run on this path
            closed["n"] += 1

    backend = WebBackend()
    handle = _Handle()
    backend._sessions["s"] = handle  # type: ignore[assignment]

    result = backend.close("s")

    assert result == {"closed": True, "clean": False}
    assert runner.calls == 0
    assert closed["n"] == 0
    assert reaped == [handle]
    assert runner.shutdown_called is True
