"""web.open's reservation protocol must not strand a session slot or a browser.

open() reserves the session id with a per-open token before the slow launch,
then registers the live handle only if the token is still its own. Two cleanup
paths hang off that (client.py's open tail), and neither had any coverage:

* a launch failure must pop the reservation -- otherwise every retry after a
  transient chromium crash reports "web session already open" forever, and the
  only way out is web.close on a session that never opened;
* a close() landing while the launch runs must win: the fresh handle is torn
  down and open reports invalid_state instead of registering a browser for a
  session that was just closed -- the backend half of the leak the service-level
  re-check (test_web_open_race_rollback) guards from above.

playwright itself is not needed: open() imports playwright.sync_api lazily, so
a fake module injected into sys.modules drives the real open() -- real
reservation locking, real _Runner thread, real registration -- with the launch
outcome scripted. The fakes survive the helper chain by construction
(_playwright_driver_pid walks private attrs and finds none, _safe_title
suppresses, goto is skipped by opening about:blank via url="").
"""

from __future__ import annotations

import sys
import types
from collections.abc import Callable
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError

JsonObject = dict[str, Any]


class _FakePage:
    url = "about:blank"

    def title(self) -> str:
        return "fake-title"


class _FakeCdp:
    def __init__(self, on_first_send: Callable[[], None] | None) -> None:
        self._on_first_send = on_first_send
        self.sent: list[str] = []

    def send(self, method: str, params: JsonObject | None = None) -> JsonObject:
        self.sent.append(method)
        if self._on_first_send is not None and len(self.sent) == 1:
            self._on_first_send()
        return {}

    def on(self, event: str, handler: Callable[..., None]) -> None:
        return None


class _FakeContext:
    def __init__(self, on_first_send: Callable[[], None] | None) -> None:
        self._on_first_send = on_first_send
        self.closed = False

    def new_page(self) -> _FakePage:
        return _FakePage()

    def new_cdp_session(self, page: _FakePage) -> _FakeCdp:
        return _FakeCdp(self._on_first_send)

    def close(self) -> None:
        self.closed = True


class _FakeBrowser:
    def __init__(self, on_first_send: Callable[[], None] | None) -> None:
        self._on_first_send = on_first_send
        self.closed = False

    def new_context(self, **kwargs: object) -> _FakeContext:
        return _FakeContext(self._on_first_send)

    def close(self) -> None:
        self.closed = True


class _FakeChromium:
    def __init__(self, fail: bool, on_first_send: Callable[[], None] | None) -> None:
        self._fail = fail
        self._on_first_send = on_first_send
        self.launched: list[_FakeBrowser] = []

    def launch(self, headless: bool = True) -> _FakeBrowser:
        if self._fail:
            raise RuntimeError("chromium exploded on launch")
        browser = _FakeBrowser(self._on_first_send)
        self.launched.append(browser)
        return browser


class _FakePlaywright:
    def __init__(self, chromium: _FakeChromium) -> None:
        self.chromium = chromium
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


class _FakeSyncPlaywright:
    def __init__(self, chromium: _FakeChromium) -> None:
        self._chromium = chromium

    def start(self) -> _FakePlaywright:
        return _FakePlaywright(self._chromium)


def _install_fake_playwright(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_launch: bool = False,
    on_first_cdp_send: Callable[[], None] | None = None,
) -> _FakeChromium:
    chromium = _FakeChromium(fail_launch, on_first_cdp_send)
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: _FakeSyncPlaywright(chromium)  # type: ignore[attr-defined]
    package = types.ModuleType("playwright")
    package.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    return chromium


def _backend() -> WebBackend:
    backend = WebBackend()
    # The availability probe imports the real playwright; the fake in
    # sys.modules would satisfy it anyway, but forcing the flag keeps the test
    # about the reservation protocol, not the probe.
    backend._available = True
    return backend


def test_a_failed_launch_releases_the_reservation_so_a_retry_can_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _backend()
    _install_fake_playwright(monkeypatch, fail_launch=True)

    with pytest.raises(WebError) as first:
        backend.open("s1", "")
    assert first.value.code == "backend_error"
    assert "chromium exploded" in first.value.message
    assert backend._sessions == {}, "a failed launch must not keep the opening token"

    # The property that matters to a caller: the retry reaches the launch again
    # (same backend_error) instead of invalid_state "web session already open".
    with pytest.raises(WebError) as retry:
        backend.open("s1", "")
    assert retry.value.code == "backend_error"
    assert backend._sessions == {}


def test_close_landing_during_the_launch_wins_over_the_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """close() pops the opening token; open() must notice its token is gone and
    refuse to register the fresh handle. The fake triggers the close from
    inside the launch (the first CDP send, on the runner thread), which is the
    deterministic version of an agent's session.close racing a slow open."""
    backend = _backend()
    closed_note: list[JsonObject] = []

    def _close_now() -> None:
        closed_note.append(backend.close("s1"))

    _install_fake_playwright(monkeypatch, on_first_cdp_send=_close_now)

    with pytest.raises(WebError) as caught:
        backend.open("s1", "")

    assert caught.value.code == "invalid_state"
    assert "closed while opening" in caught.value.message
    assert backend._sessions == {}, "the raced open must not register its handle"
    # close() saw the reservation, not a live session, and said so.
    assert closed_note == [{"closed": True, "note": "open was aborted"}]


def test_a_successful_open_registers_and_close_tears_down_on_the_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for both cleanup tests, and the documented happy shape:
    opened/url/title/headless with no status for a blank open, status() sees
    the live page, and close() runs the teardown (context and browser closed,
    playwright stopped) reporting clean=True."""
    backend = _backend()
    chromium = _install_fake_playwright(monkeypatch)

    summary = backend.open("s1", "")

    assert summary["opened"] is True
    assert summary["url"] == "about:blank"
    assert summary["title"] == "fake-title"
    assert summary["headless"] is True
    assert "status" not in summary

    status = backend.status("s1")
    assert status == {"open": True, "url": "about:blank", "title": "fake-title"}

    with pytest.raises(WebError) as second:
        backend.open("s1", "")
    assert second.value.code == "invalid_state"
    assert "already open" in second.value.message

    closed = backend.close("s1")
    assert closed == {"closed": True, "clean": True}
    assert backend._sessions == {}
    assert chromium.launched[0].closed is True, "close must reach the browser teardown"

    again = backend.close("s1")
    assert again["closed"] is False
