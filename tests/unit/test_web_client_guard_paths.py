"""web (Playwright/CDP) client guard paths behave without a real browser.

Playwright is optional and absent here, so these drive the backend with faked
sync-API objects and a real ``_Runner`` (its worker thread runs plain
callables). They cover the bounded console-text joiner, the artifact spill
helpers (inline / oversized / bad-filename / post-write cap), the CDP event
handlers wired onto a session (request/response/script/console shaping and ring
eviction), the per-method error contracts (unknown request/script,
navigate/dom/screenshot failures, closed vs opening handles), and the whole
``open`` launch path including its failure and closed-while-opening recovery.
"""

from __future__ import annotations

import sys
import types
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import (
    WebBackend,
    WebError,
    _clip_console_text,
    _playwright_driver_pid,
    _reap_driver_pid,
    _Runner,
    _safe_title,
    _spill_bytes,
    _spill_text,
    _WebSession,
)

# ----------------------------------------------------------------------
# Fake Playwright sync-API objects for the open() launch path.
# ----------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self._status = status

    @property
    def status(self) -> int:
        return self._status


class _FakePage:
    def __init__(self) -> None:
        self.url = "https://example.com/app"
        self.goto_calls: list[tuple[str, float, str]] = []

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> _FakeResponse:
        self.goto_calls.append((url, timeout, wait_until))
        self.url = url
        return _FakeResponse(200)

    def title(self) -> str:
        return "Example"


class _FakeCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.sent: list[str] = []

    def send(self, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        del params
        self.sent.append(name)
        return {}

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


class _FakeContext:
    def __init__(self, page: _FakePage, cdp: _FakeCdp) -> None:
        self._page = page
        self._cdp = cdp
        self.closed = False

    def new_page(self) -> _FakePage:
        return self._page

    def new_cdp_session(self, page: _FakePage) -> _FakeCdp:
        del page
        return self._cdp

    def close(self) -> None:
        self.closed = True


class _FakeBrowser:
    def __init__(self, context: _FakeContext, launch_exc: BaseException | None = None) -> None:
        self._context = context
        self._launch_exc = launch_exc
        self.closed = False

    def new_context(self, ignore_https_errors: bool = False) -> _FakeContext:
        del ignore_https_errors
        return self._context

    def close(self) -> None:
        self.closed = True


class _FakeChromium:
    def __init__(self, browser: _FakeBrowser) -> None:
        self._browser = browser

    def launch(self, headless: bool = True) -> _FakeBrowser:
        del headless
        if self._browser._launch_exc is not None:
            raise self._browser._launch_exc
        return self._browser


class _FakePlaywright:
    def __init__(self, browser: _FakeBrowser, driver_pid: int = 4321) -> None:
        self.chromium = _FakeChromium(browser)
        self.stopped = False
        proc = SimpleNamespace(pid=driver_pid)
        self._impl_obj = SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=proc))
        )

    def stop(self) -> None:
        self.stopped = True


class _FakeSyncContext:
    def __init__(self, pw: _FakePlaywright) -> None:
        self._pw = pw

    def start(self) -> _FakePlaywright:
        return self._pw


def _install_fake_playwright(
    monkeypatch: pytest.MonkeyPatch,
    *,
    launch_exc: BaseException | None = None,
    driver_pid: int = 4321,
) -> SimpleNamespace:
    page = _FakePage()
    cdp = _FakeCdp()
    context = _FakeContext(page, cdp)
    browser = _FakeBrowser(context, launch_exc=launch_exc)
    pw = _FakePlaywright(browser, driver_pid=driver_pid)
    module = types.ModuleType("playwright.sync_api")
    module.sync_playwright = lambda: _FakeSyncContext(pw)  # type: ignore[attr-defined]
    package = types.ModuleType("playwright")
    package.sync_api = module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", module)
    return SimpleNamespace(pw=pw, browser=browser, context=context, page=page, cdp=cdp)


# ----------------------------------------------------------------------
# _clip_console_text
# ----------------------------------------------------------------------


def test_clip_console_text_handles_no_args() -> None:
    assert _clip_console_text({"args": None}) == ("", False)


def test_clip_console_text_skips_non_dict_args_and_joins_values() -> None:
    text, truncated = _clip_console_text({"args": ["ignored", {"value": "ok"}]})

    assert text == "ok"
    assert truncated is False


def test_clip_console_text_falls_back_to_description_then_type() -> None:
    text, truncated = _clip_console_text({"args": [{"description": "d"}, {"type": "object"}]})

    assert text == "d object"
    assert truncated is False


def test_clip_console_text_stops_when_the_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # After the first arg only one byte of budget remains, so the separator
    # before the second arg cannot fit and the join stops with truncated set.
    monkeypatch.setattr(web_client, "_MAX_CONSOLE_TEXT", 3)

    text, truncated = _clip_console_text({"args": [{"value": "ab"}, {"value": "cd"}]})

    assert text == "ab"
    assert truncated is True


def test_clip_console_text_breaks_at_the_top_when_budget_hits_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First arg spends the whole budget exactly; the next iteration sees
    # remaining <= 0 at the top of the loop and stops.
    monkeypatch.setattr(web_client, "_MAX_CONSOLE_TEXT", 4)

    text, truncated = _clip_console_text({"args": [{"value": "abcd"}, {"value": "ef"}]})

    assert text == "abcd"
    assert truncated is True


# ----------------------------------------------------------------------
# _spill_text / _spill_bytes
# ----------------------------------------------------------------------


def test_spill_text_inlines_a_small_payload(tmp_path: Path) -> None:
    inline, spill, truncated = _spill_text(
        "hello", artifact_dir=tmp_path, filename="x.bin", kind="body"
    )

    assert inline == "hello"
    assert spill is None
    assert truncated is False


def test_spill_text_refuses_when_the_written_file_exceeds_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_client, "capped_file_size", lambda path, cap: (cap + 1, True))
    big = "a" * (web_client._MAX_INLINE_BODY + 10)

    with pytest.raises(WebError) as caught:
        _spill_text(big, artifact_dir=tmp_path, filename="x.bin", kind="body")

    assert caught.value.code == "too_large"


def test_spill_bytes_refuses_over_the_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)

    with pytest.raises(WebError) as caught:
        _spill_bytes(b"x" * 20, artifact_dir=tmp_path, filename="x.bin", kind="body")

    assert caught.value.code == "too_large"


def test_spill_bytes_refuses_a_traversing_filename(tmp_path: Path) -> None:
    with pytest.raises(WebError) as caught:
        _spill_bytes(b"data", artifact_dir=tmp_path, filename="../evil", kind="body")

    assert caught.value.code == "invalid_params"


def test_spill_bytes_refuses_when_the_written_file_exceeds_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_client, "capped_file_size", lambda path, cap: (cap + 1, True))

    with pytest.raises(WebError) as caught:
        _spill_bytes(b"data", artifact_dir=tmp_path, filename="x.bin", kind="body")

    assert caught.value.code == "too_large"


# ----------------------------------------------------------------------
# _safe_title / _playwright_driver_pid / _reap_driver_pid
# ----------------------------------------------------------------------


def test_safe_title_swallows_a_title_error() -> None:
    class _Page:
        def title(self) -> str:
            raise RuntimeError("page gone")

    assert _safe_title(_Page()) == ""


def test_driver_pid_walks_the_private_chain() -> None:
    proc = SimpleNamespace(pid=1234)
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=proc))
        )
    )

    assert _playwright_driver_pid(pw) == 1234


def test_driver_pid_is_none_when_the_chain_breaks() -> None:
    pw = SimpleNamespace(_impl_obj=SimpleNamespace())

    assert _playwright_driver_pid(pw) is None


def test_driver_pid_is_none_for_a_non_positive_pid() -> None:
    proc = SimpleNamespace(pid=0)
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=proc))
        )
    )

    assert _playwright_driver_pid(pw) is None


def test_reap_driver_pid_ignores_a_missing_pid() -> None:
    _reap_driver_pid(None)
    _reap_driver_pid(0)


def test_reap_driver_pid_spares_a_process_that_is_not_a_driver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/usr/bin/python3")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: terminated.append(pid))

    _reap_driver_pid(999999)

    assert terminated == []


# ----------------------------------------------------------------------
# _check_available and _Runner internals.
# ----------------------------------------------------------------------


def test_check_available_reports_playwright_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_playwright(monkeypatch)
    backend = WebBackend()

    backend._check_available()

    assert backend._available is True
    # A second call takes the cached branch and must not re-import or raise.
    backend._check_available()


def test_check_available_degrades_without_playwright(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    backend = WebBackend()

    with pytest.raises(WebError) as caught:
        backend._check_available()

    assert caught.value.code == "capability_unavailable"


def test_runner_skips_a_cancelled_future_and_keeps_serving() -> None:
    runner = _Runner("test-cancelled")
    try:
        cancelled: Future[Any] = Future()
        cancelled.cancel()
        runner._queue.put((lambda: None, cancelled))

        assert runner.call(lambda: 7) == 7
    finally:
        runner.shutdown()


# ----------------------------------------------------------------------
# CDP event handlers wired onto a session.
# ----------------------------------------------------------------------


def _wired() -> tuple[_WebSession, dict[str, Any]]:
    cdp = _FakeCdp()
    handle = _WebSession(None, None, None, _FakePage(), cdp)
    WebBackend()._wire_events(handle)
    return handle, cdp.handlers


def test_on_request_records_a_request_without_truncation() -> None:
    handle, handlers = _wired()

    handlers["Network.requestWillBeSent"](
        {"requestId": "1", "request": {"url": "https://x/", "method": "GET"}, "type": "Document"}
    )

    entry = handle.requests["1"]
    assert entry["url"] == "https://x/"
    assert "metadata_truncated" not in entry


def test_on_request_evicts_the_oldest_when_the_ring_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 1)
    handle, handlers = _wired()

    handlers["Network.requestWillBeSent"]({"requestId": "1", "request": {"url": "a"}})
    handlers["Network.requestWillBeSent"]({"requestId": "2", "request": {"url": "b"}})

    assert list(handle.requests) == ["2"]
    assert handle.requests_dropped == 1


def test_on_response_updates_a_matching_request() -> None:
    handle, handlers = _wired()
    handlers["Network.requestWillBeSent"]({"requestId": "1", "request": {"url": "a"}})

    handlers["Network.responseReceived"](
        {"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}}
    )

    assert handle.requests["1"]["status"] == 200
    assert handle.requests["1"]["mimeType"] == "text/html"
    assert "metadata_truncated" not in handle.requests["1"]


def test_on_response_ignores_an_unknown_request() -> None:
    handle, handlers = _wired()

    handlers["Network.responseReceived"](
        {"requestId": "missing", "response": {"status": 500, "mimeType": "text/html"}}
    )

    assert handle.requests == {}


def test_on_script_records_a_script_without_truncation() -> None:
    handle, handlers = _wired()

    handlers["Debugger.scriptParsed"](
        {"scriptId": "s1", "url": "https://x/app.js", "scriptLanguage": "JavaScript"}
    )

    assert handle.scripts["s1"]["url"] == "https://x/app.js"
    assert "metadata_truncated" not in handle.scripts["s1"]


def test_on_script_evicts_the_oldest_when_the_ring_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_client, "_MAX_SCRIPTS", 1)
    handle, handlers = _wired()

    handlers["Debugger.scriptParsed"]({"scriptId": "s1", "url": "a"})
    handlers["Debugger.scriptParsed"]({"scriptId": "s2", "url": "b"})

    assert list(handle.scripts) == ["s2"]
    assert handle.scripts_dropped == 1


def test_on_console_records_text_without_truncation() -> None:
    handle, handlers = _wired()

    handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "hi"}]})

    assert list(handle.console) == [{"type": "log", "text": "hi"}]


def test_on_console_counts_a_dropped_entry_when_the_ring_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_client, "_MAX_CONSOLE", 1)
    cdp = _FakeCdp()
    handle = _WebSession(None, None, None, _FakePage(), cdp)
    WebBackend()._wire_events(handle)
    handlers = cdp.handlers

    handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "one"}]})
    handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "two"}]})

    assert handle.console_dropped == 1
    assert [entry["text"] for entry in handle.console] == ["two"]


# ----------------------------------------------------------------------
# status / _runner / navigate / close and the reader methods.
# ----------------------------------------------------------------------


def test_status_reports_an_opening_reservation() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]

    assert backend.status("s") == {"open": False, "opening": True}


def test_status_reports_a_foreign_handle_as_closed() -> None:
    backend = WebBackend()
    backend._sessions["s"] = SimpleNamespace()  # type: ignore[assignment]

    assert backend.status("s") == {"open": False}


def test_status_of_a_live_session_returns_identity() -> None:
    backend = WebBackend()
    handle = _WebSession(None, None, None, _FakePage(), _FakeCdp())
    handle.runner = _Runner("test-status")
    try:
        backend._sessions["s"] = handle

        result = backend.status("s")

        assert result["open"] is True
        assert result["url"] == "https://example.com/app"
        assert result["title"] == "Example"
    finally:
        handle.runner.shutdown()


def test_runner_requires_a_browser_thread() -> None:
    backend = WebBackend()
    handle = SimpleNamespace(runner=None)

    with pytest.raises(WebError) as caught:
        backend._runner(handle)  # type: ignore[arg-type]

    assert caught.value.code == "invalid_state"


def test_navigate_maps_a_goto_failure_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = WebBackend()
    runner = _Runner("test-nav-fail")
    try:

        class _Page:
            url = "https://old/"

            def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> None:
                raise RuntimeError("net::ERR_CONNECTION_REFUSED")

            def title(self) -> str:
                return ""

        handle = SimpleNamespace(page=_Page(), runner=runner)
        monkeypatch.setattr(backend, "_get", lambda session_id: handle)

        with pytest.raises(WebError) as caught:
            backend.navigate("s", "https://example/app")

        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()


def test_close_of_a_runnerless_handle_tears_it_down() -> None:
    backend = WebBackend()
    closed: list[bool] = []
    handle = SimpleNamespace(runner=None, close=lambda: closed.append(True))
    backend._sessions["s"] = handle  # type: ignore[assignment]

    result = backend.close("s")

    assert result == {"closed": True}
    assert closed == [True]


def test_network_get_rejects_an_unknown_request(tmp_path: Path) -> None:
    backend = WebBackend()
    handle = _WebSession(None, None, None, _FakePage(), _FakeCdp())
    handle.runner = _Runner("test-netget-missing")
    try:
        backend._sessions["s"] = handle
        backend._get = lambda session_id: handle  # type: ignore[method-assign]

        with pytest.raises(WebError) as caught:
            backend.network_get("s", "nope", tmp_path)

        assert caught.value.code == "not_found"
    finally:
        handle.runner.shutdown()


def test_network_get_stringifies_a_non_string_text_body(tmp_path: Path) -> None:
    backend = WebBackend()
    cdp = _FakeCdp()
    cdp.send = lambda name, params=None: {"body": 12345, "base64Encoded": False}  # type: ignore[method-assign]
    handle = _WebSession(None, None, None, _FakePage(), cdp)
    handle.runner = _Runner("test-netget-body")
    try:
        handle.requests["r1"] = {"requestId": "r1", "url": "a", "status": 200}
        backend._get = lambda session_id: handle  # type: ignore[method-assign]

        result = backend.network_get("s", "r1", tmp_path)

        assert result["body"] == "12345"
        assert result["base64_encoded"] is False
        assert "body_path" not in result
    finally:
        handle.runner.shutdown()


def test_script_source_passes_through_a_web_error(tmp_path: Path) -> None:
    backend = WebBackend()
    cdp = _FakeCdp()

    def boom(name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise WebError("timeout", "browser did not respond")

    cdp.send = boom  # type: ignore[method-assign]
    handle = _WebSession(None, None, None, _FakePage(), cdp)
    handle.runner = _Runner("test-script-webersrc")
    try:
        backend._get = lambda session_id: handle  # type: ignore[method-assign]

        with pytest.raises(WebError) as caught:
            backend.script_source("s", "s1", tmp_path)

        assert caught.value.code == "timeout"
    finally:
        handle.runner.shutdown()


def test_script_source_maps_a_generic_failure_to_not_found(tmp_path: Path) -> None:
    backend = WebBackend()
    cdp = _FakeCdp()

    def boom(name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise RuntimeError("no such script")

    cdp.send = boom  # type: ignore[method-assign]
    handle = _WebSession(None, None, None, _FakePage(), cdp)
    handle.runner = _Runner("test-script-notfound")
    try:
        backend._get = lambda session_id: handle  # type: ignore[method-assign]

        with pytest.raises(WebError) as caught:
            backend.script_source("s", "s1", tmp_path)

        assert caught.value.code == "not_found"
    finally:
        handle.runner.shutdown()


def test_script_source_inlines_a_non_string_source(tmp_path: Path) -> None:
    backend = WebBackend()
    cdp = _FakeCdp()
    cdp.send = lambda name, params=None: {"scriptSource": 999}  # type: ignore[method-assign]
    handle = _WebSession(None, None, None, _FakePage(), cdp)
    handle.runner = _Runner("test-script-body")
    try:
        backend._get = lambda session_id: handle  # type: ignore[method-assign]

        result = backend.script_source("s", "s1", tmp_path)

        assert result["source"] == "999"
        assert "source_path" not in result
    finally:
        handle.runner.shutdown()


def test_dom_snapshot_maps_an_evaluate_failure_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = WebBackend()
    runner = _Runner("test-dom-fail")
    try:

        class _Page:
            url = "https://x/"

            def evaluate(self, script: str, arg: Any) -> Any:
                raise RuntimeError("execution context destroyed")

            def title(self) -> str:
                return ""

        handle = SimpleNamespace(page=_Page(), runner=runner)
        monkeypatch.setattr(backend, "_get", lambda session_id: handle)

        with pytest.raises(WebError) as caught:
            backend.dom_snapshot("s")

        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()


def test_dom_snapshot_rejects_a_non_dict_result(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = WebBackend()
    runner = _Runner("test-dom-nondict")
    try:

        class _Page:
            url = "https://x/"

            def evaluate(self, script: str, arg: Any) -> Any:
                return "not a dict"

            def title(self) -> str:
                return ""

        handle = SimpleNamespace(page=_Page(), runner=runner)
        monkeypatch.setattr(backend, "_get", lambda session_id: handle)

        with pytest.raises(WebError) as caught:
            backend.dom_snapshot("s")

        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()


def test_screenshot_maps_a_capture_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = WebBackend()
    runner = _Runner("test-shot-fail")
    try:

        class _Page:
            def screenshot(self, path: str, full_page: bool = False) -> None:
                raise RuntimeError("target closed")

        handle = SimpleNamespace(page=_Page(), runner=runner)
        monkeypatch.setattr(backend, "_get", lambda session_id: handle)

        with pytest.raises(WebError) as caught:
            backend.screenshot("s", tmp_path / "shot.png")

        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()


def test_close_all_closes_every_open_session() -> None:
    backend = WebBackend()
    handle = SimpleNamespace(runner=None, close=lambda: None)
    backend._sessions["s"] = handle  # type: ignore[assignment]

    backend.close_all()

    assert backend._sessions == {}


# ----------------------------------------------------------------------
# open(): happy path, launch failure, closed-while-opening recovery.
# ----------------------------------------------------------------------


def test_open_launches_navigates_and_stores_the_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install_fake_playwright(monkeypatch)
    backend = WebBackend()
    try:
        summary = backend.open("s", "https://example.com/app", timeout=10.0)

        assert summary["opened"] is True
        assert summary["status"] == 200
        assert summary["url"] == "https://example.com/app"
        assert fake.page.goto_calls[0][0] == "https://example.com/app"
        assert isinstance(backend._sessions["s"], _WebSession)
    finally:
        backend.close("s")


def test_open_without_a_url_skips_navigation(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_fake_playwright(monkeypatch)
    backend = WebBackend()
    try:
        summary = backend.open("s", "", timeout=5.0)

        assert summary["opened"] is True
        assert "status" not in summary
        assert fake.page.goto_calls == []
    finally:
        backend.close("s")


def test_open_tolerates_an_unavailable_driver_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(monkeypatch, driver_pid=0)
    backend = WebBackend()
    try:
        summary = backend.open("s", "https://example.com/app", timeout=5.0)

        assert summary["opened"] is True
        assert backend._sessions["s"].driver_pid is None
    finally:
        backend.close("s")


def test_open_reaps_the_driver_when_launch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(monkeypatch, launch_exc=RuntimeError("chromium missing"))
    reaped: list[int] = []
    monkeypatch.setattr(web_client, "_reap_driver_pid", lambda pid: reaped.append(pid))
    backend = WebBackend()

    with pytest.raises(WebError) as caught:
        backend.open("s", "https://example.com/app", timeout=5.0)

    assert caught.value.code == "backend_error"
    assert reaped == [4321]
    assert "s" not in backend._sessions


def test_open_leaves_a_foreign_reservation_untouched_when_launch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_playwright(monkeypatch, launch_exc=RuntimeError("chromium missing"))
    monkeypatch.setattr(web_client, "_reap_driver_pid", lambda pid: None)
    backend = WebBackend()

    real_runner_cls = web_client._Runner

    class _RacingRunner(real_runner_cls):  # type: ignore[valid-type,misc]
        def call(self, work: Any, *, timeout: float = web_client._CALL_TIMEOUT) -> Any:
            # A concurrent close claims the slot before the failing launch runs.
            with backend._lock:
                backend._sessions["s"] = object()  # type: ignore[assignment]
            return super().call(work, timeout=timeout)

    monkeypatch.setattr(web_client, "_Runner", _RacingRunner)

    with pytest.raises(WebError) as caught:
        backend.open("s", "https://example.com/app", timeout=5.0)

    assert caught.value.code == "backend_error"
    # The reservation now belongs to someone else, so open must not pop it.
    assert type(backend._sessions.get("s")) is object


def test_open_detects_a_session_closed_during_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_playwright(monkeypatch)
    monkeypatch.setattr(web_client, "_reap_web_session", lambda handle: None)
    backend = WebBackend()

    real_runner_cls = web_client._Runner

    class _RacingRunner(real_runner_cls):  # type: ignore[valid-type,misc]
        def call(self, work: Any, *, timeout: float = web_client._CALL_TIMEOUT) -> Any:
            result = super().call(work, timeout=timeout)
            # Simulate a concurrent web.close swapping the reservation out.
            with backend._lock:
                backend._sessions["s"] = object()  # type: ignore[assignment]
            return result

    monkeypatch.setattr(web_client, "_Runner", _RacingRunner)

    with pytest.raises(WebError) as caught:
        backend.open("s", "https://example.com/app", timeout=5.0)

    assert caught.value.code == "invalid_state"
