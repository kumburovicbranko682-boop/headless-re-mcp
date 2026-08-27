"""Guard, capture and lifecycle branches of the Web (CDP/Playwright) backend.

A real Chromium cannot run in CI, so these drive ``WebBackend`` two ways: the
pure helpers directly, and the per-session operations against a ``_WebSession``
built from fake page/CDP objects with a real ``_Runner`` thread. ``open`` is
exercised through a faked ``sync_playwright`` so the launch/teardown path is
covered without a browser. The point is the honesty contract: console text and
metadata are bounded, oversized captures are refused, a driver/CDP failure
becomes a typed ``WebError`` rather than a hung worker, spilled bodies are
written to disk, and teardown reaps the node driver a wedged session left.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE_TEXT,
    _MAX_INLINE_BODY,
    _bounded_metadata,
    _clip_console_text,
    _playwright_driver_pid,
    _reap_driver_pid,
    _response_status,
    _Runner,
    _spill_bytes,
    _spill_text,
    _WebSession,
)
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES


# ----------------------------------------------------------------------------
# Fakes.
# ----------------------------------------------------------------------------
class _FakeCDP:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self._responses = responses or {}
        self.sent: list[tuple[str, Any]] = []
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> Any:
        self.sent.append((method, params))
        value = self._responses.get(method, {})
        if isinstance(value, BaseException):
            raise value
        return value

    def on(self, event: str, cb: Any) -> None:
        self.handlers[event] = cb


class _FakePage:
    def __init__(self) -> None:
        self.url = "https://example.test/"
        self._title = "Example"
        self.evaluate_result: Any = {"html": "<html></html>", "truncated": False}
        self.evaluate_error: BaseException | None = None
        self.goto_error: BaseException | None = None
        self.screenshot_error: BaseException | None = None

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> Any:
        if self.goto_error is not None:
            raise self.goto_error
        self.url = url
        return SimpleNamespace(status=200)

    def title(self) -> str:
        return self._title

    def evaluate(self, script: str, arg: Any = None) -> Any:
        if self.evaluate_error is not None:
            raise self.evaluate_error
        return self.evaluate_result

    def screenshot(self, path: str = "", full_page: bool = False) -> None:
        if self.screenshot_error is not None:
            raise self.screenshot_error
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)


def _handle(page: _FakePage, cdp: _FakeCDP, runner: _Runner | None) -> _WebSession:
    trio = SimpleNamespace(stop=lambda: None, close=lambda: None)
    handle = _WebSession(trio, trio, trio, page, cdp)
    handle.runner = runner
    return handle


@pytest.fixture
def runner_factory() -> Any:
    created: list[_Runner] = []

    def make(name: str = "test-web-runner") -> _Runner:
        runner = _Runner(name)
        created.append(runner)
        return runner

    yield make
    for runner in created:
        runner.shutdown()


# ----------------------------------------------------------------------------
# _clip_console_text: join args, stopping at the byte budget.
# ----------------------------------------------------------------------------
def test_clip_console_joins_value_description_and_type() -> None:
    params = {
        "args": [
            {"value": "a"},
            {"description": "b"},
            {"type": "undefined"},
            "not-a-dict",
        ]
    }
    text, truncated = _clip_console_text(params)
    assert text == "a b undefined"
    assert truncated is False


def test_clip_console_truncates_a_giant_argument() -> None:
    params = {"args": [{"value": "x" * (_MAX_CONSOLE_TEXT + 10)}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True
    assert len(text) <= _MAX_CONSOLE_TEXT


def test_clip_console_stops_between_arguments_at_the_budget() -> None:
    # First argument consumes the whole budget; the next loop iteration sees no
    # remaining space and stops with truncated set.
    params = {"args": [{"value": "y" * _MAX_CONSOLE_TEXT}, {"value": "z"}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True
    assert "z" not in text


def test_clip_console_stops_when_only_the_separator_would_fit() -> None:
    # One byte of budget remains, but the separator before the second argument
    # needs it, so the join stops rather than emit a bare space.
    params = {"args": [{"value": "a" * (_MAX_CONSOLE_TEXT - 1)}, {"value": "b"}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True
    assert "b" not in text


# ----------------------------------------------------------------------------
# _spill_text / _spill_bytes: inline, spill, refuse, reject bad filenames.
# ----------------------------------------------------------------------------
def test_spill_text_inlines_small_payloads(tmp_path: Path) -> None:
    inline, spill, truncated = _spill_text(
        "hello", artifact_dir=tmp_path, filename="x.txt", kind="body"
    )
    assert inline == "hello"
    assert spill is None
    assert truncated is False


def test_spill_text_spills_large_payloads(tmp_path: Path) -> None:
    big = "a" * (_MAX_INLINE_BODY + 10)
    inline, spill, truncated = _spill_text(
        big, artifact_dir=tmp_path, filename="body.bin", kind="body"
    )
    assert truncated is True
    assert spill is not None and spill.is_file()
    assert len(inline) <= _MAX_INLINE_BODY


def test_spill_text_refuses_over_the_capture_cap(tmp_path: Path) -> None:
    with pytest.raises(WebError) as info:
        _spill_text(
            "a" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1),
            artifact_dir=tmp_path,
            filename="body.bin",
            kind="body",
        )
    assert info.value.code == "too_large"


def test_spill_bytes_refuses_over_the_capture_cap(tmp_path: Path) -> None:
    with pytest.raises(WebError) as info:
        _spill_bytes(
            b"0" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1),
            artifact_dir=tmp_path,
            filename="body.bin",
            kind="body",
        )
    assert info.value.code == "too_large"


def test_spill_bytes_rejects_a_traversal_filename(tmp_path: Path) -> None:
    for bad in ("../escape", "a/b", ""):
        with pytest.raises(WebError) as info:
            _spill_bytes(b"data", artifact_dir=tmp_path, filename=bad, kind="body")
        assert info.value.code == "invalid_params"


# ----------------------------------------------------------------------------
# _Runner: closed/wedged refusal.
# ----------------------------------------------------------------------------
def test_runner_refuses_calls_after_shutdown() -> None:
    runner = _Runner("closed-runner")
    runner.shutdown()
    with pytest.raises(WebError) as info:
        runner.call(lambda: 1)
    assert info.value.code == "invalid_state"


def test_runner_reports_a_wedged_browser(runner_factory: Any) -> None:
    runner = runner_factory()
    runner._wedged = True
    with pytest.raises(WebError) as info:
        runner.call(lambda: 1)
    assert info.value.code == "backend_error"


def test_runner_marks_itself_wedged_when_a_call_times_out(runner_factory: Any) -> None:
    import threading

    runner = runner_factory()
    release = threading.Event()
    try:
        with pytest.raises(WebError) as info:
            runner.call(lambda: release.wait(30), timeout=0.2)
        assert info.value.code == "timeout"
        # The blocked call cannot be interrupted, so the session is unusable.
        assert runner.wedged is True
    finally:
        release.set()


# ----------------------------------------------------------------------------
# _check_available.
# ----------------------------------------------------------------------------
def test_check_available_ok_when_playwright_imports() -> None:
    backend = WebBackend()
    backend._available = None
    backend._check_available()
    assert backend._available is True


def test_check_available_reports_capability_gap(monkeypatch: Any) -> None:
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    backend = WebBackend()
    backend._available = None
    with pytest.raises(WebError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"


# ----------------------------------------------------------------------------
# status().
# ----------------------------------------------------------------------------
def test_status_reports_opening_reservation() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()
    assert backend.status("s") == {"open": False, "opening": True}


def test_status_reports_not_open_for_an_unknown_handle_type() -> None:
    backend = WebBackend()
    backend._sessions["s"] = SimpleNamespace()  # type: ignore[assignment]
    assert backend.status("s") == {"open": False}


def test_status_of_a_live_session_reports_url_and_title(runner_factory: Any) -> None:
    backend = WebBackend()
    page = _FakePage()
    handle = _handle(page, _FakeCDP(), runner_factory())
    backend._sessions["s"] = handle
    payload = backend.status("s")
    assert payload["open"] is True
    assert payload["url"] == "https://example.test/"
    assert payload["title"] == "Example"


def test_operation_without_a_browser_thread_is_invalid_state() -> None:
    backend = WebBackend()
    handle = _handle(_FakePage(), _FakeCDP(), None)
    backend._sessions["s"] = handle
    with pytest.raises(WebError) as info:
        backend.status("s")
    assert info.value.code == "invalid_state"


# ----------------------------------------------------------------------------
# navigate().
# ----------------------------------------------------------------------------
def test_navigate_wraps_a_goto_failure(runner_factory: Any) -> None:
    backend = WebBackend()
    page = _FakePage()
    page.goto_error = RuntimeError("net::ERR_NAME_NOT_RESOLVED")
    backend._sessions["s"] = _handle(page, _FakeCDP(), runner_factory())
    with pytest.raises(WebError) as info:
        backend.navigate("s", "https://nope.invalid")
    assert info.value.code == "backend_error"


# ----------------------------------------------------------------------------
# network_get().
# ----------------------------------------------------------------------------
def test_network_get_unknown_request_id(runner_factory: Any, tmp_path: Path) -> None:
    backend = WebBackend()
    backend._sessions["s"] = _handle(_FakePage(), _FakeCDP(), runner_factory())
    with pytest.raises(WebError) as info:
        backend.network_get("s", "missing", tmp_path)
    assert info.value.code == "not_found"


def test_network_get_coerces_a_non_string_body(runner_factory: Any, tmp_path: Path) -> None:
    cdp = _FakeCDP({"Network.getResponseBody": {"body": 12345, "base64Encoded": False}})
    handle = _handle(_FakePage(), cdp, runner_factory())
    handle.requests["r1"] = {"requestId": "r1", "url": "u", "status": 200}
    backend = WebBackend()
    backend._sessions["s"] = handle
    result = backend.network_get("s", "r1", tmp_path)
    assert result["body"] == "12345"
    assert result["base64_encoded"] is False


def test_network_get_spills_a_large_text_body(runner_factory: Any, tmp_path: Path) -> None:
    big = "q" * (_MAX_INLINE_BODY + 50)
    cdp = _FakeCDP({"Network.getResponseBody": {"body": big, "base64Encoded": False}})
    handle = _handle(_FakePage(), cdp, runner_factory())
    handle.requests["r1"] = {"requestId": "r1", "url": "u", "status": 200}
    backend = WebBackend()
    backend._sessions["s"] = handle
    result = backend.network_get("s", "r1", tmp_path)
    assert result["body_truncated"] is True
    assert Path(result["body_path"]).is_file()


def test_network_get_reports_a_missing_body(runner_factory: Any, tmp_path: Path) -> None:
    cdp = _FakeCDP({"Network.getResponseBody": RuntimeError("No resource with given identifier")})
    handle = _handle(_FakePage(), cdp, runner_factory())
    handle.requests["r1"] = {"requestId": "r1", "url": "u", "status": 302}
    backend = WebBackend()
    backend._sessions["s"] = handle
    result = backend.network_get("s", "r1", tmp_path)
    assert result["body"] == ""
    assert result["body_truncated"] is False
    assert "body_error" in result


# ----------------------------------------------------------------------------
# script_source().
# ----------------------------------------------------------------------------
def test_script_source_reraises_a_web_error(runner_factory: Any, tmp_path: Path) -> None:
    cdp = _FakeCDP({"Debugger.getScriptSource": WebError("timeout", "browser did not respond")})
    handle = _handle(_FakePage(), cdp, runner_factory())
    backend = WebBackend()
    backend._sessions["s"] = handle
    with pytest.raises(WebError) as info:
        backend.script_source("s", "1", tmp_path)
    assert info.value.code == "timeout"


def test_script_source_maps_a_backend_failure(runner_factory: Any, tmp_path: Path) -> None:
    cdp = _FakeCDP({"Debugger.getScriptSource": RuntimeError("No script for id")})
    handle = _handle(_FakePage(), cdp, runner_factory())
    backend = WebBackend()
    backend._sessions["s"] = handle
    with pytest.raises(WebError) as info:
        backend.script_source("s", "9", tmp_path)
    assert info.value.code == "not_found"


def test_script_source_coerces_a_non_string_source(runner_factory: Any, tmp_path: Path) -> None:
    cdp = _FakeCDP({"Debugger.getScriptSource": {"scriptSource": 42}})
    handle = _handle(_FakePage(), cdp, runner_factory())
    backend = WebBackend()
    backend._sessions["s"] = handle
    result = backend.script_source("s", "1", tmp_path)
    assert result["source"] == "42"


# ----------------------------------------------------------------------------
# dom_snapshot() / screenshot().
# ----------------------------------------------------------------------------
def test_dom_snapshot_wraps_an_evaluate_failure(runner_factory: Any) -> None:
    page = _FakePage()
    page.evaluate_error = RuntimeError("execution context destroyed")
    backend = WebBackend()
    backend._sessions["s"] = _handle(page, _FakeCDP(), runner_factory())
    with pytest.raises(WebError) as info:
        backend.dom_snapshot("s")
    assert info.value.code == "backend_error"


def test_dom_snapshot_rejects_a_non_document_result(runner_factory: Any) -> None:
    page = _FakePage()
    page.evaluate_result = "not-a-dict"
    backend = WebBackend()
    backend._sessions["s"] = _handle(page, _FakeCDP(), runner_factory())
    with pytest.raises(WebError) as info:
        backend.dom_snapshot("s")
    assert info.value.code == "backend_error"


def test_screenshot_wraps_a_capture_failure(runner_factory: Any, tmp_path: Path) -> None:
    page = _FakePage()
    page.screenshot_error = RuntimeError("target crashed")
    backend = WebBackend()
    backend._sessions["s"] = _handle(page, _FakeCDP(), runner_factory())
    with pytest.raises(WebError) as info:
        backend.screenshot("s", tmp_path / "shot.png")
    assert info.value.code == "backend_error"


# ----------------------------------------------------------------------------
# close() / close_all().
# ----------------------------------------------------------------------------
def test_close_a_session_with_no_runner_tears_down_directly() -> None:
    backend = WebBackend()
    closed: list[str] = []
    trio = SimpleNamespace(stop=lambda: closed.append("pw"), close=lambda: closed.append("c"))
    handle = _WebSession(trio, trio, trio, _FakePage(), _FakeCDP())
    handle.runner = None
    backend._sessions["s"] = handle
    result = backend.close("s")
    assert result == {"closed": True}
    assert closed  # teardown ran


def test_close_all_closes_every_open_session(runner_factory: Any) -> None:
    backend = WebBackend()
    backend._sessions["s"] = _handle(_FakePage(), _FakeCDP(), runner_factory())
    backend.close_all()
    assert backend._sessions == {}


def test_close_of_an_aborted_opening_reservation() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()
    assert backend.close("s") == {"closed": True, "note": "open was aborted"}


def test_close_reaps_a_wedged_session(runner_factory: Any) -> None:
    backend = WebBackend()
    runner = runner_factory()
    runner._wedged = True
    handle = _handle(_FakePage(), _FakeCDP(), runner)
    handle.driver_pid = None
    backend._sessions["s"] = handle
    result = backend.close("s")
    assert result["closed"] is True
    # A wedged runner cannot run handle.close, so the close is not clean.
    assert result["clean"] is False


# ----------------------------------------------------------------------------
# CDP event handlers: bounded metadata and unknown-request tolerance.
# ----------------------------------------------------------------------------
def _wired() -> tuple[_WebSession, _FakeCDP]:
    cdp = _FakeCDP()
    handle = _handle(_FakePage(), cdp, None)
    WebBackend()._wire_events(handle)
    return handle, cdp


def test_on_request_marks_truncated_metadata() -> None:
    handle, cdp = _wired()
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "type": "XHR",
            "request": {"url": "https://x/" + "a" * 20000, "method": "GET"},
        }
    )
    entry = handle.requests["r1"]
    assert entry["metadata_truncated"] is True


def test_on_response_updates_status_and_ignores_unknown_ids() -> None:
    handle, cdp = _wired()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "type": "XHR", "request": {"url": "https://x/a", "method": "GET"}}
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "r1", "response": {"status": 200, "mimeType": "m" * 4096}}
    )
    assert handle.requests["r1"]["status"] == 200
    assert handle.requests["r1"]["metadata_truncated"] is True
    # A response for a request that was never seen must be dropped, not crash.
    cdp.handlers["Network.responseReceived"]({"requestId": "ghost", "response": {"status": 500}})
    assert "ghost" not in handle.requests


def test_on_script_marks_truncated_metadata() -> None:
    handle, cdp = _wired()
    cdp.handlers["Debugger.scriptParsed"](
        {"scriptId": "9", "url": "https://x/" + "b" * 20000, "scriptLanguage": "JavaScript"}
    )
    assert handle.scripts["9"]["metadata_truncated"] is True


def test_on_console_marks_truncated_text() -> None:
    handle, cdp = _wired()
    cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "log", "args": [{"value": "z" * (_MAX_CONSOLE_TEXT + 10)}]}
    )
    entry = handle.console[-1]
    assert entry["text_truncated"] is True


# ----------------------------------------------------------------------------
# _safe_title / _response_status / driver pid helpers.
# ----------------------------------------------------------------------------
def test_safe_title_falls_back_to_empty_on_error() -> None:
    from headless_re_mcp.backends.web.client import _safe_title

    class _Page:
        def title(self) -> str:
            raise RuntimeError("detached")

    assert _safe_title(_Page()) == ""


def test_response_status_handles_none_and_error() -> None:
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status=404)) == 404

    class _Resp:
        @property
        def status(self) -> int:
            raise RuntimeError("gone")

    assert _response_status(_Resp()) is None


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid=4242))
            )
        )
    )
    assert _playwright_driver_pid(pw) == 4242


def test_playwright_driver_pid_returns_none_when_the_chain_breaks() -> None:
    assert _playwright_driver_pid(SimpleNamespace()) is None
    # Chain present but pid absent/invalid.
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=SimpleNamespace()))
        )
    )
    assert _playwright_driver_pid(pw) is None


def test_reap_driver_pid_ignores_invalid_and_non_driver_pids() -> None:
    import os

    # Non-positive pid: nothing to reap.
    _reap_driver_pid(0)
    _reap_driver_pid(None)
    # A real pid whose image is not a browser/node driver is left alone. The
    # test interpreter is python, which matches no driver marker, so this must
    # return without terminating anything.
    _reap_driver_pid(os.getpid())
    assert True  # reaching here means no process was killed


def test_bounded_metadata_truncates_over_the_limit() -> None:
    text, truncated = _bounded_metadata("x" * 100, 10)
    assert truncated is True
    assert len(text.encode()) <= 10
    text, truncated = _bounded_metadata("short", 10)
    assert truncated is False
    assert text == "short"


# ----------------------------------------------------------------------------
# open(): launch and teardown, via a faked sync_playwright.
# ----------------------------------------------------------------------------
class _OpenCDP:
    def send(self, method: str, params: Any = None) -> Any:
        del method, params
        return {}

    def on(self, event: str, cb: Any) -> None:
        del event, cb


class _OpenContext:
    def __init__(self, page: _FakePage, cdp: _OpenCDP) -> None:
        self._page = page
        self._cdp = cdp

    def new_page(self) -> _FakePage:
        return self._page

    def new_cdp_session(self, page: _FakePage) -> _OpenCDP:
        del page
        return self._cdp

    def close(self) -> None:
        return None


class _OpenBrowser:
    def __init__(self, context: _OpenContext, *, launch_error: BaseException | None = None) -> None:
        self._context = context
        self._launch_error = launch_error

    def new_context(self, ignore_https_errors: bool = False) -> _OpenContext:
        del ignore_https_errors
        if self._launch_error is not None:
            raise self._launch_error
        return self._context

    def close(self) -> None:
        return None


class _OpenChromium:
    def __init__(self, browser: _OpenBrowser) -> None:
        self._browser = browser

    def launch(self, headless: bool = True) -> _OpenBrowser:
        del headless
        return self._browser


class _OpenPlaywright:
    def __init__(self, browser: _OpenBrowser) -> None:
        self.chromium = _OpenChromium(browser)
        self.stopped = False
        # A driver pid the reaper will treat as unresolvable (no such process),
        # so failure paths that reap it are safe.
        self._impl_obj = SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid=999_000_111))
            )
        )

    def stop(self) -> None:
        self.stopped = True


def _install_fake_playwright(monkeypatch: Any, pw: _OpenPlaywright) -> None:
    monkeypatch.setitem(
        sys.modules,
        "playwright.sync_api",
        SimpleNamespace(sync_playwright=lambda: SimpleNamespace(start=lambda: pw)),
    )


def test_open_launches_navigates_and_summarizes(monkeypatch: Any) -> None:
    page = _FakePage()
    pw = _OpenPlaywright(_OpenBrowser(_OpenContext(page, _OpenCDP())))
    _install_fake_playwright(monkeypatch, pw)
    backend = WebBackend()
    backend._available = True
    try:
        summary = backend.open("s", "https://example.test/app", timeout=5.0)
        assert summary["opened"] is True
        assert summary["url"] == "https://example.test/app"
        assert summary["status"] == 200
        assert backend.status("s")["open"] is True
    finally:
        backend.close_all()


def test_open_with_no_url_reports_no_status(monkeypatch: Any) -> None:
    page = _FakePage()
    pw = _OpenPlaywright(_OpenBrowser(_OpenContext(page, _OpenCDP())))
    _install_fake_playwright(monkeypatch, pw)
    backend = WebBackend()
    backend._available = True
    try:
        summary = backend.open("s", "", timeout=5.0)
        assert summary["opened"] is True
        # No navigation happened, so there is no HTTP status to report.
        assert "status" not in summary
    finally:
        backend.close_all()


def test_open_tears_down_and_reraises_on_launch_failure(monkeypatch: Any) -> None:
    boom = RuntimeError("chromium missing")
    pw = _OpenPlaywright(_OpenBrowser(_OpenContext(_FakePage(), _OpenCDP()), launch_error=boom))
    _install_fake_playwright(monkeypatch, pw)
    backend = WebBackend()
    backend._available = True
    with pytest.raises(WebError) as info:
        backend.open("s", "https://example.test/app", timeout=5.0)
    assert info.value.code == "backend_error"
    # The reservation was released and the driver stopped.
    assert "s" not in backend._sessions
    assert pw.stopped is True


def test_open_refuses_a_second_open_for_the_same_session(monkeypatch: Any) -> None:
    page = _FakePage()
    pw = _OpenPlaywright(_OpenBrowser(_OpenContext(page, _OpenCDP())))
    _install_fake_playwright(monkeypatch, pw)
    backend = WebBackend()
    backend._available = True
    try:
        backend.open("s", "https://example.test/app", timeout=5.0)
        with pytest.raises(WebError) as info:
            backend.open("s", "https://example.test/app", timeout=5.0)
        assert info.value.code == "invalid_state"
    finally:
        backend.close_all()
