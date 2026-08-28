"""Web backend paths the field/bounds suites do not reach.

These cover the console-text clipper's branch table, the spill helpers'
inline/spill/refuse decisions, the browser open flow (including the failure
cleanup that reaps the node driver), the CDP event handlers that keep the
telemetry rings bounded and flag truncation, and the per-call error contracts.
Each buffer/truncation assertion pins a fact an unattended agent draws
conclusions from: a page that reads back captured requests as complete when
some were dropped, or as untruncated when a URL was clipped, would mislead it.
"""

from __future__ import annotations

import base64
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    WebBackend,
    WebError,
    _bounded_metadata,
    _clip_console_text,
    _playwright_driver_pid,
    _reap_driver_pid,
    _response_status,
    _Runner,
    _safe_title,
    _spill_bytes,
    _spill_text,
    _WebSession,
)

_CLIENT = "headless_re_mcp.backends.web.client"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class _FakeCdp:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.handlers: dict[str, Any] = {}
        self.sent: list[tuple[str, Any]] = []
        self._responses = responses or {}

    def send(self, method: str, params: Any = None) -> Any:
        self.sent.append((method, params))
        result = self._responses.get(method)
        if isinstance(result, BaseException):
            raise result
        if callable(result):
            return result(params)
        return {} if result is None else result

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback

    def emit(self, event: str, params: Any) -> None:
        self.handlers[event](params)


class _FakePage:
    def __init__(
        self,
        *,
        url: str = "https://example.test/",
        title: str = "Example",
        goto_response: Any = None,
        goto_error: Exception | None = None,
        evaluate_result: Any = None,
        evaluate_error: Exception | None = None,
        screenshot_error: Exception | None = None,
        title_error: Exception | None = None,
    ) -> None:
        self.url = url
        self._title = title
        self._goto_response = goto_response
        self._goto_error = goto_error
        self._evaluate_result = evaluate_result
        self._evaluate_error = evaluate_error
        self._screenshot_error = screenshot_error
        self._title_error = title_error
        self.goto_calls: list[str] = []

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> Any:
        del timeout, wait_until
        self.goto_calls.append(url)
        if self._goto_error is not None:
            raise self._goto_error
        self.url = url
        return self._goto_response

    def title(self) -> str:
        if self._title_error is not None:
            raise self._title_error
        return self._title

    def evaluate(self, script: str, arg: Any = None) -> Any:
        del script, arg
        if self._evaluate_error is not None:
            raise self._evaluate_error
        return self._evaluate_result

    def screenshot(self, path: str | None = None, full_page: bool = False) -> None:
        del full_page
        if self._screenshot_error is not None:
            raise self._screenshot_error
        assert path is not None
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)


def _make_session(page: _FakePage | None = None, cdp: _FakeCdp | None = None) -> _WebSession:
    pw = SimpleNamespace(stop=lambda: None)
    browser = SimpleNamespace(close=lambda: None)
    context = SimpleNamespace(close=lambda: None)
    return _WebSession(pw, browser, context, page or _FakePage(), cdp or _FakeCdp())


@pytest.fixture
def web_env() -> Any:
    runners: list[_Runner] = []

    def make(
        page: _FakePage | None = None,
        cdp: _FakeCdp | None = None,
        *,
        session_id: str = "s",
    ) -> tuple[WebBackend, _WebSession]:
        backend = WebBackend()
        backend._available = True
        handle = _make_session(page, cdp)
        runner = _Runner(f"test-{session_id}")
        runners.append(runner)
        handle.runner = runner
        backend._sessions[session_id] = handle
        return backend, handle

    yield make
    for runner in runners:
        runner.shutdown()


# ---------------------------------------------------------------------------
# _clip_console_text: the branch table that keeps a huge console.log bounded
# ---------------------------------------------------------------------------
def test_clip_console_text_reads_value_description_then_type() -> None:
    assert _clip_console_text({"args": [{"value": "hello"}]}) == ("hello", False)
    assert _clip_console_text({"args": [{"description": "desc"}]}) == ("desc", False)
    assert _clip_console_text({"args": [{"type": "object"}]}) == ("object", False)
    # A non-dict argument is skipped, and missing args yields empty text.
    assert _clip_console_text({"args": [42, {"value": "a"}]}) == ("a", False)
    assert _clip_console_text({}) == ("", False)


def test_clip_console_text_joins_with_spaces() -> None:
    text, truncated = _clip_console_text(
        {"args": [{"value": "a"}, {"value": "b"}, {"value": "c"}]}
    )
    assert text == "a b c"
    assert truncated is False


def test_clip_console_text_truncates_a_single_long_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_CONSOLE_TEXT", 3)
    text, truncated = _clip_console_text({"args": [{"value": "abcdef"}]})
    assert text == "abc"
    assert truncated is True


def test_clip_console_text_stops_when_the_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_CONSOLE_TEXT", 3)
    # First arg consumes the whole budget; the second is never appended.
    text, truncated = _clip_console_text({"args": [{"value": "abc"}, {"value": "x"}]})
    assert text == "abc"
    assert truncated is True


def test_clip_console_text_stops_at_the_separator_when_budget_is_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_CONSOLE_TEXT", 4)
    # After "abc" one byte remains, not enough for a separator plus content.
    text, truncated = _clip_console_text({"args": [{"value": "abc"}, {"value": "x"}]})
    assert text == "abc"
    assert truncated is True


# ---------------------------------------------------------------------------
# spill helpers
# ---------------------------------------------------------------------------
def test_spill_text_inlines_small_text(tmp_path: Path) -> None:
    inline, spill, cut = _spill_text(
        "short", artifact_dir=tmp_path, filename="a.txt", kind="script source"
    )
    assert inline == "short"
    assert spill is None
    assert cut is False


def test_spill_text_spills_and_previews_large_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_INLINE_BODY", 4)
    inline, spill, cut = _spill_text(
        "abcdefgh", artifact_dir=tmp_path, filename="body.bin", kind="response body"
    )
    assert inline == "abcd"
    assert spill is not None and spill.read_bytes() == b"abcdefgh"
    assert cut is True


def test_spill_text_refuses_over_the_capture_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(f"{_CLIENT}.UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    with pytest.raises(WebError) as caught:
        _spill_text(
            "abcdefgh", artifact_dir=tmp_path, filename="body.bin", kind="response body"
        )
    assert caught.value.code == "too_large"


def test_spill_text_rejects_a_traversing_filename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_INLINE_BODY", 1)
    for bad in ("../escape", "sub/dir", ""):
        with pytest.raises(WebError) as caught:
            _spill_text("abcd", artifact_dir=tmp_path, filename=bad, kind="script source")
        assert caught.value.code == "invalid_params"


def test_spill_bytes_writes_and_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _spill_bytes(b"\x00\x01\x02", artifact_dir=tmp_path, filename="b.bin", kind="body")
    assert out.read_bytes() == b"\x00\x01\x02"

    with pytest.raises(WebError) as bad_name:
        _spill_bytes(b"x", artifact_dir=tmp_path, filename="../x", kind="body")
    assert bad_name.value.code == "invalid_params"

    monkeypatch.setattr(f"{_CLIENT}.UNREGISTERED_CAPTURE_MAX_BYTES", 1)
    with pytest.raises(WebError) as too_large:
        _spill_bytes(b"toolong", artifact_dir=tmp_path, filename="b.bin", kind="body")
    assert too_large.value.code == "too_large"


# ---------------------------------------------------------------------------
# _Runner
# ---------------------------------------------------------------------------
def test_runner_runs_work_and_refuses_after_close() -> None:
    runner = _Runner("test-runner-close")
    try:
        assert runner.call(lambda: 21 * 2) == 42
    finally:
        runner.shutdown()
    with pytest.raises(WebError) as caught:
        runner.call(lambda: 1)
    assert caught.value.code == "invalid_state"


def test_runner_refuses_once_wedged() -> None:
    runner = _Runner("test-runner-wedged")
    try:
        runner._wedged = True
        with pytest.raises(WebError) as caught:
            runner.call(lambda: 1)
        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()


def test_runner_wedges_on_timeout() -> None:
    import time

    runner = _Runner("test-runner-timeout")
    try:
        with pytest.raises(WebError) as caught:
            runner.call(lambda: time.sleep(10), timeout=0.2)
        assert caught.value.code == "timeout"
        assert runner.wedged is True
    finally:
        runner.shutdown()


# ---------------------------------------------------------------------------
# availability, status, runner lookup
# ---------------------------------------------------------------------------
def test_check_available_raises_when_marked_unavailable() -> None:
    backend = WebBackend()
    backend._available = False
    with pytest.raises(WebError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_check_available_caches_the_probe() -> None:
    backend = WebBackend()
    assert backend._available is None
    backend._check_available()  # playwright is installed in this env
    assert backend._available is True


def test_status_distinguishes_absent_opening_and_foreign_handles() -> None:
    backend = WebBackend()
    assert backend.status("missing") == {"open": False}
    backend._sessions["opening"] = object()  # bare reservation token
    assert backend.status("opening") == {"open": False, "opening": True}
    backend._sessions["foreign"] = SimpleNamespace()  # neither token nor session
    assert backend.status("foreign") == {"open": False}


def test_status_reports_url_and_title_for_a_live_session(web_env: Any) -> None:
    backend, _handle = web_env(_FakePage(url="https://live/", title="Live"))
    payload = backend.status("s")
    assert payload == {"open": True, "url": "https://live/", "title": "Live"}


def test_runner_lookup_reports_a_session_with_no_thread() -> None:
    backend = WebBackend()
    handle = _make_session()
    handle.runner = None
    with pytest.raises(WebError) as caught:
        backend._runner(handle)
    assert caught.value.code == "invalid_state"


# ---------------------------------------------------------------------------
# open: launch flow and its failure cleanup
# ---------------------------------------------------------------------------
def _install_fake_playwright(
    monkeypatch: pytest.MonkeyPatch,
    *,
    page: _FakePage,
    cdp: _FakeCdp,
) -> dict[str, Any]:
    state: dict[str, Any] = {"stopped": False}

    class _Browser:
        def new_context(self, ignore_https_errors: bool = False) -> Any:
            del ignore_https_errors
            return SimpleNamespace(
                new_page=lambda: page,
                new_cdp_session=lambda p: cdp,
                close=lambda: None,
            )

        def close(self) -> None:
            return None

    class _PW:
        chromium = SimpleNamespace(launch=lambda headless=True: _Browser())

        def stop(self) -> None:
            state["stopped"] = True

    pw = _PW()
    monkeypatch.setattr(
        "playwright.sync_api.sync_playwright",
        lambda: SimpleNamespace(start=lambda: pw),
    )
    monkeypatch.setattr(f"{_CLIENT}._playwright_driver_pid", lambda p: 4321)
    reaped: list[int] = []
    monkeypatch.setattr(f"{_CLIENT}._reap_driver_pid", lambda pid: reaped.append(pid or 0))
    state["reaped"] = reaped
    return state


def test_open_launches_wires_and_summarises(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage(url="about:blank", title="After", goto_response=SimpleNamespace(status=200))
    cdp = _FakeCdp()
    _install_fake_playwright(monkeypatch, page=page, cdp=cdp)
    backend = WebBackend()
    backend._available = True
    try:
        summary = backend.open("s", "https://after/app", headless=True, timeout=5.0)
        assert summary["opened"] is True
        # The summary reflects the page URL after navigation completed.
        assert summary["url"] == "https://after/app"
        assert summary["title"] == "After"
        assert summary["status"] == 200
        # The session is registered and the CDP domains were enabled.
        assert backend.status("s")["open"] is True
        assert ("Network.enable", None) in cdp.sent
    finally:
        backend.close("s")


def test_open_reaps_the_driver_when_launch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage(goto_error=RuntimeError("net::ERR_NAME_NOT_RESOLVED"))
    state = _install_fake_playwright(monkeypatch, page=page, cdp=_FakeCdp())
    backend = WebBackend()
    backend._available = True
    with pytest.raises(WebError) as caught:
        backend.open("s", "https://broken/", timeout=5.0)
    assert caught.value.code == "backend_error"
    # The half-built browser was stopped and its driver pid reaped; the
    # reservation is gone so the id can be opened again.
    assert state["stopped"] is True
    assert state["reaped"] == [4321]
    assert "s" not in backend._sessions


# ---------------------------------------------------------------------------
# CDP event handlers: bounded rings and truncation flags
# ---------------------------------------------------------------------------
def test_on_request_and_on_response_record_status_and_flag_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_URL_BYTES", 8)
    handle = _make_session(cdp=_FakeCdp())
    WebBackend()._wire_events(handle)
    cdp = handle.cdp
    assert isinstance(cdp, _FakeCdp)
    cdp.emit(
        "Network.requestWillBeSent",
        {"requestId": "1", "request": {"url": "https://example.test/very/long", "method": "GET"},
         "type": "Document"},
    )
    entry = handle.requests["1"]
    assert entry["status"] is None
    assert entry["metadata_truncated"] is True  # url exceeded the 8-byte bound
    # A response for a known id fills status/mime; one for an unknown id no-ops.
    cdp.emit(
        "Network.responseReceived",
        {"requestId": "1", "response": {"status": 204, "mimeType": "text/html"}},
    )
    assert handle.requests["1"]["status"] == 204
    cdp.emit("Network.responseReceived", {"requestId": "ghost", "response": {"status": 500}})
    assert "ghost" not in handle.requests


def test_on_request_drops_oldest_over_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_REQUESTS", 1)
    handle = _make_session(cdp=_FakeCdp())
    WebBackend()._wire_events(handle)
    cdp = handle.cdp
    assert isinstance(cdp, _FakeCdp)
    for rid in ("1", "2", "3"):
        cdp.emit(
            "Network.requestWillBeSent",
            {"requestId": rid, "request": {"url": "u", "method": "GET"}, "type": "XHR"},
        )
    assert len(handle.requests) == 1
    assert handle.requests_dropped == 2


def test_on_script_flags_truncation_and_drops_over_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_URL_BYTES", 4)
    monkeypatch.setattr(f"{_CLIENT}._MAX_SCRIPTS", 1)
    handle = _make_session(cdp=_FakeCdp())
    WebBackend()._wire_events(handle)
    cdp = handle.cdp
    assert isinstance(cdp, _FakeCdp)
    for sid in ("10", "11"):
        cdp.emit(
            "Debugger.scriptParsed",
            {"scriptId": sid, "url": "https://long", "scriptLanguage": "WebAssembly"},
        )
    assert len(handle.scripts) == 1
    assert handle.scripts_dropped == 1
    assert next(iter(handle.scripts.values()))["metadata_truncated"] is True


def test_on_console_truncates_and_drops(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{_CLIENT}._MAX_CONSOLE_TEXT", 3)
    handle = _make_session(cdp=_FakeCdp())
    # A tiny ring so the drop counter is exercised without 2000 events.
    handle.console = deque(maxlen=1)
    WebBackend()._wire_events(handle)
    cdp = handle.cdp
    assert isinstance(cdp, _FakeCdp)
    cdp.emit("Runtime.consoleAPICalled", {"type": "log", "args": [{"value": "abcdef"}]})
    assert handle.console[-1]["text"] == "abc"
    assert handle.console[-1]["text_truncated"] is True
    cdp.emit("Runtime.consoleAPICalled", {"type": "warning", "args": [{"value": "x"}]})
    assert handle.console_dropped == 1
    assert len(handle.console) == 1


# ---------------------------------------------------------------------------
# navigate / close / network_get / script_source / dom_snapshot / screenshot
# ---------------------------------------------------------------------------
def test_navigate_maps_a_goto_failure_to_backend_error(web_env: Any) -> None:
    backend, _handle = web_env(_FakePage(goto_error=RuntimeError("refused")))
    with pytest.raises(WebError) as caught:
        backend.navigate("s", "https://x/", timeout=5.0)
    assert caught.value.code == "backend_error"


def test_close_reports_aborted_reservation_and_missing_thread() -> None:
    backend = WebBackend()
    backend._sessions["reserved"] = object()
    assert backend.close("reserved") == {"closed": True, "note": "open was aborted"}

    handle = _make_session()
    handle.runner = None
    backend._sessions["nothread"] = handle
    assert backend.close("nothread") == {"closed": True}


def test_close_cleanly_tears_down_a_live_session(web_env: Any) -> None:
    backend, _handle = web_env()
    result = backend.close("s")
    assert result == {"closed": True, "clean": True}
    assert "s" not in backend._sessions


def test_close_kills_the_driver_when_the_runner_is_wedged(web_env: Any) -> None:
    backend, handle = web_env()
    handle.runner._wedged = True
    handle.driver_pid = None  # reap no-ops with no pid
    result = backend.close("s")
    assert result == {"closed": True, "clean": False}


def test_network_get_reports_unknown_id_and_stringifies_body(web_env: Any) -> None:
    backend, handle = web_env(cdp=_FakeCdp({"Network.getResponseBody": {"body": 123}}))
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "nope", Path("/tmp"))
    assert caught.value.code == "not_found"

    handle.requests["7"] = {"requestId": "7", "url": "u", "method": "GET", "status": 200}
    result = backend.network_get("s", "7", Path("/tmp"))
    assert result["body"] == "123"
    assert result["base64_encoded"] is False
    assert "body_path" not in result  # small body inlined, nothing spilled


def test_network_get_spills_a_binary_body(web_env: Any, tmp_path: Path) -> None:
    payload = base64.b64encode(b"\x00\x01\x02\x03").decode("ascii")
    backend, handle = web_env(
        cdp=_FakeCdp({"Network.getResponseBody": {"body": payload, "base64Encoded": True}})
    )
    handle.requests["9"] = {"requestId": "9", "url": "u", "method": "GET", "status": 200}
    result = backend.network_get("s", "9", tmp_path)
    assert result["base64_encoded"] is True
    assert result["body_bytes"] == 4
    assert Path(result["body_path"]).read_bytes() == b"\x00\x01\x02\x03"


def test_script_source_reraises_weberror_and_maps_others(web_env: Any, tmp_path: Path) -> None:
    backend, _handle = web_env(
        cdp=_FakeCdp({"Debugger.getScriptSource": WebError("timeout", "browser gone")})
    )
    with pytest.raises(WebError) as passthrough:
        backend.script_source("s", "1", tmp_path)
    assert passthrough.value.code == "timeout"

    backend2, _h2 = web_env(
        cdp=_FakeCdp({"Debugger.getScriptSource": RuntimeError("no such script")}),
        session_id="s2",
    )
    with pytest.raises(WebError) as mapped:
        backend2.script_source("s2", "1", tmp_path)
    assert mapped.value.code == "not_found"


def test_script_source_stringifies_and_inlines_small_source(web_env: Any, tmp_path: Path) -> None:
    backend, _handle = web_env(
        cdp=_FakeCdp({"Debugger.getScriptSource": {"scriptSource": 42}})
    )
    result = backend.script_source("s", "5", tmp_path)
    assert result["source"] == "42"
    assert result["truncated"] is False
    assert "source_path" not in result


def test_dom_snapshot_maps_failures(web_env: Any) -> None:
    backend, _handle = web_env(_FakePage(evaluate_error=RuntimeError("detached frame")))
    with pytest.raises(WebError) as failed:
        backend.dom_snapshot("s")
    assert failed.value.code == "backend_error"

    backend2, _h2 = web_env(_FakePage(evaluate_result="not-a-dict"), session_id="s2")
    with pytest.raises(WebError) as no_doc:
        backend2.dom_snapshot("s2")
    assert no_doc.value.code == "backend_error"


def test_dom_snapshot_returns_the_clipped_document(web_env: Any) -> None:
    backend, _handle = web_env(
        _FakePage(evaluate_result={"html": "<html></html>", "truncated": False})
    )
    payload = backend.dom_snapshot("s")
    assert payload["html"] == "<html></html>"
    assert payload["truncated"] is False


def test_screenshot_maps_a_capture_failure(web_env: Any, tmp_path: Path) -> None:
    backend, _handle = web_env(_FakePage(screenshot_error=RuntimeError("no surface")))
    with pytest.raises(WebError) as caught:
        backend.screenshot("s", tmp_path / "shot.png")
    assert caught.value.code == "backend_error"


def test_screenshot_writes_and_reports_size(web_env: Any, tmp_path: Path) -> None:
    backend, _handle = web_env()
    out = tmp_path / "sub" / "shot.png"
    payload = backend.screenshot("s", out)
    assert payload["path"] == str(out)
    assert payload["size"] > 0
    assert out.is_file()


def test_close_all_tears_down_every_open_session(web_env: Any) -> None:
    backend, _handle = web_env()
    backend.close_all()
    assert backend._sessions == {}


# ---------------------------------------------------------------------------
# module helpers
# ---------------------------------------------------------------------------
def test_safe_title_swallows_a_failing_title() -> None:
    boom = _FakePage(title_error=RuntimeError("execution context destroyed"))
    assert _safe_title(boom) == ""


def test_bounded_metadata_truncates_and_flags() -> None:
    text, truncated = _bounded_metadata("abcdef", 3)
    assert text == "abc" and truncated is True
    text2, truncated2 = _bounded_metadata(None, 3)
    assert text2 == "" and truncated2 is False


def test_response_status_handles_none_nonint_and_errors() -> None:
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status=200)) == 200
    assert _response_status(SimpleNamespace(status="200")) is None

    class _Boom:
        @property
        def status(self) -> int:
            raise RuntimeError("navigation gone")

    assert _response_status(_Boom()) is None


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    good = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid=2222))
            )
        )
    )
    assert _playwright_driver_pid(good) == 2222
    # A broken chain returns None rather than raising.
    assert _playwright_driver_pid(SimpleNamespace(_impl_obj=None)) is None
    assert _playwright_driver_pid(SimpleNamespace()) is None


def test_reap_driver_pid_ignores_non_pids_and_foreign_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[int] = []
    monkeypatch.setattr(f"{_CLIENT}.terminate_pid_tree", lambda pid: terminated.append(pid))

    _reap_driver_pid(None)
    _reap_driver_pid(0)
    assert terminated == []

    # A pid whose image is not a browser/node process is left alone.
    monkeypatch.setattr(f"{_CLIENT}.process_image_path", lambda pid: "/usr/bin/python3")
    _reap_driver_pid(1234)
    assert terminated == []

    # A pid whose image looks like the node driver is terminated.
    monkeypatch.setattr(f"{_CLIENT}.process_image_path", lambda pid: "/opt/node/bin/node")
    _reap_driver_pid(1234)
    assert terminated == [1234]
