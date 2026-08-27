"""WebBackend internals reached without a real Playwright browser.

Playwright is optional and not installed here, so open() degrades to
capability_unavailable and the live browser paths cannot run. Everything that
does not need a driver is exercised directly: the console-text clipper and body
spill guards, the session runner's closed/wedged/timeout envelopes, the CDP
event callbacks wired by _wire_events (driven through a recording fake), and the
per-tool error envelopes (not_found, backend_error, too_large) plus the process
reaping helpers a wedged session relies on.
"""

from __future__ import annotations

import time
from pathlib import Path
from threading import RLock
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE_TEXT,
    WebBackend,
    WebError,
    _clip_console_text,
    _playwright_driver_pid,
    _reap_driver_pid,
    _reap_web_session,
    _response_status,
    _Runner,
    _safe_title,
    _spill_bytes,
    _spill_text,
    _WebSession,
)


class _Immediate:
    """A runner stand-in that runs the queued work on the calling thread."""

    def call(self, work: Any, *args: Any, **kwargs: Any) -> Any:
        return work()


def _backend_with_handle(monkeypatch: Any, handle: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    return backend


# --------------------------------------------------------------------------
# _clip_console_text
# --------------------------------------------------------------------------
def test_clip_console_joins_values_with_spaces() -> None:
    text, truncated = _clip_console_text(
        {"args": [{"value": "a"}, {"value": "b"}, {"value": "c"}]}
    )
    assert text == "a b c"
    assert truncated is False


def test_clip_console_uses_description_then_type() -> None:
    text, _ = _clip_console_text(
        {"args": [{"description": "Obj"}, {"type": "undefined"}]}
    )
    assert text == "Obj undefined"


def test_clip_console_skips_non_dict_args() -> None:
    text, _ = _clip_console_text({"args": ["not-a-dict", {"value": "kept"}]})
    assert text == "kept"


def test_clip_console_handles_missing_args() -> None:
    assert _clip_console_text({}) == ("", False)


def test_clip_console_truncates_a_huge_value() -> None:
    text, truncated = _clip_console_text({"args": [{"value": "z" * (_MAX_CONSOLE_TEXT + 50)}]})
    assert truncated is True
    assert len(text) == _MAX_CONSOLE_TEXT


def test_clip_console_truncates_at_a_separator_boundary() -> None:
    # First arg exactly fills the budget; the space before the second cannot be
    # afforded, so the join stops there and reports truncation.
    text, truncated = _clip_console_text(
        {"args": [{"value": "z" * _MAX_CONSOLE_TEXT}, {"value": "tail"}]}
    )
    assert truncated is True
    assert "tail" not in text


def test_clip_console_stops_when_only_a_separator_would_fit() -> None:
    # One byte of budget remains after the first arg: not even the joining space
    # to the second arg fits, so the join stops before appending it.
    text, truncated = _clip_console_text(
        {"args": [{"value": "z" * (_MAX_CONSOLE_TEXT - 1)}, {"value": "tail"}]}
    )
    assert truncated is True
    assert "tail" not in text


# --------------------------------------------------------------------------
# _spill_text / _spill_bytes guards not already pinned elsewhere
# --------------------------------------------------------------------------
def test_spill_text_inlines_a_small_body(tmp_path: Path) -> None:
    inline, spill, truncated = _spill_text(
        "small", artifact_dir=tmp_path, filename="x.txt", kind="response body"
    )
    assert inline == "small"
    assert spill is None
    assert truncated is False


def test_spill_bytes_refuses_over_the_capture_cap(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    with pytest.raises(WebError) as excinfo:
        _spill_bytes(b"12345", artifact_dir=tmp_path, filename="x.bin", kind="response body")
    assert excinfo.value.code == "too_large"


def test_spill_bytes_refuses_an_escaping_filename(tmp_path: Path) -> None:
    with pytest.raises(WebError) as excinfo:
        _spill_bytes(
            b"data", artifact_dir=tmp_path, filename="../escape.bin", kind="response body"
        )
    assert excinfo.value.code == "invalid_params"


# --------------------------------------------------------------------------
# _Runner
# --------------------------------------------------------------------------
def test_runner_runs_and_returns() -> None:
    runner = _Runner("test-run-ok")
    try:
        assert runner.call(lambda: 42) == 42
    finally:
        runner.shutdown()


def test_runner_propagates_a_work_exception() -> None:
    runner = _Runner("test-run-raise")
    try:
        with pytest.raises(ZeroDivisionError):
            runner.call(lambda: 1 // 0)
    finally:
        runner.shutdown()


def test_runner_refuses_calls_after_shutdown() -> None:
    runner = _Runner("test-run-closed")
    runner.shutdown()
    with pytest.raises(WebError) as excinfo:
        runner.call(lambda: 1)
    assert excinfo.value.code == "invalid_state"


def test_runner_refuses_calls_once_wedged() -> None:
    runner = _Runner("test-run-wedged")
    try:
        runner._wedged = True
        with pytest.raises(WebError) as excinfo:
            runner.call(lambda: 1)
        assert excinfo.value.code == "backend_error"
    finally:
        runner.shutdown()


def test_runner_wedges_on_timeout() -> None:
    runner = _Runner("test-run-timeout")
    try:
        with pytest.raises(WebError) as excinfo:
            runner.call(lambda: time.sleep(0.4), timeout=0.05)
        assert excinfo.value.code == "timeout"
        assert runner.wedged is True
    finally:
        runner.shutdown()


# --------------------------------------------------------------------------
# _check_available / status / _get / _runner
# --------------------------------------------------------------------------
def test_open_reports_capability_unavailable_without_playwright() -> None:
    backend = WebBackend()
    with pytest.raises(WebError) as excinfo:
        backend.open("s", "https://example.com")
    assert excinfo.value.code == "capability_unavailable"


def test_open_refuses_a_session_that_is_already_open() -> None:
    backend = WebBackend()
    backend._available = True
    backend._sessions["s"] = object()  # type: ignore[assignment]
    with pytest.raises(WebError) as excinfo:
        backend.open("s", "https://example.com")
    assert excinfo.value.code == "invalid_state"


def test_status_reports_opening_for_a_reservation_token() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    assert backend.status("s") == {"open": False, "opening": True}


def test_status_reports_closed_for_an_unknown_handle_type() -> None:
    backend = WebBackend()
    backend._sessions["s"] = SimpleNamespace()  # type: ignore[assignment]
    assert backend.status("s") == {"open": False}


def test_status_reports_the_page_identity(monkeypatch: Any) -> None:
    page = SimpleNamespace(url="https://example.com/app", title=lambda: "Example")
    handle = _WebSession(None, None, None, page, None)
    backend = WebBackend()
    backend._sessions["s"] = handle
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    data = backend.status("s")
    assert data["open"] is True
    assert data["url"] == "https://example.com/app"
    assert data["title"] == "Example"


def test_runner_helper_refuses_a_handle_with_no_thread() -> None:
    handle = _WebSession(None, None, None, None, None)
    handle.runner = None
    backend = WebBackend()
    with pytest.raises(WebError) as excinfo:
        backend._runner(handle)
    assert excinfo.value.code == "invalid_state"


def test_get_returns_a_live_session_handle() -> None:
    # A real _WebSession routed through the real _get (no monkeypatch), so a
    # read tool reaches its buffers rather than the invalid_state guard.
    handle = _WebSession(None, None, None, None, None)
    handle.requests["r1"] = {"requestId": "r1", "url": "http://x/1"}
    backend = WebBackend()
    backend._sessions["s"] = handle
    data = backend.network_list("s")
    assert data["total"] == 1
    assert data["requests"][0]["requestId"] == "r1"


# --------------------------------------------------------------------------
# _wire_events CDP callbacks
# --------------------------------------------------------------------------
class _RecordingCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> None:
        return None

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def _wired_handle() -> tuple[WebBackend, _WebSession, _RecordingCdp]:
    cdp = _RecordingCdp()
    handle = _WebSession(None, None, None, None, cdp)
    backend = WebBackend()
    backend._wire_events(handle)
    return backend, handle, cdp


def test_wire_events_records_a_request_and_its_response() -> None:
    _, handle, cdp = _wired_handle()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "http://x/1", "method": "GET"}, "type": "Document"}
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "r1", "response": {"status": 200, "mimeType": "text/html"}}
    )
    entry = handle.requests["r1"]
    assert entry["status"] == 200
    assert entry["mimeType"] == "text/html"


def test_wire_events_flags_a_truncated_request_url() -> None:
    _, handle, cdp = _wired_handle()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "h" * (web_client._MAX_URL_BYTES + 5)}, "type": "X"}
    )
    assert handle.requests["r1"]["metadata_truncated"] is True


def test_wire_events_evicts_requests_past_the_cap(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 2)
    _, handle, cdp = _wired_handle()
    for index in range(3):
        cdp.handlers["Network.requestWillBeSent"](
            {"requestId": f"r{index}", "request": {"url": "http://x"}, "type": "X"}
        )
    assert len(handle.requests) == 2
    assert handle.requests_dropped == 1


def test_wire_events_records_and_evicts_scripts(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_SCRIPTS", 2)
    _, handle, cdp = _wired_handle()
    for index in range(3):
        cdp.handlers["Debugger.scriptParsed"](
            {"scriptId": f"s{index}", "url": "http://x/a.js", "scriptLanguage": "JavaScript"}
        )
    assert len(handle.scripts) == 2
    assert handle.scripts_dropped == 1


def test_wire_events_records_and_drops_console(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_CONSOLE", 2)
    _, handle, cdp = _wired_handle()
    for index in range(3):
        cdp.handlers["Runtime.consoleAPICalled"](
            {"type": "log", "args": [{"value": f"line-{index}"}]}
        )
    assert len(handle.console) == 2
    assert handle.console_dropped == 1


def test_wire_events_flags_a_truncated_console_line() -> None:
    _, handle, cdp = _wired_handle()
    cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "log", "args": [{"value": "z" * (_MAX_CONSOLE_TEXT + 10)}]}
    )
    assert handle.console[-1]["text_truncated"] is True


def test_wire_events_ignores_a_response_for_an_unknown_request() -> None:
    _, handle, cdp = _wired_handle()
    # No requestWillBeSent preceded this, so there is nothing to annotate; the
    # handler must leave the (empty) buffer untouched rather than create a row.
    cdp.handlers["Network.responseReceived"](
        {"requestId": "ghost", "response": {"status": 200, "mimeType": "text/html"}}
    )
    assert dict(handle.requests) == {}


# --------------------------------------------------------------------------
# navigate / close error and lifecycle paths
# --------------------------------------------------------------------------
def test_navigate_maps_a_goto_failure(monkeypatch: Any) -> None:
    def _goto(url: str, timeout: float = 0.0, wait_until: str = "") -> None:
        raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

    handle = SimpleNamespace(page=SimpleNamespace(url="https://x", goto=_goto), runner=object())
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.navigate("s", "https://bad")
    assert excinfo.value.code == "backend_error"


def test_close_reports_an_aborted_open() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True, "note": "open was aborted"}


def test_close_tears_down_a_runnerless_handle() -> None:
    closed: list[str] = []
    handle = SimpleNamespace(runner=None, close=lambda: closed.append("closed"), driver_pid=None)
    backend = WebBackend()
    backend._sessions["s"] = handle  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True}
    assert closed == ["closed"]


def test_close_reports_clean_when_teardown_runs() -> None:
    runner = SimpleNamespace(
        wedged=False, call=lambda fn, timeout=None: fn(), shutdown=lambda: None
    )
    closed: list[str] = []
    handle = SimpleNamespace(runner=runner, close=lambda: closed.append("closed"), driver_pid=None)
    backend = WebBackend()
    backend._sessions["s"] = handle  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True, "clean": True}
    assert closed == ["closed"]


def test_close_reaps_a_wedged_session(monkeypatch: Any) -> None:
    reaped: list[Any] = []
    monkeypatch.setattr(web_client, "_reap_web_session", lambda handle: reaped.append(handle))
    runner = SimpleNamespace(wedged=True, call=lambda fn, timeout=None: fn(), shutdown=lambda: None)
    handle = SimpleNamespace(runner=runner, close=lambda: None, driver_pid=1234)
    backend = WebBackend()
    backend._sessions["s"] = handle  # type: ignore[assignment]
    result = backend.close("s")
    assert result == {"closed": True, "clean": False}
    assert reaped == [handle]


def test_close_all_closes_every_session() -> None:
    backend = WebBackend()
    closed: list[str] = []
    for name in ("a", "b"):
        backend._sessions[name] = SimpleNamespace(  # type: ignore[assignment]
            runner=None, close=lambda name=name: closed.append(name), driver_pid=None
        )
    backend.close_all()
    assert sorted(closed) == ["a", "b"]
    assert backend._sessions == {}


# --------------------------------------------------------------------------
# network_get
# --------------------------------------------------------------------------
def _request_handle(response: Any, *, raises: BaseException | None = None) -> Any:
    class _Cdp:
        def send(self, method: str, params: Any) -> Any:
            if raises is not None:
                raise raises
            return response

    return SimpleNamespace(
        lock=RLock(),
        requests={"r1": {"requestId": "r1", "url": "http://x/1", "mimeType": "text/plain"}},
        cdp=_Cdp(),
    )


def test_network_get_reports_not_found(tmp_path: Path, monkeypatch: Any) -> None:
    handle = SimpleNamespace(lock=RLock(), requests={}, cdp=SimpleNamespace())
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.network_get("s", "missing", tmp_path)
    assert excinfo.value.code == "not_found"


def test_network_get_reports_body_error_when_cdp_has_no_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    handle = _request_handle(None, raises=RuntimeError("No resource with given identifier"))
    backend = _backend_with_handle(monkeypatch, handle)
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == ""
    assert payload["body_truncated"] is False
    assert "body_error" in payload


def test_network_get_coerces_a_non_string_body(tmp_path: Path, monkeypatch: Any) -> None:
    handle = _request_handle({"body": 12345, "base64Encoded": False})
    backend = _backend_with_handle(monkeypatch, handle)
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == "12345"
    assert payload["base64_encoded"] is False
    assert "body_path" not in payload


# --------------------------------------------------------------------------
# console / scripts
# --------------------------------------------------------------------------
def test_console_returns_the_newest_tail(monkeypatch: Any) -> None:
    handle = SimpleNamespace(
        lock=RLock(),
        console=[{"type": "log", "text": str(i)} for i in range(5)],
        console_dropped=2,
    )
    backend = _backend_with_handle(monkeypatch, handle)
    data = backend.console("s", limit=2)
    assert data["count"] == 2
    assert data["total"] == 5
    assert data["has_more"] is True
    assert data["dropped"] == 2
    assert data["console"][-1]["text"] == "4"


def test_scripts_filters_to_webassembly(monkeypatch: Any) -> None:
    handle = SimpleNamespace(
        lock=RLock(),
        scripts={
            "1": {"scriptId": "1", "language": "JavaScript"},
            "2": {"scriptId": "2", "language": "WebAssembly"},
        },
        scripts_dropped=0,
    )
    backend = _backend_with_handle(monkeypatch, handle)
    data = backend.scripts("s", wasm_only=True)
    assert data["total"] == 1
    assert data["scripts"][0]["scriptId"] == "2"


# --------------------------------------------------------------------------
# script_source
# --------------------------------------------------------------------------
def _script_handle(response: Any, *, raises: BaseException | None = None) -> Any:
    class _Cdp:
        def send(self, method: str, params: Any) -> Any:
            if raises is not None:
                raise raises
            return response

    return SimpleNamespace(cdp=_Cdp())


def test_script_source_inlines_a_small_source(tmp_path: Path, monkeypatch: Any) -> None:
    handle = _script_handle({"scriptSource": "var a = 1;"})
    backend = _backend_with_handle(monkeypatch, handle)
    data = backend.script_source("s", "42", tmp_path)
    assert data["source"] == "var a = 1;"
    assert data["truncated"] is False
    assert "source_path" not in data


def test_script_source_maps_a_fetch_failure(tmp_path: Path, monkeypatch: Any) -> None:
    handle = _script_handle(None, raises=RuntimeError("no such script"))
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.script_source("s", "42", tmp_path)
    assert excinfo.value.code == "not_found"


def test_script_source_reraises_a_web_error(tmp_path: Path, monkeypatch: Any) -> None:
    handle = _script_handle(None, raises=WebError("timeout", "browser did not respond"))
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.script_source("s", "42", tmp_path)
    assert excinfo.value.code == "timeout"


def test_script_source_coerces_a_non_string_source(tmp_path: Path, monkeypatch: Any) -> None:
    handle = _script_handle({"scriptSource": 999})
    backend = _backend_with_handle(monkeypatch, handle)
    data = backend.script_source("s", "42", tmp_path)
    assert data["source"] == "999"


# --------------------------------------------------------------------------
# dom_snapshot / screenshot / har_export
# --------------------------------------------------------------------------
def test_dom_snapshot_returns_clipped_html(monkeypatch: Any) -> None:
    page = SimpleNamespace(
        url="https://x",
        title=lambda: "T",
        evaluate=lambda script, cap: {"html": "<html></html>", "truncated": False},
    )
    handle = SimpleNamespace(page=page)
    backend = _backend_with_handle(monkeypatch, handle)
    data = backend.dom_snapshot("s")
    assert data["html"] == "<html></html>"
    assert data["truncated"] is False


def test_dom_snapshot_maps_an_evaluate_failure(monkeypatch: Any) -> None:
    def _evaluate(script: str, cap: int) -> Any:
        raise RuntimeError("execution context destroyed")

    page = SimpleNamespace(url="https://x", title=lambda: "T", evaluate=_evaluate)
    backend = _backend_with_handle(monkeypatch, SimpleNamespace(page=page))
    with pytest.raises(WebError) as excinfo:
        backend.dom_snapshot("s")
    assert excinfo.value.code == "backend_error"


def test_dom_snapshot_refuses_a_non_document(monkeypatch: Any) -> None:
    handle = SimpleNamespace(
        page=SimpleNamespace(url="https://x", title=lambda: "T", evaluate=lambda script, cap: None)
    )
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.dom_snapshot("s")
    assert excinfo.value.code == "backend_error"


def test_screenshot_reports_the_saved_size(tmp_path: Path, monkeypatch: Any) -> None:
    out = tmp_path / "shot.png"

    def _screenshot(path: str, full_page: bool = False) -> None:
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)

    handle = SimpleNamespace(page=SimpleNamespace(screenshot=_screenshot))
    backend = _backend_with_handle(monkeypatch, handle)
    data = backend.screenshot("s", out)
    assert data["path"] == str(out)
    assert data["size"] > 0


def test_screenshot_maps_a_capture_failure(tmp_path: Path, monkeypatch: Any) -> None:
    def _screenshot(path: str, full_page: bool = False) -> None:
        raise RuntimeError("target closed")

    handle = SimpleNamespace(page=SimpleNamespace(screenshot=_screenshot))
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.screenshot("s", tmp_path / "shot.png")
    assert excinfo.value.code == "backend_error"


def test_screenshot_refuses_an_oversize_capture(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    out = tmp_path / "shot.png"

    def _screenshot(path: str, full_page: bool = False) -> None:
        Path(path).write_bytes(b"0" * 64)

    handle = SimpleNamespace(page=SimpleNamespace(screenshot=_screenshot))
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.screenshot("s", out)
    assert excinfo.value.code == "too_large"


def test_har_export_writes_entries(tmp_path: Path, monkeypatch: Any) -> None:
    handle = SimpleNamespace(
        lock=RLock(),
        requests={
            "r1": {"method": "GET", "url": "http://x/1", "status": 200, "mimeType": "text/html"}
        },
    )
    backend = _backend_with_handle(monkeypatch, handle)
    out = tmp_path / "capture.har"
    data = backend.har_export("s", out)
    assert out.is_file()
    assert data["entry_count"] == 1


def test_har_export_refuses_over_the_cap(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    monkeypatch.setattr(
        web_client,
        "serialize_har",
        lambda entries, max_bytes: SimpleNamespace(
            size=max_bytes + 1, text="{}", entry_count=0, truncated=True
        ),
    )
    handle = SimpleNamespace(lock=RLock(), requests={})
    backend = _backend_with_handle(monkeypatch, handle)
    with pytest.raises(WebError) as excinfo:
        backend.har_export("s", tmp_path / "capture.har")
    assert excinfo.value.code == "too_large"


# --------------------------------------------------------------------------
# module helpers
# --------------------------------------------------------------------------
def test_safe_title_is_empty_when_title_raises() -> None:
    def _title() -> str:
        raise RuntimeError("navigation in progress")

    assert _safe_title(SimpleNamespace(title=_title)) == ""


def test_response_status_reads_an_int_status() -> None:
    assert _response_status(SimpleNamespace(status=404)) == 404


def test_response_status_is_none_without_a_response() -> None:
    assert _response_status(None) is None


def test_response_status_is_none_on_a_read_error() -> None:
    class _Resp:
        @property
        def status(self) -> int:
            raise RuntimeError("detached")

    assert _response_status(_Resp()) is None


def test_response_status_ignores_a_non_int_status() -> None:
    assert _response_status(SimpleNamespace(status="200")) is None


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=SimpleNamespace(pid=4321)))
        )
    )
    assert _playwright_driver_pid(pw) == 4321


def test_playwright_driver_pid_is_none_on_a_broken_chain() -> None:
    assert _playwright_driver_pid(SimpleNamespace(_impl_obj=None)) is None


def test_playwright_driver_pid_ignores_a_non_int_pid() -> None:
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid="nope"))
            )
        )
    )
    assert _playwright_driver_pid(pw) is None


def test_reap_driver_pid_kills_a_driver_image(monkeypatch: Any) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/usr/bin/node")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(4321)
    assert killed == [4321]


def test_reap_driver_pid_ignores_an_unrelated_image(monkeypatch: Any) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/usr/bin/python3")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(4321)
    assert killed == []


def test_reap_driver_pid_ignores_a_missing_pid(monkeypatch: Any) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(None)
    _reap_driver_pid(0)
    assert killed == []


def test_reap_web_session_forwards_the_driver_pid(monkeypatch: Any) -> None:
    seen: list[int | None] = []
    monkeypatch.setattr(web_client, "_reap_driver_pid", lambda pid: seen.append(pid))
    _reap_web_session(SimpleNamespace(driver_pid=4321))  # type: ignore[arg-type]
    assert seen == [4321]
