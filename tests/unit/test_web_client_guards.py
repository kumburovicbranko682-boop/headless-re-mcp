"""Guard, degradation and buffer-shaping paths of the Web (CDP) backend.

The browser itself cannot run in CI, but almost everything that turns raw CDP
into a bounded, honest reply is pure Python: the console-text clipper, the
request/console/script ring buffers wired in ``_wire_events``, the artifact
spill, and the per-session ``_Runner`` that keeps a wedged browser from parking
the whole session. This drives those with fake page/cdp objects through a real
runner thread, the same seam ``test_web_backends.py`` uses for the nav-timeout
tests, so a degradation reply stays a structured ``WebError`` rather than a bare
exception or a silently-dropped field.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import (
    WebBackend,
    WebError,
    _clip_console_text,
    _response_status,
    _Runner,
    _safe_title,
    _spill_bytes,
    _WebSession,
)


# ---------------------------------------------------------------------------
# _clip_console_text: every clipping branch, without a browser
# ---------------------------------------------------------------------------
def test_clip_console_text_joins_value_description_and_type_args() -> None:
    text, truncated = _clip_console_text(
        {
            "args": [
                {"value": "hello"},
                {"description": "[object Object]"},
                {"type": "undefined"},
                "not-a-dict-skipped",
                {"value": 123},
            ]
        }
    )
    assert truncated is False
    assert text == "hello [object Object] undefined 123"


def test_clip_console_text_truncates_a_single_huge_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_client, "_MAX_CONSOLE_TEXT", 5)
    text, truncated = _clip_console_text({"args": [{"value": "abcdefgh"}]})
    assert text == "abcde"
    assert truncated is True


def test_clip_console_text_stops_at_the_budget_between_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the first argument exactly spends the budget, the next iteration
    trips the top-of-loop guard rather than emitting an empty tail."""
    monkeypatch.setattr(web_client, "_MAX_CONSOLE_TEXT", 5)
    text, truncated = _clip_console_text(
        {"args": [{"value": "abcde"}, {"value": "x"}]}
    )
    assert text == "abcde"
    assert truncated is True


def test_clip_console_text_handles_no_args() -> None:
    assert _clip_console_text({}) == ("", False)


def test_clip_console_text_stops_before_a_second_arg_when_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first arg leaves one byte; the separator alone would overrun it, so
    the second arg is refused rather than emitted as an empty piece."""
    monkeypatch.setattr(web_client, "_MAX_CONSOLE_TEXT", 5)
    text, truncated = _clip_console_text(
        {"args": [{"value": "abcd"}, {"value": "efgh"}]}
    )
    assert text == "abcd"
    assert truncated is True


# ---------------------------------------------------------------------------
# _spill_bytes: binary bodies always go to disk, capped on real bytes
# ---------------------------------------------------------------------------
def test_spill_bytes_writes_the_raw_bytes(tmp_path: Path) -> None:
    out = _spill_bytes(b"\x00\x01\x02", artifact_dir=tmp_path, filename="b.bin", kind="body")
    assert out.read_bytes() == b"\x00\x01\x02"


def test_spill_bytes_refuses_over_the_capture_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 2)
    with pytest.raises(WebError) as caught:
        _spill_bytes(b"\x00\x01\x02\x03", artifact_dir=tmp_path, filename="b.bin", kind="body")
    assert caught.value.code == "too_large"
    assert not (tmp_path / "b.bin").exists()


def test_spill_bytes_refuses_a_filename_that_escapes(tmp_path: Path) -> None:
    for bad in ("../escape.bin", "a/b.bin", ".", ""):
        with pytest.raises(WebError) as caught:
            _spill_bytes(b"x", artifact_dir=tmp_path / "d", filename=bad, kind="body")
        assert caught.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# navigation-status and title helpers
# ---------------------------------------------------------------------------
def test_response_status_reports_absent_transport_and_bad_values() -> None:
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status=404)) == 404

    class _Raises:
        @property
        def status(self) -> int:
            raise RuntimeError("detached")

    assert _response_status(_Raises()) is None
    assert _response_status(SimpleNamespace(status="200")) is None


def test_safe_title_swallows_a_title_failure() -> None:
    class _Page:
        def title(self) -> str:
            raise RuntimeError("execution context destroyed")

    assert _safe_title(_Page()) == ""


# ---------------------------------------------------------------------------
# _Runner state machine
# ---------------------------------------------------------------------------
def test_runner_refuses_work_after_shutdown() -> None:
    runner = _Runner("test-closed-runner")
    runner.shutdown()
    with pytest.raises(WebError) as caught:
        runner.call(lambda: 1)
    assert caught.value.code == "invalid_state"


def test_runner_wedges_on_timeout_and_refuses_further_calls() -> None:
    runner = _Runner("test-wedge-runner")
    try:
        with pytest.raises(WebError) as caught:
            runner.call(lambda: time.sleep(0.3) or "late", timeout=0.05)
        assert caught.value.code == "timeout"
        assert runner.wedged is True
        with pytest.raises(WebError) as second:
            runner.call(lambda: 1)
        assert second.value.code == "backend_error"
    finally:
        runner.shutdown()


# ---------------------------------------------------------------------------
# fake browser plumbing for the handle-driven methods
# ---------------------------------------------------------------------------
class _FakeCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.responses: dict[str, Any] = {}
        self.raises: set[str] = set()

    def send(self, method: str, params: dict[str, Any] | None = None) -> Any:
        del params
        if method in self.raises:
            raise RuntimeError(f"no data for {method}")
        return self.responses.get(method, {})

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback

    def fire(self, event: str, params: dict[str, Any]) -> None:
        self.handlers[event](params)


class _FakePage:
    def __init__(self) -> None:
        self.url = "https://example/app"
        self._evaluate: Any = {"html": "<html></html>", "truncated": False}
        self.screenshot_raises = False

    def title(self) -> str:
        return "Example"

    def evaluate(self, script: str, cap: int) -> Any:
        del script, cap
        if isinstance(self._evaluate, Exception):
            raise self._evaluate
        return self._evaluate

    def screenshot(self, path: str, full_page: bool = False) -> None:
        del full_page
        if self.screenshot_raises:
            raise RuntimeError("target closed")
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)


_Rig = tuple[WebBackend, str, _WebSession, _FakeCdp, _FakePage, _Runner]


def _make_backend_with_handle() -> _Rig:
    backend = WebBackend()
    cdp = _FakeCdp()
    page = _FakePage()
    context = SimpleNamespace(close=lambda: None)
    browser = SimpleNamespace(close=lambda: None)
    playwright = SimpleNamespace(stop=lambda: None)
    handle = _WebSession(playwright, browser, context, page, cdp)
    handle.driver_pid = None
    backend._wire_events(handle)
    runner = _Runner("test-web-handle")
    handle.runner = runner
    session_id = "web-session"
    backend._sessions[session_id] = handle
    return backend, session_id, handle, cdp, page, runner


# ---------------------------------------------------------------------------
# _wire_events ring buffers, read back through the paginated readers
# ---------------------------------------------------------------------------
def test_request_and_response_events_populate_and_shape_the_ring() -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "GET"}, "type": "Doc"},
        )
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "2", "request": {"url": "https://b", "method": "POST"}, "type": "XHR"},
        )
        cdp.fire(
            "Network.responseReceived",
            {"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}},
        )
        listed = backend.network_list(session_id, offset=0, limit=1)
        assert listed["count"] == 1
        assert listed["total"] == 2
        assert listed["has_more"] is True
        assert listed["requests"][0]["status"] == 200
        assert listed["requests"][0]["mimeType"] == "text/html"
    finally:
        runner.shutdown()
        backend.close_all()


def test_request_ring_drops_oldest_and_counts_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 1)
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        for i in range(3):
            cdp.fire(
                "Network.requestWillBeSent",
                {"requestId": str(i), "request": {"url": f"https://{i}", "method": "GET"}},
            )
        listed = backend.network_list(session_id)
        assert listed["total"] == 1
        assert listed["dropped"] == 2
    finally:
        runner.shutdown()
        backend.close_all()


def test_request_event_flags_truncated_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_client, "_MAX_METADATA_BYTES", 3)
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "DELETE"}, "type": "XHR"},
        )
        entry = backend.network_list(session_id)["requests"][0]
        assert entry["metadata_truncated"] is True
    finally:
        runner.shutdown()
        backend.close_all()


def test_script_events_and_wasm_filter() -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Debugger.scriptParsed",
            {"scriptId": "1", "url": "https://a.js", "scriptLanguage": "JavaScript"},
        )
        cdp.fire(
            "Debugger.scriptParsed",
            {"scriptId": "2", "url": "https://m.wasm", "scriptLanguage": "WebAssembly"},
        )
        every = backend.scripts(session_id)
        assert every["total"] == 2
        wasm = backend.scripts(session_id, wasm_only=True)
        assert wasm["total"] == 1
        assert wasm["scripts"][0]["scriptId"] == "2"
    finally:
        runner.shutdown()
        backend.close_all()


def test_script_ring_drops_oldest_and_counts_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_client, "_MAX_SCRIPTS", 1)
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        for i in range(3):
            cdp.fire("Debugger.scriptParsed", {"scriptId": str(i), "url": f"https://{i}.js"})
        listed = backend.scripts(session_id)
        assert listed["total"] == 1
        assert listed["dropped"] == 2
    finally:
        runner.shutdown()
        backend.close_all()


def test_console_events_populate_the_ring() -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Runtime.consoleAPICalled",
            {"type": "error", "args": [{"value": "boom"}]},
        )
        payload = backend.console(session_id)
        assert payload["total"] == 1
        assert payload["console"][0]["type"] == "error"
        assert payload["console"][0]["text"] == "boom"
    finally:
        runner.shutdown()
        backend.close_all()


# ---------------------------------------------------------------------------
# handle-driven methods
# ---------------------------------------------------------------------------
def test_status_of_an_open_session_reports_url_and_title() -> None:
    backend, session_id, handle, _cdp, _page, runner = _make_backend_with_handle()
    try:
        payload = backend.status(session_id)
        assert payload["open"] is True
        assert payload["url"] == "https://example/app"
        assert payload["title"] == "Example"
    finally:
        runner.shutdown()
        backend.close_all()


def test_network_get_returns_a_text_body_inline(tmp_path: Path) -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "GET"}},
        )
        cdp.responses["Network.getResponseBody"] = {"body": "hello world", "base64Encoded": False}
        result = backend.network_get(session_id, "1", tmp_path)
        assert result["body"] == "hello world"
        assert result["base64_encoded"] is False
        assert result["body_truncated"] is False
    finally:
        runner.shutdown()
        backend.close_all()


def test_network_get_spills_a_binary_base64_body(tmp_path: Path) -> None:
    import base64

    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "GET"}},
        )
        cdp.responses["Network.getResponseBody"] = {
            "body": base64.b64encode(b"\x89PNG").decode(),
            "base64Encoded": True,
        }
        result = backend.network_get(session_id, "1", tmp_path)
        assert result["base64_encoded"] is True
        assert result["body"] == ""
        assert result["body_bytes"] == 4
        assert Path(result["body_path"]).read_bytes() == b"\x89PNG"
    finally:
        runner.shutdown()
        backend.close_all()


def test_network_get_reports_an_unfetchable_body_without_a_missing_key(tmp_path: Path) -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "GET"}},
        )
        cdp.raises.add("Network.getResponseBody")
        result = backend.network_get(session_id, "1", tmp_path)
        assert result["body"] == ""
        assert result["base64_encoded"] is False
        assert result["body_truncated"] is False
        assert "body_error" in result
    finally:
        runner.shutdown()
        backend.close_all()


def test_network_get_reports_invalid_base64_as_body_error(tmp_path: Path) -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "GET"}},
        )
        cdp.responses["Network.getResponseBody"] = {"body": "AAAAA", "base64Encoded": True}
        result = backend.network_get(session_id, "1", tmp_path)
        assert "not valid base64" in result["body_error"]
    finally:
        runner.shutdown()
        backend.close_all()


def test_network_get_unknown_request_is_not_found(tmp_path: Path) -> None:
    backend, session_id, handle, _cdp, _page, runner = _make_backend_with_handle()
    try:
        with pytest.raises(WebError) as caught:
            backend.network_get(session_id, "missing", tmp_path)
        assert caught.value.code == "not_found"
    finally:
        runner.shutdown()
        backend.close_all()


def test_script_source_returns_the_source_and_maps_a_failure(tmp_path: Path) -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.responses["Debugger.getScriptSource"] = {"scriptSource": "var a = 1;"}
        ok = backend.script_source(session_id, "1", tmp_path)
        assert ok["source"] == "var a = 1;"
        assert ok["truncated"] is False

        cdp.raises.add("Debugger.getScriptSource")
        with pytest.raises(WebError) as caught:
            backend.script_source(session_id, "2", tmp_path)
        assert caught.value.code == "not_found"
    finally:
        runner.shutdown()
        backend.close_all()


def test_dom_snapshot_returns_html_and_maps_failures() -> None:
    backend, session_id, handle, _cdp, page, runner = _make_backend_with_handle()
    try:
        ok = backend.dom_snapshot(session_id)
        assert ok["html"] == "<html></html>"
        assert ok["truncated"] is False

        page._evaluate = "not-a-dict"
        with pytest.raises(WebError) as no_doc:
            backend.dom_snapshot(session_id)
        assert no_doc.value.code == "backend_error"

        page._evaluate = RuntimeError("navigation in flight")
        with pytest.raises(WebError) as boom:
            backend.dom_snapshot(session_id)
        assert boom.value.code == "backend_error"
    finally:
        runner.shutdown()
        backend.close_all()


def test_screenshot_writes_reports_size_and_maps_failure(tmp_path: Path) -> None:
    backend, session_id, handle, _cdp, page, runner = _make_backend_with_handle()
    try:
        out = tmp_path / "shot.png"
        payload = backend.screenshot(session_id, out)
        assert payload["path"] == str(out)
        assert payload["size"] > 0
        assert out.is_file()

        page.screenshot_raises = True
        with pytest.raises(WebError) as caught:
            backend.screenshot(session_id, tmp_path / "again.png")
        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()
        backend.close_all()


def test_screenshot_refuses_over_the_capture_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    backend, session_id, handle, _cdp, _page, runner = _make_backend_with_handle()
    try:
        with pytest.raises(WebError) as caught:
            backend.screenshot(session_id, tmp_path / "big.png")
        assert caught.value.code == "too_large"
    finally:
        runner.shutdown()
        backend.close_all()


def test_har_export_writes_entries_from_the_request_ring(tmp_path: Path) -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "GET"}, "type": "Doc"},
        )
        cdp.fire(
            "Network.responseReceived",
            {"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}},
        )
        out = tmp_path / "capture.har"
        payload = backend.har_export(session_id, out)
        assert payload["entry_count"] == 1
        assert out.is_file()
    finally:
        runner.shutdown()
        backend.close_all()


# ---------------------------------------------------------------------------
# close: reservation token, no-runner handle, wedged reap
# ---------------------------------------------------------------------------
def test_close_of_an_open_reservation_reports_aborted() -> None:
    backend = WebBackend()
    backend._sessions["opening"] = object()  # type: ignore[assignment]
    result = backend.close("opening")
    assert result["closed"] is True
    assert result["note"] == "open was aborted"


def test_close_of_a_handle_without_a_runner_tears_it_down() -> None:
    backend = WebBackend()
    closed: list[str] = []
    context = SimpleNamespace(close=lambda: closed.append("context"))
    browser = SimpleNamespace(close=lambda: closed.append("browser"))
    playwright = SimpleNamespace(stop=lambda: closed.append("playwright"))
    handle = _WebSession(playwright, browser, context, SimpleNamespace(), SimpleNamespace())
    handle.runner = None
    backend._sessions["s"] = handle
    result = backend.close("s")
    assert result == {"closed": True}
    assert set(closed) == {"context", "browser", "playwright"}


def test_close_of_a_wedged_session_reaps_instead_of_calling_the_browser() -> None:
    backend, session_id, handle, _cdp, _page, runner = _make_backend_with_handle()
    try:
        runner._wedged = True
        result = backend.close(session_id)
        assert result["closed"] is True
        assert result["clean"] is False
    finally:
        runner.shutdown()


# ---------------------------------------------------------------------------
# remaining guards: availability, status reservations, missing runner, pid
# ---------------------------------------------------------------------------
def test_open_without_playwright_is_capability_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = WebBackend()
    backend._available = False
    with pytest.raises(WebError) as caught:
        backend.open("s", "https://a")
    assert caught.value.code == "capability_unavailable"


def test_status_reports_an_opening_reservation_and_an_unexpected_handle() -> None:
    backend = WebBackend()
    backend._sessions["opening"] = object()  # type: ignore[assignment]
    assert backend.status("opening") == {"open": False, "opening": True}
    backend._sessions["weird"] = "not a handle"  # type: ignore[assignment]
    assert backend.status("weird") == {"open": False}


def test_runner_guard_reports_a_handle_with_no_browser_thread() -> None:
    backend = WebBackend()
    stub = SimpleNamespace()
    handle = _WebSession(stub, stub, stub, stub, stub)
    handle.runner = None
    backend._sessions["s"] = handle
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")
    assert caught.value.code == "invalid_state"


def test_navigate_maps_a_goto_failure_to_backend_error() -> None:
    backend, session_id, handle, _cdp, page, runner = _make_backend_with_handle()
    try:
        def boom(url: str, timeout: float = 0.0, wait_until: str = "") -> None:
            raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

        page.goto = boom  # type: ignore[attr-defined]
        with pytest.raises(WebError) as caught:
            backend.navigate(session_id, "https://nope", timeout=5.0)
        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()
        backend.close_all()


def test_network_get_stringifies_a_non_string_body(tmp_path: Path) -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.requestWillBeSent",
            {"requestId": "1", "request": {"url": "https://a", "method": "GET"}},
        )
        cdp.responses["Network.getResponseBody"] = {"body": 12345, "base64Encoded": False}
        result = backend.network_get(session_id, "1", tmp_path)
        assert result["body"] == "12345"
    finally:
        runner.shutdown()
        backend.close_all()


def test_script_source_stringifies_a_non_string_source(tmp_path: Path) -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.responses["Debugger.getScriptSource"] = {"scriptSource": 999}
        result = backend.script_source(session_id, "1", tmp_path)
        assert result["source"] == "999"
    finally:
        runner.shutdown()
        backend.close_all()


def test_response_event_for_an_unknown_request_id_is_dropped() -> None:
    backend, session_id, handle, cdp, _page, runner = _make_backend_with_handle()
    try:
        cdp.fire(
            "Network.responseReceived",
            {"requestId": "ghost", "response": {"status": 200, "mimeType": "text/html"}},
        )
        assert backend.network_list(session_id)["total"] == 0
    finally:
        runner.shutdown()
        backend.close_all()


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    from headless_re_mcp.backends.web.client import _playwright_driver_pid

    good = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid=4321))
            )
        )
    )
    assert _playwright_driver_pid(good) == 4321
    # A broken chain yields None rather than raising.
    assert _playwright_driver_pid(SimpleNamespace()) is None
    bad_pid = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=SimpleNamespace(pid=0)))
        )
    )
    assert _playwright_driver_pid(bad_pid) is None
