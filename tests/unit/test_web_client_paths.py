"""Helper, event-handler, and method guard paths for the Web (CDP) backend.

The session-scoping and navigation-timeout contracts live in
``test_web_backends.py`` / ``test_web_launch.py``. This file covers the layers
those skip: the console-clipping and artifact-spill helpers, the availability
gate, the ``_Runner`` refusals, the CDP event handlers (eviction and drop
accounting), and the per-method error/spill arms of network/script/dom/
screenshot readers. A fake Playwright package drives ``open`` and ``_wire_events``
without a real browser; the runner itself needs no Playwright and executes the
queued callable on its own thread, so the method paths run for real.
"""

from __future__ import annotations

import base64
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_mod
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

# ---------------------------------------------------------------------------
# _clip_console_text
# ---------------------------------------------------------------------------


def test_clip_console_text_reads_value_description_and_type() -> None:
    params = {
        "args": [
            {"value": "hello"},
            {"description": "obj#1"},
            {"type": "undefined"},
        ]
    }
    text, truncated = _clip_console_text(params)
    assert text == "hello obj#1 undefined"
    assert truncated is False


def test_clip_console_text_skips_non_dict_args() -> None:
    params = {"args": ["not-a-dict", {"value": "kept"}]}
    text, truncated = _clip_console_text(params)
    assert text == "kept"
    assert truncated is False


def test_clip_console_text_truncates_a_giant_argument() -> None:
    params = {"args": [{"value": "x" * (web_mod._MAX_CONSOLE_TEXT + 500)}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True
    assert len(text) == web_mod._MAX_CONSOLE_TEXT


def test_clip_console_text_stops_at_the_separator_boundary() -> None:
    # First arg leaves exactly one byte of budget; the separator the second arg
    # would need then trips the remaining<=1 guard before it is joined.
    params = {"args": [{"value": "y" * (web_mod._MAX_CONSOLE_TEXT - 1)}, {"value": "z"}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True
    assert "z" not in text


def test_clip_console_text_stops_when_the_budget_is_exhausted() -> None:
    # First arg consumes the whole budget; the next iteration bails at the top.
    params = {"args": [{"value": "y" * web_mod._MAX_CONSOLE_TEXT}, {"value": "z"}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True
    assert "z" not in text


# ---------------------------------------------------------------------------
# _spill_text / _spill_bytes
# ---------------------------------------------------------------------------


def test_spill_text_inlines_a_small_payload(tmp_path: Path) -> None:
    inline, spill, cut = _spill_text(
        "small", artifact_dir=tmp_path, filename="x.txt", kind="script source"
    )
    assert inline == "small"
    assert spill is None
    assert cut is False


def test_spill_text_refuses_over_the_cap_up_front(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(web_mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    with pytest.raises(WebError) as caught:
        _spill_text("12345", artifact_dir=tmp_path, filename="x.txt", kind="script source")
    assert caught.value.code == "too_large"


def test_spill_text_rejects_a_traversal_filename(tmp_path: Path) -> None:
    big = "a" * (web_mod._MAX_INLINE_BODY + 10)
    with pytest.raises(WebError) as caught:
        _spill_text(big, artifact_dir=tmp_path, filename="../x.txt", kind="script source")
    assert caught.value.code == "invalid_params"


def test_spill_text_writes_a_preview_and_spill_for_a_large_payload(tmp_path: Path) -> None:
    big = "a" * (web_mod._MAX_INLINE_BODY + 500)
    inline, spill, cut = _spill_text(
        big, artifact_dir=tmp_path, filename="big.txt", kind="script source"
    )
    assert cut is True
    assert spill is not None and spill.exists()
    assert len(inline) == web_mod._MAX_INLINE_BODY


def test_spill_text_refuses_over_cap_after_write(tmp_path: Path, monkeypatch: Any) -> None:
    big = "a" * (web_mod._MAX_INLINE_BODY + 1000)
    monkeypatch.setattr(web_mod, "capped_file_size", lambda path, cap: (cap + 1, True))
    with pytest.raises(WebError) as caught:
        _spill_text(big, artifact_dir=tmp_path, filename="x.txt", kind="script source")
    assert caught.value.code == "too_large"


def test_spill_bytes_refuses_over_the_cap(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(web_mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    with pytest.raises(WebError) as caught:
        _spill_bytes(b"12345", artifact_dir=tmp_path, filename="x.bin", kind="response body")
    assert caught.value.code == "too_large"


def test_spill_bytes_rejects_a_traversal_filename(tmp_path: Path) -> None:
    for bad in ("../evil", "a/b", "", "."):
        with pytest.raises(WebError) as caught:
            _spill_bytes(b"ok", artifact_dir=tmp_path, filename=bad, kind="response body")
        assert caught.value.code == "invalid_params"


def test_spill_bytes_refuses_over_cap_after_write(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(web_mod, "capped_file_size", lambda path, cap: (cap + 1, True))
    with pytest.raises(WebError) as caught:
        _spill_bytes(b"ok", artifact_dir=tmp_path, filename="x.bin", kind="response body")
    assert caught.value.code == "too_large"


def test_spill_bytes_writes_and_returns_the_path(tmp_path: Path) -> None:
    out = _spill_bytes(b"payload", artifact_dir=tmp_path, filename="x.bin", kind="response body")
    assert out.read_bytes() == b"payload"


# ---------------------------------------------------------------------------
# small metadata / status helpers
# ---------------------------------------------------------------------------


def test_bounded_metadata_truncates_over_budget() -> None:
    text, truncated = _bounded_metadata("abcdef", 3)
    assert text == "abc"
    assert truncated is True
    assert _bounded_metadata(None, 10) == ("", False)


def test_response_status_handles_none_and_broken_response() -> None:
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status=200)) == 200

    class _Broken:
        @property
        def status(self) -> int:
            raise RuntimeError("detached")

    assert _response_status(_Broken()) is None


def test_safe_title_returns_empty_when_title_raises() -> None:
    class _Page:
        def title(self) -> str:
            raise RuntimeError("navigating")

    assert _safe_title(_Page()) == ""


# ---------------------------------------------------------------------------
# _playwright_driver_pid / _reap_driver_pid
# ---------------------------------------------------------------------------


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    proc = SimpleNamespace(pid=4321)
    transport = SimpleNamespace(_proc=proc)
    connection = SimpleNamespace(_transport=transport)
    impl = SimpleNamespace(_connection=connection)
    pw = SimpleNamespace(_impl_obj=impl)
    assert _playwright_driver_pid(pw) == 4321
    # A broken chain yields None rather than raising.
    assert _playwright_driver_pid(SimpleNamespace()) is None


def test_reap_driver_pid_ignores_bad_pids_and_non_driver_images(monkeypatch: Any) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web_mod, "terminate_pid_tree", lambda pid: killed.append(pid))
    # Non-positive pid: nothing happens.
    _reap_driver_pid(0)
    assert killed == []
    # A pid whose image is not a driver is left alone.
    monkeypatch.setattr(web_mod, "process_image_path", lambda pid: "/usr/bin/python3")
    _reap_driver_pid(1234)
    assert killed == []
    # A node/chromium image is reaped.
    monkeypatch.setattr(web_mod, "process_image_path", lambda pid: "/opt/node/bin/node")
    _reap_driver_pid(1234)
    assert killed == [1234]


# ---------------------------------------------------------------------------
# _check_available
# ---------------------------------------------------------------------------


def test_check_available_raises_when_playwright_missing() -> None:
    backend = WebBackend()
    backend._available = False
    with pytest.raises(WebError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_check_available_probes_the_import_once(monkeypatch: Any) -> None:
    # Ensure playwright is unimportable, then let the lazy probe run: it must set
    # _available False and refuse, not raise ImportError.
    monkeypatch.setitem(sys.modules, "playwright", None)
    backend = WebBackend()
    assert backend._available is None
    with pytest.raises(WebError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"
    assert backend._available is False


def test_check_available_caches_a_successful_import(monkeypatch: Any) -> None:
    root = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    monkeypatch.setitem(sys.modules, "playwright", root)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    backend = WebBackend()
    backend._check_available()
    assert backend._available is True


# ---------------------------------------------------------------------------
# _Runner refusals
# ---------------------------------------------------------------------------


def test_runner_refuses_after_shutdown() -> None:
    runner = _Runner("test-closed")
    runner.shutdown()
    with pytest.raises(WebError) as caught:
        runner.call(lambda: 1)
    assert caught.value.code == "invalid_state"


def test_runner_refuses_when_wedged() -> None:
    runner = _Runner("test-wedged")
    try:
        runner._wedged = True
        with pytest.raises(WebError) as caught:
            runner.call(lambda: 1)
        assert caught.value.code == "backend_error"
    finally:
        runner.shutdown()


def test_runner_marks_itself_wedged_on_timeout() -> None:
    import time

    runner = _Runner("test-timeout")
    try:
        # The work outlasts the deadline: the call times out, the runner thread
        # stays blocked (it is a daemon), and the runner is marked wedged so the
        # whole session refuses further work instead of queueing behind it.
        with pytest.raises(WebError) as caught:
            runner.call(lambda: time.sleep(2.0), timeout=0.05)
        assert caught.value.code == "timeout"
        assert runner.wedged is True
    finally:
        runner.shutdown()


# ---------------------------------------------------------------------------
# fake browser objects + session fixtures
# ---------------------------------------------------------------------------


class _FakeCDP:
    def __init__(self, responder: Any = None) -> None:
        self.handlers: dict[str, Any] = {}
        self.sent: list[tuple[str, Any]] = []
        self._responder = responder

    def send(self, method: str, params: Any = None) -> Any:
        self.sent.append((method, params))
        if self._responder is not None:
            return self._responder(method, params)
        return {}

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


class _FakePage:
    def __init__(self, *, url: str = "https://example.com/app") -> None:
        self.url = url
        self._evaluate: Any = None
        self._screenshot_error: Exception | None = None
        self._goto_error: Exception | None = None

    def title(self) -> str:
        return "Example"

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> Any:
        if self._goto_error is not None:
            raise self._goto_error
        self.url = url
        return SimpleNamespace(status=200)

    def evaluate(self, script: str, cap: int) -> Any:
        if callable(self._evaluate):
            return self._evaluate(cap)
        return self._evaluate

    def screenshot(self, path: str = "", full_page: bool = False) -> None:
        if self._screenshot_error is not None:
            raise self._screenshot_error
        Path(path).write_bytes(b"\x89PNG fake")


@pytest.fixture
def make_session() -> Any:
    backend = WebBackend()
    runners: list[_Runner] = []

    def _make(*, page: Any = None, cdp: Any = None, sid: str = "s") -> tuple[WebBackend, Any]:
        handle = _WebSession(
            SimpleNamespace(stop=lambda: None),
            SimpleNamespace(close=lambda: None),
            SimpleNamespace(close=lambda: None),
            page or _FakePage(),
            cdp or _FakeCDP(),
        )
        runner = _Runner(f"test-{sid}")
        runners.append(runner)
        handle.runner = runner
        backend._sessions[sid] = handle
        return backend, handle

    yield _make
    for runner in runners:
        runner.shutdown()


# ---------------------------------------------------------------------------
# status / _runner
# ---------------------------------------------------------------------------


def test_status_reports_opening_for_a_reservation_token() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # the bare open() reservation sentinel
    assert backend.status("s") == {"open": False, "opening": True}


def test_status_reports_closed_for_an_unknown_handle_type() -> None:
    backend = WebBackend()
    backend._sessions["s"] = SimpleNamespace()  # neither sentinel nor session
    assert backend.status("s") == {"open": False}


def test_status_reports_open_page_identity(make_session: Any) -> None:
    backend, _ = make_session(page=_FakePage(url="https://live/app"))
    payload = backend.status("s")
    assert payload["open"] is True
    assert payload["url"] == "https://live/app"
    assert payload["title"] == "Example"


def test_runner_rejects_a_handle_without_a_browser_thread() -> None:
    backend = WebBackend()
    handle = _WebSession(
        SimpleNamespace(stop=lambda: None),
        SimpleNamespace(close=lambda: None),
        SimpleNamespace(close=lambda: None),
        _FakePage(),
        _FakeCDP(),
    )
    handle.runner = None
    with pytest.raises(WebError) as caught:
        backend._runner(handle)
    assert caught.value.code == "invalid_state"


# ---------------------------------------------------------------------------
# navigate error arm
# ---------------------------------------------------------------------------


def test_navigate_wraps_a_goto_failure(make_session: Any) -> None:
    page = _FakePage()
    page._goto_error = RuntimeError("net::ERR_NAME_NOT_RESOLVED")
    backend, _ = make_session(page=page)
    with pytest.raises(WebError) as caught:
        backend.navigate("s", "https://nope.invalid")
    assert caught.value.code == "backend_error"


def test_navigate_reports_the_response_status(make_session: Any) -> None:
    backend, _ = make_session(page=_FakePage())
    payload = backend.navigate("s", "https://example.com/app")
    assert payload["url"] == "https://example.com/app"
    assert payload["status"] == 200


# ---------------------------------------------------------------------------
# paginated readers: network_list / console / scripts / har_export
# ---------------------------------------------------------------------------


def test_network_list_paginates_and_reports_totals(make_session: Any) -> None:
    backend, handle = make_session()
    for index in range(5):
        handle.requests[str(index)] = {"requestId": str(index), "url": f"http://{index}"}
    handle.requests_dropped = 2
    payload = backend.network_list("s", offset=1, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["offset"] == 1
    assert payload["has_more"] is True
    assert payload["dropped"] == 2


def test_console_returns_the_newest_tail(make_session: Any) -> None:
    backend, handle = make_session()
    for index in range(4):
        handle.console.append({"type": "log", "text": f"line{index}"})
    handle.console_dropped = 1
    payload = backend.console("s", limit=2)
    assert payload["count"] == 2
    assert payload["console"][-1]["text"] == "line3"
    assert payload["has_more"] is True
    assert payload["dropped"] == 1


def test_scripts_filters_wasm_only(make_session: Any) -> None:
    backend, handle = make_session()
    handle.scripts["1"] = {"scriptId": "1", "url": "a.js", "language": "JavaScript"}
    handle.scripts["2"] = {"scriptId": "2", "url": "b.wasm", "language": "WebAssembly"}
    payload = backend.scripts("s", wasm_only=True)
    assert payload["total"] == 1
    assert payload["scripts"][0]["scriptId"] == "2"


def test_scripts_lists_everything_without_the_wasm_filter(make_session: Any) -> None:
    backend, handle = make_session()
    handle.scripts["1"] = {"scriptId": "1", "url": "a.js", "language": "JavaScript"}
    handle.scripts["2"] = {"scriptId": "2", "url": "b.wasm", "language": "WebAssembly"}
    payload = backend.scripts("s")
    assert payload["total"] == 2


def test_har_export_refuses_over_the_capture_cap(
    make_session: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    backend, handle = make_session()
    handle.requests["1"] = {"requestId": "1", "url": "http://a", "method": "GET"}
    over = web_mod.UNREGISTERED_CAPTURE_MAX_BYTES + 1
    monkeypatch.setattr(
        web_mod,
        "serialize_har",
        lambda entries, max_bytes: SimpleNamespace(
            text="{}", size=over, entry_count=1, truncated=True
        ),
    )
    with pytest.raises(WebError) as caught:
        backend.har_export("s", tmp_path / "capture.har")
    assert caught.value.code == "too_large"


def test_har_export_writes_a_har_file(make_session: Any, tmp_path: Path) -> None:
    backend, handle = make_session()
    handle.requests["1"] = {
        "requestId": "1",
        "url": "http://a",
        "method": "GET",
        "status": 200,
        "mimeType": "text/html",
        "resourceType": "document",
    }
    out = tmp_path / "capture.har"
    payload = backend.har_export("s", out)
    assert payload["entry_count"] == 1
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("{")


def test_network_get_inlines_and_spills_a_large_text_body(
    make_session: Any, tmp_path: Path
) -> None:
    big = "b" * (web_mod._MAX_INLINE_BODY + 300)

    def _responder(method: str, params: Any) -> Any:
        return {"body": big, "base64Encoded": False}

    backend, handle = make_session(cdp=_FakeCDP(responder=_responder))
    handle.requests["r1"] = {"requestId": "r1", "url": "u"}
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body_truncated"] is True
    assert Path(payload["body_path"]).exists()


def test_script_source_spills_a_large_source(make_session: Any, tmp_path: Path) -> None:
    big = "x" * (web_mod._MAX_INLINE_BODY + 300)

    def _responder(method: str, params: Any) -> Any:
        return {"scriptSource": big}

    backend, _ = make_session(cdp=_FakeCDP(responder=_responder))
    payload = backend.script_source("s", "1", tmp_path)
    assert payload["truncated"] is True
    assert Path(payload["source_path"]).exists()


# ---------------------------------------------------------------------------
# close when the runner is wedged
# ---------------------------------------------------------------------------


def test_close_reaps_the_driver_when_the_runner_is_wedged(monkeypatch: Any) -> None:
    reaped: list[int] = []
    monkeypatch.setattr(web_mod, "_reap_driver_pid", lambda pid: reaped.append(pid or 0))
    backend = WebBackend()
    handle = _WebSession(
        SimpleNamespace(stop=lambda: None),
        SimpleNamespace(close=lambda: None),
        SimpleNamespace(close=lambda: None),
        _FakePage(),
        _FakeCDP(),
    )
    handle.driver_pid = 5150
    runner = _Runner("test-wedged-close")
    runner._wedged = True
    handle.runner = runner
    backend._sessions["s"] = handle
    payload = backend.close("s")
    assert payload == {"closed": True, "clean": False}
    assert reaped == [5150]


# ---------------------------------------------------------------------------
# network_get
# ---------------------------------------------------------------------------


def test_network_get_reports_an_unknown_request_id(make_session: Any, tmp_path: Path) -> None:
    backend, _ = make_session()
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "missing", tmp_path)
    assert caught.value.code == "not_found"


def test_network_get_returns_body_error_when_cdp_has_no_body(
    make_session: Any, tmp_path: Path
) -> None:
    def _responder(method: str, params: Any) -> Any:
        raise RuntimeError("No resource with given identifier found")

    cdp = _FakeCDP(responder=_responder)
    backend, handle = make_session(cdp=cdp)
    handle.requests["r1"] = {"requestId": "r1", "url": "u", "status": 200}
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == ""
    assert payload["body_error"]
    assert payload["body_truncated"] is False


def test_network_get_stringifies_a_non_string_text_body(
    make_session: Any, tmp_path: Path
) -> None:
    def _responder(method: str, params: Any) -> Any:
        return {"body": 12345, "base64Encoded": False}

    backend, handle = make_session(cdp=_FakeCDP(responder=_responder))
    handle.requests["r1"] = {"requestId": "r1", "url": "u"}
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == "12345"
    assert payload["base64_encoded"] is False


def test_network_get_decodes_and_spills_a_base64_body(
    make_session: Any, tmp_path: Path
) -> None:
    encoded = base64.b64encode(b"\x00\x01\x02binary").decode("ascii")

    def _responder(method: str, params: Any) -> Any:
        return {"body": encoded, "base64Encoded": True}

    backend, handle = make_session(cdp=_FakeCDP(responder=_responder))
    handle.requests["r1"] = {"requestId": "r1", "url": "u"}
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["base64_encoded"] is True
    assert payload["body_bytes"] == len(b"\x00\x01\x02binary")
    assert Path(payload["body_path"]).read_bytes() == b"\x00\x01\x02binary"


def test_network_get_reports_invalid_base64(make_session: Any, tmp_path: Path) -> None:
    def _responder(method: str, params: Any) -> Any:
        return {"body": "a", "base64Encoded": True}  # 1 char cannot be base64

    backend, handle = make_session(cdp=_FakeCDP(responder=_responder))
    handle.requests["r1"] = {"requestId": "r1", "url": "u"}
    payload = backend.network_get("s", "r1", tmp_path)
    assert "not valid base64" in payload["body_error"]


# ---------------------------------------------------------------------------
# script_source
# ---------------------------------------------------------------------------


def test_script_source_reraises_a_web_error(make_session: Any, tmp_path: Path) -> None:
    def _responder(method: str, params: Any) -> Any:
        raise WebError("timeout", "runner stalled")

    backend, _ = make_session(cdp=_FakeCDP(responder=_responder))
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "1", tmp_path)
    assert caught.value.code == "timeout"


def test_script_source_maps_a_generic_failure_to_not_found(
    make_session: Any, tmp_path: Path
) -> None:
    def _responder(method: str, params: Any) -> Any:
        raise RuntimeError("no script with id")

    backend, _ = make_session(cdp=_FakeCDP(responder=_responder))
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "1", tmp_path)
    assert caught.value.code == "not_found"


def test_script_source_stringifies_a_non_string_source(
    make_session: Any, tmp_path: Path
) -> None:
    def _responder(method: str, params: Any) -> Any:
        return {"scriptSource": 999}

    backend, _ = make_session(cdp=_FakeCDP(responder=_responder))
    payload = backend.script_source("s", "1", tmp_path)
    assert payload["source"] == "999"


# ---------------------------------------------------------------------------
# dom_snapshot / screenshot
# ---------------------------------------------------------------------------


def test_dom_snapshot_wraps_an_evaluate_failure(make_session: Any) -> None:
    page = _FakePage()
    page._evaluate = lambda cap: (_ for _ in ()).throw(RuntimeError("execution ctx destroyed"))
    backend, _ = make_session(page=page)
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")
    assert caught.value.code == "backend_error"


def test_dom_snapshot_rejects_a_non_dict_result(make_session: Any) -> None:
    page = _FakePage()
    page._evaluate = "not-a-dict"
    backend, _ = make_session(page=page)
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")
    assert caught.value.code == "backend_error"


def test_dom_snapshot_returns_clipped_html(make_session: Any) -> None:
    page = _FakePage()
    page._evaluate = {"html": "<html></html>", "truncated": False}
    backend, _ = make_session(page=page)
    payload = backend.dom_snapshot("s")
    assert payload["html"] == "<html></html>"
    assert payload["truncated"] is False


def test_screenshot_wraps_a_capture_failure(make_session: Any, tmp_path: Path) -> None:
    page = _FakePage()
    page._screenshot_error = RuntimeError("target closed")
    backend, _ = make_session(page=page)
    with pytest.raises(WebError) as caught:
        backend.screenshot("s", tmp_path / "shot.png")
    assert caught.value.code == "backend_error"


def test_screenshot_refuses_over_cap(make_session: Any, tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(web_mod, "capped_file_size", lambda path, cap: (cap + 1, True))
    backend, _ = make_session()
    with pytest.raises(WebError) as caught:
        backend.screenshot("s", tmp_path / "shot.png")
    assert caught.value.code == "too_large"


def test_screenshot_success_reports_size(make_session: Any, tmp_path: Path) -> None:
    backend, _ = make_session()
    payload = backend.screenshot("s", tmp_path / "shot.png")
    assert payload["size"] == len(b"\x89PNG fake")
    assert Path(payload["path"]).exists()


# ---------------------------------------------------------------------------
# event handlers via _wire_events (eviction + drop accounting)
# ---------------------------------------------------------------------------


def _wired_handle(monkeypatch: Any, **caps: int) -> tuple[WebBackend, Any, _FakeCDP]:
    for name, value in caps.items():
        monkeypatch.setattr(web_mod, name, value)
    backend = WebBackend()
    cdp = _FakeCDP()
    handle = _WebSession(
        SimpleNamespace(stop=lambda: None),
        SimpleNamespace(close=lambda: None),
        SimpleNamespace(close=lambda: None),
        _FakePage(),
        cdp,
    )
    backend._wire_events(handle)
    return backend, handle, cdp


def test_on_request_evicts_the_oldest_over_the_cap(monkeypatch: Any) -> None:
    backend, handle, cdp = _wired_handle(monkeypatch, _MAX_REQUESTS=1)
    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_request({"requestId": "a", "request": {"url": "http://a", "method": "GET"}})
    on_request({"requestId": "b", "request": {"url": "http://b", "method": "GET"}})
    assert handle.requests_dropped == 1
    assert "b" in handle.requests
    assert "a" not in handle.requests


def test_on_response_updates_status_and_mime(monkeypatch: Any) -> None:
    backend, handle, cdp = _wired_handle(monkeypatch)
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "a", "request": {"url": "http://a", "method": "GET"}}
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "a", "response": {"status": 404, "mimeType": "text/html"}}
    )
    assert handle.requests["a"]["status"] == 404
    assert handle.requests["a"]["mimeType"] == "text/html"


def test_on_script_evicts_the_oldest_over_the_cap(monkeypatch: Any) -> None:
    backend, handle, cdp = _wired_handle(monkeypatch, _MAX_SCRIPTS=1)
    on_script = cdp.handlers["Debugger.scriptParsed"]
    on_script({"scriptId": "1", "url": "http://a.js"})
    on_script({"scriptId": "2", "url": "http://b.js", "scriptLanguage": "WebAssembly"})
    assert handle.scripts_dropped == 1
    assert "2" in handle.scripts


def test_on_console_counts_drops_when_the_ring_is_full(monkeypatch: Any) -> None:
    backend, handle, cdp = _wired_handle(monkeypatch, _MAX_CONSOLE=1)
    on_console = cdp.handlers["Runtime.consoleAPICalled"]
    on_console({"type": "log", "args": [{"value": "first"}]})
    on_console({"type": "warn", "args": [{"value": "second"}]})
    assert handle.console_dropped == 1
    assert list(handle.console)[-1]["text"] == "second"


def test_handlers_flag_metadata_truncation(monkeypatch: Any) -> None:
    backend, handle, cdp = _wired_handle(monkeypatch)
    huge = "u" * (web_mod._MAX_URL_BYTES + 50)
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "a", "request": {"url": huge, "method": "GET"}}
    )
    assert handle.requests["a"]["metadata_truncated"] is True

    big_mime = "m" * (web_mod._MAX_METADATA_BYTES + 5)
    cdp.handlers["Network.responseReceived"](
        {"requestId": "a", "response": {"status": 200, "mimeType": big_mime}}
    )
    assert handle.requests["a"]["metadata_truncated"] is True

    cdp.handlers["Debugger.scriptParsed"]({"scriptId": "1", "url": huge})
    assert handle.scripts["1"]["metadata_truncated"] is True

    cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "log", "args": [{"value": "z" * (web_mod._MAX_CONSOLE_TEXT + 5)}]}
    )
    assert list(handle.console)[-1]["text_truncated"] is True


def test_on_response_ignores_an_unknown_request_id(monkeypatch: Any) -> None:
    backend, handle, cdp = _wired_handle(monkeypatch)
    # No matching requestWillBeSent: the response update finds no entry and is a
    # no-op rather than creating a partial row.
    cdp.handlers["Network.responseReceived"](
        {"requestId": "ghost", "response": {"status": 200, "mimeType": "text/html"}}
    )
    assert "ghost" not in handle.requests


# ---------------------------------------------------------------------------
# close / close_all
# ---------------------------------------------------------------------------


def test_close_uses_direct_teardown_when_there_is_no_runner() -> None:
    backend = WebBackend()
    closed: list[str] = []
    handle = _WebSession(
        SimpleNamespace(stop=lambda: closed.append("stop")),
        SimpleNamespace(close=lambda: closed.append("browser")),
        SimpleNamespace(close=lambda: closed.append("context")),
        _FakePage(),
        _FakeCDP(),
    )
    handle.runner = None
    backend._sessions["s"] = handle
    assert backend.close("s") == {"closed": True}
    assert closed == ["context", "browser", "stop"]


def test_close_reports_aborted_open_for_a_reservation_token() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()
    assert backend.close("s") == {"closed": True, "note": "open was aborted"}


def test_close_all_closes_each_live_session(make_session: Any) -> None:
    backend, _ = make_session(sid="s")
    # close_all must iterate and reclaim without raising.
    backend.close_all()
    assert backend._sessions == {}


# ---------------------------------------------------------------------------
# open() through a fake Playwright
# ---------------------------------------------------------------------------


def _install_fake_playwright(
    monkeypatch: Any, *, launch_error: Exception | None = None, driver_pid: int | None = 999001
) -> None:
    page = _FakePage()

    class _Context:
        def new_page(self) -> Any:
            return page

        def new_cdp_session(self, page: Any) -> Any:
            return _FakeCDP()

        def close(self) -> None:
            pass

    class _Browser:
        def new_context(self, **kwargs: Any) -> Any:
            return _Context()

        def close(self) -> None:
            pass

    class _Chromium:
        def launch(self, headless: bool = True) -> Any:
            if launch_error is not None:
                raise launch_error
            return _Browser()

    class _Playwright:
        chromium = _Chromium()
        # The private chain _playwright_driver_pid walks to find the node driver.
        # A None pid models a Playwright build that does not expose the chain.
        _impl_obj = SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid=driver_pid))
            )
        )

        def stop(self) -> None:
            pass

    class _SyncCtx:
        def start(self) -> Any:
            return _Playwright()

    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: _SyncCtx()  # type: ignore[attr-defined]
    root = types.ModuleType("playwright")
    monkeypatch.setitem(sys.modules, "playwright", root)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)


def test_open_launches_wires_and_navigates(monkeypatch: Any) -> None:
    _install_fake_playwright(monkeypatch)
    backend = WebBackend()
    try:
        summary = backend.open("s", "https://example.com/app", timeout=5.0)
        assert summary["opened"] is True
        assert summary["status"] == 200
        assert summary["url"] == "https://example.com/app"
        assert backend.status("s")["open"] is True
    finally:
        backend.close_all()


def test_open_with_no_url_skips_navigation(monkeypatch: Any) -> None:
    # driver_pid None exercises the "no pid to track" branch as well.
    _install_fake_playwright(monkeypatch, driver_pid=None)
    backend = WebBackend()
    try:
        summary = backend.open("s", "", timeout=5.0)
        assert summary["opened"] is True
        # No navigation happened, so there is no HTTP status to report.
        assert "status" not in summary
    finally:
        backend.close_all()


def test_open_rejects_a_second_open_for_the_same_session(monkeypatch: Any) -> None:
    _install_fake_playwright(monkeypatch)
    backend = WebBackend()
    try:
        backend.open("s", "https://example.com/app", timeout=5.0)
        with pytest.raises(WebError) as caught:
            backend.open("s", "https://example.com/app", timeout=5.0)
        assert caught.value.code == "invalid_state"
    finally:
        backend.close_all()


def test_open_cleans_up_and_frees_the_slot_on_launch_failure(monkeypatch: Any) -> None:
    _install_fake_playwright(monkeypatch, launch_error=RuntimeError("chrome crashed"))
    reaped: list[int] = []
    monkeypatch.setattr(web_mod, "_reap_driver_pid", lambda pid: reaped.append(pid or 0))
    backend = WebBackend()
    with pytest.raises(WebError) as caught:
        backend.open("s", "https://example.com/app", timeout=5.0)
    assert caught.value.code == "backend_error"
    # The reservation must not linger, so a retry can open the same id, and the
    # driver pid captured before the crash is reaped.
    assert "s" not in backend._sessions
    assert reaped == [999001]


def test_module_error_is_a_runtime_error() -> None:
    assert issubclass(web_mod.WebError, RuntimeError)
