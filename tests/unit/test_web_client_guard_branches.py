"""Guard, error and payload-shape branches of the Web (CDP) backend.

The web line's existing tests cover navigation timeout clamping, capture
registration, and the binary-body spill. What they leave unexercised are the
smaller decisions that keep an unattended browser session honest: the console
clipper that must stop copying a page-sized log into the ring, the artifact
spill that must refuse a traversal filename, the availability probe, and the
translations that turn a raw Playwright failure into a code the caller can
branch on. Each test here pins one of those branches.

Playwright's browser cannot run in CI, so the page / cdp / session objects here
are stand-ins returning exactly what the driver would at each seam; the backend
logic under test is Python either way. Where a byte threshold matters it is
monkeypatched down so a test asserts the boundary without allocating it.
"""

from __future__ import annotations

import sys
import types
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as webmod
from headless_re_mcp.backends.web.client import (
    WebBackend,
    WebError,
    _clip_console_text,
    _playwright_driver_pid,
    _reap_driver_pid,
    _reap_web_session,
    _response_status,
    _safe_title,
    _spill_bytes,
    _spill_text,
    _WebSession,
)


class _Immediate:
    """A runner stand-in that runs the work inline on the calling thread."""

    def call(self, work: Any, *, timeout: float | None = None) -> Any:
        return work()


def _make_session(page: Any = None, *, runner: Any = None) -> _WebSession:
    closed: list[str] = []
    fake = page or types.SimpleNamespace(url="https://x/", title=lambda: "T")
    context = types.SimpleNamespace(close=lambda: closed.append("context"))
    browser = types.SimpleNamespace(close=lambda: closed.append("browser"))
    playwright = types.SimpleNamespace(stop=lambda: closed.append("stop"))
    handle = _WebSession(playwright, browser, context, fake, cdp=object())
    handle.runner = runner
    handle._closed_markers = closed  # type: ignore[attr-defined]
    return handle


# ---------------------------------------------------------------------------
# _clip_console_text: keep a page-sized log out of the ring.
# ---------------------------------------------------------------------------
def test_clip_console_reads_value_description_then_type() -> None:
    """Each console argument is rendered from value, else description, else type.

    A remote object that ships only a type (an un-previewed function, say) still
    contributes its type name rather than an empty string, so the stored line is
    not silently shorter than what the page logged.
    """
    params = {
        "args": [
            {"value": "hello"},
            {"description": "Error: boom"},
            {"type": "function"},
        ]
    }
    text, truncated = _clip_console_text(params)
    assert text == "hello Error: boom function"
    assert truncated is False


def test_clip_console_skips_a_non_dict_argument() -> None:
    params = {"args": ["not-a-dict", {"value": "kept"}]}
    text, truncated = _clip_console_text(params)
    assert text == "kept"
    assert truncated is False


def test_clip_console_truncates_a_single_oversize_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(webmod, "_MAX_CONSOLE_TEXT", 4)
    text, truncated = _clip_console_text({"args": [{"value": "toolong"}]})
    assert text == "tool"
    assert truncated is True


def test_clip_console_stops_once_the_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A first argument that exactly fills the budget leaves nothing for the
    next, so the loop reports truncation on the following pass rather than
    appending an empty piece.
    """
    monkeypatch.setattr(webmod, "_MAX_CONSOLE_TEXT", 5)
    text, truncated = _clip_console_text({"args": [{"value": "12345"}, {"value": "x"}]})
    assert text == "12345"
    assert truncated is True


def test_clip_console_reserves_a_byte_for_the_separator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Joining costs a space; the second piece stops when only the separator fits."""
    monkeypatch.setattr(webmod, "_MAX_CONSOLE_TEXT", 6)
    text, truncated = _clip_console_text({"args": [{"value": "12345"}, {"value": "y"}]})
    # Five chars consume the budget to 1; the join needs that last byte, so the
    # second argument is dropped and truncation is reported.
    assert text == "12345"
    assert truncated is True


def test_clip_console_joins_two_pieces_within_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(webmod, "_MAX_CONSOLE_TEXT", 8)
    text, truncated = _clip_console_text({"args": [{"value": "12"}, {"value": "34"}]})
    assert text == "12 34"
    assert truncated is False


# ---------------------------------------------------------------------------
# _spill_text / _spill_bytes: inline, spill, or refuse.
# ---------------------------------------------------------------------------
def test_spill_text_inlines_a_small_body(tmp_path: Path) -> None:
    inline, spill, truncated = _spill_text(
        "small", artifact_dir=tmp_path, filename="body.bin", kind="response body"
    )
    assert inline == "small"
    assert spill is None
    assert truncated is False


def test_spill_text_refuses_a_traversal_filename_once_it_must_spill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A body too big to inline goes to disk, and the disk name is guarded.

    The filename comes from the backend, but the same helper serves callers that
    could pass one through, so a name that climbs out of the artifact dir is
    refused before any write.
    """
    monkeypatch.setattr(webmod, "_MAX_INLINE_BODY", 4)
    for bad in ("../escape", "a/b", "."):
        with pytest.raises(WebError) as info:
            _spill_text(
                "way-too-long", artifact_dir=tmp_path, filename=bad, kind="response body"
            )
        assert info.value.code == "invalid_params"


def test_spill_text_spills_the_overflow_and_previews_the_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(webmod, "_MAX_INLINE_BODY", 4)
    inline, spill, truncated = _spill_text(
        "abcdefgh", artifact_dir=tmp_path, filename="body.bin", kind="response body"
    )
    assert inline == "abcd"
    assert truncated is True
    assert spill is not None and spill.read_bytes() == b"abcdefgh"


def test_spill_text_refuses_a_body_over_the_capture_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(webmod, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    with pytest.raises(WebError) as info:
        _spill_text(
            "x" * 32, artifact_dir=tmp_path, filename="body.bin", kind="response body"
        )
    assert info.value.code == "too_large"


def test_spill_bytes_refuses_over_cap_and_bad_filename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(webmod, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    with pytest.raises(WebError) as too_big:
        _spill_bytes(b"x" * 32, artifact_dir=tmp_path, filename="b.bin", kind="response body")
    assert too_big.value.code == "too_large"

    monkeypatch.setattr(webmod, "UNREGISTERED_CAPTURE_MAX_BYTES", 1024)
    with pytest.raises(WebError) as bad_name:
        _spill_bytes(b"raw", artifact_dir=tmp_path, filename="../x", kind="response body")
    assert bad_name.value.code == "invalid_params"


def test_spill_bytes_writes_the_exact_bytes(tmp_path: Path) -> None:
    out = _spill_bytes(
        b"\x00\x01\x02", artifact_dir=tmp_path, filename="b.bin", kind="response body"
    )
    assert out.read_bytes() == b"\x00\x01\x02"


# ---------------------------------------------------------------------------
# _check_available.
# ---------------------------------------------------------------------------
def test_check_available_caches_a_successful_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present playwright flips the probe to available and stays cached.

    The probe imports once; a later call must not re-import, so removing the
    module afterwards leaves an already-available backend unaffected.
    """
    fake_pw = types.ModuleType("playwright")
    fake_sync = types.ModuleType("playwright.sync_api")
    fake_pw.sync_api = fake_sync  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", fake_pw)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync)

    backend = WebBackend()
    backend._check_available()
    assert backend._available is True

    monkeypatch.delitem(sys.modules, "playwright.sync_api", raising=False)
    monkeypatch.delitem(sys.modules, "playwright", raising=False)
    backend._check_available()  # cached: no re-import, no raise


def test_check_available_degrades_when_playwright_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "playwright", None)
    backend = WebBackend()
    backend._available = None
    with pytest.raises(WebError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# status / _get / _runner reservation and handle-shape guards.
# ---------------------------------------------------------------------------
def test_status_reports_a_reservation_as_opening() -> None:
    """A bare object() in the map is an in-flight open, not a live page."""
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    assert backend.status("s") == {"open": False, "opening": True}


def test_status_treats_an_unexpected_handle_as_not_open() -> None:
    backend = WebBackend()
    backend._sessions["s"] = ["not", "a", "session"]  # type: ignore[assignment]
    assert backend.status("s") == {"open": False}


def test_status_of_a_live_session_reports_url_and_title(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = WebBackend()
    handle = _make_session(
        page=types.SimpleNamespace(url="https://live/app", title=lambda: "Live")
    )
    backend._sessions["s"] = handle
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.status("s")
    assert payload == {"open": True, "url": "https://live/app", "title": "Live"}


def test_runner_refuses_a_handle_without_a_browser_thread() -> None:
    backend = WebBackend()
    handle = _make_session(runner=None)
    with pytest.raises(WebError) as info:
        backend._runner(handle)
    assert info.value.code == "invalid_state"


# ---------------------------------------------------------------------------
# navigate / network_get / script_source / dom_snapshot / screenshot errors.
# ---------------------------------------------------------------------------
def test_navigate_wraps_a_goto_failure_as_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(url: str, timeout: float = 0.0, wait_until: str = "") -> None:
        raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

    handle = _make_session(page=types.SimpleNamespace(url="https://x/", goto=boom))
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as info:
        backend.navigate("s", "https://nope.invalid")
    assert info.value.code == "backend_error"


def test_network_get_reports_an_unknown_request_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _Handle:
        lock = Lock()
        requests: dict[str, Any] = {}

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: _Handle())
    with pytest.raises(WebError) as info:
        backend.network_get("s", "missing", tmp_path)
    assert info.value.code == "not_found"


def test_network_get_returns_body_error_when_cdp_has_no_body(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A request with no retrievable body keeps the documented shape.

    CDP has no body for a redirect or an evicted cache entry. The reader must
    still answer with the empty-body fields plus body_error, so a caller reading
    result["body"] never hits a missing key on this path.
    """

    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("No resource with given identifier found")

    class _Handle:
        lock = Lock()
        requests = {"r1": {"requestId": "r1", "url": "https://x/redir", "status": 302}}
        cdp = _Cdp()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == ""
    assert payload["base64_encoded"] is False
    assert payload["body_truncated"] is False
    assert "No resource" in payload["body_error"]
    assert payload["status"] == 302


def test_script_source_passes_through_a_web_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A timeout WebError from the runner is not relabelled as not_found."""

    class _Runner:
        def call(self, work: Any, *, timeout: float | None = None) -> Any:
            raise WebError("timeout", "browser did not respond")

    class _Handle:
        cdp = object()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda h: _Runner())
    with pytest.raises(WebError) as info:
        backend.script_source("s", "42", tmp_path)
    assert info.value.code == "timeout"


def test_script_source_maps_a_missing_script_to_not_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("No script for id: 999")

    class _Handle:
        cdp = _Cdp()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as info:
        backend.script_source("s", "999", tmp_path)
    assert info.value.code == "not_found"


def test_dom_snapshot_wraps_a_failure_and_a_missing_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _RaisingPage:
        url = "https://x/"

        def title(self) -> str:
            return "T"

        def evaluate(self, script: str, arg: int) -> Any:
            raise RuntimeError("execution context destroyed")

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: _make_session(page=_RaisingPage()))
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as info:
        backend.dom_snapshot("s")
    assert info.value.code == "backend_error"

    class _NoDocPage(_RaisingPage):
        def evaluate(self, script: str, arg: int) -> Any:
            return None

    monkeypatch.setattr(backend, "_get", lambda sid: _make_session(page=_NoDocPage()))
    with pytest.raises(WebError) as info2:
        backend.dom_snapshot("s")
    assert info2.value.code == "backend_error"


def test_screenshot_wraps_a_capture_failure_as_backend_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _Page:
        def screenshot(self, path: str, full_page: bool = False) -> None:
            raise RuntimeError("target closed")

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: _make_session(page=_Page()))
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as info:
        backend.screenshot("s", tmp_path / "shot.png")
    assert info.value.code == "backend_error"


# ---------------------------------------------------------------------------
# close reservation / no-runner paths.
# ---------------------------------------------------------------------------
def test_close_of_a_reservation_reports_open_aborted() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True, "note": "open was aborted"}


def test_close_of_a_handle_without_a_runner_tears_down_directly() -> None:
    backend = WebBackend()
    handle = _make_session(runner=None)
    backend._sessions["s"] = handle
    assert backend.close("s") == {"closed": True}
    assert handle._closed_markers == ["context", "browser", "stop"]  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Module helpers: status, driver pid, reaping.
# ---------------------------------------------------------------------------
def test_safe_title_swallows_a_title_failure() -> None:
    class _Page:
        def title(self) -> str:
            raise RuntimeError("detached")

    assert _safe_title(_Page()) == ""


def test_response_status_handles_none_error_and_non_int() -> None:
    assert _response_status(None) is None

    class _Raises:
        @property
        def status(self) -> int:
            raise RuntimeError("gone")

    assert _response_status(_Raises()) is None
    assert _response_status(types.SimpleNamespace(status="200")) is None
    assert _response_status(types.SimpleNamespace(status=404)) == 404


def test_playwright_driver_pid_returns_none_without_the_private_chain() -> None:
    assert _playwright_driver_pid(object()) is None


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    proc = types.SimpleNamespace(pid=4321)
    transport = types.SimpleNamespace(_proc=proc)
    connection = types.SimpleNamespace(_transport=transport)
    impl = types.SimpleNamespace(_connection=connection)
    pw = types.SimpleNamespace(_impl_obj=impl)
    assert _playwright_driver_pid(pw) == 4321


def test_reap_driver_pid_ignores_a_non_driver_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reaping is limited to node/chromium images so a recycled pid is safe.

    The driver pid is discovered, then the OS may recycle it after the driver
    dies. Killing whatever now holds that number would be reaping a stranger, so
    an image that matches no driver marker is left alone.
    """
    terminated: list[int] = []
    monkeypatch.setattr(webmod, "process_image_path", lambda pid: "/usr/bin/unrelated")
    monkeypatch.setattr(webmod, "terminate_pid_tree", lambda pid: terminated.append(pid))
    _reap_driver_pid(0)  # non-positive: returns before any lookup
    _reap_driver_pid(12345)  # positive, but image matches no driver marker
    assert terminated == []


def test_reap_web_session_is_a_noop_without_a_driver_pid() -> None:
    handle = _make_session(runner=None)
    handle.driver_pid = None
    _reap_web_session(handle)  # must not raise


# ---------------------------------------------------------------------------
# _wire_events: the CDP telemetry handlers and their bounded buffers.
# ---------------------------------------------------------------------------
class _CapturingCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.enabled: list[str] = []

    def send(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.enabled.append(method)

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def test_wire_events_enables_the_four_domains_and_registers_handlers() -> None:
    backend = WebBackend()
    handle = _make_session(runner=None)
    handle.cdp = _CapturingCdp()
    backend._wire_events(handle)
    cdp = handle.cdp
    assert set(cdp.enabled) == {
        "Network.enable",
        "Runtime.enable",
        "Debugger.enable",
        "Page.enable",
    }
    assert set(cdp.handlers) == {
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Debugger.scriptParsed",
        "Runtime.consoleAPICalled",
    }


def test_request_ring_drops_oldest_and_response_updates_in_place(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The request ring is bounded, and a response fills in the entry it matches.

    A long-lived tab issues far more requests than a session should retain, so
    the oldest are evicted and counted; a later response for a retained request
    updates status and mime in place rather than appending a second row.
    """
    monkeypatch.setattr(webmod, "_MAX_REQUESTS", 2)
    backend = WebBackend()
    handle = _make_session(runner=None)
    handle.cdp = _CapturingCdp()
    backend._wire_events(handle)
    on_request = handle.cdp.handlers["Network.requestWillBeSent"]
    on_response = handle.cdp.handlers["Network.responseReceived"]

    for index in range(3):
        on_request(
            {
                "requestId": f"r{index}",
                "request": {"url": f"https://x/{index}", "method": "GET"},
                "type": "Document",
            }
        )
    assert handle.requests_dropped == 1
    assert "r0" not in handle.requests

    on_response({"requestId": "r2", "response": {"status": 200, "mimeType": "text/html"}})
    assert handle.requests["r2"]["status"] == 200
    assert handle.requests["r2"]["mimeType"] == "text/html"

    # A response whose request was evicted (or never seen) updates nothing.
    on_response({"requestId": "gone", "response": {"status": 500, "mimeType": "text/html"}})
    assert "gone" not in handle.requests


def test_request_marks_metadata_truncated_when_a_field_is_clipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(webmod, "_MAX_METADATA_BYTES", 3)
    backend = WebBackend()
    handle = _make_session(runner=None)
    handle.cdp = _CapturingCdp()
    backend._wire_events(handle)
    on_request = handle.cdp.handlers["Network.requestWillBeSent"]
    on_request(
        {
            "requestId": "r1",
            "request": {"url": "https://x/", "method": "DELETE"},
            "type": "XHR",
        }
    )
    assert handle.requests["r1"]["metadata_truncated"] is True


def test_script_ring_drops_oldest_and_records_language() -> None:
    backend = WebBackend()
    handle = _make_session(runner=None)
    handle.cdp = _CapturingCdp()
    backend._wire_events(handle)
    on_script = handle.cdp.handlers["Debugger.scriptParsed"]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(webmod, "_MAX_SCRIPTS", 1)
        on_script({"scriptId": "s0", "url": "https://x/a.js"})
        on_script({"scriptId": "s1", "url": "https://x/b.wasm", "scriptLanguage": "WebAssembly"})
    assert handle.scripts_dropped == 1
    assert "s0" not in handle.scripts
    assert handle.scripts["s1"]["language"] == "WebAssembly"


def test_console_ring_counts_drops_once_it_is_full() -> None:
    """A full console ring counts what it evicts, so total stays honest."""
    backend = WebBackend()
    handle = _make_session(runner=None)
    handle.cdp = _CapturingCdp()
    handle.console = deque(maxlen=2)
    backend._wire_events(handle)
    on_console = handle.cdp.handlers["Runtime.consoleAPICalled"]
    for index in range(3):
        on_console({"type": "log", "args": [{"value": f"line {index}"}]})
    assert handle.console_dropped == 1
    assert len(handle.console) == 2
    assert handle.console[-1]["text"] == "line 2"


def test_console_entry_marks_a_truncated_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """An oversize console line is stored clipped and flagged, not verbatim."""
    monkeypatch.setattr(webmod, "_MAX_CONSOLE_TEXT", 4)
    backend = WebBackend()
    handle = _make_session(runner=None)
    handle.cdp = _CapturingCdp()
    backend._wire_events(handle)
    on_console = handle.cdp.handlers["Runtime.consoleAPICalled"]
    on_console({"type": "warning", "args": [{"value": "a-very-long-line"}]})
    stored = handle.console[-1]
    assert stored["type"] == "warning"
    assert stored["text"] == "a-ve"
    assert stored["text_truncated"] is True


# ---------------------------------------------------------------------------
# open(): the launch, reservation and teardown path, on a fake driver.
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class _FakePage:
    def __init__(self) -> None:
        self.url = "https://example/app"
        self._goto_fail = False

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> _FakeResponse:
        if self._goto_fail:
            raise RuntimeError("net::ERR_CONNECTION_REFUSED")
        self.url = url
        return _FakeResponse(200)

    def title(self) -> str:
        return "Example"


class _FakeContext:
    def __init__(self, page: _FakePage) -> None:
        self._page = page
        self.closed = False

    def new_page(self) -> _FakePage:
        return self._page

    def new_cdp_session(self, page: _FakePage) -> _CapturingCdp:
        return _CapturingCdp()

    def close(self) -> None:
        self.closed = True


class _FakeBrowser:
    def __init__(self, page: _FakePage) -> None:
        self._page = page
        self.closed = False

    def new_context(self, ignore_https_errors: bool = False) -> _FakeContext:
        return _FakeContext(self._page)

    def close(self) -> None:
        self.closed = True


class _FakePlaywright:
    def __init__(self, page: _FakePage) -> None:
        self.chromium = types.SimpleNamespace(launch=lambda headless=True: _FakeBrowser(page))
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


def _install_fake_playwright(monkeypatch: pytest.MonkeyPatch, page: _FakePage) -> None:
    def sync_playwright() -> Any:
        return types.SimpleNamespace(start=lambda: _FakePlaywright(page))

    fake_sync = types.ModuleType("playwright.sync_api")
    fake_sync.sync_playwright = sync_playwright  # type: ignore[attr-defined]
    fake_pw = types.ModuleType("playwright")
    fake_pw.sync_api = fake_sync  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", fake_pw)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync)


def test_open_launches_navigates_and_registers_the_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """open builds the browser, navigates, and summarises in one runner call.

    The summary is built on the browser thread rather than by a second status
    call, because between the two a browser exists that no session refers to,
    and a failure there would leave nothing able to close it.
    """
    page = _FakePage()
    _install_fake_playwright(monkeypatch, page)
    backend = WebBackend()
    try:
        summary = backend.open("s", "https://example/app")
        assert summary["opened"] is True
        assert summary["url"] == "https://example/app"
        assert summary["title"] == "Example"
        assert summary["status"] == 200
        assert backend.status("s")["open"] is True
    finally:
        backend.close_all()


def test_open_refuses_a_second_open_for_the_same_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _FakePage()
    _install_fake_playwright(monkeypatch, page)
    backend = WebBackend()
    try:
        backend.open("s", "https://example/app")
        with pytest.raises(WebError) as info:
            backend.open("s", "https://example/app")
        assert info.value.code == "invalid_state"
    finally:
        backend.close_all()


def test_open_reclaims_the_reservation_when_launch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A navigation failure stops the browser and frees the session slot.

    The reservation token is popped so the id is openable again, and the fake
    playwright records that stop() ran, matching the real teardown that keeps a
    failed launch from leaking a Chromium.
    """
    page = _FakePage()
    page._goto_fail = True
    _install_fake_playwright(monkeypatch, page)
    backend = WebBackend()
    try:
        with pytest.raises(WebError) as info:
            backend.open("s", "https://example/app")
        assert info.value.code == "backend_error"
        assert "s" not in backend._sessions
        # The slot is free, so a later good open reuses the id.
        page._goto_fail = False
        summary = backend.open("s", "https://example/app")
        assert summary["opened"] is True
    finally:
        backend.close_all()
