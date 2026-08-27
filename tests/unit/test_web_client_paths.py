"""WebBackend pure helpers, the _Runner state machine, and method contracts.

The browser-driving path needs Chromium and is exercised elsewhere; what is
covered here is everything around it that does not:

* the pure helpers -- navigation-timeout clamping, metadata/console clipping,
  the text/bytes artifact spillers, the title/status/driver-pid readers, and
  the driver reaper's image-marker gate;
* the ``_Runner`` thread contract -- closed/wedged refusal, the timeout that
  wedges a session, and normal result/exception delivery;
* the ``WebBackend`` guards and readouts that run against a fake session --
  status/get/runner guards, navigate/dom/screenshot error mapping, the
  network/console/scripts pagers, the response-body spill (text and base64),
  and the close lifecycle (no session, aborted open, clean, wedged).

No real browser is launched; a fake page/CDP pair backs a real ``_Runner``.
"""

from __future__ import annotations

import base64
import sys
import types
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web
from headless_re_mcp.backends.web.client import (
    UNREGISTERED_CAPTURE_MAX_BYTES,
    WebBackend,
    WebError,
    _bound_nav_timeout,
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

_RUNNERS: list[_Runner] = []


@pytest.fixture(autouse=True)
def _shutdown_runners() -> Any:
    yield
    while _RUNNERS:
        runner = _RUNNERS.pop()
        runner.shutdown()


# --------------------------------------------------------------------------
# _bound_nav_timeout / _bounded_metadata
# --------------------------------------------------------------------------
def test_bound_nav_timeout_clamps_and_refuses_non_positive() -> None:
    assert _bound_nav_timeout(10) == 10.0
    assert _bound_nav_timeout(10_000) == web._MAX_NAV_TIMEOUT_S
    with pytest.raises(WebError) as caught:
        _bound_nav_timeout(0)
    assert caught.value.code == "invalid_params"


def test_bounded_metadata_passes_short_and_truncates_long() -> None:
    assert _bounded_metadata("short", 100) == ("short", False)
    assert _bounded_metadata(None, 100) == ("", False)
    assert _bounded_metadata(1234, 100) == ("1234", False)
    text, truncated = _bounded_metadata("x" * 50, 10)
    assert truncated is True and len(text.encode("utf-8")) <= 10


# --------------------------------------------------------------------------
# _clip_console_text
# --------------------------------------------------------------------------
def test_clip_console_text_reads_value_description_and_type() -> None:
    params = {
        "args": [
            {"value": "hello"},
            {"description": "world"},
            {"type": "object"},
            "not-a-dict",
        ]
    }
    text, truncated = _clip_console_text(params)
    assert text == "hello world object" and truncated is False


def test_clip_console_text_truncates_a_giant_argument() -> None:
    params = {"args": [{"value": "a" * (web._MAX_CONSOLE_TEXT + 10)}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True and len(text) <= web._MAX_CONSOLE_TEXT


def test_clip_console_text_stops_between_arguments_at_the_ceiling() -> None:
    # The first argument exactly fills the budget; the separator before the
    # second cannot fit, so it stops and reports truncation.
    params = {"args": [{"value": "a" * web._MAX_CONSOLE_TEXT}, {"value": "b"}]}
    text, truncated = _clip_console_text(params)
    assert truncated is True and "b" not in text


# --------------------------------------------------------------------------
# _spill_text / _spill_bytes
# --------------------------------------------------------------------------
def test_spill_text_inlines_small_and_spills_large(tmp_path: Path) -> None:
    inline, spill, cut = _spill_text(
        "small", artifact_dir=tmp_path, filename="a.txt", kind="body"
    )
    assert inline == "small" and spill is None and cut is False

    big = "x" * (web._MAX_INLINE_BODY + 1000)
    inline, spill, cut = _spill_text(
        big, artifact_dir=tmp_path, filename="b.txt", kind="body"
    )
    assert cut is True and spill is not None and spill.read_bytes() == big.encode("utf-8")


def test_spill_text_refuses_over_cap_and_bad_filename(tmp_path: Path) -> None:
    huge = "x" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1)
    with pytest.raises(WebError) as too_large:
        _spill_text(huge, artifact_dir=tmp_path, filename="c.txt", kind="body")
    assert too_large.value.code == "too_large"

    big = "x" * (web._MAX_INLINE_BODY + 1)
    with pytest.raises(WebError) as bad_name:
        _spill_text(big, artifact_dir=tmp_path, filename="../escape", kind="body")
    assert bad_name.value.code == "invalid_params"


def test_spill_bytes_writes_and_refuses(tmp_path: Path) -> None:
    out = _spill_bytes(b"binary", artifact_dir=tmp_path, filename="d.bin", kind="body")
    assert out.read_bytes() == b"binary"

    with pytest.raises(WebError) as too_large:
        _spill_bytes(
            b"x" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1),
            artifact_dir=tmp_path,
            filename="e.bin",
            kind="body",
        )
    assert too_large.value.code == "too_large"

    with pytest.raises(WebError) as bad_name:
        _spill_bytes(b"x", artifact_dir=tmp_path, filename="a/b", kind="body")
    assert bad_name.value.code == "invalid_params"


# --------------------------------------------------------------------------
# trailing readers
# --------------------------------------------------------------------------
def test_safe_title_reads_and_swallows_failures() -> None:
    assert _safe_title(types.SimpleNamespace(title=lambda: "Home")) == "Home"

    def _boom() -> str:
        raise RuntimeError("page gone")

    assert _safe_title(types.SimpleNamespace(title=_boom)) == ""


def test_response_status_reads_ints_and_absences() -> None:
    assert _response_status(None) is None
    assert _response_status(types.SimpleNamespace(status=200)) == 200
    assert _response_status(types.SimpleNamespace(status="oops")) is None

    class _Boom:
        @property
        def status(self) -> int:
            raise RuntimeError("no status")

    assert _response_status(_Boom()) is None


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    proc = types.SimpleNamespace(pid=4321)
    transport = types.SimpleNamespace(_proc=proc)
    connection = types.SimpleNamespace(_transport=transport)
    impl = types.SimpleNamespace(_connection=connection)
    pw = types.SimpleNamespace(_impl_obj=impl)
    assert _playwright_driver_pid(pw) == 4321

    # A broken chain reports None rather than raising.
    assert _playwright_driver_pid(types.SimpleNamespace(_impl_obj=None)) is None
    # A non-positive pid is not a usable handle.
    proc0 = types.SimpleNamespace(pid=0)
    pw0 = types.SimpleNamespace(
        _impl_obj=types.SimpleNamespace(
            _connection=types.SimpleNamespace(
                _transport=types.SimpleNamespace(_proc=proc0)
            )
        )
    )
    assert _playwright_driver_pid(pw0) is None


def test_reap_driver_pid_only_kills_a_matching_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web, "terminate_pid_tree", lambda pid: killed.append(pid))

    # Not a pid -> nothing happens.
    _reap_driver_pid(None)
    assert killed == []

    # An image that is not a browser driver is left alone.
    monkeypatch.setattr(web, "process_image_path", lambda pid: "/usr/bin/python")
    _reap_driver_pid(1234)
    assert killed == []

    # A node/chromium image is reaped.
    monkeypatch.setattr(web, "process_image_path", lambda pid: "/opt/node/bin/node")
    _reap_driver_pid(1234)
    assert killed == [1234]


# --------------------------------------------------------------------------
# _Runner
# --------------------------------------------------------------------------
def _runner(name: str = "test") -> _Runner:
    runner = _Runner(name)
    _RUNNERS.append(runner)
    return runner


def test_runner_delivers_results_and_exceptions() -> None:
    runner = _runner()
    assert runner.call(lambda: 21 * 2) == 42

    def _boom() -> None:
        raise ValueError("work failed")

    with pytest.raises(ValueError):
        runner.call(_boom)


def test_runner_refuses_after_close() -> None:
    runner = _runner()
    runner.shutdown()
    with pytest.raises(WebError) as caught:
        runner.call(lambda: 1)
    assert caught.value.code == "invalid_state"


def test_runner_wedges_on_timeout_then_refuses() -> None:
    import time

    runner = _runner()
    with pytest.raises(WebError) as caught:
        runner.call(lambda: time.sleep(1.0), timeout=0.05)
    assert caught.value.code == "timeout"
    assert runner.wedged is True
    # A wedged runner refuses further work with a distinct code.
    with pytest.raises(WebError) as refused:
        runner.call(lambda: 1)
    assert refused.value.code == "backend_error"


# --------------------------------------------------------------------------
# session fakes
# --------------------------------------------------------------------------
class _FakePage:
    def __init__(self, url: str = "https://example.test/", title: str = "Example") -> None:
        self.url = url
        self._title = title

    def title(self) -> str:
        return self._title

    def goto(self, url: str, timeout: float | None = None, wait_until: str | None = None) -> Any:
        self.url = url
        return types.SimpleNamespace(status=200)

    def evaluate(self, script: str, cap: int) -> Any:
        return {"html": "<html></html>", "truncated": False}

    def screenshot(self, path: str | None = None, full_page: bool = False) -> None:
        Path(path).write_bytes(b"PNGDATA")


class _FakeCdp:
    def __init__(self, responder: Any = None) -> None:
        self._responder = responder or (lambda method, params=None: {})

    def send(self, method: str, params: Any = None) -> Any:
        return self._responder(method, params)

    def on(self, event: str, handler: Any) -> None:
        return None


def _make_session(page: Any = None, cdp: Any = None) -> _WebSession:
    pw = types.SimpleNamespace(stop=lambda: None)
    browser = types.SimpleNamespace(close=lambda: None)
    context = types.SimpleNamespace(close=lambda: None)
    return _WebSession(pw, browser, context, page or _FakePage(), cdp or _FakeCdp())


def _backend(session_id: str, handle: _WebSession | None) -> WebBackend:
    backend = WebBackend()
    backend._available = True
    if handle is not None:
        handle.runner = _runner(f"web-{session_id}")
        backend._sessions[session_id] = handle
    return backend


# --------------------------------------------------------------------------
# _wire_events
# --------------------------------------------------------------------------
class _CapturingCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.enabled: list[str] = []

    def send(self, method: str, params: Any = None) -> Any:
        self.enabled.append(method)
        return {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def test_wire_events_records_telemetry_and_flags_truncation() -> None:
    cdp = _CapturingCdp()
    handle = _make_session(cdp=cdp)
    backend = _backend("s", handle)
    backend._wire_events(handle)
    assert "Network.enable" in cdp.enabled

    long_url = "https://example.test/" + "q" * (web._MAX_URL_BYTES + 100)
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "1", "request": {"url": long_url, "method": "GET"}, "type": "Document"}
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}}
    )
    cdp.handlers["Debugger.scriptParsed"](
        {"scriptId": "s1", "url": "a.js", "scriptLanguage": "JavaScript"}
    )
    cdp.handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "hi"}]})

    entry = handle.requests["1"]
    assert entry["status"] == 200 and entry["mimeType"] == "text/html"
    # The oversized URL tripped the metadata-truncation flag.
    assert entry["metadata_truncated"] is True
    assert handle.scripts["s1"]["url"] == "a.js"
    assert handle.console[-1]["text"] == "hi"

    # A response for an unknown request id is dropped rather than crashing.
    cdp.handlers["Network.responseReceived"](
        {"requestId": "ghost", "response": {"status": 404, "mimeType": "text/plain"}}
    )
    assert "ghost" not in handle.requests


# --------------------------------------------------------------------------
# availability + status + guards
# --------------------------------------------------------------------------
def test_check_available_refuses_without_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    backend = WebBackend()
    backend._available = None
    with pytest.raises(WebError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_status_reports_closed_opening_and_open() -> None:
    backend = WebBackend()
    assert backend.status("nope") == {"open": False}

    backend._sessions["opening"] = object()  # type: ignore[assignment]
    assert backend.status("opening") == {"open": False, "opening": True}

    handle = _make_session()
    live = _backend("live", handle)
    payload = live.status("live")
    assert payload["open"] is True and payload["title"] == "Example"


def test_get_and_runner_guards() -> None:
    backend = WebBackend()
    with pytest.raises(WebError) as caught:
        backend._get("missing")
    assert caught.value.code == "invalid_state"

    handle = _make_session()
    handle.runner = None
    with pytest.raises(WebError) as no_runner:
        backend._runner(handle)
    assert no_runner.value.code == "invalid_state"


# --------------------------------------------------------------------------
# navigate / dom_snapshot / screenshot error mapping
# --------------------------------------------------------------------------
def test_navigate_success_and_failure() -> None:
    handle = _make_session()
    backend = _backend("s", handle)
    payload = backend.navigate("s", "https://example.test/next")
    assert payload["status"] == 200 and payload["title"] == "Example"

    class _BoomPage(_FakePage):
        def goto(
            self, url: str, timeout: float | None = None, wait_until: str | None = None
        ) -> Any:
            raise RuntimeError("dns failure")

    handle = _make_session(page=_BoomPage())
    backend = _backend("boom", handle)
    with pytest.raises(WebError) as caught:
        backend.navigate("boom", "https://bad.test/")
    assert caught.value.code == "backend_error"


def test_dom_snapshot_maps_bad_documents() -> None:
    handle = _make_session()
    backend = _backend("s", handle)
    assert backend.dom_snapshot("s")["html"] == "<html></html>"

    class _NonDict(_FakePage):
        def evaluate(self, script: str, cap: int) -> Any:
            return "not-a-dict"

    handle = _make_session(page=_NonDict())
    backend = _backend("n", handle)
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("n")
    assert caught.value.code == "backend_error"

    class _BoomEval(_FakePage):
        def evaluate(self, script: str, cap: int) -> Any:
            raise RuntimeError("eval crashed")

    handle = _make_session(page=_BoomEval())
    backend = _backend("b", handle)
    with pytest.raises(WebError) as boom:
        backend.dom_snapshot("b")
    assert boom.value.code == "backend_error"


def test_screenshot_writes_and_maps_failure(tmp_path: Path) -> None:
    handle = _make_session()
    backend = _backend("s", handle)
    payload = backend.screenshot("s", tmp_path / "shots" / "s.png")
    assert payload["size"] == len(b"PNGDATA")

    class _BoomShot(_FakePage):
        def screenshot(self, path: str | None = None, full_page: bool = False) -> None:
            raise RuntimeError("screencap failed")

    handle = _make_session(page=_BoomShot())
    backend = _backend("b", handle)
    with pytest.raises(WebError) as caught:
        backend.screenshot("b", tmp_path / "b.png")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# pagers: network_list / console / scripts
# --------------------------------------------------------------------------
def test_network_list_pages_and_reports_dropped() -> None:
    handle = _make_session()
    for index in range(5):
        handle.requests[str(index)] = {"requestId": str(index), "url": f"u{index}"}
    handle.requests_dropped = 2
    backend = _backend("s", handle)
    payload = backend.network_list("s", offset=1, limit=2)
    assert payload["count"] == 2 and payload["total"] == 5
    assert payload["has_more"] is True and payload["dropped"] == 2


def test_console_returns_the_newest_tail() -> None:
    handle = _make_session()
    for index in range(4):
        handle.console.append({"type": "log", "text": f"m{index}"})
    handle.console_dropped = 1
    backend = _backend("s", handle)
    payload = backend.console("s", limit=2)
    assert [e["text"] for e in payload["console"]] == ["m2", "m3"]
    assert payload["has_more"] is True and payload["dropped"] == 1


def test_scripts_filters_wasm_only() -> None:
    handle = _make_session()
    handle.scripts["1"] = {"scriptId": "1", "url": "a.js", "language": "JavaScript"}
    handle.scripts["2"] = {"scriptId": "2", "url": "b.wasm", "language": "WebAssembly"}
    backend = _backend("s", handle)
    all_scripts = backend.scripts("s")
    assert all_scripts["total"] == 2
    wasm = backend.scripts("s", wasm_only=True)
    assert wasm["total"] == 1 and wasm["scripts"][0]["scriptId"] == "2"


# --------------------------------------------------------------------------
# network_get / script_source body handling
# --------------------------------------------------------------------------
def test_network_get_unknown_id_and_body_error(tmp_path: Path) -> None:
    handle = _make_session()
    backend = _backend("s", handle)
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "missing", tmp_path)
    assert caught.value.code == "not_found"

    handle.requests["r1"] = {"requestId": "r1", "url": "u", "status": 200}

    def _boom(method: str, params: Any = None) -> Any:
        raise RuntimeError("no body cached")

    handle.cdp = _FakeCdp(_boom)
    result = backend.network_get("s", "r1", tmp_path)
    assert result["body"] == "" and "body_error" in result


def test_network_get_spills_text_and_base64(tmp_path: Path) -> None:
    handle = _make_session()
    handle.requests["t"] = {"requestId": "t", "url": "u"}
    handle.requests["b"] = {"requestId": "b", "url": "u"}
    backend = _backend("s", handle)

    handle.cdp = _FakeCdp(
        lambda method, params=None: {"body": "plain text", "base64Encoded": False}
    )
    text_result = backend.network_get("s", "t", tmp_path)
    assert text_result["body"] == "plain text" and text_result["base64_encoded"] is False

    encoded = base64.b64encode(b"\x00\x01\x02binary").decode("ascii")
    handle.cdp = _FakeCdp(lambda method, params=None: {"body": encoded, "base64Encoded": True})
    bin_result = backend.network_get("s", "b", tmp_path)
    assert bin_result["base64_encoded"] is True
    assert Path(bin_result["body_path"]).read_bytes() == b"\x00\x01\x02binary"


def test_network_get_reports_bad_base64(tmp_path: Path) -> None:
    handle = _make_session()
    handle.requests["x"] = {"requestId": "x", "url": "u"}
    backend = _backend("s", handle)
    handle.cdp = _FakeCdp(
        lambda method, params=None: {"body": "!!!notb64!!!", "base64Encoded": True}
    )
    result = backend.network_get("s", "x", tmp_path)
    assert "body_error" in result and "base64" in result["body_error"]


def test_script_source_maps_a_fetch_failure(tmp_path: Path) -> None:
    handle = _make_session()
    backend = _backend("s", handle)

    def _boom(method: str, params: Any = None) -> Any:
        raise RuntimeError("no such script")

    handle.cdp = _FakeCdp(_boom)
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "42", tmp_path)
    assert caught.value.code == "not_found"


def test_script_source_returns_inline_source(tmp_path: Path) -> None:
    handle = _make_session()
    backend = _backend("s", handle)
    handle.cdp = _FakeCdp(lambda method, params=None: {"scriptSource": "console.log(1)"})
    result = backend.script_source("s", "42", tmp_path)
    assert result["source"] == "console.log(1)" and result["truncated"] is False


# --------------------------------------------------------------------------
# har_export
# --------------------------------------------------------------------------
def test_har_export_writes_entries(tmp_path: Path) -> None:
    handle = _make_session()
    handle.requests["1"] = {
        "method": "GET",
        "url": "https://example.test/",
        "status": 200,
        "mimeType": "text/html",
        "resourceType": "document",
    }
    backend = _backend("s", handle)
    out = tmp_path / "capture.har"
    payload = backend.har_export("s", out)
    assert payload["entry_count"] == 1 and out.exists()


# --------------------------------------------------------------------------
# close lifecycle
# --------------------------------------------------------------------------
def test_close_reports_no_session_and_aborted_open() -> None:
    backend = WebBackend()
    assert backend.close("nope") == {"closed": False, "note": "no web session was open"}

    backend._sessions["opening"] = object()  # type: ignore[assignment]
    assert backend.close("opening") == {"closed": True, "note": "open was aborted"}


def test_close_without_a_runner_closes_directly() -> None:
    backend = WebBackend()
    handle = _make_session()
    handle.runner = None
    backend._sessions["s"] = handle
    assert backend.close("s") == {"closed": True}


def test_close_runs_teardown_on_the_runner_thread() -> None:
    handle = _make_session()
    backend = _backend("s", handle)
    result = backend.close("s")
    assert result == {"closed": True, "clean": True}


def test_close_reaps_a_wedged_session(monkeypatch: pytest.MonkeyPatch) -> None:
    reaped: list[Any] = []
    monkeypatch.setattr(web, "_reap_web_session", lambda handle: reaped.append(handle))
    handle = _make_session()
    backend = _backend("s", handle)
    backend._sessions["s"].runner._wedged = True  # type: ignore[union-attr]
    result = backend.close("s")
    assert result == {"closed": True, "clean": False} and reaped == [handle]


def test_close_all_closes_each_session() -> None:
    handle = _make_session()
    backend = _backend("s", handle)
    backend.close_all()
    assert backend._sessions == {}
