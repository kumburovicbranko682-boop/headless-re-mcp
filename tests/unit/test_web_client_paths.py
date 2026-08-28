"""Device-free method paths and helpers of the Playwright web backend.

The many test_web_*_fields.py files pin each tool's happy-path envelope. What is
left are the error, guard, and degradation branches that do not need a live
browser: how a fetched body or script source that cannot be read is reported,
how a wasm module or oversized capture is bounded, how the HAR export sheds
entries to stay under the cap, and the small process helpers used only when a
session wedges. Every test drives a real _WebSession whose Playwright objects
are replaced by fakes and whose runner executes work synchronously on the
calling thread, so no browser or node driver is ever launched.
"""

from __future__ import annotations

import base64
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web_client
from headless_re_mcp.backends.web.client import (
    _MAX_INLINE_BODY,
    WebBackend,
    WebError,
    _playwright_driver_pid,
    _reap_driver_pid,
    _safe_title,
    _spill_text,
    _WebSession,
)


class _FakeRunner:
    """Runs work inline; stands in for the per-session Playwright thread."""

    def __init__(self) -> None:
        self.wedged = False
        self.shutdowns = 0

    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()

    def shutdown(self) -> None:
        self.shutdowns += 1


def _raise(exc: BaseException) -> Any:
    def _boom(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise exc

    return _boom


def _make_session(
    backend: WebBackend,
    sid: str = "s",
    *,
    page: Any = None,
    cdp: Any = None,
    runner: Any = "default",
) -> _WebSession:
    pw = SimpleNamespace(stop=lambda: None)
    browser = SimpleNamespace(close=lambda: None)
    context = SimpleNamespace(close=lambda: None)
    handle = _WebSession(
        pw,
        browser,
        context,
        page or SimpleNamespace(url="http://x/", title=lambda: "T"),
        cdp or SimpleNamespace(send=lambda *a, **k: {}),
    )
    handle.runner = _FakeRunner() if runner == "default" else runner
    backend._sessions[sid] = handle
    return handle


# --- _spill_text / _wasm_module_source bounds ----------------------------


def test_spill_text_inlines_a_small_payload(tmp_path: Path) -> None:
    inline, spill, truncated = _spill_text(
        "small", artifact_dir=tmp_path, filename="body.bin", kind="response body"
    )
    assert inline == "small"
    assert spill is None
    assert truncated is False
    assert list(tmp_path.iterdir()) == []


def test_wasm_module_source_refuses_a_module_over_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    backend = WebBackend()
    bytecode = base64.b64encode(b"hello").decode("ascii")  # decodes to 5 bytes
    with pytest.raises(WebError) as caught:
        backend._wasm_module_source("s1", bytecode, tmp_path)
    assert caught.value.code == "too_large"
    assert list(tmp_path.iterdir()) == []


def test_spill_text_refuses_a_body_that_lands_over_the_cap_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The in-memory size passed the cap, but the file measured larger once
    # written (encoding expansion, a racing writer). The on-disk recheck is the
    # backstop that must still refuse it rather than hand back an over-cap spill.
    monkeypatch.setattr(web_client, "capped_file_size", lambda path, cap: (cap + 1, True))
    big = "z" * (_MAX_INLINE_BODY + 1)  # over the inline cap, so it spills to a file
    with pytest.raises(WebError) as caught:
        _spill_text(big, artifact_dir=tmp_path, filename="body.bin", kind="response body")
    assert caught.value.code == "too_large"


def test_wasm_module_source_refuses_a_file_that_lands_over_the_cap_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same backstop for the wasm path: the decoded bytes fit, but the written
    # .wasm measured over the cap, so it is refused after the write.
    monkeypatch.setattr(web_client, "capped_file_size", lambda path, cap: (cap + 1, True))
    backend = WebBackend()
    bytecode = base64.b64encode(b"hello").decode("ascii")  # 5 bytes, under the cap
    with pytest.raises(WebError) as caught:
        backend._wasm_module_source("s1", bytecode, tmp_path)
    assert caught.value.code == "too_large"


# --- capability / status / runner guards ---------------------------------


def test_check_available_raises_when_playwright_is_absent() -> None:
    backend = WebBackend()
    backend._available = False
    with pytest.raises(WebError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_check_available_detects_the_installed_driver() -> None:
    # Fresh backend: the first call runs the import probe and caches the result;
    # the second takes the cached path. playwright is installed here, so neither
    # raises.
    backend = WebBackend()
    backend._check_available()
    backend._check_available()
    assert backend._available is True


def test_status_reports_opening_for_a_reserved_slot() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # the bare open() reservation token
    assert backend.status("s") == {"open": False, "opening": True}


def test_status_reports_closed_for_a_foreign_handle() -> None:
    backend = WebBackend()
    backend._sessions["s"] = SimpleNamespace()  # neither token nor _WebSession
    assert backend.status("s") == {"open": False}


def test_status_of_an_open_session_reports_page_identity() -> None:
    backend = WebBackend()
    _make_session(backend, page=SimpleNamespace(url="http://x/page", title=lambda: "Home"))
    status = backend.status("s")
    assert status["open"] is True
    assert status["url"] == "http://x/page"
    assert status["title"] == "Home"


def test_runner_refuses_a_session_without_a_browser_thread() -> None:
    backend = WebBackend()
    handle = _make_session(backend, runner=None)
    with pytest.raises(WebError) as caught:
        backend._runner(handle)
    assert caught.value.code == "invalid_state"


# --- navigate / dom_snapshot / screenshot error mapping ------------------


def test_navigate_maps_a_goto_failure_to_backend_error() -> None:
    backend = WebBackend()
    _make_session(
        backend,
        page=SimpleNamespace(url="http://x/", title=lambda: "T", goto=_raise(RuntimeError("nav"))),
    )
    with pytest.raises(WebError) as caught:
        backend.navigate("s", "http://x/next")
    assert caught.value.code == "backend_error"
    assert caught.value.details["url"] == "http://x/next"


def test_dom_snapshot_maps_evaluate_failure_and_non_dict() -> None:
    backend = WebBackend()
    _make_session(
        backend,
        page=SimpleNamespace(
            url="http://x/", title=lambda: "T", evaluate=_raise(RuntimeError("dom"))
        ),
    )
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")
    assert caught.value.code == "backend_error"

    backend2 = WebBackend()
    _make_session(
        backend2,
        page=SimpleNamespace(
            url="http://x/", title=lambda: "T", evaluate=lambda *a: "not-a-dict"
        ),
    )
    with pytest.raises(WebError) as caught2:
        backend2.dom_snapshot("s")
    assert caught2.value.code == "backend_error"


def test_screenshot_maps_a_capture_failure_to_backend_error(tmp_path: Path) -> None:
    backend = WebBackend()
    _make_session(
        backend,
        page=SimpleNamespace(
            url="http://x/", title=lambda: "T", screenshot=_raise(RuntimeError("shot"))
        ),
    )
    with pytest.raises(WebError) as caught:
        backend.screenshot("s", tmp_path / "shot.png")
    assert caught.value.code == "backend_error"


# --- network_get body handling -------------------------------------------


def test_network_get_reports_not_found_for_an_unknown_request(tmp_path: Path) -> None:
    backend = WebBackend()
    _make_session(backend)
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "missing", tmp_path)
    assert caught.value.code == "not_found"


def test_network_get_reports_body_error_when_cdp_fails(tmp_path: Path) -> None:
    backend = WebBackend()
    handle = _make_session(backend, cdp=SimpleNamespace(send=_raise(RuntimeError("no body"))))
    handle.requests["r1"] = {"requestId": "r1", "url": "http://x/1", "method": "GET"}
    result = backend.network_get("s", "r1", tmp_path)
    # The entry is still returned, annotated with why the body is missing.
    assert result["requestId"] == "r1"
    assert "no body" in result["body_error"]


def test_network_get_stringifies_a_non_text_body(tmp_path: Path) -> None:
    backend = WebBackend()
    handle = _make_session(
        backend,
        cdp=SimpleNamespace(send=lambda *a, **k: {"body": 12345, "base64Encoded": False}),
    )
    handle.requests["r1"] = {"requestId": "r1", "url": "http://x/1", "method": "GET"}
    result = backend.network_get("s", "r1", tmp_path)
    assert result["body"] == "12345"
    assert result["base64_encoded"] is False


def test_network_get_spills_a_large_body_to_a_file(tmp_path: Path) -> None:
    big = "x" * (_MAX_INLINE_BODY + 1)
    backend = WebBackend()
    handle = _make_session(
        backend,
        cdp=SimpleNamespace(send=lambda *a, **k: {"body": big, "base64Encoded": False}),
    )
    handle.requests["r1"] = {"requestId": "r1", "url": "http://x/1", "method": "GET"}
    result = backend.network_get("s", "r1", tmp_path)
    assert result["body_truncated"] is True
    spilled = Path(result["body_path"])
    assert spilled.parent == tmp_path
    assert spilled.is_file()


# --- script_source: errors, non-text, wasm, spill ------------------------


def test_script_source_maps_a_generic_failure_to_not_found(tmp_path: Path) -> None:
    backend = WebBackend()
    _make_session(backend, cdp=SimpleNamespace(send=_raise(RuntimeError("gone"))))
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "sid1", tmp_path)
    assert caught.value.code == "not_found"


def test_script_source_reraises_a_weberror_untouched(tmp_path: Path) -> None:
    backend = WebBackend()
    _make_session(backend, cdp=SimpleNamespace(send=_raise(WebError("timeout", "browser hung"))))
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "sid1", tmp_path)
    # A timeout must not be relabelled not_found; the runner's WebError passes through.
    assert caught.value.code == "timeout"


def test_script_source_stringifies_a_non_text_source(tmp_path: Path) -> None:
    backend = WebBackend()
    _make_session(backend, cdp=SimpleNamespace(send=lambda *a, **k: {"scriptSource": 999}))
    result = backend.script_source("s", "sid1", tmp_path)
    assert result["source"] == "999"
    assert result["truncated"] is False


def test_script_source_returns_a_wasm_module_by_path(tmp_path: Path) -> None:
    wasm = b"\x00asm\x01\x00\x00\x00"
    backend = WebBackend()
    _make_session(
        backend,
        cdp=SimpleNamespace(
            send=lambda *a, **k: {"scriptSource": "", "bytecode": base64.b64encode(wasm).decode()}
        ),
    )
    result = backend.script_source("s", "wasm1", tmp_path)
    assert result["wasm"] is True
    assert result["language"] == "WebAssembly"
    out = Path(result["source_path"])
    assert out.suffix == ".wasm"
    assert out.read_bytes() == wasm


def test_script_source_spills_a_large_source(tmp_path: Path) -> None:
    big = "y" * (_MAX_INLINE_BODY + 1)
    backend = WebBackend()
    _make_session(backend, cdp=SimpleNamespace(send=lambda *a, **k: {"scriptSource": big}))
    result = backend.script_source("s", "sid1", tmp_path)
    assert result["truncated"] is True
    assert Path(result["source_path"]).is_file()


# --- har_export truncation and overflow ----------------------------------


def _populate_requests(handle: _WebSession, count: int) -> None:
    for index in range(count):
        rid = f"r{index}"
        handle.requests[rid] = {
            "requestId": rid,
            "url": f"http://example.test/resource/{index}",
            "method": "GET",
            "status": 200,
            "mimeType": "text/plain",
            "resourceType": "document",
        }


def test_har_export_sheds_entries_to_fit_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 400)
    backend = WebBackend()
    handle = _make_session(backend)
    _populate_requests(handle, 40)
    out = tmp_path / "capture.har"
    result = backend.har_export("s", out)
    assert result["truncated"] is True
    assert 0 < result["entry_count"] < 40
    assert result["size"] <= 400
    assert out.is_file()


def test_har_export_reports_too_large_when_even_empty_overflows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A cap below the empty-HAR skeleton cannot be met by dropping entries.
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 20)
    backend = WebBackend()
    handle = _make_session(backend)
    _populate_requests(handle, 5)
    with pytest.raises(WebError) as caught:
        backend.har_export("s", tmp_path / "capture.har")
    assert caught.value.code == "too_large"


# --- CDP telemetry handlers ----------------------------------------------


class _RecordingCdp:
    """Captures the handlers _wire_events registers so they can be driven."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.enabled: list[str] = []

    def send(self, method: str, params: Any = None) -> dict[str, Any]:
        del params
        self.enabled.append(method)
        return {}

    def on(self, event: str, fn: Any) -> None:
        self.handlers[event] = fn


def test_cdp_handlers_record_and_bound_page_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Small caps so eviction and truncation fire without megabytes of input.
    monkeypatch.setattr(web_client, "_MAX_REQUESTS", 2)
    monkeypatch.setattr(web_client, "_MAX_SCRIPTS", 2)
    monkeypatch.setattr(web_client, "_MAX_CONSOLE", 2)
    monkeypatch.setattr(web_client, "_MAX_URL_BYTES", 8)
    monkeypatch.setattr(web_client, "_MAX_METADATA_BYTES", 4)

    backend = WebBackend()
    cdp = _RecordingCdp()
    handle = _make_session(backend, cdp=cdp)
    backend._wire_events(handle)
    assert "Network.enable" in cdp.enabled

    on_request = cdp.handlers["Network.requestWillBeSent"]
    for index in range(3):
        on_request(
            {
                "requestId": f"r{index}",
                "request": {"url": f"http://example/{index}", "method": "GET"},
                "type": "Document",
            }
        )
    # Three requests, cap two: oldest evicted, drop counted, urls truncated.
    assert len(handle.requests) == 2
    assert handle.requests_dropped == 1
    assert handle.requests["r2"]["metadata_truncated"] is True

    on_response = cdp.handlers["Network.responseReceived"]
    on_response({"requestId": "r2", "response": {"status": 200, "mimeType": "application/json"}})
    assert handle.requests["r2"]["status"] == 200
    assert handle.requests["r2"]["mimeType"] != "application/json"  # truncated to the cap
    # A response for an already-evicted request is a no-op, not a crash.
    on_response({"requestId": "r0", "response": {"status": 500, "mimeType": "text/plain"}})
    assert "r0" not in handle.requests

    on_script = cdp.handlers["Debugger.scriptParsed"]
    for index in range(3):
        on_script(
            {
                "scriptId": f"s{index}",
                "url": f"http://example/s{index}.js",
                "scriptLanguage": "JavaScript",
            }
        )
    assert len(handle.scripts) == 2
    assert handle.scripts_dropped == 1

    on_console = cdp.handlers["Runtime.consoleAPICalled"]
    for index in range(3):
        on_console({"type": "log", "args": [{"value": f"line {index}"}]})
    assert len(handle.console) == 2
    assert handle.console_dropped == 1


def test_cdp_handlers_leave_short_metadata_untruncated() -> None:
    # The bounds test drives the truncation branches with tiny caps; the mirror
    # case -- short values under the default caps -- must NOT stamp the
    # metadata_truncated flag on any of request, response, or script.
    backend = WebBackend()
    cdp = _RecordingCdp()
    handle = _make_session(backend, cdp=cdp)
    backend._wire_events(handle)

    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_request(
        {"requestId": "r1", "request": {"url": "http://x/", "method": "GET"}, "type": "Document"}
    )
    assert "metadata_truncated" not in handle.requests["r1"]

    on_response = cdp.handlers["Network.responseReceived"]
    on_response({"requestId": "r1", "response": {"status": 200, "mimeType": "text/html"}})
    assert handle.requests["r1"]["status"] == 200
    assert handle.requests["r1"]["mimeType"] == "text/html"
    assert "metadata_truncated" not in handle.requests["r1"]

    on_script = cdp.handlers["Debugger.scriptParsed"]
    on_script({"scriptId": "s1", "url": "http://x/a.js", "scriptLanguage": "JavaScript"})
    assert "metadata_truncated" not in handle.scripts["s1"]


# --- open(): build, install, and rollback --------------------------------


class _InlineNamedRunner:
    """A _Runner replacement that runs build() inline on the calling thread.

    open() constructs its own _Runner(name); swapping the class lets the whole
    launch/install path run without a browser thread while still exercising the
    real bookkeeping (reservation token, driver-pid reaping, session install).
    """

    last: _InlineNamedRunner | None = None

    def __init__(self, name: str) -> None:
        self.name = name
        self.wedged = False
        self.shutdowns = 0
        _InlineNamedRunner.last = self

    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()

    def shutdown(self) -> None:
        self.shutdowns += 1


def _install_fake_playwright(
    monkeypatch: pytest.MonkeyPatch,
    *,
    launch_error: BaseException | None = None,
    driver_pid: int | None = 4321,
    page_url: str = "http://x/loaded",
    title: str = "Fake Title",
) -> tuple[SimpleNamespace, _RecordingCdp, list[bool]]:
    """Wire a fake ``playwright.sync_api`` and inline runner into the module.

    Returns the fake page, the recording cdp, and a list that records whether
    ``pw.stop()`` was called (the build-failure cleanup).
    """
    cdp = _RecordingCdp()
    page = SimpleNamespace(
        url=page_url,
        title=lambda: title,
        goto=lambda url, timeout=None, wait_until=None: None,
    )
    context = SimpleNamespace(
        new_page=lambda: page,
        new_cdp_session=lambda p: cdp,
        close=lambda: None,
    )

    def launch(**kwargs: Any) -> Any:
        if launch_error is not None:
            raise launch_error
        return SimpleNamespace(
            new_context=lambda ignore_https_errors=False: context, close=lambda: None
        )

    stopped: list[bool] = []
    pw = SimpleNamespace(
        chromium=SimpleNamespace(launch=launch),
        stop=lambda: stopped.append(True),
    )
    if driver_pid is not None:
        proc = SimpleNamespace(pid=driver_pid)
        pw._impl_obj = SimpleNamespace(  # type: ignore[attr-defined]
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=proc))
        )

    fake_module = types.ModuleType("playwright.sync_api")
    fake_module.sync_playwright = lambda: SimpleNamespace(start=lambda: pw)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_module)
    monkeypatch.setattr(web_client, "_Runner", _InlineNamedRunner)
    return page, cdp, stopped


def test_open_launches_installs_the_session_and_returns_a_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page, cdp, _ = _install_fake_playwright(monkeypatch)
    backend = WebBackend()
    backend._check_available = lambda: None  # type: ignore[method-assign]

    summary = backend.open("s", "http://x/start", proxy="http://127.0.0.1:8080")

    assert summary["opened"] is True
    assert summary["url"] == page.url
    assert summary["title"] == "Fake Title"
    assert summary["headless"] is True
    assert summary["proxy"] == "http://127.0.0.1:8080"
    # The session is installed under its id and the CDP domains were enabled.
    handle = backend._sessions["s"]
    assert isinstance(handle, _WebSession)
    assert handle.driver_pid == 4321
    assert "Network.enable" in cdp.enabled


def test_open_without_a_url_skips_navigation_and_still_installs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    goto_calls: list[str] = []
    # driver_pid=None: the pid chain dead-ends, so the discovery returns None and
    # open() must still install the session (just with nothing to reap later).
    page, _, _ = _install_fake_playwright(monkeypatch, driver_pid=None)
    page.goto = lambda url, timeout=None, wait_until=None: goto_calls.append(url)
    backend = WebBackend()
    backend._check_available = lambda: None  # type: ignore[method-assign]

    summary = backend.open("s", "")

    assert summary["opened"] is True
    assert goto_calls == []  # no url -> no navigation
    handle = backend._sessions["s"]
    assert isinstance(handle, _WebSession)
    assert handle.driver_pid is None


def test_open_rolls_back_and_reaps_the_driver_when_launch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed: list[int] = []
    _install_fake_playwright(monkeypatch, launch_error=RuntimeError("no chromium here"))
    # Keep the reap fully in-process: a driver image name so the reap fires, but
    # a stubbed terminate so nothing real is signalled.
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/opt/ms-playwright/node")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))

    backend = WebBackend()
    backend._check_available = lambda: None  # type: ignore[method-assign]

    with pytest.raises(WebError) as caught:
        backend.open("s", "http://x/start")
    assert caught.value.code == "backend_error"
    # The failed launch left no reservation behind and reaped the node driver.
    assert backend._sessions == {}
    assert _InlineNamedRunner.last is not None
    assert _InlineNamedRunner.last.shutdowns == 1
    assert killed == [4321]


# --- close paths and process helpers -------------------------------------


def test_close_of_a_runnerless_handle_tears_down_directly() -> None:
    backend = WebBackend()
    _make_session(backend, runner=None)
    assert backend.close("s") == {"closed": True}


def test_close_all_closes_every_open_session() -> None:
    backend = WebBackend()
    _make_session(backend, "a")
    _make_session(backend, "b")
    backend.close_all()
    assert backend._sessions == {}


def test_safe_title_swallows_a_failing_title_call() -> None:
    assert _safe_title(SimpleNamespace(title=_raise(RuntimeError("no title")))) == ""


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    # A short chain that dead-ends returns None rather than raising.
    assert _playwright_driver_pid(object()) is None
    # A full chain hands back the node driver pid.
    proc = SimpleNamespace(pid=4321)
    transport = SimpleNamespace(_proc=proc)
    connection = SimpleNamespace(_transport=transport)
    impl = SimpleNamespace(_connection=connection)
    pw = SimpleNamespace(_impl_obj=impl)
    assert _playwright_driver_pid(pw) == 4321


def test_reap_driver_pid_ignores_non_pids_and_foreign_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))

    _reap_driver_pid(0)  # not a pid
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/usr/bin/python3")
    _reap_driver_pid(4321)  # real pid, but not a browser/driver image
    assert killed == []

    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/opt/ms-playwright/node")
    _reap_driver_pid(4321)  # a driver image: this one is reaped
    assert killed == [4321]
