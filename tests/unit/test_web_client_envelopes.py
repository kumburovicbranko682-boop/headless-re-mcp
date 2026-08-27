"""WebBackend must bound telemetry, wrap driver failures, and clean up on open.

The field-shape and spill-safety modules pin the success payloads; what is
exercised here is the machinery underneath them, which the service trusts never
to leak a raw Playwright/CDP failure or an unbounded buffer:

* the CDP event handlers wired by ``_wire_events`` (metadata truncation, the
  request/script ring caps, the console drop counter),
* ``open`` launching through an injected fake driver and tearing the whole tree
  down when the build fails,
* the per-method ``backend_error`` / ``not_found`` envelopes (navigate, close,
  network_get, script_source, dom_snapshot, screenshot),
* the pure spill / metadata / driver-pid helpers.

Playwright is not installed in CI, so ``open`` is driven with a fake
``playwright.sync_api`` module injected into ``sys.modules`` -- no browser, no
node driver. Every other method is driven with a fake session and an immediate
runner that runs the work inline.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from threading import RLock
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web
from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE,
    _MAX_METADATA_BYTES,
    _MAX_REQUESTS,
    _MAX_SCRIPTS,
    _MAX_URL_BYTES,
    WebBackend,
    WebError,
    _bound_nav_timeout,
    _clip_console_text,
    _playwright_driver_pid,
    _reap_driver_pid,
    _safe_title,
    _spill_bytes,
    _spill_text,
    _WebSession,
)
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES


class _Dummy:
    def close(self) -> None:
        return None

    def stop(self) -> None:
        return None


class _Immediate:
    """A runner that runs work inline, like a warm greenlet thread would."""

    wedged = False

    def __init__(self) -> None:
        self.shutdown_called = False

    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()

    def shutdown(self) -> None:
        self.shutdown_called = True


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def test_bound_nav_timeout_rejects_non_positive() -> None:
    with pytest.raises(WebError) as caught:
        _bound_nav_timeout(0)
    assert caught.value.code == "invalid_params"


def test_bound_nav_timeout_rejects_nan() -> None:
    with pytest.raises(WebError):
        _bound_nav_timeout(float("nan"))


def test_bound_nav_timeout_caps_a_huge_value() -> None:
    assert _bound_nav_timeout(10_000) == 120.0


def test_clip_console_text_joins_and_reads_arg_shapes() -> None:
    text, truncated = _clip_console_text(
        {"args": [{"value": "a"}, {"description": "b"}, {"type": "object"}, "skip", {"z": 1}]}
    )
    assert text == "a b object "
    assert truncated is False


def test_clip_console_text_truncates_a_huge_argument() -> None:
    text, truncated = _clip_console_text({"args": [{"value": "x" * 20000}]})
    assert truncated is True
    assert len(text) <= 8 * 1024


def test_clip_console_text_stops_at_the_top_when_the_budget_is_spent() -> None:
    # The first argument fills the budget exactly (no truncation of its own),
    # so the second is refused at the loop head.
    text, truncated = _clip_console_text({"args": [{"value": "x" * (8 * 1024)}, {"value": "y"}]})
    assert truncated is True
    assert text == "x" * (8 * 1024)


def test_clip_console_text_stops_before_a_separator_it_cannot_afford() -> None:
    # The first argument leaves a single byte, not enough for the join space.
    text, truncated = _clip_console_text(
        {"args": [{"value": "x" * (8 * 1024 - 1)}, {"value": "y"}]}
    )
    assert truncated is True
    assert text == "x" * (8 * 1024 - 1)


def test_spill_text_inlines_a_small_string(tmp_path: Path) -> None:
    inline, spill, cut = _spill_text("small", artifact_dir=tmp_path, filename="x.bin", kind="body")
    assert inline == "small"
    assert spill is None
    assert cut is False


def test_spill_bytes_refuses_over_the_cap(tmp_path: Path) -> None:
    huge = b"\x00" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1)
    with pytest.raises(WebError) as caught:
        _spill_bytes(huge, artifact_dir=tmp_path, filename="x.bin", kind="body")
    assert caught.value.code == "too_large"


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b.bin", "a\\b.bin"])
def test_spill_bytes_refuses_a_bad_filename(tmp_path: Path, bad: str) -> None:
    with pytest.raises(WebError) as caught:
        _spill_bytes(b"data", artifact_dir=tmp_path, filename=bad, kind="body")
    assert caught.value.code == "invalid_params"


def test_safe_title_swallows_a_failure() -> None:
    class _Page:
        def title(self) -> str:
            raise RuntimeError("detached")

    assert _safe_title(_Page()) == ""


def test_driver_pid_is_none_without_the_private_chain() -> None:
    assert _playwright_driver_pid(object()) is None


def test_driver_pid_reads_the_private_chain() -> None:
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid=4321))
            )
        )
    )
    assert _playwright_driver_pid(pw) == 4321


def test_driver_pid_rejects_a_non_positive_pid() -> None:
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=SimpleNamespace(pid=0)))
        )
    )
    assert _playwright_driver_pid(pw) is None


def test_reap_driver_pid_ignores_a_bad_pid() -> None:
    # No exception, no termination attempt.
    _reap_driver_pid(None)
    _reap_driver_pid(0)


def test_reap_driver_pid_skips_a_foreign_image(monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web, "process_image_path", lambda pid: "/usr/bin/some-other-tool")
    monkeypatch.setattr(web, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(4321)
    assert killed == []


def test_reap_driver_pid_terminates_a_driver_image(monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web, "process_image_path", lambda pid: "/opt/node/bin/node")
    monkeypatch.setattr(web, "terminate_pid_tree", lambda pid: killed.append(pid))
    _reap_driver_pid(4321)
    assert killed == [4321]


# --------------------------------------------------------------------------
# _check_available
# --------------------------------------------------------------------------


def test_check_available_raises_when_already_marked_unavailable() -> None:
    backend = WebBackend()
    backend._available = False
    with pytest.raises(WebError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"


def test_check_available_marks_unavailable_when_import_fails() -> None:
    # playwright is not installed in CI, so the import inside _check_available
    # fails and the backend must degrade rather than raise ImportError.
    backend = WebBackend()
    with pytest.raises(WebError) as caught:
        backend._check_available()
    assert caught.value.code == "capability_unavailable"
    assert backend._available is False


# --------------------------------------------------------------------------
# status / _runner
# --------------------------------------------------------------------------


def test_status_reports_closed_for_an_unknown_session() -> None:
    assert WebBackend().status("nope") == {"open": False}


def test_status_reports_opening_for_a_reservation_token() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    assert backend.status("s") == {"open": False, "opening": True}


def test_status_reports_closed_for_a_non_session_handle() -> None:
    backend = WebBackend()
    backend._sessions["s"] = "not a session"  # type: ignore[assignment]
    assert backend.status("s") == {"open": False}


def _session_with(page: Any, *, runner: Any = None, cdp: Any = None) -> _WebSession:
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), page, cdp or _Dummy())
    handle.runner = runner
    return handle


def test_status_reports_a_live_page() -> None:
    backend = WebBackend()
    page = SimpleNamespace(url="https://example.com/", title=lambda: "Example")
    backend._sessions["s"] = _session_with(page, runner=_Immediate())
    payload = backend.status("s")
    assert payload == {"open": True, "url": "https://example.com/", "title": "Example"}


def test_runner_requires_a_browser_thread() -> None:
    backend = WebBackend()
    page = SimpleNamespace(url="https://x/", title=lambda: "x")
    backend._sessions["s"] = _session_with(page, runner=None)
    with pytest.raises(WebError) as caught:
        backend.status("s")
    assert caught.value.code == "invalid_state"


# --------------------------------------------------------------------------
# _wire_events: the CDP handlers
# --------------------------------------------------------------------------


class _CaptureCDP:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> dict[str, Any]:
        return {}

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def _wired() -> tuple[WebBackend, _WebSession, _CaptureCDP]:
    backend = WebBackend()
    cdp = _CaptureCDP()
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), cdp)
    handle.lock = RLock()
    backend._wire_events(handle)
    return backend, handle, cdp


def test_on_request_records_and_flags_truncated_metadata() -> None:
    _, handle, cdp = _wired()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    on_request({"requestId": "r1", "request": {"url": "https://x", "method": "GET"}, "type": "Doc"})
    on_request(
        {
            "requestId": "r2",
            "request": {"url": "h" * (_MAX_URL_BYTES + 10), "method": "GET"},
            "type": "Doc",
        }
    )
    assert handle.requests["r1"]["url"] == "https://x"
    assert handle.requests["r2"]["metadata_truncated"] is True


def test_on_request_evicts_the_oldest_over_the_cap() -> None:
    _, handle, cdp = _wired()
    on_request = cdp.handlers["Network.requestWillBeSent"]
    for index in range(_MAX_REQUESTS):
        handle.requests[str(index)] = {"requestId": str(index)}
    on_request({"requestId": "new", "request": {"url": "https://x"}, "type": "Doc"})
    assert handle.requests_dropped == 1
    assert "0" not in handle.requests


def test_on_response_updates_a_known_request_and_ignores_unknown() -> None:
    _, handle, cdp = _wired()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "https://x", "method": "GET"}, "type": "Doc"}
    )
    on_response = cdp.handlers["Network.responseReceived"]
    long_mime = "m" * (_MAX_METADATA_BYTES + 5)
    on_response({"requestId": "r1", "response": {"status": 200, "mimeType": long_mime}})
    assert handle.requests["r1"]["status"] == 200
    assert handle.requests["r1"]["metadata_truncated"] is True
    # An unknown request id is a no-op, not a new empty entry.
    on_response({"requestId": "ghost", "response": {"status": 500}})
    assert "ghost" not in handle.requests


def test_on_response_leaves_short_metadata_unflagged() -> None:
    _, handle, cdp = _wired()
    cdp.handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "https://x", "method": "GET"}, "type": "Doc"}
    )
    cdp.handlers["Network.responseReceived"](
        {"requestId": "r1", "response": {"status": 200, "mimeType": "text/html"}}
    )
    assert handle.requests["r1"]["status"] == 200
    assert "metadata_truncated" not in handle.requests["r1"]


def test_on_script_records_flags_and_evicts() -> None:
    _, handle, cdp = _wired()
    on_script = cdp.handlers["Debugger.scriptParsed"]
    on_script({"scriptId": "s1", "url": "https://x/app.js", "scriptLanguage": "JavaScript"})
    on_script({"scriptId": "s2", "url": "h" * (_MAX_URL_BYTES + 10)})
    assert handle.scripts["s1"]["language"] == "JavaScript"
    assert handle.scripts["s2"]["metadata_truncated"] is True
    for index in range(_MAX_SCRIPTS):
        handle.scripts[f"pre{index}"] = {"scriptId": f"pre{index}"}
    on_script({"scriptId": "overflow", "url": "https://x/y.js"})
    assert handle.scripts_dropped >= 1


def test_on_console_flags_truncation_and_counts_drops() -> None:
    _, handle, cdp = _wired()
    on_console = cdp.handlers["Runtime.consoleAPICalled"]
    on_console({"type": "log", "args": [{"value": "x" * 20000}]})
    assert handle.console[-1]["text_truncated"] is True
    # Fill the ring to capacity so the next append counts a drop.
    handle.console.clear()
    handle.console.extend({"type": "log", "text": str(i)} for i in range(_MAX_CONSOLE))
    on_console({"type": "log", "args": [{"value": "one more"}]})
    assert handle.console_dropped == 1


# --------------------------------------------------------------------------
# navigate / close
# --------------------------------------------------------------------------


def test_navigate_wraps_a_goto_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Page:
        url = "https://x/"

        def goto(
            self, url: str, timeout: float | None = None, wait_until: str | None = None
        ) -> Any:
            raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

        def title(self) -> str:
            return "x"

    backend = WebBackend()
    handle = _session_with(_Page(), runner=_Immediate())
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as caught:
        backend.navigate("s", "https://bad.invalid")
    assert caught.value.code == "backend_error"


def test_close_reports_aborted_for_a_reservation_token() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True, "note": "open was aborted"}


def test_close_tears_down_a_runnerless_handle() -> None:
    backend = WebBackend()
    closed: list[str] = []

    class _Ctx:
        def close(self) -> None:
            closed.append("ctx")

    handle = _WebSession(_Dummy(), _Dummy(), _Ctx(), _Dummy(), _Dummy())
    handle.runner = None
    backend._sessions["s"] = handle
    assert backend.close("s") == {"closed": True}
    assert closed == ["ctx"]


def test_close_kills_the_driver_when_the_runner_is_wedged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reaped: list[int] = []
    monkeypatch.setattr(web, "_reap_web_session", lambda handle: reaped.append(1))

    class _Wedged:
        wedged = True

        def call(self, work: Any, timeout: float | None = None) -> Any:
            raise AssertionError("a wedged runner must not run work")

        def shutdown(self) -> None:
            return None

    backend = WebBackend()
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Dummy())
    handle.runner = _Wedged()  # type: ignore[assignment]
    backend._sessions["s"] = handle
    payload = backend.close("s")
    assert payload == {"closed": True, "clean": False}
    assert reaped == [1]


def test_close_all_closes_every_session() -> None:
    backend = WebBackend()
    backend._sessions["reservation"] = object()  # type: ignore[assignment]
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Dummy())
    handle.runner = None
    backend._sessions["live"] = handle
    backend.close_all()
    assert backend._sessions == {}


# --------------------------------------------------------------------------
# network_get / script_source envelopes
# --------------------------------------------------------------------------


def test_network_get_rejects_an_unknown_request_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Dummy())
    handle.lock = RLock()
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "missing", tmp_path)
    assert caught.value.code == "not_found"


def test_network_get_stringifies_a_non_string_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Cdp:
        def send(self, method: str, params: Any = None) -> dict[str, Any]:
            return {"body": 12345, "base64Encoded": False}

    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Cdp())
    handle.lock = RLock()
    handle.requests["r1"] = {"requestId": "r1", "url": "https://x"}
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == "12345"
    assert "body_path" not in payload


def test_script_source_passes_a_weberror_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Runner:
        wedged = False

        def call(self, work: Any, timeout: float | None = None) -> Any:
            raise WebError("timeout", "browser did not respond")

    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Dummy())
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Runner())
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "sid", tmp_path)
    assert caught.value.code == "timeout"


def test_script_source_maps_a_cdp_failure_to_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Cdp:
        def send(self, method: str, params: Any = None) -> dict[str, Any]:
            raise RuntimeError("No script for id")

    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Cdp())
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "sid", tmp_path)
    assert caught.value.code == "not_found"


def test_script_source_inlines_a_non_string_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Cdp:
        def send(self, method: str, params: Any = None) -> dict[str, Any]:
            return {"scriptSource": 999}

    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Cdp())
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.script_source("s", "sid", tmp_path)
    assert payload["source"] == "999"
    assert "source_path" not in payload


# --------------------------------------------------------------------------
# dom_snapshot / screenshot envelopes
# --------------------------------------------------------------------------


def test_dom_snapshot_wraps_an_evaluate_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Page:
        url = "https://x/"

        def evaluate(self, script: str, arg: Any = None) -> Any:
            raise RuntimeError("execution context destroyed")

        def title(self) -> str:
            return "x"

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _session_with(_Page()))
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")
    assert caught.value.code == "backend_error"


def test_dom_snapshot_refuses_a_non_dict_result(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Page:
        url = "https://x/"

        def evaluate(self, script: str, arg: Any = None) -> Any:
            return "not a dict"

        def title(self) -> str:
            return "x"

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _session_with(_Page()))
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")
    assert caught.value.code == "backend_error"


def test_dom_snapshot_returns_the_document(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Page:
        url = "https://x/"

        def evaluate(self, script: str, arg: Any = None) -> Any:
            return {"html": "<html></html>", "truncated": False}

        def title(self) -> str:
            return "Doc"

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _session_with(_Page()))
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.dom_snapshot("s")
    assert payload["html"] == "<html></html>"
    assert payload["truncated"] is False


def test_screenshot_returns_size_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Page:
        def screenshot(self, path: str, full_page: bool = False) -> None:
            Path(path).write_bytes(b"\x89PNG\r\n")

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _session_with(_Page()))
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    payload = backend.screenshot("s", tmp_path / "shot.png")
    assert payload["size"] == 6


def test_screenshot_wraps_a_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Page:
        def screenshot(self, path: str, full_page: bool = False) -> None:
            raise RuntimeError("target closed")

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _session_with(_Page()))
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    with pytest.raises(WebError) as caught:
        backend.screenshot("s", tmp_path / "shot.png")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# open: launch through an injected fake driver, and its cleanup path
# --------------------------------------------------------------------------


class _FakeGoto:
    status = 200


class _FakePage:
    url = "https://example.com/"

    def __init__(self, goto_exc: BaseException | None = None) -> None:
        self._goto_exc = goto_exc

    def goto(
        self, url: str, timeout: float | None = None, wait_until: str | None = None
    ) -> Any:
        if self._goto_exc is not None:
            raise self._goto_exc
        return _FakeGoto()

    def title(self) -> str:
        return "Example Domain"


class _FakeCdpSession:
    def send(self, method: str, params: Any = None) -> dict[str, Any]:
        return {}

    def on(self, event: str, callback: Any) -> None:
        return None


class _FakeContext:
    def __init__(self, page: _FakePage, cdp: _FakeCdpSession) -> None:
        self._page = page
        self._cdp = cdp

    def new_page(self) -> _FakePage:
        return self._page

    def new_cdp_session(self, page: _FakePage) -> _FakeCdpSession:
        return self._cdp

    def close(self) -> None:
        return None


class _FakeBrowser:
    def __init__(self, context: _FakeContext) -> None:
        self._context = context

    def new_context(self, ignore_https_errors: bool = False) -> _FakeContext:
        return self._context

    def close(self) -> None:
        return None


class _FakeChromium:
    def __init__(self, browser: _FakeBrowser) -> None:
        self._browser = browser

    def launch(self, headless: bool = True) -> _FakeBrowser:
        return self._browser


class _FakePlaywright:
    def __init__(self, goto_exc: BaseException | None = None, pid: int | None = None) -> None:
        page = _FakePage(goto_exc)
        context = _FakeContext(page, _FakeCdpSession())
        self.chromium = _FakeChromium(_FakeBrowser(context))
        if pid is not None:
            self._impl_obj = SimpleNamespace(
                _connection=SimpleNamespace(
                    _transport=SimpleNamespace(_proc=SimpleNamespace(pid=pid))
                )
            )

    def stop(self) -> None:
        return None


class _FakeSyncPlaywright:
    def __init__(self, pw: _FakePlaywright) -> None:
        self._pw = pw

    def start(self) -> _FakePlaywright:
        return self._pw


def _install_fake_playwright(monkeypatch: pytest.MonkeyPatch, pw: _FakePlaywright) -> None:
    package = types.ModuleType("playwright")
    module = types.ModuleType("playwright.sync_api")
    module.sync_playwright = lambda: _FakeSyncPlaywright(pw)  # type: ignore[attr-defined]
    package.sync_api = module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", module)


def test_open_launches_and_summarises(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(monkeypatch, _FakePlaywright(pid=999_999))
    backend = WebBackend()
    try:
        summary = backend.open("s", "https://example.com")
        assert summary["opened"] is True
        assert summary["status"] == 200
        assert summary["title"] == "Example Domain"
        assert "s" in backend._sessions
    finally:
        backend.close_all()


def test_open_without_a_url_skips_navigation(monkeypatch: pytest.MonkeyPatch) -> None:
    # No url and no driver pid: the goto and the status are both skipped.
    _install_fake_playwright(monkeypatch, _FakePlaywright(pid=None))
    backend = WebBackend()
    try:
        summary = backend.open("s", "")
        assert summary["opened"] is True
        assert "status" not in summary
    finally:
        backend.close_all()


def test_open_refuses_an_already_open_session(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(monkeypatch, _FakePlaywright())
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    with pytest.raises(WebError) as caught:
        backend.open("s", "https://example.com")
    assert caught.value.code == "invalid_state"


def test_open_cleans_up_when_the_build_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    reaped: list[int] = []
    monkeypatch.setattr(web, "_reap_driver_pid", lambda pid: reaped.append(pid))
    _install_fake_playwright(
        monkeypatch, _FakePlaywright(goto_exc=RuntimeError("net::ERR"), pid=999_999)
    )
    backend = WebBackend()
    with pytest.raises(WebError) as caught:
        backend.open("s", "https://example.com")
    assert caught.value.code == "backend_error"
    # The reservation is released and the driver pid is scheduled for reaping.
    assert "s" not in backend._sessions
    assert reaped == [999_999]
