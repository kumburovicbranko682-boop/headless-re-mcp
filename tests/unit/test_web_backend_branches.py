"""Web/CDP backend guard, degradation, and buffer-honesty branches.

The live paths (drive a real Chromium over CDP) live in
``tests/integration/test_web_lifecycle_gate.py`` and only run where Playwright's
browser is installed. Everything here drives the backend through fakes so the
decisions that hold on every machine run on every machine: the bounded ring
buffers and their drop accounting, the spill/too-large/invalid-filename rules,
"this request has no body" vs a real body, and the open/close reclamation that
must not leak a browser when a launch fails midway.
"""

from __future__ import annotations

import sys
from collections import OrderedDict, deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE_TEXT,
    WebBackend,
    WebError,
    _bounded_metadata,
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

MP = pytest.MonkeyPatch


# ----------------------------------------------------------------------------
# Fakes
# ----------------------------------------------------------------------------
class _FakePage:
    def __init__(
        self,
        url: str = "https://example/app/",
        *,
        goto_error: BaseException | None = None,
        evaluate_result: Any = None,
        evaluate_error: BaseException | None = None,
        screenshot_error: BaseException | None = None,
        title_error: BaseException | None = None,
        response_status: int | None = 200,
    ) -> None:
        self.url = url
        self._goto_error = goto_error
        self._evaluate_result = evaluate_result
        self._evaluate_error = evaluate_error
        self._screenshot_error = screenshot_error
        self._title_error = title_error
        self._response_status = response_status
        self.goto_calls: list[tuple[str, float, str]] = []
        self.screenshot_calls: list[tuple[str, bool]] = []

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> Any:
        self.goto_calls.append((url, timeout, wait_until))
        if self._goto_error is not None:
            raise self._goto_error
        self.url = url
        if self._response_status is None:
            return None
        return SimpleNamespace(status=self._response_status)

    def title(self) -> str:
        if self._title_error is not None:
            raise self._title_error
        return "Example Title"

    def evaluate(self, script: str, arg: Any) -> Any:
        if self._evaluate_error is not None:
            raise self._evaluate_error
        return self._evaluate_result

    def screenshot(self, path: str, full_page: bool = False) -> None:
        if self._screenshot_error is not None:
            raise self._screenshot_error
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
        self.screenshot_calls.append((path, full_page))


class _FakeCdp:
    def __init__(
        self,
        *,
        bodies: dict[str, Any] | None = None,
        sources: dict[str, str] | None = None,
        body_error: bool = False,
        source_error: BaseException | None = None,
    ) -> None:
        self.sent: list[tuple[str, Any]] = []
        self.handlers: dict[str, Any] = {}
        self._bodies = bodies or {}
        self._sources = sources or {}
        self._body_error = body_error
        self._source_error = source_error

    def send(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self.sent.append((method, params))
        if method == "Network.getResponseBody":
            if self._body_error:
                raise RuntimeError("No resource with given identifier")
            assert params is not None
            return self._bodies.get(params["requestId"], {"body": "", "base64Encoded": False})
        if method == "Debugger.getScriptSource":
            if self._source_error is not None:
                raise self._source_error
            assert params is not None
            return {"scriptSource": self._sources.get(params["scriptId"], "")}
        return {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


@pytest.fixture
def runners() -> Any:
    created: list[_Runner] = []
    yield created
    for runner in created:
        runner.shutdown()


def _handle(
    runners: list[_Runner],
    page: _FakePage | None = None,
    cdp: _FakeCdp | None = None,
) -> _WebSession:
    pw = SimpleNamespace(stop=lambda: None)
    browser = SimpleNamespace(close=lambda: None)
    context = SimpleNamespace(close=lambda: None)
    handle = _WebSession(pw, browser, context, page or _FakePage(), cdp or _FakeCdp())
    runner = _Runner("test-web")
    runners.append(runner)
    handle.runner = runner
    return handle


def _backend(handle: _WebSession, monkeypatch: MP) -> WebBackend:
    backend = WebBackend()
    backend._available = True
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    return backend


# ----------------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------------
class TestBoundedMetadata:
    def test_short_value_is_untouched(self) -> None:
        text, truncated = _bounded_metadata("https://x/", 1024)
        assert text == "https://x/"
        assert truncated is False

    def test_long_value_is_clipped_and_flagged(self) -> None:
        text, truncated = _bounded_metadata("a" * 5000, 100)
        assert len(text.encode()) <= 100
        assert truncated is True

    def test_non_string_and_none_are_coerced(self) -> None:
        assert _bounded_metadata(None, 100) == ("", False)
        assert _bounded_metadata(1234, 100) == ("1234", False)


class TestClipConsoleText:
    def test_short_args_join_untruncated(self) -> None:
        text, truncated = _clip_console_text({"args": [{"value": "a"}, {"value": "b"}]})
        assert text == "a b"
        assert truncated is False

    def test_non_dict_args_are_skipped(self) -> None:
        text, truncated = _clip_console_text(
            {"args": [{"value": "a"}, "not-a-dict", {"value": "b"}]}
        )
        assert text == "a b"
        assert truncated is False

    def test_description_and_type_fallbacks(self) -> None:
        text, _ = _clip_console_text({"args": [{"description": "desc"}, {"type": "object"}]})
        assert text == "desc object"

    def test_a_single_oversized_arg_is_sliced(self) -> None:
        text, truncated = _clip_console_text({"args": [{"value": "x" * (10 * 1024)}]})
        assert truncated is True
        assert len(text) == _MAX_CONSOLE_TEXT

    def test_budget_exhausted_before_next_arg(self) -> None:
        # First arg exactly fills the budget; the second cannot start.
        text, truncated = _clip_console_text(
            {"args": [{"value": "x" * _MAX_CONSOLE_TEXT}, {"value": "y"}]}
        )
        assert truncated is True
        assert text == "x" * _MAX_CONSOLE_TEXT

    def test_separator_alone_would_overflow(self) -> None:
        # One byte of headroom left, but a second arg needs a space first.
        text, truncated = _clip_console_text(
            {"args": [{"value": "x" * (_MAX_CONSOLE_TEXT - 1)}, {"value": "y"}]}
        )
        assert truncated is True
        assert text == "x" * (_MAX_CONSOLE_TEXT - 1)

    def test_no_args_is_empty(self) -> None:
        assert _clip_console_text({}) == ("", False)


class TestSpillText:
    def test_small_body_is_inlined(self, tmp_path: Path) -> None:
        inline, spill, cut = _spill_text(
            "hi", artifact_dir=tmp_path, filename="a.bin", kind="body"
        )
        assert inline == "hi"
        assert spill is None and cut is False

    def test_large_body_spills_to_disk(self, tmp_path: Path) -> None:
        body = "a" * 250_000
        inline, spill, cut = _spill_text(
            body, artifact_dir=tmp_path, filename="a.bin", kind="body"
        )
        assert cut is True
        assert spill is not None and spill.is_file()
        assert len(inline) < len(body)

    def test_over_cap_is_refused(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
        with pytest.raises(WebError) as info:
            _spill_text("way too large", artifact_dir=tmp_path, filename="a.bin", kind="body")
        assert info.value.code == "too_large"

    def test_bad_filename_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(WebError) as info:
            _spill_text("a" * 250_000, artifact_dir=tmp_path, filename="../evil", kind="body")
        assert info.value.code == "invalid_params"


class TestSpillBytes:
    def test_writes_raw_bytes(self, tmp_path: Path) -> None:
        out = _spill_bytes(b"\x00\x01\x02", artifact_dir=tmp_path, filename="b.bin", kind="body")
        assert out.read_bytes() == b"\x00\x01\x02"

    def test_over_cap_is_refused(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 2)
        with pytest.raises(WebError) as info:
            _spill_bytes(b"\x00\x01\x02", artifact_dir=tmp_path, filename="b.bin", kind="body")
        assert info.value.code == "too_large"

    def test_bad_filename_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(WebError) as info:
            _spill_bytes(b"\x00", artifact_dir=tmp_path, filename="a/b", kind="body")
        assert info.value.code == "invalid_params"


class TestSafeTitleAndResponseStatus:
    def test_safe_title_swallows_a_raising_page(self) -> None:
        assert _safe_title(_FakePage(title_error=RuntimeError("detached"))) == ""

    def test_response_status_none_int_and_raising(self) -> None:
        assert _response_status(None) is None
        assert _response_status(SimpleNamespace(status=404)) == 404
        assert _response_status(SimpleNamespace(status="oops")) is None

        class _Boom:
            @property
            def status(self) -> int:
                raise RuntimeError("gone")

        assert _response_status(_Boom()) is None


class TestDriverPidHelpers:
    def test_pid_walks_the_private_chain(self) -> None:
        pw = SimpleNamespace(
            _impl_obj=SimpleNamespace(
                _connection=SimpleNamespace(
                    _transport=SimpleNamespace(_proc=SimpleNamespace(pid=4321))
                )
            )
        )
        assert _playwright_driver_pid(pw) == 4321

    def test_broken_chain_is_none(self) -> None:
        assert _playwright_driver_pid(SimpleNamespace(_impl_obj=None)) is None
        assert _playwright_driver_pid(SimpleNamespace()) is None

    def test_reap_ignores_bad_pid_and_foreign_image(self) -> None:
        # A non-positive pid is a no-op; a live pid whose image is not a browser
        # driver must not be terminated (this test process is Python, not node).
        import os

        _reap_driver_pid(0)
        _reap_driver_pid(None)  # type: ignore[arg-type]
        _reap_driver_pid(os.getpid())  # returns without killing this process
        _reap_web_session(SimpleNamespace(driver_pid=None))  # type: ignore[arg-type]


# ----------------------------------------------------------------------------
# _Runner
# ----------------------------------------------------------------------------
class TestRunner:
    def test_runs_work_on_its_own_thread(self, runners: list[_Runner]) -> None:
        runner = _Runner("t")
        runners.append(runner)
        assert runner.call(lambda: 21 * 2) == 42

    def test_closed_runner_refuses_work(self) -> None:
        runner = _Runner("t")
        runner.shutdown()
        with pytest.raises(WebError) as info:
            runner.call(lambda: 1)
        assert info.value.code == "invalid_state"

    def test_wedged_runner_refuses_and_points_at_close(self, runners: list[_Runner]) -> None:
        runner = _Runner("t")
        runners.append(runner)
        runner._wedged = True
        with pytest.raises(WebError) as info:
            runner.call(lambda: 1)
        assert info.value.code == "backend_error"
        assert "web.close" in info.value.message

    def test_timeout_wedges_the_runner(self, runners: list[_Runner]) -> None:
        import time

        runner = _Runner("t")
        runners.append(runner)
        with pytest.raises(WebError) as info:
            runner.call(lambda: time.sleep(5), timeout=0.05)
        assert info.value.code == "timeout"
        assert runner.wedged is True


# ----------------------------------------------------------------------------
# check_available degradation
# ----------------------------------------------------------------------------
def test_missing_playwright_degrades(monkeypatch: MP) -> None:
    backend = WebBackend()
    backend._available = None
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    with pytest.raises(WebError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"


# ----------------------------------------------------------------------------
# status / _runner
# ----------------------------------------------------------------------------
class TestStatus:
    def test_opening_reservation_reads_as_opening(self) -> None:
        backend = WebBackend()
        backend._sessions["s"] = object()  # type: ignore[assignment]
        assert backend.status("s") == {"open": False, "opening": True}

    def test_open_session_reports_url_and_title(self, runners: list[_Runner]) -> None:
        backend = WebBackend()
        handle = _handle(runners, page=_FakePage(url="https://live/"))
        backend._sessions["s"] = handle
        result = backend.status("s")
        assert result == {"open": True, "url": "https://live/", "title": "Example Title"}

    def test_runner_missing_is_invalid_state(self, runners: list[_Runner]) -> None:
        backend = WebBackend()
        handle = _handle(runners)
        handle.runner = None
        with pytest.raises(WebError) as info:
            backend._runner(handle)
        assert info.value.code == "invalid_state"


# ----------------------------------------------------------------------------
# open (fake sync_playwright)
# ----------------------------------------------------------------------------
class _FakeContextObj:
    def __init__(self, pw: _FakePWObj) -> None:
        self._pw = pw

    def new_page(self) -> _FakePage:
        return self._pw.page

    def new_cdp_session(self, page: _FakePage) -> _FakeCdp:
        return self._pw.cdp

    def close(self) -> None:
        self._pw.closed.append("context")


class _FakeBrowserObj:
    def __init__(self, pw: _FakePWObj) -> None:
        self._pw = pw

    def new_context(self, ignore_https_errors: bool = False) -> _FakeContextObj:
        return _FakeContextObj(self._pw)

    def close(self) -> None:
        self._pw.closed.append("browser")


class _FakeChromium:
    def __init__(self, pw: _FakePWObj) -> None:
        self._pw = pw

    def launch(self, headless: bool = True) -> _FakeBrowserObj:
        if self._pw.launch_error is not None:
            raise self._pw.launch_error
        return _FakeBrowserObj(self._pw)


class _FakePWObj:
    def __init__(self, page: _FakePage, cdp: _FakeCdp, launch_error: BaseException | None) -> None:
        self.page = page
        self.cdp = cdp
        self.launch_error = launch_error
        self.chromium = _FakeChromium(self)
        self.closed: list[str] = []
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


class _FakeSyncPlaywright:
    def __init__(self, pw: _FakePWObj) -> None:
        self._pw = pw

    def start(self) -> _FakePWObj:
        return self._pw


class TestOpen:
    def _patch(self, monkeypatch: MP, pw: _FakePWObj) -> None:
        import playwright.sync_api as spa

        monkeypatch.setattr(spa, "sync_playwright", lambda: _FakeSyncPlaywright(pw))

    def test_open_launches_navigates_and_registers(self, monkeypatch: MP) -> None:
        pw = _FakePWObj(_FakePage(url="https://loaded/"), _FakeCdp(), None)
        self._patch(monkeypatch, pw)
        backend = WebBackend()
        try:
            summary = backend.open("s", "https://loaded/", timeout=5.0)
            assert summary["opened"] is True
            assert summary["status"] == 200
            assert summary["url"] == "https://loaded/"
            # The CDP domains the buffers rely on were enabled during wiring.
            assert ("Network.enable", None) in pw.cdp.sent
            assert backend.status("s")["open"] is True
        finally:
            backend.close("s")

    def test_double_open_is_rejected(self, monkeypatch: MP) -> None:
        pw = _FakePWObj(_FakePage(), _FakeCdp(), None)
        self._patch(monkeypatch, pw)
        backend = WebBackend()
        try:
            backend.open("s", "https://loaded/", timeout=5.0)
            with pytest.raises(WebError) as info:
                backend.open("s", "https://loaded/", timeout=5.0)
            assert info.value.code == "invalid_state"
        finally:
            backend.close("s")

    def test_launch_failure_reaps_and_frees_the_slot(self, monkeypatch: MP) -> None:
        pw = _FakePWObj(_FakePage(), _FakeCdp(), RuntimeError("no chromium"))
        self._patch(monkeypatch, pw)
        backend = WebBackend()
        with pytest.raises(WebError) as info:
            backend.open("s", "https://x/", timeout=5.0)
        assert info.value.code == "backend_error"
        assert pw.stopped is True
        # The reservation was released, so a later open can reuse the id.
        assert "s" not in backend._sessions


# ----------------------------------------------------------------------------
# navigate
# ----------------------------------------------------------------------------
class TestNavigate:
    def test_navigation_failure_is_backend_error(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        handle = _handle(runners, page=_FakePage(goto_error=RuntimeError("net::ERR")))
        backend = _backend(handle, monkeypatch)
        with pytest.raises(WebError) as info:
            backend.navigate("s", "https://x/", timeout=5.0)
        assert info.value.code == "backend_error"

    def test_navigation_without_a_response_omits_status(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        handle = _handle(runners, page=_FakePage(response_status=None))
        backend = _backend(handle, monkeypatch)
        result = backend.navigate("s", "about:blank", timeout=5.0)
        assert "status" not in result

    def test_navigation_surfaces_an_error_status(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        # A 4xx main document resolves normally; the status must be reported so
        # a navigation onto an error page is not read as a clean hit.
        handle = _handle(runners, page=_FakePage(response_status=404))
        backend = _backend(handle, monkeypatch)
        result = backend.navigate("s", "https://x/missing", timeout=5.0)
        assert result["status"] == 404


# ----------------------------------------------------------------------------
# event wiring: buffers, truncation, eviction, drop accounting
# ----------------------------------------------------------------------------
class TestEventWiring:
    def _wire(self, runners: list[_Runner]) -> tuple[WebBackend, _WebSession, _FakeCdp]:
        cdp = _FakeCdp()
        handle = _handle(runners, cdp=cdp)
        backend = WebBackend()
        backend._wire_events(handle)
        return backend, handle, cdp

    def test_request_and_response_merge_into_one_entry(self, runners: list[_Runner]) -> None:
        _, handle, cdp = self._wire(runners)
        cdp.handlers["Network.requestWillBeSent"](
            {
                "requestId": "1",
                "request": {"url": "https://x/", "method": "GET"},
                "type": "Document",
            }
        )
        cdp.handlers["Network.responseReceived"](
            {"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}}
        )
        entry = handle.requests["1"]
        assert entry["status"] == 200
        assert entry["mimeType"] == "text/html"

    def test_response_for_unknown_request_is_ignored(self, runners: list[_Runner]) -> None:
        _, handle, cdp = self._wire(runners)
        cdp.handlers["Network.responseReceived"](
            {"requestId": "missing", "response": {"status": 500, "mimeType": "x"}}
        )
        assert "missing" not in handle.requests

    def test_oversized_response_mime_is_flagged(self, runners: list[_Runner]) -> None:
        _, handle, cdp = self._wire(runners)
        cdp.handlers["Network.requestWillBeSent"](
            {"requestId": "1", "request": {"url": "https://x/", "method": "GET"}}
        )
        cdp.handlers["Network.responseReceived"](
            {"requestId": "1", "response": {"status": 200, "mimeType": "m" * 4096}}
        )
        assert handle.requests["1"]["metadata_truncated"] is True

    def test_oversized_request_metadata_is_flagged(self, runners: list[_Runner]) -> None:
        _, handle, cdp = self._wire(runners)
        cdp.handlers["Network.requestWillBeSent"](
            {"requestId": "1", "request": {"url": "https://x/" + "a" * 20000, "method": "GET"}}
        )
        assert handle.requests["1"]["metadata_truncated"] is True

    def test_request_ring_drops_oldest(self, runners: list[_Runner]) -> None:
        _, handle, cdp = self._wire(runners)
        handle.requests = OrderedDict(
            (str(i), {"requestId": str(i)}) for i in range(web_client._MAX_REQUESTS)
        )
        cdp.handlers["Network.requestWillBeSent"](
            {"requestId": "new", "request": {"url": "https://x/", "method": "GET"}}
        )
        assert handle.requests_dropped == 1
        assert "0" not in handle.requests

    def test_script_parsed_is_recorded_and_evicts(self, runners: list[_Runner]) -> None:
        _, handle, cdp = self._wire(runners)
        cdp.handlers["Debugger.scriptParsed"](
            {"scriptId": "s1", "url": "https://x/a.js", "scriptLanguage": "JavaScript"}
        )
        assert handle.scripts["s1"]["language"] == "JavaScript"
        handle.scripts = OrderedDict(
            (str(i), {"scriptId": str(i)}) for i in range(web_client._MAX_SCRIPTS)
        )
        cdp.handlers["Debugger.scriptParsed"]({"scriptId": "new", "url": "u" * 20000})
        assert handle.scripts_dropped == 1
        assert handle.scripts["new"]["metadata_truncated"] is True

    def test_console_records_and_counts_drops(self, runners: list[_Runner]) -> None:
        _, handle, cdp = self._wire(runners)
        handle.console = deque(maxlen=1)
        cdp.handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "first"}]})
        cdp.handlers["Runtime.consoleAPICalled"](
            {"type": "warning", "args": [{"value": "x" * (10 * 1024)}]}
        )
        assert handle.console_dropped == 1
        assert handle.console[0]["text_truncated"] is True


# ----------------------------------------------------------------------------
# network_list / network_get / console / scripts / script_source
# ----------------------------------------------------------------------------
class TestReaders:
    def test_network_list_paginates(self, runners: list[_Runner], monkeypatch: MP) -> None:
        handle = _handle(runners)
        handle.requests = OrderedDict((str(i), {"requestId": str(i)}) for i in range(5))
        handle.requests_dropped = 2
        backend = _backend(handle, monkeypatch)
        result = backend.network_list("s", offset=1, limit=2)
        assert result["count"] == 2
        assert result["total"] == 5
        assert result["offset"] == 1
        assert result["has_more"] is True
        assert result["dropped"] == 2

    def test_network_get_unknown_request(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        handle = _handle(runners)
        backend = _backend(handle, monkeypatch)
        with pytest.raises(WebError) as info:
            backend.network_get("s", "nope", tmp_path)
        assert info.value.code == "not_found"

    def test_network_get_reports_missing_body(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        handle = _handle(runners, cdp=_FakeCdp(body_error=True))
        handle.requests["1"] = {"requestId": "1", "url": "https://x/", "status": 302}
        backend = _backend(handle, monkeypatch)
        result = backend.network_get("s", "1", tmp_path)
        assert result["body"] == ""
        assert result["body_error"]
        assert result["base64_encoded"] is False

    def test_network_get_inlines_text_body(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        cdp = _FakeCdp(bodies={"1": {"body": "hello world", "base64Encoded": False}})
        handle = _handle(runners, cdp=cdp)
        handle.requests["1"] = {"requestId": "1", "url": "https://x/"}
        backend = _backend(handle, monkeypatch)
        result = backend.network_get("s", "1", tmp_path)
        assert result["body"] == "hello world"
        assert result["body_truncated"] is False

    def test_network_get_spills_large_text_body(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        cdp = _FakeCdp(bodies={"1": {"body": "a" * 250_000, "base64Encoded": False}})
        handle = _handle(runners, cdp=cdp)
        handle.requests["1"] = {"requestId": "1", "url": "https://x/"}
        backend = _backend(handle, monkeypatch)
        result = backend.network_get("s", "1", tmp_path)
        assert result["body_truncated"] is True
        assert Path(result["body_path"]).is_file()

    def test_network_get_coerces_non_string_body(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        cdp = _FakeCdp(bodies={"1": {"body": 12345, "base64Encoded": False}})
        handle = _handle(runners, cdp=cdp)
        handle.requests["1"] = {"requestId": "1", "url": "https://x/"}
        backend = _backend(handle, monkeypatch)
        result = backend.network_get("s", "1", tmp_path)
        assert result["body"] == "12345"

    def test_network_get_decodes_base64_binary_body(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        import base64

        raw = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        encoded = base64.b64encode(raw).decode()
        cdp = _FakeCdp(bodies={"1": {"body": encoded, "base64Encoded": True}})
        handle = _handle(runners, cdp=cdp)
        handle.requests["1"] = {"requestId": "1", "url": "https://x/"}
        backend = _backend(handle, monkeypatch)
        result = backend.network_get("s", "1", tmp_path)
        assert result["base64_encoded"] is True
        assert result["body_bytes"] == len(raw)
        assert Path(result["body_path"]).read_bytes() == raw

    def test_network_get_rejects_invalid_base64(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        cdp = _FakeCdp(bodies={"1": {"body": "A", "base64Encoded": True}})
        handle = _handle(runners, cdp=cdp)
        handle.requests["1"] = {"requestId": "1", "url": "https://x/"}
        backend = _backend(handle, monkeypatch)
        result = backend.network_get("s", "1", tmp_path)
        assert "not valid base64" in result["body_error"]

    def test_console_returns_tail_with_totals(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        handle = _handle(runners)
        for i in range(5):
            handle.console.append({"type": "log", "text": str(i)})
        handle.console_dropped = 7
        backend = _backend(handle, monkeypatch)
        result = backend.console("s", limit=2)
        assert [e["text"] for e in result["console"]] == ["3", "4"]
        assert result["total"] == 5
        assert result["has_more"] is True
        assert result["dropped"] == 7

    def test_scripts_filter_and_paginate(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        handle = _handle(runners)
        handle.scripts["a"] = {"scriptId": "a", "language": "JavaScript"}
        handle.scripts["b"] = {"scriptId": "b", "language": "WebAssembly"}
        handle.scripts["c"] = {"scriptId": "c", "language": "WebAssembly"}
        backend = _backend(handle, monkeypatch)
        wasm = backend.scripts("s", wasm_only=True, offset=0, limit=1)
        assert wasm["total"] == 2
        assert wasm["count"] == 1
        assert wasm["has_more"] is True
        # Unfiltered lists every parsed script, not just WebAssembly.
        every = backend.scripts("s", wasm_only=False)
        assert every["total"] == 3

    def test_script_source_reraises_backend_wedge(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        # A wedged runner surfaces its own WebError; script_source must not
        # relabel that as a not_found "missing script".
        handle = _handle(runners, cdp=_FakeCdp(sources={"s1": "x"}))
        assert handle.runner is not None
        handle.runner._wedged = True
        backend = _backend(handle, monkeypatch)
        with pytest.raises(WebError) as info:
            backend.script_source("s", "s1", tmp_path)
        assert info.value.code == "backend_error"

    def test_script_source_spills(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        cdp = _FakeCdp(sources={"s1": "x" * 250_000})
        handle = _handle(runners, cdp=cdp)
        backend = _backend(handle, monkeypatch)
        result = backend.script_source("s", "s1", tmp_path)
        assert result["truncated"] is True
        assert Path(result["source_path"]).is_file()

    def test_script_source_coerces_non_string(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        class _IntSourceCdp(_FakeCdp):
            def send(self, method: str, params: dict[str, Any] | None = None) -> Any:
                if method == "Debugger.getScriptSource":
                    return {"scriptSource": 999}
                return {}

        handle = _handle(runners, cdp=_IntSourceCdp())
        backend = _backend(handle, monkeypatch)
        result = backend.script_source("s", "s1", tmp_path)
        assert result["source"] == "999"

    def test_script_source_missing_is_not_found(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        handle = _handle(runners, cdp=_FakeCdp(source_error=RuntimeError("no such script")))
        backend = _backend(handle, monkeypatch)
        with pytest.raises(WebError) as info:
            backend.script_source("s", "s1", tmp_path)
        assert info.value.code == "not_found"


# ----------------------------------------------------------------------------
# dom_snapshot / screenshot / har_export
# ----------------------------------------------------------------------------
class TestPageOperations:
    def test_dom_snapshot_returns_clipped_html(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        page = _FakePage(evaluate_result={"html": "<html></html>", "truncated": False})
        handle = _handle(runners, page=page)
        backend = _backend(handle, monkeypatch)
        result = backend.dom_snapshot("s")
        assert result["html"] == "<html></html>"
        assert result["truncated"] is False

    def test_dom_snapshot_non_dict_is_backend_error(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        handle = _handle(runners, page=_FakePage(evaluate_result="not a dict"))
        backend = _backend(handle, monkeypatch)
        with pytest.raises(WebError) as info:
            backend.dom_snapshot("s")
        assert info.value.code == "backend_error"

    def test_dom_snapshot_evaluate_failure_is_backend_error(
        self, runners: list[_Runner], monkeypatch: MP
    ) -> None:
        handle = _handle(runners, page=_FakePage(evaluate_error=RuntimeError("execution ctx")))
        backend = _backend(handle, monkeypatch)
        with pytest.raises(WebError) as info:
            backend.dom_snapshot("s")
        assert info.value.code == "backend_error"

    def test_screenshot_writes_and_sizes(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        handle = _handle(runners)
        backend = _backend(handle, monkeypatch)
        out = tmp_path / "shot.png"
        result = backend.screenshot("s", out, full_page=True)
        assert result["size"] > 0
        assert Path(result["path"]).is_file()

    def test_screenshot_failure_is_backend_error(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        handle = _handle(runners, page=_FakePage(screenshot_error=RuntimeError("gpu crash")))
        backend = _backend(handle, monkeypatch)
        with pytest.raises(WebError) as info:
            backend.screenshot("s", tmp_path / "shot.png")
        assert info.value.code == "backend_error"

    def test_screenshot_over_cap_is_refused(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
        handle = _handle(runners)
        backend = _backend(handle, monkeypatch)
        out = tmp_path / "shot.png"
        with pytest.raises(WebError) as info:
            backend.screenshot("s", out)
        assert info.value.code == "too_large"
        assert not out.exists()

    def test_har_export_writes_json(
        self, runners: list[_Runner], monkeypatch: MP, tmp_path: Path
    ) -> None:
        handle = _handle(runners)
        handle.requests["1"] = {
            "requestId": "1",
            "method": "GET",
            "url": "https://x/",
            "status": 200,
            "mimeType": "text/html",
            "resourceType": "Document",
        }
        backend = _backend(handle, monkeypatch)
        out = tmp_path / "capture.har"
        result = backend.har_export("s", out)
        assert result["entry_count"] == 1
        assert out.is_file()


# ----------------------------------------------------------------------------
# close / close_all
# ----------------------------------------------------------------------------
class TestClose:
    def test_close_aborted_open_token(self) -> None:
        backend = WebBackend()
        backend._sessions["s"] = object()  # type: ignore[assignment]
        assert backend.close("s") == {"closed": True, "note": "open was aborted"}

    def test_close_without_runner_tears_down_directly(self) -> None:
        backend = WebBackend()
        closed: list[str] = []
        pw = SimpleNamespace(stop=lambda: closed.append("pw"))
        browser = SimpleNamespace(close=lambda: closed.append("browser"))
        context = SimpleNamespace(close=lambda: closed.append("context"))
        handle = _WebSession(pw, browser, context, _FakePage(), _FakeCdp())
        handle.runner = None
        backend._sessions["s"] = handle
        assert backend.close("s") == {"closed": True}
        assert closed == ["context", "browser", "pw"]

    def test_close_clean_when_runner_is_healthy(self, runners: list[_Runner]) -> None:
        backend = WebBackend()
        handle = _handle(runners)
        backend._sessions["s"] = handle
        result = backend.close("s")
        assert result == {"closed": True, "clean": True}

    def test_close_wedged_reaps_and_reports_unclean(self, runners: list[_Runner]) -> None:
        backend = WebBackend()
        handle = _handle(runners)
        assert handle.runner is not None
        handle.runner._wedged = True
        backend._sessions["s"] = handle
        result = backend.close("s")
        assert result == {"closed": True, "clean": False}

    def test_close_all_closes_each_session(self, runners: list[_Runner]) -> None:
        backend = WebBackend()
        backend._sessions["a"] = _handle(runners)
        backend._sessions["b"] = _handle(runners)
        backend.close_all()
        assert backend._sessions == {}
