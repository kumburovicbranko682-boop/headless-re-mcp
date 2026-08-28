"""Branch coverage for the Playwright-backed web client.

The browser is faked end to end: a stand-in ``sync_playwright`` for ``open``,
stand-in handles for the session-scoped readers, and a live ``_Runner`` for the
thread-affinity and wedging paths. Nothing here launches Chromium.
"""

from __future__ import annotations

import sys
import threading
import types
from collections import OrderedDict, deque
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web
from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE,
    _MAX_CONSOLE_TEXT,
    _MAX_INLINE_BODY,
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
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES

# --------------------------------------------------------------------------
# _clip_console_text
# --------------------------------------------------------------------------


def test_clip_console_text_joins_values_descriptions_and_types() -> None:
    text, truncated = _clip_console_text(
        {
            "args": [
                {"value": "hello"},
                {"description": "world"},
                {"type": "object"},
                "not-a-dict",
            ]
        }
    )
    assert text == "hello world object"
    assert truncated is False


def test_clip_console_text_truncates_a_long_argument() -> None:
    text, truncated = _clip_console_text({"args": [{"value": "x" * (_MAX_CONSOLE_TEXT + 50)}]})
    assert truncated is True
    assert len(text) == _MAX_CONSOLE_TEXT


def test_clip_console_text_truncates_at_the_joining_space() -> None:
    first = "a" * (_MAX_CONSOLE_TEXT - 1)
    text, truncated = _clip_console_text({"args": [{"value": first}, {"value": "b"}]})
    assert truncated is True
    assert text == first


def test_clip_console_text_stops_when_the_budget_is_already_spent() -> None:
    filler = "a" * _MAX_CONSOLE_TEXT
    text, truncated = _clip_console_text(
        {"args": [{"value": filler}, {"value": "b"}, {"value": "c"}]}
    )
    assert truncated is True
    assert text == filler


def test_clip_console_text_handles_no_args() -> None:
    assert _clip_console_text({}) == ("", False)


# --------------------------------------------------------------------------
# _spill_text / _spill_bytes
# --------------------------------------------------------------------------


def test_spill_text_inlines_small_bodies(tmp_path: Path) -> None:
    inline, spill, truncated = _spill_text(
        "small", artifact_dir=tmp_path, filename="b.bin", kind="response body"
    )
    assert inline == "small"
    assert spill is None
    assert truncated is False


def test_spill_text_spills_large_bodies(tmp_path: Path) -> None:
    body = "y" * (_MAX_INLINE_BODY + 100)
    inline, spill, truncated = _spill_text(
        body, artifact_dir=tmp_path, filename="b.bin", kind="response body"
    )
    assert truncated is True
    assert spill is not None and spill.is_file()
    assert len(inline) == _MAX_INLINE_BODY


def test_spill_text_refuses_over_the_capture_cap(tmp_path: Path) -> None:
    body = "z" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1)
    with pytest.raises(WebError) as info:
        _spill_text(body, artifact_dir=tmp_path, filename="b.bin", kind="response body")
    assert info.value.code == "too_large"


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b"])
def test_spill_text_rejects_bad_filenames(tmp_path: Path, bad: str) -> None:
    body = "y" * (_MAX_INLINE_BODY + 100)
    with pytest.raises(WebError) as info:
        _spill_text(body, artifact_dir=tmp_path, filename=bad, kind="response body")
    assert info.value.code == "invalid_params"


def test_spill_text_refuses_when_the_written_file_trips_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = "y" * (_MAX_INLINE_BODY + 100)
    monkeypatch.setattr(web, "capped_file_size", lambda path, *, cap: (cap + 1, True))
    with pytest.raises(WebError) as info:
        _spill_text(body, artifact_dir=tmp_path, filename="b.bin", kind="response body")
    assert info.value.code == "too_large"


def test_spill_bytes_writes_a_binary_artifact(tmp_path: Path) -> None:
    out = _spill_bytes(
        b"\x00\x01\x02", artifact_dir=tmp_path, filename="b.bin", kind="response body"
    )
    assert out.is_file()
    assert out.read_bytes() == b"\x00\x01\x02"


def test_spill_bytes_refuses_over_the_capture_cap(tmp_path: Path) -> None:
    with pytest.raises(WebError) as info:
        _spill_bytes(
            b"0" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1),
            artifact_dir=tmp_path,
            filename="b.bin",
            kind="response body",
        )
    assert info.value.code == "too_large"


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b"])
def test_spill_bytes_rejects_bad_filenames(tmp_path: Path, bad: str) -> None:
    with pytest.raises(WebError) as info:
        _spill_bytes(b"data", artifact_dir=tmp_path, filename=bad, kind="response body")
    assert info.value.code == "invalid_params"


def test_spill_bytes_refuses_when_the_written_file_trips_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web, "capped_file_size", lambda path, *, cap: (cap + 1, True))
    with pytest.raises(WebError) as info:
        _spill_bytes(b"data", artifact_dir=tmp_path, filename="b.bin", kind="response body")
    assert info.value.code == "too_large"


# --------------------------------------------------------------------------
# small module helpers
# --------------------------------------------------------------------------


def test_bounded_metadata_truncates_and_passes_through() -> None:
    assert _bounded_metadata("plain", 100) == ("plain", False)
    assert _bounded_metadata(None, 100) == ("", False)
    assert _bounded_metadata(1234, 100) == ("1234", False)
    text, truncated = _bounded_metadata("a" * 50, 10)
    assert truncated is True
    assert len(text.encode("utf-8")) <= 10


def test_response_status_reads_absent_and_broken_responses() -> None:
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status=200)) == 200
    assert _response_status(SimpleNamespace(status="oops")) is None

    class _Broken:
        @property
        def status(self) -> int:
            raise RuntimeError("gone")

    assert _response_status(_Broken()) is None


def test_safe_title_swallows_failures() -> None:
    assert _safe_title(SimpleNamespace(title=lambda: "Example")) == "Example"

    def _boom() -> str:
        raise RuntimeError("title crashed")

    assert _safe_title(SimpleNamespace(title=_boom)) == ""


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    proc = SimpleNamespace(pid=4321)
    transport = SimpleNamespace(_proc=proc)
    connection = SimpleNamespace(_transport=transport)
    impl = SimpleNamespace(_connection=connection)
    pw = SimpleNamespace(_impl_obj=impl)
    assert _playwright_driver_pid(pw) == 4321


def test_playwright_driver_pid_returns_none_on_a_broken_chain() -> None:
    assert _playwright_driver_pid(SimpleNamespace()) is None
    proc = SimpleNamespace(pid="not-an-int")
    pw = SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(_transport=SimpleNamespace(_proc=proc))
        )
    )
    assert _playwright_driver_pid(pw) is None


def test_reap_driver_pid_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web, "terminate_pid_tree", lambda pid: killed.append(pid))

    _reap_driver_pid(None)
    _reap_driver_pid(0)
    assert killed == []

    monkeypatch.setattr(web, "process_image_path", lambda pid: None)
    _reap_driver_pid(123)
    monkeypatch.setattr(web, "process_image_path", lambda pid: "/usr/bin/bash")
    _reap_driver_pid(123)
    assert killed == []

    monkeypatch.setattr(web, "process_image_path", lambda pid: "/opt/node/bin/node")
    _reap_driver_pid(123)
    assert killed == [123]


def test_reap_web_session_forwards_the_handle_driver_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(web, "_reap_driver_pid", lambda pid: seen.append(pid))
    web._reap_web_session(SimpleNamespace(driver_pid=4242))  # type: ignore[arg-type]
    web._reap_web_session(SimpleNamespace())  # type: ignore[arg-type]
    assert seen == [4242, None]


# --------------------------------------------------------------------------
# _Runner
# --------------------------------------------------------------------------


def test_runner_runs_work_and_shuts_down() -> None:
    runner = _Runner("test-basic")
    try:
        assert runner.call(lambda: 7) == 7
    finally:
        runner.shutdown()


def test_runner_refuses_after_close() -> None:
    runner = _Runner("test-closed")
    runner.shutdown()
    with pytest.raises(WebError) as info:
        runner.call(lambda: 1)
    assert info.value.code == "invalid_state"


def test_runner_wedges_on_timeout_then_refuses() -> None:
    runner = _Runner("test-wedge")
    release = threading.Event()
    try:
        with pytest.raises(WebError) as info:
            runner.call(lambda: release.wait(5.0), timeout=0.1)
        assert info.value.code == "timeout"
        assert runner.wedged is True
        with pytest.raises(WebError) as info2:
            runner.call(lambda: 1)
        assert info2.value.code == "backend_error"
    finally:
        release.set()
        runner.shutdown()


def test_runner_skips_a_future_cancelled_before_it_runs() -> None:
    runner = _Runner("test-cancel")
    started = threading.Event()
    release = threading.Event()

    def block() -> str:
        started.set()
        release.wait(3.0)
        return "done"

    worker = threading.Thread(target=lambda: runner.call(block, timeout=5.0))
    worker.start()
    try:
        assert started.wait(2.0)
        cancelled: Future[Any] = Future()
        runner._queue.put((lambda: "never", cancelled))
        assert cancelled.cancel() is True
        release.set()
        worker.join(3.0)
        # The loop discarded the cancelled item and is still serving work.
        assert runner.call(lambda: "alive", timeout=2.0) == "alive"
    finally:
        release.set()
        runner.shutdown()


# --------------------------------------------------------------------------
# WebBackend session-scoped readers with faked handles
# --------------------------------------------------------------------------


class _DirectRunner:
    """Runs work inline; stands in for the greenlet-affine session thread."""

    wedged = False

    def __init__(self, *, send: Any = None) -> None:
        self._send = send

    def call(self, work: Any, *, timeout: float = 60.0) -> Any:
        return work()

    def shutdown(self) -> None:
        return None


def _handle(**over: Any) -> Any:
    handle = SimpleNamespace(
        lock=threading.RLock(),
        requests=OrderedDict(),
        console=deque(maxlen=_MAX_CONSOLE),
        scripts=OrderedDict(),
        requests_dropped=0,
        console_dropped=0,
        scripts_dropped=0,
        runner=_DirectRunner(),
        cdp=SimpleNamespace(),
        page=SimpleNamespace(url="https://site/", title=lambda: "Site"),
        driver_pid=None,
    )
    for key, value in over.items():
        setattr(handle, key, value)
    return handle


def _backend_with(handle: Any) -> WebBackend:
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    return backend


def test_runner_helper_refuses_a_handle_without_a_thread() -> None:
    backend = WebBackend()
    with pytest.raises(WebError) as info:
        backend._runner(_handle(runner=None))
    assert info.value.code == "invalid_state"


def test_status_reports_opening_and_foreign_handles() -> None:
    backend = WebBackend()
    backend._sessions["opening"] = object()  # type: ignore[assignment]
    backend._sessions["foreign"] = SimpleNamespace()  # type: ignore[assignment]
    assert backend.status("missing") == {"open": False}
    assert backend.status("opening") == {"open": False, "opening": True}
    assert backend.status("foreign") == {"open": False}


def test_status_of_a_live_session_reads_page_identity() -> None:
    session = _WebSession(
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(url="https://live/", title=lambda: "Live"),
        SimpleNamespace(),
    )
    session.runner = _DirectRunner()  # type: ignore[assignment]
    backend = WebBackend()
    backend._sessions["s"] = session
    result = backend.status("s")
    assert result == {"open": True, "url": "https://live/", "title": "Live"}


def test_network_list_paginates() -> None:
    handle = _handle()
    handle.requests["a"] = {"requestId": "a"}
    handle.requests["b"] = {"requestId": "b"}
    handle.requests_dropped = 3
    backend = _backend_with(handle)
    result = backend.network_list("s", offset=0, limit=1)
    assert result["count"] == 1
    assert result["total"] == 2
    assert result["has_more"] is True
    assert result["dropped"] == 3


def test_network_get_unknown_request_is_not_found() -> None:
    backend = _backend_with(_handle())
    with pytest.raises(WebError) as info:
        backend.network_get("s", "missing", Path("/tmp"))
    assert info.value.code == "not_found"


def test_network_get_reports_a_body_error(tmp_path: Path) -> None:
    handle = _handle()
    handle.requests["r"] = {"requestId": "r", "url": "u"}

    def _boom() -> Any:
        raise RuntimeError("no body cached")

    handle.cdp.send = lambda *a, **k: _boom()
    backend = _backend_with(handle)
    result = backend.network_get("s", "r", tmp_path)
    assert result["body"] == ""
    assert result["body_error"] == "no body cached"
    assert result["body_truncated"] is False


def test_network_get_inlines_a_small_text_body(tmp_path: Path) -> None:
    handle = _handle()
    handle.requests["r"] = {"requestId": "r"}
    handle.cdp.send = lambda *a, **k: {"body": "hi", "base64Encoded": False}
    backend = _backend_with(handle)
    result = backend.network_get("s", "r", tmp_path)
    assert result["body"] == "hi"
    assert result["base64_encoded"] is False
    assert "body_path" not in result


def test_network_get_spills_a_large_text_body(tmp_path: Path) -> None:
    handle = _handle()
    handle.requests["r"] = {"requestId": "r"}
    big = "t" * (_MAX_INLINE_BODY + 10)
    handle.cdp.send = lambda *a, **k: {"body": big, "base64Encoded": False}
    backend = _backend_with(handle)
    result = backend.network_get("s", "r", tmp_path)
    assert result["body_truncated"] is True
    assert Path(result["body_path"]).is_file()


def test_network_get_coerces_a_non_string_body(tmp_path: Path) -> None:
    handle = _handle()
    handle.requests["r"] = {"requestId": "r"}
    handle.cdp.send = lambda *a, **k: {"body": 12345, "base64Encoded": False}
    backend = _backend_with(handle)
    result = backend.network_get("s", "r", tmp_path)
    assert result["body"] == "12345"


def test_network_get_decodes_a_base64_body_to_bytes(tmp_path: Path) -> None:
    handle = _handle()
    handle.requests["r"] = {"requestId": "r"}
    import base64

    encoded = base64.b64encode(b"\x89PNG\r\n").decode("ascii")
    handle.cdp.send = lambda *a, **k: {"body": encoded, "base64Encoded": True}
    backend = _backend_with(handle)
    result = backend.network_get("s", "r", tmp_path)
    assert result["base64_encoded"] is True
    assert result["body_bytes"] == 6
    assert Path(result["body_path"]).read_bytes() == b"\x89PNG\r\n"


def test_network_get_reports_invalid_base64(tmp_path: Path) -> None:
    handle = _handle()
    handle.requests["r"] = {"requestId": "r"}
    handle.cdp.send = lambda *a, **k: {"body": "!!!not base64!!!", "base64Encoded": True}
    backend = _backend_with(handle)
    result = backend.network_get("s", "r", tmp_path)
    assert "was not valid base64" in result["body_error"]
    # Same documented shape as every other network_get error path, so a caller
    # reading result["body"] does not hit a missing key on this one.
    assert result["body"] == ""
    assert result["base64_encoded"] is False
    assert result["body_truncated"] is False


def test_console_returns_the_newest_tail() -> None:
    handle = _handle()
    for i in range(5):
        handle.console.append({"type": "log", "text": str(i)})
    handle.console_dropped = 2
    backend = _backend_with(handle)
    result = backend.console("s", limit=2)
    assert [e["text"] for e in result["console"]] == ["3", "4"]
    assert result["has_more"] is True
    assert result["dropped"] == 2


def test_scripts_filters_wasm_and_paginates() -> None:
    handle = _handle()
    handle.scripts["1"] = {"scriptId": "1", "language": "JavaScript"}
    handle.scripts["2"] = {"scriptId": "2", "language": "WebAssembly"}
    backend = _backend_with(handle)
    everything = backend.scripts("s")
    assert everything["total"] == 2
    wasm = backend.scripts("s", wasm_only=True)
    assert wasm["total"] == 1
    assert wasm["scripts"][0]["scriptId"] == "2"


def test_script_source_inlines_and_spills(tmp_path: Path) -> None:
    handle = _handle()
    handle.cdp.send = lambda *a, **k: {"scriptSource": "var a=1;"}
    backend = _backend_with(handle)
    result = backend.script_source("s", "9", tmp_path)
    assert result["source"] == "var a=1;"
    assert "source_path" not in result

    big = "x" * (_MAX_INLINE_BODY + 5)
    handle.cdp.send = lambda *a, **k: {"scriptSource": big}
    spilled = backend.script_source("s", "9", tmp_path)
    assert spilled["truncated"] is True
    assert Path(spilled["source_path"]).is_file()


def test_script_source_coerces_a_non_string_source(tmp_path: Path) -> None:
    handle = _handle()
    handle.cdp.send = lambda *a, **k: {"scriptSource": 999}
    backend = _backend_with(handle)
    result = backend.script_source("s", "9", tmp_path)
    assert result["source"] == "999"


def test_script_source_maps_a_cdp_failure(tmp_path: Path) -> None:
    handle = _handle()

    def _boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("no such script")

    handle.cdp.send = _boom
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.script_source("s", "9", tmp_path)
    assert info.value.code == "not_found"


def test_script_source_reraises_a_web_error(tmp_path: Path) -> None:
    handle = _handle()

    def _boom(*a: Any, **k: Any) -> Any:
        raise WebError("timeout", "browser did not respond")

    handle.cdp.send = _boom
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.script_source("s", "9", tmp_path)
    assert info.value.code == "timeout"


def test_dom_snapshot_reads_and_clips() -> None:
    handle = _handle()
    handle.page.evaluate = lambda script, cap: {"html": "<html></html>", "truncated": False}
    backend = _backend_with(handle)
    result = backend.dom_snapshot("s")
    assert result["html"] == "<html></html>"
    assert result["truncated"] is False


def test_dom_snapshot_maps_an_evaluation_failure() -> None:
    handle = _handle()

    def _boom(script: str, cap: int) -> Any:
        raise RuntimeError("evaluate failed")

    handle.page.evaluate = _boom
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.dom_snapshot("s")
    assert info.value.code == "backend_error"


def test_dom_snapshot_refuses_a_non_document_result() -> None:
    handle = _handle()
    handle.page.evaluate = lambda script, cap: "not-a-dict"
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.dom_snapshot("s")
    assert "no document" in info.value.message


def test_screenshot_writes_and_reports_size(tmp_path: Path) -> None:
    out = tmp_path / "shots" / "shot.png"
    handle = _handle()
    handle.page.screenshot = lambda path, full_page: Path(path).write_bytes(b"\x89PNG")
    backend = _backend_with(handle)
    result = backend.screenshot("s", out, full_page=True)
    assert result["path"] == str(out)
    assert result["size"] == 4


def test_screenshot_maps_a_capture_failure(tmp_path: Path) -> None:
    handle = _handle()

    def _boom(path: str, full_page: bool) -> None:
        raise RuntimeError("screenshot failed")

    handle.page.screenshot = _boom
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.screenshot("s", tmp_path / "x.png")
    assert info.value.code == "backend_error"


def test_screenshot_refuses_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "shot.png"
    handle = _handle()
    handle.page.screenshot = lambda path, full_page: Path(path).write_bytes(b"big")
    monkeypatch.setattr(web, "capped_file_size", lambda path, *, cap: (cap + 1, True))
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.screenshot("s", out)
    assert info.value.code == "too_large"


def test_har_export_writes_entries(tmp_path: Path) -> None:
    handle = _handle()
    handle.requests["r"] = {
        "method": "GET",
        "url": "https://site/",
        "status": 200,
        "mimeType": "text/html",
        "resourceType": "document",
    }
    out = tmp_path / "out" / "session.har"
    backend = _backend_with(handle)
    result = backend.har_export("s", out)
    assert Path(result["path"]).is_file()
    assert result["entry_count"] == 1


def test_har_export_refuses_an_oversized_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _handle()
    monkeypatch.setattr(
        web,
        "serialize_har",
        lambda entries, *, max_bytes: SimpleNamespace(
            size=max_bytes + 1, text="{}", entry_count=0, truncated=True
        ),
    )
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.har_export("s", tmp_path / "big.har")
    assert info.value.code == "too_large"


def test_navigate_maps_a_navigation_failure() -> None:
    handle = _handle()

    def _boom(url: str, timeout: float, wait_until: str) -> Any:
        raise RuntimeError("navigation blew up")

    handle.page.goto = _boom
    backend = _backend_with(handle)
    with pytest.raises(WebError) as info:
        backend.navigate("s", "https://site/next", timeout=5.0)
    assert info.value.code == "backend_error"


# --------------------------------------------------------------------------
# close
# --------------------------------------------------------------------------


def test_close_reports_no_session() -> None:
    assert WebBackend().close("missing") == {"closed": False, "note": "no web session was open"}


def test_close_reports_an_aborted_open() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True, "note": "open was aborted"}


def test_close_of_a_runnerless_handle_calls_close() -> None:
    closed = {"n": 0}
    handle = _handle(runner=None, close=lambda: closed.__setitem__("n", closed["n"] + 1))
    backend = WebBackend()
    backend._sessions["s"] = handle
    assert backend.close("s") == {"closed": True}
    assert closed["n"] == 1


def test_close_of_a_wedged_runner_reaps_the_driver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reaped: list[int] = []
    monkeypatch.setattr(web, "_reap_web_session", lambda handle: reaped.append(1))

    class _WedgedRunner(_DirectRunner):
        wedged = True

        def call(self, work: Any, *, timeout: float = 60.0) -> Any:
            raise WebError("timeout", "wedged")

    handle = _handle(runner=_WedgedRunner(), close=lambda: None)
    backend = WebBackend()
    backend._sessions["s"] = handle
    result = backend.close("s")
    assert result == {"closed": True, "clean": False}
    assert reaped == [1]


def test_close_of_a_healthy_runner_is_clean() -> None:
    handle = _handle(close=lambda: None)
    backend = WebBackend()
    backend._sessions["s"] = handle
    result = backend.close("s")
    assert result == {"closed": True, "clean": True}


def test_close_all_tears_down_every_session(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = WebBackend()
    backend._sessions["a"] = object()  # type: ignore[assignment]
    backend._sessions["b"] = object()  # type: ignore[assignment]
    backend.close_all()
    assert backend._sessions == {}


def test_web_session_close_is_best_effort() -> None:
    calls: list[str] = []

    def _closer(name: str) -> Any:
        def _fn() -> None:
            calls.append(name)
            if name == "browser":
                raise RuntimeError("already gone")

        return _fn

    session = _WebSession(
        SimpleNamespace(stop=_closer("stop")),
        SimpleNamespace(close=_closer("browser")),
        SimpleNamespace(close=_closer("context")),
        SimpleNamespace(),
        SimpleNamespace(),
    )
    session.close()
    assert calls == ["context", "browser", "stop"]


# --------------------------------------------------------------------------
# _wire_events handlers
# --------------------------------------------------------------------------


def _wire_and_capture(backend: WebBackend, handle: Any) -> dict[str, Any]:
    handlers: dict[str, Any] = {}
    handle.cdp = SimpleNamespace(
        send=lambda *a, **k: None,
        on=lambda event, cb: handlers.__setitem__(event, cb),
    )
    backend._wire_events(handle)
    return handlers


def test_wire_events_records_requests_and_evicts_the_oldest() -> None:
    handle = _handle()
    handlers = _wire_and_capture(WebBackend(), handle)
    on_request = handlers["Network.requestWillBeSent"]
    on_request(
        {
            "requestId": "keep",
            "request": {"url": "u" * (web._MAX_URL_BYTES + 10), "method": "GET"},
            "type": "Document",
        }
    )
    assert handle.requests["keep"]["metadata_truncated"] is True

    from headless_re_mcp.backends.web import client as mod

    original = mod._MAX_REQUESTS
    try:
        mod._MAX_REQUESTS = 1
        on_request({"requestId": "second", "request": {"url": "x", "method": "GET"}})
        assert "keep" not in handle.requests
        assert handle.requests_dropped == 1
    finally:
        mod._MAX_REQUESTS = original


def test_wire_events_updates_responses_and_ignores_unknown_ids() -> None:
    handle = _handle()
    handlers = _wire_and_capture(WebBackend(), handle)
    on_request = handlers["Network.requestWillBeSent"]
    on_response = handlers["Network.responseReceived"]
    on_request({"requestId": "r", "request": {"url": "u", "method": "GET"}})
    on_response(
        {
            "requestId": "r",
            "response": {"status": 200, "mimeType": "z" * (web._MAX_METADATA_BYTES + 5)},
        }
    )
    assert handle.requests["r"]["status"] == 200
    assert handle.requests["r"]["metadata_truncated"] is True
    # An unknown id is dropped rather than resurrected.
    on_response({"requestId": "ghost", "response": {"status": 500}})
    assert "ghost" not in handle.requests


def test_wire_events_updates_a_response_without_truncating_metadata() -> None:
    handle = _handle()
    handlers = _wire_and_capture(WebBackend(), handle)
    handlers["Network.requestWillBeSent"](
        {"requestId": "r", "request": {"url": "u", "method": "GET"}}
    )
    handlers["Network.responseReceived"](
        {"requestId": "r", "response": {"status": 204, "mimeType": "text/plain"}}
    )
    assert handle.requests["r"]["status"] == 204
    assert handle.requests["r"]["mimeType"] == "text/plain"
    assert "metadata_truncated" not in handle.requests["r"]


def test_wire_events_records_scripts_and_evicts_the_oldest() -> None:
    handle = _handle()
    handlers = _wire_and_capture(WebBackend(), handle)
    on_script = handlers["Debugger.scriptParsed"]
    on_script(
        {
            "scriptId": "keep",
            "url": "u" * (web._MAX_URL_BYTES + 10),
            "scriptLanguage": "WebAssembly",
        }
    )
    assert handle.scripts["keep"]["metadata_truncated"] is True

    from headless_re_mcp.backends.web import client as mod

    original = mod._MAX_SCRIPTS
    try:
        mod._MAX_SCRIPTS = 1
        on_script({"scriptId": "second", "url": "x"})
        assert "keep" not in handle.scripts
        assert handle.scripts_dropped == 1
    finally:
        mod._MAX_SCRIPTS = original


def test_wire_events_records_console_and_counts_drops() -> None:
    handle = _handle(console=deque(maxlen=1))
    handlers = _wire_and_capture(WebBackend(), handle)
    on_console = handlers["Runtime.consoleAPICalled"]
    on_console({"type": "log", "args": [{"value": "x" * (_MAX_CONSOLE_TEXT + 10)}]})
    assert handle.console[-1]["text_truncated"] is True
    on_console({"type": "warn", "args": [{"value": "y"}]})
    assert handle.console_dropped == 1
    assert handle.console[-1]["type"] == "warn"


# --------------------------------------------------------------------------
# _check_available
# --------------------------------------------------------------------------


def test_check_available_caches_a_successful_import(monkeypatch: pytest.MonkeyPatch) -> None:
    # CI quality jobs run without the browser extra, so fake the import instead
    # of requiring a real playwright installation.
    backend = WebBackend()
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", types.ModuleType("playwright.sync_api"))
    backend._check_available()
    assert backend._available is True
    # Cached: a second call takes the fast path and never re-imports.
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    backend._check_available()


def test_check_available_detects_a_missing_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = WebBackend()
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    with pytest.raises(WebError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"
    assert backend._available is False


def test_check_available_raises_when_already_marked_unavailable() -> None:
    backend = WebBackend()
    backend._available = False
    with pytest.raises(WebError) as info:
        backend._check_available()
    assert info.value.code == "capability_unavailable"


# --------------------------------------------------------------------------
# open()
# --------------------------------------------------------------------------


class _FakePage:
    def __init__(self, *, goto_error: Exception | None = None) -> None:
        self.url = "https://opened/"
        self._goto_error = goto_error

    def goto(self, url: str, timeout: float, wait_until: str) -> Any:
        if self._goto_error is not None:
            raise self._goto_error
        self.url = url
        return SimpleNamespace(status=200)

    def title(self) -> str:
        return "Opened"


class _FakePlaywright:
    def __init__(self, page: _FakePage, *, pid: int | None) -> None:
        self._page = page
        self.stopped = False
        self.cdp = SimpleNamespace(send=lambda *a, **k: None, on=lambda *a, **k: None)
        self.chromium = SimpleNamespace(launch=lambda headless: self._browser())
        if pid is not None:
            self._impl_obj = SimpleNamespace(
                _connection=SimpleNamespace(
                    _transport=SimpleNamespace(_proc=SimpleNamespace(pid=pid))
                )
            )

    def _browser(self) -> Any:
        context = SimpleNamespace(
            new_page=lambda: self._page,
            new_cdp_session=lambda page: self.cdp,
            close=lambda: None,
        )
        return SimpleNamespace(
            new_context=lambda ignore_https_errors: context,
            close=lambda: None,
        )

    def stop(self) -> None:
        self.stopped = True


def _install_fake_playwright(monkeypatch: pytest.MonkeyPatch, pw: _FakePlaywright) -> None:
    starter = SimpleNamespace(start=lambda: pw)
    fake_module = SimpleNamespace(sync_playwright=lambda: starter)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_module)


def test_open_launches_a_browser_and_navigates(monkeypatch: pytest.MonkeyPatch) -> None:
    pw = _FakePlaywright(_FakePage(), pid=99999)
    _install_fake_playwright(monkeypatch, pw)
    monkeypatch.setattr(web, "_reap_driver_pid", lambda pid: None)
    backend = WebBackend()
    backend._available = True
    try:
        summary = backend.open("s", "https://target/", headless=True, timeout=5.0)
        assert summary["opened"] is True
        assert summary["url"] == "https://target/"
        assert summary["status"] == 200
        assert isinstance(backend._sessions["s"], _WebSession)
    finally:
        backend.close_all()


def test_open_without_a_url_skips_navigation(monkeypatch: pytest.MonkeyPatch) -> None:
    pw = _FakePlaywright(_FakePage(), pid=None)
    _install_fake_playwright(monkeypatch, pw)
    backend = WebBackend()
    backend._available = True
    try:
        summary = backend.open("s", "", timeout=5.0)
        assert summary["opened"] is True
        assert "status" not in summary
    finally:
        backend.close_all()


def test_open_refuses_a_second_open(monkeypatch: pytest.MonkeyPatch) -> None:
    pw = _FakePlaywright(_FakePage(), pid=None)
    _install_fake_playwright(monkeypatch, pw)
    backend = WebBackend()
    backend._available = True
    try:
        backend.open("s", "", timeout=5.0)
        with pytest.raises(WebError) as info:
            backend.open("s", "", timeout=5.0)
        assert info.value.code == "invalid_state"
    finally:
        backend.close_all()


def test_open_cleans_up_when_launch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    pw = _FakePlaywright(_FakePage(goto_error=RuntimeError("dns")), pid=99999)
    _install_fake_playwright(monkeypatch, pw)
    reaped: list[int] = []
    monkeypatch.setattr(web, "_reap_driver_pid", lambda pid: reaped.append(pid or 0))
    backend = WebBackend()
    backend._available = True
    with pytest.raises(WebError) as info:
        backend.open("s", "https://target/", timeout=5.0)
    assert info.value.code == "backend_error"
    assert pw.stopped is True
    assert reaped == [99999]
    assert "s" not in backend._sessions


def test_open_cleanup_tolerates_a_reservation_already_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _FakePage()
    pw = _FakePlaywright(page, pid=None)
    _install_fake_playwright(monkeypatch, pw)
    backend = WebBackend()
    backend._available = True

    def goto_steal_then_fail(url: str, timeout: float, wait_until: str) -> Any:
        # The slot is popped by a concurrent close, then the launch fails, so
        # the cleanup finds no reservation of its own to remove.
        with backend._lock:
            backend._sessions.pop("s", None)
        raise RuntimeError("launch died after the slot was taken")

    page.goto = goto_steal_then_fail  # type: ignore[method-assign]
    with pytest.raises(WebError) as info:
        backend.open("s", "https://target/", timeout=5.0)
    assert info.value.code == "backend_error"
    assert "s" not in backend._sessions


def test_open_reclaims_if_the_slot_was_taken_during_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _FakePage()
    pw = _FakePlaywright(page, pid=None)
    _install_fake_playwright(monkeypatch, pw)
    reaped: list[int] = []
    monkeypatch.setattr(web, "_reap_web_session", lambda handle: reaped.append(1))
    backend = WebBackend()
    backend._available = True

    original_goto = page.goto

    def goto_then_steal(url: str, timeout: float, wait_until: str) -> Any:
        # Simulate a concurrent close that pops the opening reservation.
        with backend._lock:
            backend._sessions.pop("s", None)
        return original_goto(url, timeout, wait_until)

    page.goto = goto_then_steal  # type: ignore[method-assign]
    with pytest.raises(WebError) as info:
        backend.open("s", "https://target/", timeout=5.0)
    assert info.value.code == "invalid_state"
    assert reaped == [1]
