"""Web (CDP/Playwright) backend helper and method branches without a browser.

The live browser gate needs Chromium and skips where Playwright cannot launch,
so the parts that do not need a page -- console clipping, body/text spill caps,
navigation-status honesty, driver-pid reaping, and the not_found / backend_error
contracts of network_get / script_source / dom_snapshot / screenshot -- were
thin under unit coverage. These drive them with fake CDP/page objects on a real
runner thread, matching the existing web-backend tests.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import (
    WebBackend,
    WebError,
    _clip_console_text,
    _playwright_driver_pid,
    _reap_driver_pid,
    _response_status,
    _Runner,
    _safe_title,
    _spill_bytes,
    _spill_text,
)
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES


@pytest.fixture
def runner() -> Iterator[_Runner]:
    made = _Runner("test-web-runner")
    try:
        yield made
    finally:
        made.shutdown()


def _handle(*, page: Any = None, cdp: Any = None, runner: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        page=page,
        cdp=cdp,
        runner=runner,
        lock=threading.RLock(),
        requests=OrderedDict(),
        requests_dropped=0,
    )


# ----------------------------------------------------------------------
# Pure helpers.
# ----------------------------------------------------------------------
def test_response_status_absent_or_unreadable_is_none() -> None:
    """goto returns None for about:blank; a broken response reads as no status."""
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status=200)) == 200
    assert _response_status(SimpleNamespace(status="oops")) is None

    class _Raises:
        @property
        def status(self) -> int:
            raise RuntimeError("detached")

    assert _response_status(_Raises()) is None


def test_safe_title_swallows_a_title_failure() -> None:
    class _Page:
        def title(self) -> str:
            raise RuntimeError("navigation in progress")

    assert _safe_title(_Page()) == ""
    assert _safe_title(SimpleNamespace(title=lambda: "Example")) == "Example"


def test_clip_console_text_joins_bounds_and_flags_truncation() -> None:
    text, truncated = _clip_console_text(
        {"args": [{"value": "hello"}, {"description": "world"}, {"type": "object"}]}
    )
    assert text == "hello world object"
    assert truncated is False
    # Non-dict arguments are skipped rather than crashing the handler.
    text, truncated = _clip_console_text({"args": ["bare", {"value": "kept"}]})
    assert text == "kept"
    big = "x" * (web_client._MAX_CONSOLE_TEXT + 50)
    text, truncated = _clip_console_text({"args": [{"value": big}]})
    assert truncated is True
    assert len(text) <= web_client._MAX_CONSOLE_TEXT


def test_spill_text_inlines_small_spills_large_and_refuses_over_cap(tmp_path: Path) -> None:
    inline, spill, cut = _spill_text(
        "small", artifact_dir=tmp_path, filename="a.txt", kind="script source"
    )
    assert inline == "small"
    assert spill is None
    assert cut is False

    big = "y" * (web_client._MAX_INLINE_BODY + 100)
    inline, spill, cut = _spill_text(
        big, artifact_dir=tmp_path, filename="big.txt", kind="script source"
    )
    assert spill is not None and spill.is_file()
    assert cut is True
    assert len(inline) <= web_client._MAX_INLINE_BODY

    with pytest.raises(WebError) as caught:
        _spill_text(
            "z" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1),
            artifact_dir=tmp_path,
            filename="huge.txt",
            kind="script source",
        )
    assert caught.value.code == "too_large"


def test_spill_text_rejects_a_traversing_filename(tmp_path: Path) -> None:
    big = "y" * (web_client._MAX_INLINE_BODY + 100)
    for bad in ("../escape", "sub/dir", "", "."):
        with pytest.raises(WebError) as caught:
            _spill_text(big, artifact_dir=tmp_path, filename=bad, kind="script source")
        assert caught.value.code == "invalid_params"


def test_spill_bytes_writes_and_bounds(tmp_path: Path) -> None:
    out = _spill_bytes(b"\x00\x01", artifact_dir=tmp_path, filename="b.bin", kind="response body")
    assert out.is_file()
    assert out.read_bytes() == b"\x00\x01"

    with pytest.raises(WebError) as caught:
        _spill_bytes(
            b"0" * (UNREGISTERED_CAPTURE_MAX_BYTES + 1),
            artifact_dir=tmp_path,
            filename="big.bin",
            kind="response body",
        )
    assert caught.value.code == "too_large"

    with pytest.raises(WebError) as caught:
        _spill_bytes(b"x", artifact_dir=tmp_path, filename="../escape", kind="response body")
    assert caught.value.code == "invalid_params"


def test_playwright_driver_pid_walks_the_private_chain() -> None:
    assert _playwright_driver_pid(SimpleNamespace()) is None
    proc = SimpleNamespace(pid=4321)
    transport = SimpleNamespace(_proc=proc)
    connection = SimpleNamespace(_transport=transport)
    impl = SimpleNamespace(_connection=connection)
    pw = SimpleNamespace(_impl_obj=impl)
    assert _playwright_driver_pid(pw) == 4321
    # A non-positive pid is treated as no pid.
    proc.pid = 0
    assert _playwright_driver_pid(pw) is None


def test_reap_driver_pid_only_kills_a_browser_image(monkeypatch: Any) -> None:
    killed: list[int] = []
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: killed.append(pid))

    # A non-int pid is ignored outright.
    _reap_driver_pid(None)
    assert killed == []

    # A pid whose image is not a browser is left alone -- pid reuse is real.
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/usr/bin/postgres")
    _reap_driver_pid(999)
    assert killed == []

    # A node/chromium image is the driver, so its tree is reaped.
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/opt/node/bin/node")
    _reap_driver_pid(999)
    assert killed == [999]


# ----------------------------------------------------------------------
# Availability and session scoping.
# ----------------------------------------------------------------------
def test_check_available_reflects_the_playwright_import() -> None:
    """Whichever way the import lands, availability is cached honestly."""
    backend = WebBackend()
    try:
        import playwright.sync_api  # noqa: F401

        installed = True
    except Exception:
        installed = False
    if installed:
        backend._check_available()
        assert backend._available is True
    else:
        with pytest.raises(WebError) as caught:
            backend._check_available()
        assert caught.value.code == "capability_unavailable"
        assert backend._available is False


def test_open_reports_capability_unavailable_when_playwright_is_absent() -> None:
    backend = WebBackend()
    backend._available = False
    with pytest.raises(WebError) as caught:
        backend.open("s", "https://example/app")
    assert caught.value.code == "capability_unavailable"


def test_runner_refuses_work_once_closed() -> None:
    made = _Runner("closed-runner")
    made.shutdown()
    with pytest.raises(WebError) as caught:
        made.call(lambda: 1)
    assert caught.value.code == "invalid_state"


def test_runner_refuses_work_once_wedged() -> None:
    made = _Runner("wedged-runner")
    try:
        made._wedged = True
        with pytest.raises(WebError) as caught:
            made.call(lambda: 1)
        assert caught.value.code == "backend_error"
    finally:
        made.shutdown()


def test_runner_marks_itself_wedged_on_a_call_that_never_returns() -> None:
    """A driver that dies takes its own timeouts with it; the outer bound fires.

    The runner thread stays blocked in the work, so it is marked wedged and
    every later call fails fast instead of queueing behind a call that will
    never return.
    """
    import threading as _threading

    made = _Runner("hang-runner")
    release = _threading.Event()
    try:
        with pytest.raises(WebError) as caught:
            made.call(release.wait, timeout=0.2)
        assert caught.value.code == "timeout"
        assert made.wedged is True
    finally:
        release.set()
        made.shutdown()


def test_status_reports_opening_and_stale_handles() -> None:
    backend = WebBackend()
    backend._sessions["opening"] = object()
    assert backend.status("opening") == {"open": False, "opening": True}
    backend._sessions["stale"] = "not-a-session"  # type: ignore[assignment]
    assert backend.status("stale") == {"open": False}


def test_runner_raises_when_a_handle_has_no_browser_thread() -> None:
    backend = WebBackend()
    with pytest.raises(WebError) as caught:
        backend._runner(_handle(runner=None))  # type: ignore[arg-type]
    assert caught.value.code == "invalid_state"


# ----------------------------------------------------------------------
# network_get.
# ----------------------------------------------------------------------
def test_network_get_reports_an_unknown_request_id(monkeypatch: Any, tmp_path: Path) -> None:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: _handle(cdp=object(), runner=object()))
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "missing", tmp_path)
    assert caught.value.code == "not_found"


def test_network_get_returns_body_error_when_cdp_has_no_body(
    monkeypatch: Any, tmp_path: Path, runner: _Runner
) -> None:
    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("No resource with given identifier found")

    handle = _handle(cdp=_Cdp(), runner=runner)
    handle.requests["r1"] = {"requestId": "r1", "url": "http://x", "status": 200}
    monkeypatch.setattr(backend := WebBackend(), "_get", lambda sid: handle)
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["body"] == ""
    assert payload["base64_encoded"] is False
    assert payload["body_truncated"] is False
    assert "body_error" in payload


def test_network_get_spills_a_base64_body_as_real_bytes(
    monkeypatch: Any, tmp_path: Path, runner: _Runner
) -> None:
    import base64

    raw = b"\x89PNG\r\n\x1a\n" + b"binary-body"
    encoded = base64.b64encode(raw).decode()

    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            return {"body": encoded, "base64Encoded": True}

    handle = _handle(cdp=_Cdp(), runner=runner)
    handle.requests["r1"] = {"requestId": "r1", "url": "http://x"}
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["base64_encoded"] is True
    assert payload["body"] == ""
    assert payload["body_bytes"] == len(raw)
    assert Path(payload["body_path"]).read_bytes() == raw


def test_network_get_reports_invalid_base64(
    monkeypatch: Any, tmp_path: Path, runner: _Runner
) -> None:
    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            return {"body": "!!!not base64!!!", "base64Encoded": True}

    handle = _handle(cdp=_Cdp(), runner=runner)
    handle.requests["r1"] = {"requestId": "r1", "url": "http://x"}
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    payload = backend.network_get("s", "r1", tmp_path)
    assert "body_error" in payload


# ----------------------------------------------------------------------
# script_source and dom_snapshot.
# ----------------------------------------------------------------------
def test_script_source_maps_a_cdp_failure_to_not_found(
    monkeypatch: Any, tmp_path: Path, runner: _Runner
) -> None:
    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("no such script")

    handle = _handle(cdp=_Cdp(), runner=runner)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    with pytest.raises(WebError) as caught:
        backend.script_source("s", "42", tmp_path)
    assert caught.value.code == "not_found"


def test_script_source_returns_the_source(
    monkeypatch: Any, tmp_path: Path, runner: _Runner
) -> None:
    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            return {"scriptSource": "var a = 1;"}

    handle = _handle(cdp=_Cdp(), runner=runner)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    payload = backend.script_source("s", "42", tmp_path)
    assert payload["source"] == "var a = 1;"
    assert payload["truncated"] is False


def test_dom_snapshot_maps_an_evaluate_failure(
    monkeypatch: Any, runner: _Runner
) -> None:
    class _Page:
        url = "https://x/"

        def title(self) -> str:
            return "X"

        def evaluate(self, script: str, cap: int) -> Any:
            raise RuntimeError("execution context destroyed")

    handle = _handle(page=_Page(), runner=runner)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")
    assert caught.value.code == "backend_error"


def test_dom_snapshot_returns_the_clipped_html(monkeypatch: Any, runner: _Runner) -> None:
    class _Page:
        url = "https://x/"

        def title(self) -> str:
            return "X"

        def evaluate(self, script: str, cap: int) -> Any:
            return {"html": "<html></html>", "truncated": False}

    handle = _handle(page=_Page(), runner=runner)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    payload = backend.dom_snapshot("s")
    assert payload["html"] == "<html></html>"
    assert payload["truncated"] is False


# ----------------------------------------------------------------------
# screenshot and har_export.
# ----------------------------------------------------------------------
def test_screenshot_maps_a_capture_failure(
    monkeypatch: Any, tmp_path: Path, runner: _Runner
) -> None:
    class _Page:
        def screenshot(self, path: str, full_page: bool = False) -> None:
            raise RuntimeError("target crashed")

    handle = _handle(page=_Page(), runner=runner)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    with pytest.raises(WebError) as caught:
        backend.screenshot("s", tmp_path / "shot.png")
    assert caught.value.code == "backend_error"


def test_har_export_refuses_a_capture_over_the_cap(
    monkeypatch: Any, tmp_path: Path
) -> None:
    handle = _handle()
    cap = UNREGISTERED_CAPTURE_MAX_BYTES
    monkeypatch.setattr(
        web_client,
        "serialize_har",
        lambda entries, max_bytes: SimpleNamespace(
            size=cap + 1, text="x", entry_count=0, truncated=True
        ),
    )
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda sid: handle)
    with pytest.raises(WebError) as caught:
        backend.har_export("s", tmp_path / "out.har")
    assert caught.value.code == "too_large"


# ----------------------------------------------------------------------
# close paths.
# ----------------------------------------------------------------------
def test_close_of_an_aborted_open_reports_open_was_aborted() -> None:
    backend = WebBackend()
    backend._sessions["s"] = object()
    assert backend.close("s") == {"closed": True, "note": "open was aborted"}


def test_close_of_a_runnerless_handle_calls_handle_close() -> None:
    closed: list[bool] = []
    handle = SimpleNamespace(runner=None, close=lambda: closed.append(True))
    backend = WebBackend()
    backend._sessions["s"] = handle  # type: ignore[assignment]
    assert backend.close("s") == {"closed": True}
    assert closed == [True]


def test_close_reaps_the_driver_when_the_runner_is_wedged(monkeypatch: Any) -> None:
    """A wedged runner cannot run handle.close; the driver pid is reaped instead."""
    reaped: list[int] = []
    monkeypatch.setattr(web_client, "_reap_web_session", lambda h: reaped.append(h.driver_pid))

    class _WedgedRunner:
        wedged = True

        def shutdown(self) -> None:
            return None

    handle = SimpleNamespace(runner=_WedgedRunner(), driver_pid=777, close=lambda: None)
    backend = WebBackend()
    backend._sessions["s"] = handle  # type: ignore[assignment]
    payload = backend.close("s")
    assert payload == {"closed": True, "clean": False}
    assert reaped == [777]


def test_close_all_closes_every_registered_session() -> None:
    closed: list[str] = []

    class _Runner2:
        wedged = False

        def call(self, work: Any, timeout: float = 0.0) -> Any:
            return work()

        def shutdown(self) -> None:
            return None

    backend = WebBackend()
    for name in ("a", "b"):
        backend._sessions[name] = SimpleNamespace(
            runner=_Runner2(), close=lambda n=name: closed.append(n)
        )  # type: ignore[assignment]
    backend.close_all()
    assert sorted(closed) == ["a", "b"]
    assert backend._sessions == {}
