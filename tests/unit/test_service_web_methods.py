"""Browser dynamic-analysis service methods against a fake WebBackend.

These wrappers each validate a session, forward one backend call, spill large
payloads to the session artifact area, and map WebError -> failure. The tests
drive that surface with an in-memory registry/repository and a cooperative fake
backend, so success, capture registration, the mid-open close guard, and every
error handler run without a real browser.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service_web import WebAnalysisMixin
from headless_re_mcp.core.session import SessionRegistry

JsonObject = dict[str, Any]


class _FakeWeb:
    """A cooperative WebBackend double; individual tests override one method."""

    def __init__(self, registry: SessionRegistry | None = None) -> None:
        self.registry = registry
        self.closed: list[str] = []

    def status(self, session_id: str) -> JsonObject:
        return {"open": True, "url": "https://example.test"}

    def screenshot(self, session_id: str, out: Path, full_page: bool = False) -> JsonObject:
        out.write_bytes(b"\x89PNG\r\n")
        return {"path": str(out), "full_page": full_page}

    def open(
        self, session_id: str, target: str, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        return {"url": target or "about:blank", "headless": headless}

    def close(self, session_id: str) -> JsonObject:
        self.closed.append(session_id)
        return {"closed": True}

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        body = artifact_dir / "body.bin"
        body.write_bytes(b"response-body")
        return {"request_id": request_id, "body_path": str(body)}

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        source = artifact_dir / "source.js"
        source.write_text("// source", encoding="utf-8")
        return {"script_id": script_id, "source_path": str(source)}

    def navigate(self, session_id: str, url: str, timeout: float = 30.0) -> JsonObject:
        return {"navigated": url}

    def network_list(self, session_id: str, offset: int = 0, limit: int = 100) -> JsonObject:
        return {"requests": [], "offset": offset, "limit": limit}

    def console(self, session_id: str, limit: int = 200) -> JsonObject:
        return {"messages": [], "limit": limit}

    def scripts(
        self, session_id: str, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        return {"scripts": [], "wasm_only": wasm_only, "offset": offset, "limit": limit}

    def dom_snapshot(self, session_id: str, artifact_dir: Path) -> JsonObject:
        del artifact_dir
        return {"nodes": 1}

    def har_export(self, session_id: str, out: Path) -> JsonObject:
        out.write_text("{}", encoding="utf-8")
        return {"path": str(out)}


class _Host(WebAnalysisMixin):
    def __init__(self, settings: Settings, web: _FakeWeb) -> None:
        self.settings = settings
        self.registry = SessionRegistry()
        self.repository = InMemoryAnalysisRepository(settings.artifact_root)
        self._web_backend = web  # type: ignore[assignment]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return replace(Settings.load(), artifact_root=tmp_path / "artifacts")


def _host(settings: Settings, web: _FakeWeb | None = None) -> _Host:
    backend = web or _FakeWeb()
    host = _Host(settings, backend)
    backend.registry = host.registry
    return host


def _adopt(
    host: _Host,
    *,
    target: TargetKind = TargetKind.WEB,
    state: SessionState = SessionState.READY,
    locator: str | None = "https://example.test",
) -> str:
    session = Session(target=target, locator=locator, state=state)
    host.registry.adopt(session)
    return session.id


# --- status / preview -----------------------------------------------------


def test_web_status_merges_session_fields(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_status(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["locator"] == "https://example.test"
    assert result.data["target"] == "web"
    assert result.data["state"] == "ready"


def test_web_status_maps_web_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.status = lambda session_id: (_ for _ in ()).throw(WebError("no_browser", "not open"))  # type: ignore[method-assign]
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_status(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "no_browser"


def test_web_status_maps_unexpected_error(settings: Settings) -> None:
    host = _host(settings)
    # session_id is never adopted -> registry.get raises SessionNotFound
    result = host.web_status("0123456789abcdef0123456789abcdef")
    assert result.ok is False
    assert result.error is not None


def test_web_preview_writes_stable_png(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_preview(session_id)
    assert result.ok, result.error
    assert (settings.artifact_root / "web" / session_id / "preview.png").is_file()


def test_web_preview_maps_web_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.screenshot = lambda session_id, out, full_page=False: (_ for _ in ()).throw(  # type: ignore[method-assign]
        WebError("no_browser", "not open")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_preview(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "no_browser"


def test_web_preview_maps_unexpected_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.screenshot = lambda session_id, out, full_page=False: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("headless crash")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_preview(session_id)
    assert result.ok is False
    assert result.error is not None


# --- open / navigate / close ----------------------------------------------


def test_web_open_records_backend_and_timeline(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_open(session_id, url="https://target.test")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["url"] == "https://target.test"
    assert host.repository.list_backends(session_id)
    events = host.repository.list_timeline(session_id)["events"]
    assert any(e["event"] == "web.open" for e in events)


def test_web_open_requires_url_for_non_web_session(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host, target=TargetKind.PE, locator=None)
    result = host.web_open(session_id, url="")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_web_open_refused_on_closed_session(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host, state=SessionState.CLOSED)
    result = host.web_open(session_id)
    assert result.ok is False
    assert result.error is not None


def test_web_open_closes_browser_if_session_closes_mid_open(settings: Settings) -> None:
    class _CloseMidOpen(_FakeWeb):
        def open(
            self, session_id: str, target: str, headless: bool = True, timeout: float = 30.0
        ) -> JsonObject:
            assert self.registry is not None
            self.registry.transition(session_id, SessionState.CLOSING)
            return {"url": target}

    web = _CloseMidOpen()
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_open(session_id, url="https://target.test")
    assert result.ok is False
    assert result.error is not None
    assert web.closed == [session_id]  # the orphaned browser was torn down


def test_web_navigate_forwards_to_backend(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_navigate(session_id, "https://next.test")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["navigated"] == "https://next.test"


def test_web_close_emits_timeline(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_close(session_id)
    assert result.ok, result.error
    events = host.repository.list_timeline(session_id)["events"]
    assert any(e["event"] == "web.close" for e in events)


def test_web_close_maps_web_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.close = lambda session_id: (_ for _ in ()).throw(WebError("close_failed", "boom"))  # type: ignore[method-assign]
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_close(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "close_failed"


def test_web_close_maps_unexpected_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.close = lambda session_id: (_ for _ in ()).throw(RuntimeError("io error"))  # type: ignore[method-assign]
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_close(session_id)
    assert result.ok is False
    assert result.error is not None


# --- network / scripts capture --------------------------------------------


def test_web_network_get_registers_spilled_body(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_network_get(session_id, "req-1")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_web_network_get_without_spill_returns_inline(settings: Settings) -> None:
    web = _FakeWeb()
    web.network_get = lambda session_id, request_id, artifact_dir: {"request_id": request_id}  # type: ignore[method-assign]
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_network_get(session_id, "req-2")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_web_network_get_maps_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.network_get = lambda session_id, request_id, artifact_dir: (_ for _ in ()).throw(  # type: ignore[method-assign]
        WebError("unknown_request", "no such request")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_network_get(session_id, "missing")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unknown_request"


def test_web_network_get_maps_unexpected_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.network_get = lambda session_id, request_id, artifact_dir: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("spill crash")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_network_get(session_id, "req")
    assert result.ok is False
    assert result.error is not None


def test_web_script_source_registers_spilled_source(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_script_source(session_id, "script-1")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_web_script_source_without_spill_returns_inline(settings: Settings) -> None:
    web = _FakeWeb()
    web.script_source = lambda session_id, script_id, artifact_dir: {"script_id": script_id}  # type: ignore[method-assign]
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_script_source(session_id, "script-2")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_web_script_source_maps_web_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.script_source = lambda session_id, script_id, artifact_dir: (_ for _ in ()).throw(  # type: ignore[method-assign]
        WebError("unknown_script", "no such script")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_script_source(session_id, "missing")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unknown_script"


def test_web_script_source_maps_unexpected_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.script_source = lambda session_id, script_id, artifact_dir: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("decode crash")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_script_source(session_id, "script")
    assert result.ok is False
    assert result.error is not None


def test_web_scripts_and_wasm_list_forward_flags(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    scripts = host.web_scripts(session_id, wasm_only=False, limit=5)
    assert scripts.ok and scripts.data is not None
    assert scripts.data["wasm_only"] is False
    wasm = host.web_wasm_list(session_id)
    assert wasm.ok and wasm.data is not None
    assert wasm.data["wasm_only"] is True


def test_web_network_list_and_console_and_dom_forward(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    assert host.web_network_list(session_id, offset=2, limit=3).data["offset"] == 2  # type: ignore[index]
    assert host.web_console(session_id, limit=7).data["limit"] == 7  # type: ignore[index]
    assert host.web_dom_snapshot(session_id).data["nodes"] == 1  # type: ignore[index]


# --- screenshot / har artifacts -------------------------------------------


def test_web_screenshot_registers_artifact(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_screenshot(session_id, full_page=True)
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_web_screenshot_maps_unexpected_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.screenshot = lambda session_id, out, full_page=False: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("capture crash")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_screenshot(session_id)
    assert result.ok is False
    assert result.error is not None


def test_web_har_export_registers_artifact(settings: Settings) -> None:
    host = _host(settings)
    session_id = _adopt(host)
    result = host.web_har_export(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_web_har_export_maps_web_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.har_export = lambda session_id, out: (_ for _ in ()).throw(  # type: ignore[method-assign]
        WebError("har_failed", "no capture")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_har_export(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "har_failed"


def test_web_har_export_maps_unexpected_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.har_export = lambda session_id, out: (_ for _ in ()).throw(RuntimeError("disk full"))  # type: ignore[method-assign]
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_har_export(session_id)
    assert result.ok is False
    assert result.error is not None


# --- artifact-dir guard and generic wrapper errors ------------------------


def test_web_screenshot_rejects_unsafe_session_id(settings: Settings) -> None:
    host = _host(settings)
    result = host.web_screenshot("../escape")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_web_wrap_maps_web_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.console = lambda session_id, limit=200: (_ for _ in ()).throw(  # type: ignore[method-assign]
        WebError("console_failed", "no console")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_console(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "console_failed"


def test_web_wrap_maps_unexpected_error(settings: Settings) -> None:
    web = _FakeWeb()
    web.dom_snapshot = lambda session_id, artifact_dir: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("cdp died")
    )
    host = _host(settings, web)
    session_id = _adopt(host)
    result = host.web_dom_snapshot(session_id)
    assert result.ok is False
    assert result.error is not None
