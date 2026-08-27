"""Branch coverage for the browser dynamic-analysis service mixin.

Each call wraps the WebBackend into a Result: a backend WebError becomes a
structured failure and an unexpected exception is still captured. Large
payloads (response bodies, script sources, screenshots, HAR) spill to the
session artifact tree and are registered so retention can reclaim them, and a
close arriving mid-open must tear the browser down rather than report success.
These fakes drive those branches without a real browser; the live gate
(tests/integration/test_web_re_gate.py) pins Playwright.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState, TargetKind
from headless_re_mcp.core.service import AnalysisService

MP = pytest.MonkeyPatch


class _FakeWeb:
    def status(self, session_id: str) -> dict[str, Any]:
        return {"open": True}

    def screenshot(self, session_id: str, out: Path, full_page: bool = False) -> dict[str, Any]:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_bytes(b"\x89PNG")
        return {"path": str(out), "full_page": full_page}

    def open(
        self, session_id: str, target: str, *, headless: bool = True, timeout: float = 30.0
    ) -> dict[str, Any]:
        return {"url": target or "about:blank"}

    def close(self, session_id: str) -> dict[str, Any]:
        return {"closed": True}

    def close_all(self) -> None:
        return None

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> dict[str, Any]:
        body = Path(artifact_dir) / "body.bin"
        body.write_bytes(b"payload")
        return {"request_id": request_id, "body_path": str(body)}

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> dict[str, Any]:
        src = Path(artifact_dir) / "script.js"
        src.write_text("console.log(1)")
        return {"script_id": script_id, "source_path": str(src)}

    def har_export(self, session_id: str, out: Path) -> dict[str, Any]:
        Path(out).write_text("{}")
        return {"path": str(out)}

    def console(self, session_id: str, limit: int = 200) -> dict[str, Any]:
        return {"messages": []}

    def navigate(self, session_id: str, url: str, timeout: float = 30.0) -> dict[str, Any]:
        return {"url": url}

    def scripts(
        self, session_id: str, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        return {"scripts": [], "wasm_only": wasm_only}

    def dom_snapshot(self, session_id: str) -> dict[str, Any]:
        return {"nodes": 0}


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    svc._web_backend = _FakeWeb()  # type: ignore[assignment]
    try:
        yield svc
    finally:
        svc.close_all()


def _session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _force_state(service: AnalysisService, session_id: str, state: SessionState) -> None:
    service.registry._sessions[session_id].state = state


class TestStatusAndPreview:
    def test_status_success(self, service: AnalysisService) -> None:
        sid = _session(service)
        result = service.web_status(sid)
        assert result.ok is True and result.data is not None
        assert result.data["state"] and result.data["target"] == "web"

    def test_status_maps_web_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.status = lambda s: (_ for _ in ()).throw(  # type: ignore[attr-defined]
            WebError("backend_error", "cdp lost")
        )
        result = service.web_status(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"

    def test_status_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.status = lambda s: (_ for _ in ()).throw(  # type: ignore[attr-defined]
            RuntimeError("boom")
        )
        assert service.web_status(sid).ok is False

    def test_preview_success(self, service: AnalysisService) -> None:
        sid = _session(service)
        result = service.web_preview(sid)
        assert result.ok is True and result.data is not None

    def test_preview_maps_web_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.screenshot = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(WebError("backend_error", "no page"))
        result = service.web_preview(sid)
        assert result.ok is False and result.error is not None

    def test_preview_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.screenshot = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(RuntimeError("boom"))
        assert service.web_preview(sid).ok is False

    def test_artifact_dir_rejects_a_bad_session_id(self, service: AnalysisService) -> None:
        result = service.web_preview("../evil")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"


class TestOpenCloseNavigate:
    def test_open_success_records_backend(self, service: AnalysisService) -> None:
        sid = _session(service)
        result = service.web_open(sid, url="https://example.com/x")
        assert result.ok is True and result.data is not None
        assert result.data["url"] == "https://example.com/x"

    def test_open_maps_web_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.open = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[attr-defined]
            WebError("timeout", "nav timed out")
        )
        result = service.web_open(sid, url="https://example.com/x")
        assert result.ok is False and result.error is not None
        assert result.error.code == "timeout"

    def test_open_refuses_a_closed_session(self, service: AnalysisService) -> None:
        sid = _session(service)
        _force_state(service, sid, SessionState.CLOSED)
        assert service.web_open(sid, url="https://x").ok is False

    def test_open_tears_down_if_the_session_closes_mid_open(
        self, service: AnalysisService
    ) -> None:
        sid = _session(service)
        closed: list[str] = []
        service._web_backend.close = lambda s: closed.append(s) or {  # type: ignore[attr-defined]
            "closed": True
        }

        def _open_then_close(session_id: str, target: str, **kwargs: Any) -> dict[str, Any]:
            _force_state(service, sid, SessionState.CLOSED)
            return {"url": target}

        service._web_backend.open = _open_then_close  # type: ignore[attr-defined]
        result = service.web_open(sid, url="https://example.com/x")
        assert result.ok is False
        assert closed == [sid]  # browser was torn down rather than left dangling

    def test_open_requires_a_url_for_a_non_web_session(self, service: AnalysisService) -> None:
        sid = _session(service)
        record = service.registry._sessions[sid]
        record.target = TargetKind.APK
        record.locator = ""
        result = service.web_open(sid, url="")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"

    def test_close_success(self, service: AnalysisService) -> None:
        sid = _session(service)
        result = service.web_close(sid)
        assert result.ok is True and result.data is not None
        assert result.data["closed"] is True

    def test_close_maps_web_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.close = lambda s: (_ for _ in ()).throw(  # type: ignore[attr-defined]
            WebError("backend_error", "close failed")
        )
        assert service.web_close(sid).ok is False

    def test_close_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.close = lambda s: (_ for _ in ()).throw(  # type: ignore[attr-defined]
            RuntimeError("boom")
        )
        assert service.web_close(sid).ok is False

    def test_navigate_via_wrap_success(self, service: AnalysisService) -> None:
        sid = _session(service)
        result = service.web_navigate(sid, "https://example.com/y")
        assert result.ok is True and result.data is not None
        assert result.data["url"] == "https://example.com/y"


class TestCapturesAndWrap:
    def test_network_get_registers_a_spilled_body(self, service: AnalysisService) -> None:
        sid = _session(service)
        result = service.web_network_get(sid, "req-1")
        assert result.ok is True and result.data is not None
        assert "body_path" in result.data

    def test_network_get_without_a_spill(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.network_get = lambda *a, **k: {  # type: ignore[attr-defined]
            "request_id": "req-2",
            "body_path": None,
        }
        result = service.web_network_get(sid, "req-2")
        assert result.ok is True

    def test_network_get_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.network_get = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(RuntimeError("boom"))
        assert service.web_network_get(sid, "req").ok is False

    def test_network_list_via_wrap(self, service: AnalysisService) -> None:
        sid = _session(service)
        # network_list is not on the fake by default; wire a minimal one.
        service._web_backend.network_list = lambda *a, **k: {  # type: ignore[attr-defined]
            "requests": [],
            "count": 0,
        }
        result = service.web_network_list(sid)
        assert result.ok is True and result.data is not None
        assert result.data["count"] == 0

    def test_network_get_maps_web_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.network_get = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(WebError("not_found", "no such request"))
        result = service.web_network_get(sid, "missing")
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found"

    def test_script_source_registers_a_spill(self, service: AnalysisService) -> None:
        sid = _session(service)
        result = service.web_script_source(sid, "script-1")
        assert result.ok is True and result.data is not None

    def test_script_source_without_a_spill(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.script_source = lambda *a, **k: {  # type: ignore[attr-defined]
            "script_id": "s",
            "source_path": None,
        }
        assert service.web_script_source(sid, "s").ok is True

    def test_script_source_maps_web_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.script_source = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(WebError("not_found", "no such script"))
        assert service.web_script_source(sid, "x").ok is False

    def test_script_source_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.script_source = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(RuntimeError("boom"))
        assert service.web_script_source(sid, "x").ok is False

    def test_screenshot_success_and_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        assert service.web_screenshot(sid, full_page=True).ok is True
        service._web_backend.screenshot = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(WebError("backend_error", "shot failed"))
        assert service.web_screenshot(sid).ok is False

    def test_screenshot_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.screenshot = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(RuntimeError("boom"))
        assert service.web_screenshot(sid).ok is False

    def test_har_export_success_and_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        assert service.web_har_export(sid).ok is True
        service._web_backend.har_export = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(WebError("backend_error", "har failed"))
        assert service.web_har_export(sid).ok is False

    def test_har_export_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.har_export = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(RuntimeError("boom"))
        assert service.web_har_export(sid).ok is False

    def test_wrap_success_paths(self, service: AnalysisService) -> None:
        sid = _session(service)
        assert service.web_console(sid).ok is True
        assert service.web_scripts(sid).ok is True
        assert service.web_wasm_list(sid).ok is True
        assert service.web_dom_snapshot(sid).ok is True

    def test_wrap_maps_web_error(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.console = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[attr-defined]
            WebError("invalid_state", "no page")
        )
        result = service.web_console(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"

    def test_wrap_captures_unexpected(self, service: AnalysisService) -> None:
        sid = _session(service)
        service._web_backend.dom_snapshot = lambda *a, **k: (  # type: ignore[attr-defined]
            _ for _ in ()
        ).throw(RuntimeError("boom"))
        assert service.web_dom_snapshot(sid).ok is False
