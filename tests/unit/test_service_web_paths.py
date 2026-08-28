"""Web service-layer paths (WebAnalysisMixin) beyond the capture-registration suite.

The WebBackend is exercised directly elsewhere; here the service orchestration is
pinned: status enrichment, the stable preview PNG, open with its state guard, the
_web_wrap-based read ops (navigate/console/scripts/wasm/dom/network.list),
network.get body spill registration, and the WebError -> structured-envelope
mapping every method funnels failures through.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._web_backend = _FakeWeb()  # type: ignore[assignment]
    return service


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _fail(service: AnalysisService, op: str, exc: BaseException) -> None:
    backend: Any = service._web_backend
    backend.raise_on[op] = exc


class _FakeWeb:
    def __init__(self) -> None:
        self.raise_on: dict[str, BaseException] = {}
        self.opened: list[tuple[str, str]] = []
        self.spill_body: bool = True

    def _maybe(self, op: str) -> None:
        exc = self.raise_on.get(op)
        if exc is not None:
            raise exc

    def status(self, session_id: str) -> dict[str, Any]:
        self._maybe("status")
        return {"open": True, "url": "https://example.com/app"}

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> dict[str, Any]:
        self._maybe("open")
        self.opened.append((session_id, url))
        return {"opened": True, "url": url or "about:blank", "title": "Example"}

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> dict[str, Any]:
        self._maybe("navigate")
        return {"url": url, "title": "Example", "status": 200}

    def close(self, session_id: str) -> dict[str, Any]:
        self._maybe("close")
        return {"closed": True, "clean": True}

    def network_list(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._maybe("network_list")
        return {"requests": [], "count": 0, "total": 0, "offset": offset, "has_more": False}

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> dict[str, Any]:
        self._maybe("network_get")
        if not self.spill_body:
            return {"body": "inline", "base64_encoded": False, "body_truncated": False}
        Path(artifact_dir).mkdir(parents=True, exist_ok=True)
        spill = Path(artifact_dir) / f"body-{request_id}.bin"
        spill.write_bytes(b"a large response body" * 8)
        return {
            "body": "",
            "base64_encoded": False,
            "body_truncated": True,
            "body_path": str(spill),
        }

    def console(self, session_id: str, *, limit: int = 200) -> dict[str, Any]:
        self._maybe("console")
        return {"console": [], "count": 0, "total": 0, "has_more": False, "dropped": 0}

    def scripts(
        self, session_id: str, *, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._maybe("scripts")
        return {"scripts": [], "count": 0, "total": 0, "offset": offset, "has_more": False}

    def dom_snapshot(self, session_id: str) -> dict[str, Any]:
        self._maybe("dom_snapshot")
        return {"url": "https://example.com/app", "title": "Example", "html": "<html></html>"}

    def screenshot(
        self, session_id: str, out_path: Path, *, full_page: bool = False
    ) -> dict[str, Any]:
        self._maybe("screenshot")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
        return {"path": str(out_path), "size": out_path.stat().st_size}

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> dict[str, Any]:
        self._maybe("script_source")
        Path(artifact_dir).mkdir(parents=True, exist_ok=True)
        spill = Path(artifact_dir) / f"script-{script_id}.js"
        spill.write_text("var a=1;" * 50, encoding="utf-8")
        return {"scriptId": script_id, "bytes": 400, "truncated": True, "source_path": str(spill)}

    def har_export(self, session_id: str, out_path: Path) -> dict[str, Any]:
        self._maybe("har_export")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out_path), "entry_count": 0, "truncated": False}

    def close_all(self) -> None:
        return None


# ---------------------------------------------------------------------------
# web_status / web_preview
# ---------------------------------------------------------------------------
def test_web_status_enriches_with_session_facts(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        result = service.web_status(sid)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["locator"] == "https://example.com/app"
        assert result.data["target"] == "web"
        assert result.data["open"] is True
    finally:
        service.close_all()


def test_web_status_maps_backend_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _fail(service, "status", WebError("invalid_state", "no browser"))
    try:
        sid = _web_session(service)
        result = service.web_status(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_state"
    finally:
        service.close_all()


def test_web_preview_writes_a_stable_png_without_registering(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        result = service.web_preview(sid)
        assert result.ok, result.error
        assert result.data is not None
        assert Path(result.data["path"]).name == "preview.png"
        listed = service.repository.list_artifacts(sid)
        assert listed["artifacts"] == []
    finally:
        service.close_all()


def test_web_preview_maps_backend_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _fail(service, "screenshot", WebError("timeout", "capture stalled"))
    try:
        sid = _web_session(service)
        result = service.web_preview(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "timeout"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# web_open
# ---------------------------------------------------------------------------
def test_web_open_records_backend_and_reports_url(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        result = service.web_open(sid)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["url"] == "https://example.com/app"
        assert result.meta["backend"] == "web"
    finally:
        service.close_all()


def test_web_open_maps_backend_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _fail(service, "open", WebError("backend_error", "chrome crashed"))
    try:
        sid = _web_session(service)
        result = service.web_open(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_web_open_refused_on_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        assert service.close_session(sid).ok
        result = service.web_open(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_request"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# read ops via _web_wrap + web_close
# ---------------------------------------------------------------------------
def test_web_read_ops_succeed(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        assert service.web_navigate(sid, "https://example.com/next").ok
        assert service.web_network_list(sid, offset=0, limit=10).ok
        assert service.web_console(sid, limit=50).ok
        assert service.web_scripts(sid, wasm_only=False, offset=0, limit=10).ok
        assert service.web_wasm_list(sid, offset=0, limit=10).ok
        assert service.web_dom_snapshot(sid).ok
        assert service.web_close(sid).ok
    finally:
        service.close_all()


def test_web_wrap_maps_web_error_and_unexpected(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        _fail(service, "navigate", WebError("timeout", "nav stalled"))
        mapped = service.web_navigate(sid, "https://x/y")
        assert mapped.ok is False
        assert mapped.error is not None and mapped.error.code == "timeout"

        _fail(service, "console", RuntimeError("ring corrupt"))
        unexpected = service.web_console(sid)
        assert unexpected.ok is False
        assert unexpected.error is not None and unexpected.error.code == "internal_error"
    finally:
        service.close_all()


def test_web_close_maps_backend_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _fail(service, "close", WebError("backend_error", "already gone"))
    try:
        sid = _web_session(service)
        result = service.web_close(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# web_network_get body spill
# ---------------------------------------------------------------------------
def test_web_network_get_registers_a_spilled_body(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        result = service.web_network_get(sid, "req-1")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["artifact_id"]
    finally:
        service.close_all()


def test_web_network_get_inline_body_is_not_registered(tmp_path: Path) -> None:
    service = _service(tmp_path)
    backend: Any = service._web_backend
    backend.spill_body = False
    try:
        sid = _web_session(service)
        result = service.web_network_get(sid, "req-2")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" not in result.data
    finally:
        service.close_all()


def test_web_network_get_maps_backend_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _fail(service, "network_get", WebError("not_found", "unknown request"))
    try:
        sid = _web_session(service)
        result = service.web_network_get(sid, "missing")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()
