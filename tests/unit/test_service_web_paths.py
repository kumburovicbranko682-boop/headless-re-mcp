"""WebAnalysisMixin guard, error-mapping, and capture-registration paths.

These run without a browser: a fake WebBackend is swapped into the service's
``_web_backend`` slot, so every method's success/error contract is exercised on
a machine where Playwright is not installed. The real registry and repository
are used, so capture registration and the session state gates behave exactly as
they do in production.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.service import AnalysisService


class _FakeWeb:
    """A WebBackend stand-in that writes real files for capture registration."""

    def __init__(self) -> None:
        self.raise_on: dict[str, BaseException] = {}
        self.closed: list[str] = []
        self.calls: list[str] = []
        self.on_open: Any = None
        self.spill: bool = True

    def _maybe_raise(self, name: str) -> None:
        exc = self.raise_on.get(name)
        if exc is not None:
            raise exc

    def status(self, session_id: str) -> dict[str, Any]:
        self.calls.append("status")
        self._maybe_raise("status")
        return {"open": True, "session_id": session_id}

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> dict[str, Any]:
        self.calls.append("open")
        self._maybe_raise("open")
        if self.on_open is not None:
            self.on_open(session_id)
        return {"url": url or "about:blank"}

    def close(self, session_id: str) -> dict[str, Any]:
        self.calls.append("close")
        self.closed.append(session_id)
        self._maybe_raise("close")
        return {"closed": True}

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> dict[str, Any]:
        self.calls.append("navigate")
        self._maybe_raise("navigate")
        return {"url": url}

    def network_list(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self.calls.append("network_list")
        self._maybe_raise("network_list")
        return {"requests": [], "offset": offset, "limit": limit}

    def network_get(
        self, session_id: str, request_id: str, artifact_dir: Path
    ) -> dict[str, Any]:
        self.calls.append("network_get")
        self._maybe_raise("network_get")
        if not self.spill:
            return {"request_id": request_id}
        body = artifact_dir / f"body-{request_id}.bin"
        body.write_bytes(b"response-body")
        return {"request_id": request_id, "body_path": str(body)}

    def console(self, session_id: str, *, limit: int = 200) -> dict[str, Any]:
        self.calls.append("console")
        self._maybe_raise("console")
        return {"messages": [], "limit": limit}

    def scripts(
        self, session_id: str, *, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self.calls.append("scripts")
        self._maybe_raise("scripts")
        return {"scripts": [], "wasm_only": wasm_only, "offset": offset, "limit": limit}

    def script_source(
        self, session_id: str, script_id: str, artifact_dir: Path
    ) -> dict[str, Any]:
        self.calls.append("script_source")
        self._maybe_raise("script_source")
        if not self.spill:
            return {"script_id": script_id}
        src = artifact_dir / f"script-{script_id}.js"
        src.write_text("console.log(1)", encoding="utf-8")
        return {"script_id": script_id, "source_path": str(src)}

    def dom_snapshot(self, session_id: str) -> dict[str, Any]:
        self.calls.append("dom_snapshot")
        self._maybe_raise("dom_snapshot")
        return {"html": "<html></html>"}

    def screenshot(
        self, session_id: str, out_path: Path, *, full_page: bool = False
    ) -> dict[str, Any]:
        self.calls.append("screenshot")
        self._maybe_raise("screenshot")
        out_path.write_bytes(b"\x89PNG\r\n")
        return {"path": str(out_path), "full_page": full_page}

    def har_export(self, session_id: str, out_path: Path) -> dict[str, Any]:
        self.calls.append("har_export")
        self._maybe_raise("har_export")
        out_path.write_text("{}", encoding="utf-8")
        return {"path": str(out_path)}

    def close_all(self) -> None:
        self.calls.append("close_all")


def _service_with_fake(tmp_path: Path) -> tuple[AnalysisService, _FakeWeb]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeWeb()
    service._web_backend = fake  # type: ignore[assignment]
    return service, fake


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def test_web_status_reports_session_fields_and_maps_errors(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        ok = service.web_status(session_id)
        assert ok.ok and ok.data is not None
        assert ok.data["state"] == SessionState.CREATED.value
        assert ok.data["target"] == "web"
        assert ok.data["open"] is True

        fake.raise_on["status"] = WebError("backend_error", "cdp gone")
        mapped = service.web_status(session_id)
        assert mapped.ok is False and mapped.error is not None
        assert mapped.error.code == "backend_error"

        fake.raise_on["status"] = ValueError("boom")
        generic = service.web_status(session_id)
        assert generic.ok is False
    finally:
        service.close_all()


def test_web_preview_writes_a_stable_png_and_maps_errors(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        ok = service.web_preview(session_id)
        assert ok.ok, ok.error
        preview = tmp_path / "artifacts" / "web" / session_id / "preview.png"
        assert preview.is_file()
        # Not registered as an artifact.
        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None
        assert listed.data["artifacts"] == []

        fake.raise_on["screenshot"] = WebError("timeout", "slow")
        assert service.web_preview(session_id).ok is False
        fake.raise_on["screenshot"] = RuntimeError("nope")
        assert service.web_preview(session_id).ok is False
    finally:
        service.close_all()


def test_web_open_success_records_backend_and_timeline(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        opened = service.web_open(session_id)
        assert opened.ok, opened.error
        assert opened.data is not None and opened.data["url"] == "https://example.com/app"
        timeline = service.timeline_list(session_id)
        assert timeline.ok and timeline.data is not None
        events = [row.get("event") for row in timeline.data["events"]]
        assert "web.open" in events
    finally:
        service.close_all()


def test_web_open_requires_a_url_for_a_non_web_session(tmp_path: Path) -> None:
    service, _fake = _service_with_fake(tmp_path)
    try:
        # A non-web session with no locator cannot supply an implicit target, so
        # web.open must ask for a url rather than open "about:blank" silently.
        adopted = service.registry.adopt(Session(target=TargetKind.APK, locator=""))
        result = service.web_open(adopted.id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_web_open_refuses_a_closed_session(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        service.registry.transition(session_id, SessionState.FAILED)
        result = service.web_open(session_id)
        assert result.ok is False
        assert fake.calls == []  # never reached the backend
    finally:
        service.close_all()


def test_web_open_rolls_back_when_the_session_closes_mid_open(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)

        def _close_during(sid: str) -> None:
            service.registry.transition(sid, SessionState.FAILED)

        fake.on_open = _close_during
        result = service.web_open(session_id)
        assert result.ok is False
        # The browser the open created must be closed on rollback.
        assert session_id in fake.closed
    finally:
        service.close_all()


def test_web_open_maps_web_and_generic_errors(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        fake.raise_on["open"] = WebError("navigation_failed", "dns")
        mapped = service.web_open(session_id)
        assert mapped.ok is False and mapped.error is not None
        assert mapped.error.code == "navigation_failed"

        fake.raise_on["open"] = RuntimeError("driver crash")
        assert service.web_open(session_id).ok is False
    finally:
        service.close_all()


def test_web_close_appends_timeline_and_maps_errors(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        ok = service.web_close(session_id)
        assert ok.ok, ok.error

        fake.raise_on["close"] = WebError("backend_error", "already gone")
        assert service.web_close(session_id).ok is False
        fake.raise_on["close"] = KeyError("x")
        assert service.web_close(session_id).ok is False
    finally:
        service.close_all()


def test_web_wrap_methods_map_errors(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        assert service.web_navigate(session_id, "https://a.test").ok
        assert service.web_network_list(session_id).ok
        assert service.web_console(session_id).ok
        assert service.web_scripts(session_id).ok
        assert service.web_wasm_list(session_id).ok
        assert service.web_dom_snapshot(session_id).ok

        fake.raise_on["navigate"] = WebError("timeout", "slow")
        nav = service.web_navigate(session_id, "https://a.test")
        assert nav.ok is False and nav.error is not None
        assert nav.error.code == "timeout"

        fake.raise_on["dom_snapshot"] = RuntimeError("boom")
        assert service.web_dom_snapshot(session_id).ok is False
    finally:
        service.close_all()


def test_web_network_get_registers_the_spilled_body(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.web_network_get(session_id, "req-1")
        assert result.ok and result.data is not None
        assert "artifact_id" in result.data
        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None
        kinds = {row["kind"] for row in listed.data["artifacts"]}
        assert "web_response_body" in kinds

        # A response with no spilled body registers nothing but still succeeds.
        fake.spill = False
        no_body = service.web_network_get(session_id, "req-2")
        assert no_body.ok and no_body.data is not None
        assert "artifact_id" not in no_body.data
        fake.spill = True

        fake.raise_on["network_get"] = WebError("not_found", "no such request")
        assert service.web_network_get(session_id, "missing").ok is False
        fake.raise_on["network_get"] = RuntimeError("boom")
        assert service.web_network_get(session_id, "boom").ok is False
    finally:
        service.close_all()


def test_web_script_source_registers_the_spilled_source(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.web_script_source(session_id, "script-9")
        assert result.ok and result.data is not None
        assert "artifact_id" in result.data
        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None
        kinds = {row["kind"] for row in listed.data["artifacts"]}
        assert "web_script_source" in kinds

        # A script with no spilled source registers nothing but still succeeds.
        fake.spill = False
        no_src = service.web_script_source(session_id, "inline")
        assert no_src.ok and no_src.data is not None
        assert "artifact_id" not in no_src.data
        fake.spill = True

        fake.raise_on["script_source"] = WebError("not_found", "no script")
        assert service.web_script_source(session_id, "missing").ok is False
        fake.raise_on["script_source"] = RuntimeError("boom")
        assert service.web_script_source(session_id, "boom").ok is False
    finally:
        service.close_all()


def test_web_screenshot_registers_capture_and_maps_errors(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.web_screenshot(session_id, full_page=True)
        assert result.ok and result.data is not None
        assert "artifact_id" in result.data
        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None
        kinds = {row["kind"] for row in listed.data["artifacts"]}
        assert "web_screenshot" in kinds

        fake.raise_on["screenshot"] = WebError("backend_error", "no page")
        assert service.web_screenshot(session_id).ok is False
        fake.raise_on["screenshot"] = RuntimeError("boom")
        assert service.web_screenshot(session_id).ok is False
    finally:
        service.close_all()


def test_web_har_export_registers_capture_and_maps_errors(tmp_path: Path) -> None:
    service, fake = _service_with_fake(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.web_har_export(session_id)
        assert result.ok and result.data is not None
        assert "artifact_id" in result.data
        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None
        kinds = {row["kind"] for row in listed.data["artifacts"]}
        assert "web_har" in kinds

        fake.raise_on["har_export"] = WebError("backend_error", "no page")
        assert service.web_har_export(session_id).ok is False
        fake.raise_on["har_export"] = RuntimeError("boom")
        assert service.web_har_export(session_id).ok is False
    finally:
        service.close_all()
