"""service_web's wrappers: read passthroughs, capture spill wiring, and the
success/error envelopes for status/preview/open/close/network/script.

The web *backend* is exercised by the field tests and the leak-guard races by
test_web_backends.py, but a whole band of the service layer only runs when a
browser is actually driven, which needs Playwright. That left the thin read
passthroughs (network.list / console / scripts / wasm.list), the
spill->register_capture wiring on network.get / script.source / dom.snapshot,
web.status / web.preview / web.close, web.open's *success* tail, and the
_web_wrap `except BaseException` catch-all with no unit coverage. A fake
WebBackend stands in for the browser so the service wiring is what is pinned,
without Playwright.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeWeb:
    """A WebBackend stand-in: fixed sensible replies, optional per-op failures.

    ``raises`` maps an op name to the exception it should raise, so one fake can
    drive both a success and a WebError/crash path for the same method.
    """

    def __init__(
        self,
        *,
        spill: bool = True,
        raises: dict[str, BaseException] | None = None,
    ) -> None:
        self.spill = spill
        self._raises = raises or {}
        self.closed: list[str] = []

    def _maybe_fail(self, op: str) -> None:
        exc = self._raises.get(op)
        if exc is not None:
            raise exc

    def status(self, session_id: str) -> JsonObject:
        self._maybe_fail("status")
        return {"url": "https://app/", "title": "T"}

    def screenshot(self, session_id: str, out: Path, full_page: bool = False) -> JsonObject:
        self._maybe_fail("screenshot")
        Path(out).write_bytes(b"\x89PNG\r\n")
        return {"path": str(out), "bytes": 6, "full_page": full_page}

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        self._maybe_fail("open")
        return {"opened": True, "url": url or "https://app/", "title": "T", "headless": headless}

    def close(self, session_id: str) -> JsonObject:
        self._maybe_fail("close")
        self.closed.append(session_id)
        return {"closed": True}

    def network_list(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        self._maybe_fail("network_list")
        return {"requests": [], "offset": offset, "limit": limit}

    def network_get(self, session_id: str, request_id: str, out_dir: Path) -> JsonObject:
        self._maybe_fail("network_get")
        payload: JsonObject = {"request_id": request_id, "status": 200}
        if self.spill:
            body = Path(out_dir) / "body.bin"
            body.write_bytes(b"response-body")
            payload["body_path"] = str(body)
        return payload

    def console(self, session_id: str, *, limit: int = 200) -> JsonObject:
        self._maybe_fail("console")
        return {"messages": [], "limit": limit}

    def scripts(
        self, session_id: str, *, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        self._maybe_fail("scripts")
        return {"scripts": [], "wasm_only": wasm_only, "offset": offset, "limit": limit}

    def script_source(self, session_id: str, script_id: str, out_dir: Path) -> JsonObject:
        self._maybe_fail("script_source")
        payload: JsonObject = {"script_id": script_id}
        if self.spill:
            src = Path(out_dir) / "source.js"
            src.write_text("console.log(1)", encoding="utf-8")
            payload["source_path"] = str(src)
        return payload

    def dom_snapshot(self, session_id: str, out_dir: Path) -> JsonObject:
        self._maybe_fail("dom_snapshot")
        payload: JsonObject = {"html": "<html></html>", "truncated": False}
        if self.spill:
            doc = Path(out_dir) / "dom.html"
            doc.write_text("<html>big</html>", encoding="utf-8")
            payload["truncated"] = True
            payload["html_path"] = str(doc)
        return payload

    def har_export(self, session_id: str, out: Path) -> JsonObject:
        self._maybe_fail("har_export")
        Path(out).write_text("{}", encoding="utf-8")
        return {"path": str(out)}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path, **web_kwargs: Any) -> tuple[AnalysisService, str, _FakeWeb]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeWeb(**web_kwargs)
    service._web_backend = fake  # type: ignore[assignment]
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], fake


def _timeline(service: AnalysisService, session_id: str, name: str) -> list[JsonObject]:
    page = service.repository.list_timeline(session_id)
    return [item for item in page["events"] if item.get("event") == name]


def test_read_passthroughs_delegate_and_wrap_with_session_and_backend(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path)
    try:
        for result in (
            service.web_network_list(session_id, offset=5, limit=10),
            service.web_console(session_id, limit=25),
            service.web_scripts(session_id, offset=1, limit=2),
        ):
            assert result.ok is True, result.error
            assert result.meta.get("session_id") == session_id
            assert result.meta.get("backend") == "web"

        # wasm.list is scripts with wasm_only forced True regardless of the caller.
        wasm = service.web_wasm_list(session_id, offset=0, limit=3)
        assert wasm.ok and wasm.data is not None
        assert wasm.data["wasm_only"] is True
    finally:
        service.close_all()


def test_web_status_merges_the_session_locator_state_and_target(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path)
    try:
        result = service.web_status(session_id)
        assert result.ok is True, result.error
        assert result.data is not None
        assert result.data["target"] == "web"
        assert result.data["locator"] == "https://example.com/app"
        assert "state" in result.data
    finally:
        service.close_all()


def test_web_status_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"status": WebError("backend_error", "status probe failed")}
    )
    try:
        result = service.web_status(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_web_preview_writes_a_stable_png_and_wraps_it(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path)
    try:
        result = service.web_preview(session_id)
        assert result.ok is True, result.error
        assert result.data is not None
        assert (tmp_path / "artifacts" / "web" / session_id / "preview.png").is_file()
    finally:
        service.close_all()


def test_web_preview_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"screenshot": WebError("backend_error", "no page")}
    )
    try:
        result = service.web_preview(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_web_open_success_records_backend_and_timeline(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path)
    try:
        result = service.web_open(session_id, url="https://example.com/app", headless=True)
        assert result.ok is True, result.error
        assert result.data is not None and result.data["opened"] is True
        assert result.meta.get("backend") == "web"
        assert len(_timeline(service, session_id, "web.open")) == 1
    finally:
        service.close_all()


def test_web_open_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"open": WebError("backend_error", "launch failed")}
    )
    try:
        result = service.web_open(session_id, url="https://example.com/app")
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_web_close_records_a_timeline_entry(tmp_path: Path) -> None:
    service, session_id, fake = _service(tmp_path)
    try:
        result = service.web_close(session_id)
        assert result.ok is True, result.error
        assert session_id in fake.closed
        assert len(_timeline(service, session_id, "web.close")) == 1
    finally:
        service.close_all()


def test_web_close_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"close": WebError("backend_error", "close failed")}
    )
    try:
        result = service.web_close(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_network_get_registers_a_spilled_body_as_an_artifact(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path, spill=True)
    try:
        result = service.web_network_get(session_id, "req-1")
        assert result.ok is True, result.error
        assert result.data is not None
        # The spilled body was registered, so it carries an artifact id back.
        assert "artifact_id" in result.data
    finally:
        service.close_all()


def test_network_get_without_a_spill_just_wraps_the_payload(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path, spill=False)
    try:
        result = service.web_network_get(session_id, "req-2")
        assert result.ok is True, result.error
        assert result.data is not None
        assert result.data["request_id"] == "req-2"
    finally:
        service.close_all()


def test_network_get_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"network_get": WebError("not_found", "no such request")}
    )
    try:
        result = service.web_network_get(session_id, "missing")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


def test_script_source_registers_a_spilled_source(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path, spill=True)
    try:
        result = service.web_script_source(session_id, "script-1")
        assert result.ok is True, result.error
        assert result.data is not None
        assert "artifact_id" in result.data
    finally:
        service.close_all()


def test_script_source_without_a_spill_just_wraps_the_payload(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path, spill=False)
    try:
        result = service.web_script_source(session_id, "script-2")
        assert result.ok is True, result.error
        assert result.data is not None
        assert result.data["script_id"] == "script-2"
    finally:
        service.close_all()


def test_script_source_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"script_source": WebError("not_found", "no such script")}
    )
    try:
        result = service.web_script_source(session_id, "missing")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


def test_dom_snapshot_registers_a_spilled_document(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path, spill=True)
    try:
        result = service.web_dom_snapshot(session_id)
        assert result.ok is True, result.error
        assert result.data is not None
        # The oversized DOM was written to the artifact area and registered, so
        # the full document is recoverable rather than lost at the inline clip.
        assert result.data["truncated"] is True
        assert "artifact_id" in result.data
    finally:
        service.close_all()


def test_dom_snapshot_without_a_spill_just_wraps_the_payload(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path, spill=False)
    try:
        result = service.web_dom_snapshot(session_id)
        assert result.ok is True, result.error
        assert result.data is not None
        assert result.data["truncated"] is False
        assert "html_path" not in result.data
        assert "artifact_id" not in result.data
    finally:
        service.close_all()


def test_dom_snapshot_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"dom_snapshot": WebError("backend_error", "no document")}
    )
    try:
        result = service.web_dom_snapshot(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_web_status_maps_an_unexpected_fault_to_internal_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"status": RuntimeError("status probe crashed")}
    )
    try:
        result = service.web_status(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_web_close_maps_an_unexpected_fault_to_internal_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"close": RuntimeError("close crashed")}
    )
    try:
        result = service.web_close(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_web_screenshot_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"screenshot": WebError("backend_error", "no page to shoot")}
    )
    try:
        result = service.web_screenshot(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_web_har_export_maps_a_backend_error(tmp_path: Path) -> None:
    service, session_id, _ = _service(
        tmp_path, raises={"har_export": WebError("backend_error", "no context")}
    )
    try:
        result = service.web_har_export(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_web_wrap_turns_an_unexpected_backend_fault_into_internal_error(tmp_path: Path) -> None:
    """A non-WebError raised by a backend op must fail closed as a structured
    envelope, not escape _web_wrap into the RPC loop."""
    service, session_id, _ = _service(
        tmp_path, raises={"network_list": RuntimeError("browser crashed")}
    )
    try:
        result = service.web_network_list(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_dom_snapshot_maps_an_unexpected_fault_to_internal_error(tmp_path: Path) -> None:
    """dom_snapshot has its own try/except now (not _web_wrap) because it spills;
    an unexpected backend fault must still fail closed as internal_error."""
    service, session_id, _ = _service(
        tmp_path, raises={"dom_snapshot": RuntimeError("browser crashed")}
    )
    try:
        result = service.web_dom_snapshot(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()
