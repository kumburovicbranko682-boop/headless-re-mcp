"""Device-free coverage for the web (Playwright) service contract.

``service_web`` is the boundary between the browser backend and the RPC
envelope. Its happy captures (screenshot / HAR / spilled script source) are
pinned in test_web_backends, and the closed/mid-launch guards on web.open are
pinned there too, but the *error* half of every method -- turning a WebError
into an XdbgRpcError that keeps its code, letting anything else fall through
the canonical dispatch -- plus the successful web.open bookkeeping, the
non-web url guard, and the "body/source stayed inline" (no spill) branches
had no device-free coverage.

These use a fake WebBackend whose signatures match the real one (notably
``open(..., proxy=...)``, whose omission is what let the reclaim test pass
without reaching the guard), so the mapping and wiring are pinned without a
browser.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_web
from headless_re_mcp.core.models import SessionState, TargetKind
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeWeb:
    """A browser backend that writes what a real capture writes, or raises.

    ``raises`` maps a method name to the exception it should raise; ``spill``
    toggles whether network_get / script_source emit an on-disk artifact path
    (the register branch) or an inline body (the skip-register branch).
    """

    def __init__(
        self, *, raises: dict[str, BaseException] | None = None, spill: bool = True
    ) -> None:
        self.raises = raises or {}
        self.spill = spill
        self.opened: list[str] = []
        self.closed: list[str] = []

    def _maybe(self, name: str) -> None:
        exc = self.raises.get(name)
        if exc is not None:
            raise exc

    def status(self, session_id: str) -> JsonObject:
        self._maybe("status")
        return {"open": True, "url": "https://example.com"}

    def open(
        self,
        session_id: str,
        url: str,
        *,
        headless: bool = True,
        timeout: float = 30.0,
        proxy: str | None = None,
    ) -> JsonObject:
        self._maybe("open")
        self.opened.append(session_id)
        return {"opened": True, "url": url or "https://example.com", "title": "T"}

    def close(self, session_id: str) -> JsonObject:
        self._maybe("close")
        self.closed.append(session_id)
        return {"closed": True}

    def screenshot(self, session_id: str, out_path: Path, *, full_page: bool = False) -> JsonObject:
        self._maybe("screenshot")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
        return {"path": str(out_path)}

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        self._maybe("network_get")
        if not self.spill:
            return {"requestId": request_id, "body": "inline", "truncated": False}
        artifact_dir.mkdir(parents=True, exist_ok=True)
        body = artifact_dir / f"body-{request_id}.bin"
        body.write_bytes(b"response-bytes" * 8)
        return {"requestId": request_id, "body_path": str(body)}

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        self._maybe("script_source")
        if not self.spill:
            return {"scriptId": script_id, "source": "var a=1;", "truncated": False}
        artifact_dir.mkdir(parents=True, exist_ok=True)
        spill = artifact_dir / f"script-{script_id}.js"
        spill.write_text("var a=1;" * 64, encoding="utf-8")
        return {"scriptId": script_id, "source_path": str(spill), "truncated": True}

    def har_export(self, session_id: str, out_path: Path) -> JsonObject:
        self._maybe("har_export")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out_path), "entry_count": 0}

    def navigate(self, session_id: str, url: str, timeout: float = 30.0) -> JsonObject:
        self._maybe("navigate")
        return {"url": url, "status": 200}

    def console(self, session_id: str, limit: int = 200) -> JsonObject:
        self._maybe("console")
        return {"messages": [], "count": 0}

    def network_list(self, session_id: str, offset: int = 0, limit: int = 100) -> JsonObject:
        self._maybe("network_list")
        return {"requests": [], "count": 0, "has_more": False}

    def scripts(
        self, session_id: str, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        self._maybe("scripts")
        return {"scripts": [], "count": 0, "has_more": False, "wasm_only": wasm_only}

    def dom_snapshot(self, session_id: str) -> JsonObject:
        self._maybe("dom_snapshot")
        return {"nodes": 1}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path, backend: _FakeWeb) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._web_backend = backend  # type: ignore[assignment]
    return service


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.data is not None
    return str(created.data["session"]["id"])


# --- web.status -------------------------------------------------------------


def test_status_reports_the_session_locator_state_and_target(tmp_path: Path) -> None:
    backend = _FakeWeb()
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_status(sid)
        assert res.ok, res.error
        assert res.data is not None
        # The service overlays the session's own view on the backend's answer.
        assert res.data["target"] == "web"
        assert res.data["open"] is True
        assert "state" in res.data and "locator" in res.data
    finally:
        service.close_all()


def test_status_maps_a_web_error_to_its_code(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"status": WebError("invalid_state", "no browser open")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_status(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_state"
    finally:
        service.close_all()


def test_status_maps_an_unexpected_error_to_an_incident(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"status": RuntimeError("driver crashed")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_status(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "internal_error"
    finally:
        service.close_all()


# --- web.preview ------------------------------------------------------------


def test_preview_writes_the_stable_png(tmp_path: Path) -> None:
    backend = _FakeWeb()
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_preview(sid)
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["path"].endswith("preview.png")
        assert Path(res.data["path"]).is_file()
    finally:
        service.close_all()


def test_preview_maps_a_web_error(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"screenshot": WebError("invalid_state", "no page")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_preview(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_state"
    finally:
        service.close_all()


# --- web.open ---------------------------------------------------------------


def test_open_records_the_backend_and_returns_the_url(tmp_path: Path) -> None:
    backend = _FakeWeb()
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_open(sid, url="https://target.example/app")
        # res.ok proves the post-open recheck passed and the success bookkeeping
        # (_record_backend + _timeline_append) ran before the envelope was built.
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["url"] == "https://target.example/app"
        assert backend.opened == [sid]
    finally:
        service.close_all()


def test_open_requires_a_url_for_a_non_web_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _FakeWeb()
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        # A non-web session with no locator and no url has nothing to navigate
        # to; the guard must refuse it before the backend is ever touched.
        fake = SimpleNamespace(target=TargetKind.APK, locator="", state=SessionState.CREATED)
        monkeypatch.setattr(service.registry, "get", lambda _sid: fake)
        res = service.web_open(sid, url="")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_params"
        assert backend.opened == []
    finally:
        service.close_all()


def test_open_maps_a_backend_web_error(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"open": WebError("backend_error", "launch failed")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_open(sid, url="https://x")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "backend_error"
    finally:
        service.close_all()


# --- web.close --------------------------------------------------------------


def test_close_reports_success_and_records_the_timeline(tmp_path: Path) -> None:
    backend = _FakeWeb()
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_close(sid)
        assert res.ok, res.error
        assert backend.closed == [sid]
    finally:
        service.close_all()


def test_close_maps_a_web_error(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"close": WebError("backend_error", "detach failed")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_close(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "backend_error"
    finally:
        service.close_all()


# --- web.network.get --------------------------------------------------------


def test_network_get_registers_a_spilled_body(tmp_path: Path) -> None:
    backend = _FakeWeb(spill=True)
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_network_get(sid, "req-1")
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["artifact_id"]
        listed = service.repository.list_artifacts(sid)
        kinds = {item["kind"] for item in listed["artifacts"]}
        assert "web_response_body" in kinds
    finally:
        service.close_all()


def test_network_get_leaves_an_inline_body_unregistered(tmp_path: Path) -> None:
    backend = _FakeWeb(spill=False)
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_network_get(sid, "req-2")
        assert res.ok, res.error
        assert res.data is not None
        assert "artifact_id" not in res.data
        assert res.data["body"] == "inline"
    finally:
        service.close_all()


def test_network_get_maps_a_web_error(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"network_get": WebError("not_found", "no such request")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_network_get(sid, "gone")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "not_found"
    finally:
        service.close_all()


# --- web.script.source ------------------------------------------------------


def test_script_source_leaves_inline_source_unregistered(tmp_path: Path) -> None:
    # The no-spill branch: a small script comes back inline, so there is no
    # source_path to register as a capture.
    backend = _FakeWeb(spill=False)
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_script_source(sid, "7")
        assert res.ok, res.error
        assert res.data is not None
        assert "artifact_id" not in res.data
        assert res.data["source"] == "var a=1;"
    finally:
        service.close_all()


def test_script_source_maps_a_web_error(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"script_source": WebError("not_found", "no such script")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_script_source(sid, "gone")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "not_found"
    finally:
        service.close_all()


# --- _web_wrap (navigate / console / dom_snapshot) --------------------------


def test_wrap_success_shapes_the_envelope(tmp_path: Path) -> None:
    backend = _FakeWeb()
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_navigate(sid, "https://x")
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["status"] == 200
        assert res.meta["backend"] == "web"
    finally:
        service.close_all()


def test_wrap_delegations_reach_the_backend(tmp_path: Path) -> None:
    # network_list / scripts / wasm_list are thin _web_wrap delegations; drive
    # each so the delegation itself is exercised, not just navigate/console.
    backend = _FakeWeb()
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        assert service.web_network_list(sid).ok
        assert service.web_scripts(sid).ok
        wasm = service.web_wasm_list(sid)
        assert wasm.ok
        assert wasm.data is not None
        assert wasm.data["wasm_only"] is True
    finally:
        service.close_all()


def test_wrap_maps_a_web_error(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"dom_snapshot": WebError("invalid_state", "no page")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_dom_snapshot(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_state"
    finally:
        service.close_all()


def test_wrap_maps_an_unexpected_error_to_an_incident(tmp_path: Path) -> None:
    backend = _FakeWeb(raises={"console": RuntimeError("cdp exploded")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = service.web_console(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "internal_error"
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "backend_op", "args"),
    [
        ("web_preview", "screenshot", ()),
        ("web_close", "close", ()),
        ("web_network_get", "network_get", ("req",)),
        ("web_script_source", "script_source", ("s",)),
        ("web_screenshot", "screenshot", ()),
        ("web_har_export", "har_export", ()),
    ],
)
def test_each_method_maps_an_unexpected_error_to_an_incident(
    tmp_path: Path, method: str, backend_op: str, args: tuple[Any, ...]
) -> None:
    # Every method's own try/except must route a non-WebError through the
    # canonical dispatch rather than letting it escape the envelope.
    backend = _FakeWeb(raises={backend_op: RuntimeError("driver died")})
    service = _service(tmp_path, backend)
    try:
        sid = _web_session(service)
        res = getattr(service, method)(sid, *args)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "internal_error"
    finally:
        service.close_all()


def test_as_rpc_copies_details() -> None:
    err = WebError("too_large", "body too big", request_id="r1")
    rpc = service_web._as_rpc(err)
    assert rpc.code == "too_large"
    assert str(rpc) == "body too big"
    assert rpc.details == {"request_id": "r1"}
    err.details["request_id"] = "mutated"
    assert rpc.details["request_id"] == "r1"
