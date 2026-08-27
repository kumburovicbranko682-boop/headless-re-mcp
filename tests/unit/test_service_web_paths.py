"""Path coverage for the browser service mixin (``core/service_web``).

Existing web tests reach the backend and a couple of success shapes; left
uncovered were the mixin's own envelopes: web_status' failure arcs, web_preview
publishing an inspect PNG, web_open's happy path and its non-web-without-url
refusal, web_close's error arcs, web_network_get registering a spilled body,
the WebError arcs of network_get/script_source/screenshot/har_export, and
_web_wrap's success and generic-error arcs. These drive them on a real
AnalysisService with a web session and a faked WebBackend.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.service import AnalysisService


def _service_with_web_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    created = service.create_session("https://example.com/app", target="web")
    assert created.data is not None
    return service, created.data["session"]["id"]


def _raiser(exc: BaseException) -> Any:
    def _fn(*args: Any, **kwargs: Any) -> Any:
        raise exc

    return _fn


def test_web_status_maps_web_and_generic_errors(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._web_backend, "status", _raiser(WebError("no_browser", "not open"))
        )
        mapped = service.web_status(session_id)
        assert mapped.ok is False
        assert mapped.error is not None
        assert mapped.error.code == "no_browser"

        monkeypatch.setattr(
            service._web_backend, "status", _raiser(RuntimeError("boom"))
        )
        generic = service.web_status(session_id)
        assert generic.ok is False
    finally:
        service.close_all()


def test_web_preview_publishes_and_maps_web_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def fake_shot(sid: str, out: Path, full_page: bool = False) -> dict[str, Any]:
            out.write_bytes(b"\x89PNG")
            return {"path": str(out), "full_page": full_page}

        monkeypatch.setattr(service._web_backend, "screenshot", fake_shot)
        ok = service.web_preview(session_id)
        assert ok.ok, ok.error
        assert ok.data is not None
        assert ok.data["path"].endswith("preview.png")

        monkeypatch.setattr(
            service._web_backend, "screenshot", _raiser(WebError("no_page", "blank"))
        )
        failed = service.web_preview(session_id)
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "no_page"
    finally:
        service.close_all()


def test_web_open_records_backend_and_timeline_on_success(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def fake_open(sid: str, target: str, *, headless: bool, timeout: float) -> dict[str, Any]:
            return {"url": target or "https://example.com/app"}

        monkeypatch.setattr(service._web_backend, "open", fake_open)
        result = service.web_open(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["url"] == "https://example.com/app"
    finally:
        service.close_all()


def test_web_open_refuses_a_non_web_session_without_a_url(tmp_path: Path) -> None:
    service, _ = _service_with_web_session(tmp_path)
    try:
        pe_session = Session(target=TargetKind.PE, state=SessionState.READY)
        service.registry.adopt(pe_session)
        result = service.web_open(pe_session.id, url="")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_web_close_maps_web_and_generic_errors(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._web_backend, "close", _raiser(WebError("not_open", "no browser"))
        )
        mapped = service.web_close(session_id)
        assert mapped.ok is False
        assert mapped.error is not None
        assert mapped.error.code == "not_open"

        monkeypatch.setattr(
            service._web_backend, "close", _raiser(RuntimeError("crash"))
        )
        generic = service.web_close(session_id)
        assert generic.ok is False
    finally:
        service.close_all()


def test_web_network_get_registers_a_spilled_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def fake_ng(sid: str, rid: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            body = artifact_dir / "resp.bin"
            body.write_bytes(bytes(range(64)))
            return {"request_id": rid, "status": 200, "body_path": str(body)}

        monkeypatch.setattr(service._web_backend, "network_get", fake_ng)
        result = service.web_network_get(session_id, "req-1")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" in result.data

        # A response with no spilled body is returned untouched, not registered.
        monkeypatch.setattr(
            service._web_backend,
            "network_get",
            lambda sid, rid, adir: {"request_id": rid, "status": 204},
        )
        inline = service.web_network_get(session_id, "req-2")
        assert inline.ok, inline.error
        assert inline.data is not None
        assert "artifact_id" not in inline.data
    finally:
        service.close_all()


def test_web_network_get_maps_a_web_error(tmp_path: Path, monkeypatch: Any) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._web_backend, "network_get", _raiser(WebError("no_request", "gone"))
        )
        result = service.web_network_get(session_id, "missing")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "no_request"
    finally:
        service.close_all()


def test_web_script_source_returns_inline_source_and_maps_a_web_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        # Small source stays inline, so there is no source_path to register.
        monkeypatch.setattr(
            service._web_backend,
            "script_source",
            lambda sid, sid2, adir: {"script_id": sid2, "source": "let x = 1;"},
        )
        inline = service.web_script_source(session_id, "s-1")
        assert inline.ok, inline.error
        assert inline.data is not None
        assert "artifact_id" not in inline.data

        monkeypatch.setattr(
            service._web_backend,
            "script_source",
            _raiser(WebError("no_script", "unknown id")),
        )
        result = service.web_script_source(session_id, "s-99")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "no_script"
    finally:
        service.close_all()


def test_web_screenshot_maps_a_web_error(tmp_path: Path, monkeypatch: Any) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._web_backend, "screenshot", _raiser(WebError("no_page", "blank"))
        )
        result = service.web_screenshot(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "no_page"
    finally:
        service.close_all()


def test_web_har_export_maps_a_web_error(tmp_path: Path, monkeypatch: Any) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._web_backend, "har_export", _raiser(WebError("empty", "no flows"))
        )
        result = service.web_har_export(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "empty"
    finally:
        service.close_all()


def test_web_wrap_returns_success_and_maps_a_generic_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._web_backend, "dom_snapshot", lambda sid: {"nodes": 3}
        )
        ok = service.web_dom_snapshot(session_id)
        assert ok.ok, ok.error
        assert ok.data is not None
        assert ok.data["nodes"] == 3

        monkeypatch.setattr(
            service._web_backend, "console", _raiser(RuntimeError("wrap blew up"))
        )
        generic = service.web_console(session_id)
        assert generic.ok is False
    finally:
        service.close_all()
