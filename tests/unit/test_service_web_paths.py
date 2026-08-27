"""Guard, capture and error-mapping paths of the web (CDP) service mixin.

The Playwright backend has its own suite; this file exercises the thin service
layer -- the ``WebError`` / unexpected-error arms on every method, the
``_web_wrap`` delegator, and the capture registration on network bodies,
script sources, screenshots and HAR. A real ``AnalysisService`` is built with a
web session and the backend methods are stubbed, so no browser is launched.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


def _web_session(svc: AnalysisService) -> str:
    created = svc.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _patch(monkeypatch: pytest.MonkeyPatch, svc: AnalysisService, name: str, fn: Any) -> None:
    monkeypatch.setattr(svc._web_backend, name, fn)


def _raiser(exc: BaseException) -> Any:
    def _fn(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise exc

    return _fn


# ---------------------------------------------------------------------------
# web_status


def test_web_status_folds_in_the_session_fields(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "status", lambda sid: {"running": True})

    result = service.web_status(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["running"] is True
    assert result.data["locator"] == "https://example.com/app"
    assert result.data["target"] == "web"


def test_web_status_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "status", _raiser(WebError("backend_error", "cdp gone")))

    result = service.web_status(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_web_status_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "status", _raiser(ValueError("boom")))

    result = service.web_status(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# web_preview


def test_web_preview_overwrites_the_stable_png(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def fake_shot(sid: str, out: Path, full_page: bool = False) -> dict[str, Any]:
        out.write_bytes(b"\x89PNG")
        return {"path": str(out)}

    _patch(monkeypatch, service, "screenshot", fake_shot)

    result = service.web_preview(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert Path(result.data["path"]).name == "preview.png"


def test_web_preview_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "screenshot", _raiser(WebError("not_ready", "no page")))

    result = service.web_preview(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_ready"


# ---------------------------------------------------------------------------
# web_open


def test_web_open_records_the_backend_and_endpoint(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(
        monkeypatch,
        service,
        "open",
        lambda sid, target, headless=True, timeout=30.0: {"url": "https://example.com/app"},
    )

    result = service.web_open(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["url"] == "https://example.com/app"


def test_web_open_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "open", _raiser(WebError("navigation_failed", "dns error")))

    result = service.web_open(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "navigation_failed"


# ---------------------------------------------------------------------------
# web_close


def test_web_close_reports_the_backend_payload(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "close", lambda sid: {"closed": True})

    result = service.web_close(session_id)

    assert result.ok, result.error
    assert result.data == {"closed": True}


def test_web_close_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "close", _raiser(WebError("backend_error", "kill failed")))

    result = service.web_close(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_web_close_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "close", _raiser(ValueError("boom")))

    result = service.web_close(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# _web_wrap delegators: navigate / network_list / console / scripts / wasm / dom


def test_web_navigate_delegates_through_the_wrapper(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    seen: dict[str, Any] = {}

    def fake_nav(sid: str, url: str, timeout: float = 30.0) -> dict[str, Any]:
        seen.update(sid=sid, url=url, timeout=timeout)
        return {"url": url}

    _patch(monkeypatch, service, "navigate", fake_nav)

    result = service.web_navigate(session_id, "https://example.com/next", timeout=12.0)

    assert result.ok, result.error
    assert seen == {"sid": session_id, "url": "https://example.com/next", "timeout": 12.0}


def test_web_network_list_passes_paging(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    seen: dict[str, Any] = {}

    def fake_list(sid: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        seen.update(offset=offset, limit=limit)
        return {"requests": []}

    _patch(monkeypatch, service, "network_list", fake_list)

    result = service.web_network_list(session_id, offset=3, limit=7)

    assert result.ok, result.error
    assert seen == {"offset": 3, "limit": 7}


def test_web_console_delegates(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "console", lambda sid, limit=200: {"messages": []})

    result = service.web_console(session_id, limit=50)

    assert result.ok, result.error


def test_web_scripts_delegates(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    seen: dict[str, Any] = {}

    def fake_scripts(
        sid: str, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        seen["wasm_only"] = wasm_only
        return {"scripts": []}

    _patch(monkeypatch, service, "scripts", fake_scripts)

    result = service.web_scripts(session_id)

    assert result.ok, result.error
    assert seen["wasm_only"] is False


def test_web_wasm_list_forces_wasm_only(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    seen: dict[str, Any] = {}

    def fake_scripts(
        sid: str, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        seen["wasm_only"] = wasm_only
        return {"scripts": []}

    _patch(monkeypatch, service, "scripts", fake_scripts)

    result = service.web_wasm_list(session_id)

    assert result.ok, result.error
    assert seen["wasm_only"] is True


def test_web_dom_snapshot_delegates(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "dom_snapshot", lambda sid: {"nodes": 1})

    result = service.web_dom_snapshot(session_id)

    assert result.ok, result.error


def test_web_wrap_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "navigate", _raiser(WebError("timeout", "load timed out")))

    result = service.web_navigate(session_id, "https://example.com/next")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "timeout"


def test_web_wrap_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "console", _raiser(ValueError("boom")))

    result = service.web_console(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# web_network_get / web_script_source: spill registration


def test_web_network_get_registers_a_spilled_body(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def fake_get(sid: str, rid: str, artifact_dir: Path) -> dict[str, Any]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        body = artifact_dir / "resp.bin"
        body.write_bytes(bytes(range(64)))
        return {"request_id": rid, "body_path": str(body)}

    _patch(monkeypatch, service, "network_get", fake_get)

    result = service.web_network_get(session_id, "req-1")

    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_web_network_get_leaves_an_inline_body_alone(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(
        monkeypatch,
        service,
        "network_get",
        lambda sid, rid, artifact_dir: {"request_id": rid, "body": "inline"},
    )

    result = service.web_network_get(session_id, "req-2")

    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_web_network_get_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "network_get", _raiser(WebError("not_found", "no request")))

    result = service.web_network_get(session_id, "missing")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


def test_web_script_source_registers_a_spilled_source(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def fake_source(sid: str, script_id: str, artifact_dir: Path) -> dict[str, Any]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        src = artifact_dir / "script.js"
        src.write_text("console.log(1)", encoding="utf-8")
        return {"script_id": script_id, "source_path": str(src)}

    _patch(monkeypatch, service, "script_source", fake_source)

    result = service.web_script_source(session_id, "s-1")

    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_web_script_source_leaves_an_inline_source_alone(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(
        monkeypatch,
        service,
        "script_source",
        lambda sid, script_id, artifact_dir: {"script_id": script_id, "source": "x"},
    )

    result = service.web_script_source(session_id, "s-2")

    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_web_script_source_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "script_source", _raiser(WebError("not_found", "no script")))

    result = service.web_script_source(session_id, "missing")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


# ---------------------------------------------------------------------------
# web_screenshot / web_har_export error arms


def test_web_screenshot_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "screenshot", _raiser(WebError("not_ready", "no page")))

    result = service.web_screenshot(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_ready"


def test_web_har_export_maps_a_web_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _patch(monkeypatch, service, "har_export", _raiser(WebError("backend_error", "no har")))

    result = service.web_har_export(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"
