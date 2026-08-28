"""Authenticated passthroughs and guard branches of the legacy web routes.

test_web_console.py covers auth, loopback, the file-serving path guards and a
few endpoints end to end. This file drives the many thin session sub-routes on
an authenticated client (each just wraps a service Result), the mcp-export
client variants, the setup field guards, the SSE monitor's sleep and
client-disconnect arms, and the capture/preview fail-closed branches that need
a mocked service Result.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

TOKEN = "test-token-value-0123456789abcdef"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )


def _client(tmp_path: Path) -> tuple[TestClient, AnalysisService]:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    client = TestClient(create_app(service, token=TOKEN, settings=settings))
    return client, service


def _client_with_session(tmp_path: Path) -> tuple[TestClient, AnalysisService, str]:
    from tests.unit.test_session import _write_minimal_pe

    sample = tmp_path / "sample.exe"
    _write_minimal_pe(sample, 0x8664)
    client, service = _client(tmp_path)
    created = client.post("/api/sessions", headers=HEADERS, json={"binary": str(sample)})
    assert created.status_code == 200, created.text
    sid = str(created.json()["data"]["session"]["id"])
    return client, service, sid


def test_authenticated_session_passthroughs_all_return_200(tmp_path: Path) -> None:
    client, service, sid = _client_with_session(tmp_path)
    try:
        gets = [
            "/api/meta",
            "/api/metrics",
            "/api/artifacts",
            "/api/audit",
            f"/api/sessions/{sid}",
            f"/api/sessions/{sid}/last-known",
            f"/api/sessions/{sid}/static/functions",
            f"/api/sessions/{sid}/static/strings",
            f"/api/sessions/{sid}/static/decompile?address=4096",
            f"/api/sessions/{sid}/dynamic/state",
            f"/api/sessions/{sid}/dynamic/registers",
            f"/api/sessions/{sid}/modules",
            f"/api/sessions/{sid}/breakpoints",
            f"/api/sessions/{sid}/workflow",
            f"/api/sessions/{sid}/web/network",
            f"/api/sessions/{sid}/web/console",
            f"/api/sessions/{sid}/web/scripts",
            f"/api/sessions/{sid}/knowledge",
            f"/api/sessions/{sid}/timeline",
            f"/api/sessions/{sid}/unpack",
            f"/api/sessions/{sid}/unpack/artifacts",
            f"/api/sessions/{sid}/virtual-desktop",
        ]
        for path in gets:
            response = client.get(path, headers=HEADERS)
            assert response.status_code == 200, (path, response.status_code, response.text[:200])

        posts = [
            f"/api/sessions/{sid}/static/open",
            f"/api/sessions/{sid}/dynamic/open",
            f"/api/sessions/{sid}/dynamic/resume",
            f"/api/sessions/{sid}/dynamic/pause",
            f"/api/sessions/{sid}/web/close",
            f"/api/sessions/{sid}/apk/open",
            f"/api/sessions/{sid}/report",
        ]
        for path in posts:
            response = client.post(path, headers=HEADERS, json={})
            assert response.status_code == 200, (path, response.status_code, response.text[:200])
    finally:
        service.close_all()


def test_meta_reports_loopback_only_contract(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    try:
        body = client.get("/api/meta", headers=HEADERS).json()
        assert body["ok"] is True
        assert body["loopback_only"] is True
        assert body["claims_universal_unpack"] is False
    finally:
        service.close_all()


def test_mcp_export_client_variants(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    try:
        for client_kind in ("all", "stdio", "claude"):
            response = client.get(f"/api/mcp/export?client={client_kind}", headers=HEADERS)
            assert response.status_code == 200, (client_kind, response.text[:200])
        # "all" carries both the stdio block and the per-client examples.
        combined = client.get("/api/mcp/export?client=all", headers=HEADERS).json()
        assert "stdio" in combined and "examples" in combined
        rejected = client.get("/api/mcp/export?client=bogus", headers=HEADERS)
        assert rejected.status_code == 400
        assert rejected.json()["detail"] == "unknown_client"
    finally:
        service.close_all()


def test_setup_endpoints_reject_missing_fields(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    try:
        no_home = client.post("/api/setup/ida", headers=HEADERS, json={"confirm": True})
        assert no_home.status_code == 400
        assert no_home.json()["detail"] == "ida_home_required"

        no_step = client.post("/api/setup/run", headers=HEADERS, json={"confirm": True})
        assert no_step.status_code == 400
        assert no_step.json()["detail"] == "step_required"
    finally:
        service.close_all()


def test_pick_file_reports_unavailable_off_windows(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    try:
        picked = client.post("/api/ui/pick-file", headers=HEADERS)
        assert picked.status_code == 200
        data = picked.json()["data"]
        assert data["available"] is False
        assert data["path"] is None
    finally:
        service.close_all()


def test_web_open_reads_the_body_and_navigate_requires_a_url(tmp_path: Path) -> None:
    client, service, sid = _client_with_session(tmp_path)
    try:
        opened = client.post(
            f"/api/sessions/{sid}/web/open",
            headers=HEADERS,
            json={"url": "https://example.com", "headless": False},
        )
        assert opened.status_code == 200

        no_url = client.post(f"/api/sessions/{sid}/web/navigate", headers=HEADERS, json={})
        assert no_url.status_code == 400
        assert no_url.json()["detail"] == "url_required"

        with_url = client.post(
            f"/api/sessions/{sid}/web/navigate",
            headers=HEADERS,
            json={"url": "https://example.com/next"},
        )
        assert with_url.status_code == 200
    finally:
        service.close_all()


def test_web_preview_reports_a_missing_path_as_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = _client(tmp_path)
    monkeypatch.setattr(
        AnalysisService,
        "web_preview",
        lambda self, sid: Result(ok=True, data={"note": "no path key"}),
    )
    try:
        response = client.get("/api/sessions/s1/web/preview", headers=HEADERS)
        assert response.status_code == 500
        assert response.json()["detail"] == "preview_path_missing"
    finally:
        service.close_all()


def test_virtual_desktop_frame_error_missing_and_degraded_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    client = TestClient(create_app(service, token=TOKEN, settings=settings))
    try:
        monkeypatch.setattr(
            AnalysisService,
            "virtual_desktop_capture",
            lambda self, sid, hwnd=None: Result(ok=False, error=RpcError(code="x", message="m")),
        )
        failed = client.get("/api/sessions/s1/virtual-desktop/frame", headers=HEADERS)
        assert failed.status_code == 409

        monkeypatch.setattr(
            AnalysisService,
            "virtual_desktop_capture",
            lambda self, sid, hwnd=None: Result(ok=True, data={"note": "no path"}),
        )
        pathless = client.get("/api/sessions/s1/virtual-desktop/frame", headers=HEADERS)
        assert pathless.status_code == 500
        assert pathless.json()["detail"] == "capture_path_missing"

        inside = settings.artifact_root / "ui" / "s1" / "frame.bmp"
        inside.parent.mkdir(parents=True, exist_ok=True)
        inside.write_bytes(b"BMreal")
        monkeypatch.setattr(
            AnalysisService,
            "virtual_desktop_capture",
            lambda self, sid, hwnd=None: Result(
                ok=True,
                data={
                    "path": str(inside),
                    "degraded": True,
                    "degraded_reason": "slow capture",
                    "backend": "gdi",
                    "hwnd": 42,
                },
            ),
        )
        served = client.get("/api/sessions/s1/virtual-desktop/frame", headers=HEADERS)
        assert served.status_code == 200
        assert served.headers["x-capture-degraded"] == "1"
        assert served.headers["x-capture-degraded-reason"] == "slow capture"
        assert served.content == b"BMreal"
    finally:
        service.close_all()


def test_artifact_file_reports_a_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = _client(tmp_path)
    monkeypatch.setattr(
        AnalysisService,
        "artifacts_describe",
        lambda self, artifact_id: Result(ok=True, data={"artifact": {"id": artifact_id}}),
    )
    try:
        response = client.get("/api/artifacts/x/file", headers=HEADERS)
        assert response.status_code == 404
        assert response.json()["detail"] == "artifact_path_missing"
    finally:
        service.close_all()


def test_monitor_stream_sleeps_between_multiple_frames(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    try:
        response = client.get(
            "/api/sessions/nope/monitor/stream?interval_ms=250&max_frames=2",
            headers=HEADERS,
        )
        assert response.status_code == 200
        assert response.text.count("event: monitor") == 2
        assert "event: end" in response.text
    finally:
        service.close_all()


def test_monitor_stream_stops_when_the_client_disconnects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _disconnected(self: object) -> bool:
        return True

    monkeypatch.setattr("starlette.requests.Request.is_disconnected", _disconnected)
    client, service = _client(tmp_path)
    try:
        response = client.get("/api/sessions/nope/monitor/stream?max_frames=5", headers=HEADERS)
        assert response.status_code == 200
        # It broke on the first disconnect check, so no monitor frame was built.
        assert "event: monitor" not in response.text
        assert "event: end" in response.text
    finally:
        service.close_all()


def test_web_open_without_a_body_defaults_to_headless(tmp_path: Path) -> None:
    client, service, sid = _client_with_session(tmp_path)
    try:
        opened = client.post(f"/api/sessions/{sid}/web/open", headers=HEADERS)
        assert opened.status_code == 200
    finally:
        service.close_all()


def test_setup_ida_with_an_invalid_home_skips_the_settings_reload(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    original = service.settings
    not_ida = tmp_path / "not-ida"
    not_ida.mkdir()
    try:
        response = client.post(
            "/api/setup/ida",
            headers=HEADERS,
            json={"confirm": True, "ida_home": str(not_ida)},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is False
        assert body["saved"] is False
        # A failed configure must not swap in a half-built Settings object.
        assert service.settings is original
    finally:
        service.close_all()


def test_setup_run_configure_ida_hot_reloads_settings_with_the_new_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp import config as cfgmod
    from headless_re_mcp.config import ida_library_names

    fake_ida = tmp_path / "IDA Professional 9.9"
    fake_ida.mkdir()
    (fake_ida / ida_library_names()[0]).write_bytes(b"MZ")
    config_path = tmp_path / "user-config.json"
    monkeypatch.setattr(cfgmod, "default_config_path", lambda: config_path)

    client, service = _client(tmp_path)
    try:
        response = client.post(
            "/api/setup/run",
            headers=HEADERS,
            json={
                "confirm": True,
                "step": "configure_ida",
                "ida_home": str(fake_ida),
                "activate": False,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert body["settings_reloaded"] is True
        assert service.settings.ida_home == fake_ida.resolve()
    finally:
        service.close_all()


def test_loopback_guard_refuses_a_client_host_that_is_not_an_ip(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    app = create_app(service, token=TOKEN, settings=settings)

    async def call() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, client=("not-an-ip", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://console") as client:
            return await client.get("/api/sessions", headers=HEADERS)

    try:
        refused = asyncio.run(call())
        assert refused.status_code == 403
        assert refused.json()["detail"] == "loopback_only"
    finally:
        service.close_all()


def test_bootstrap_session_set_is_capped(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    app = create_app(service, token=TOKEN, settings=settings)
    client = TestClient(app)
    try:
        for _ in range(40):
            assert client.get("/?token=" + TOKEN).status_code == 200
        # The set is bounded, so a long-lived console cannot accrete cookies.
        assert len(app.state.bootstrap_sessions) <= 32
    finally:
        service.close_all()
