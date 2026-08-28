"""Coverage for the legacy web routes' guard, delegation, and edge arms.

Drives ``register_legacy_routes`` through a real FastAPI app: the loopback
guard for non-IP and remote hosts, bootstrap-cookie session eviction, the MCP
export client variants, setup wizard guards, every session delegation
endpoint against a service without backends, the SSE monitor stream, and the
file-serving edge arms for web previews, virtual-desktop frames, and
artifacts.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headless_re_mcp.config import Settings
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app
from headless_re_mcp.web.commands import WebCommandAdapter

_TOKEN = "web-secret"
_HEADERS = {"Authorization": f"Bearer {_TOKEN}"}


def _build_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[FastAPI, AnalysisService]:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    return create_app(service, token=_TOKEN, settings=settings), service


@pytest.mark.asyncio
async def test_loopback_guard_rejects_non_ip_and_remote_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _service = _build_app(tmp_path, monkeypatch)

    hostname = httpx.ASGITransport(app=app, client=("evil.example", 9))
    async with httpx.AsyncClient(transport=hostname, base_url="http://t") as client:
        response = await client.get("/api/meta", headers=_HEADERS)
        assert response.status_code == 403
        assert response.json()["detail"] == "loopback_only"

    remote = httpx.ASGITransport(app=app, client=("203.0.113.9", 9))
    async with httpx.AsyncClient(transport=remote, base_url="http://t") as client:
        response = await client.get("/api/meta", headers=_HEADERS)
        assert response.status_code == 403


def test_bootstrap_cookie_eviction_meta_pickfile_and_setup_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _service = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        # Fill the session set so the next successful bootstrap must evict one.
        app.state.bootstrap_sessions.update(f"session-{i:02d}" for i in range(32))
        page = client.get(f"/?token={_TOKEN}")
        assert page.status_code == 200
        assert "headless_re_bootstrap" in page.cookies
        assert len(app.state.bootstrap_sessions) == 32

        meta = client.get("/api/meta", headers=_HEADERS)
        assert meta.status_code == 200
        assert meta.json()["loopback_only"] is True

        picked = client.post("/api/ui/pick-file", headers=_HEADERS)
        assert picked.status_code == 200
        assert picked.json()["data"]["available"] in {False, True}

        metrics = client.get("/api/metrics", headers=_HEADERS)
        assert metrics.status_code == 200

        no_home = client.post("/api/setup/ida", headers=_HEADERS, json={"confirm": True})
        assert no_home.status_code == 400
        assert no_home.json()["detail"] == "ida_home_required"

        no_step = client.post("/api/setup/run", headers=_HEADERS, json={"confirm": True})
        assert no_step.status_code == 400
        assert no_step.json()["detail"] == "step_required"


def test_mcp_export_client_variants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app, _service = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        assert client.get("/api/mcp/export?client=bogus", headers=_HEADERS).status_code == 400

        everything = client.get("/api/mcp/export", headers=_HEADERS)
        assert everything.status_code == 200
        assert "stdio" in everything.json()
        assert "examples" in everything.json()

        stdio = client.get("/api/mcp/export?client=stdio", headers=_HEADERS)
        assert stdio.status_code == 200
        assert stdio.json()["config"] == stdio.json()["stdio"]

        claude = client.get("/api/mcp/export?client=claude", headers=_HEADERS)
        assert claude.status_code == 200
        assert claude.json()["client"] == "claude_desktop"


def test_session_endpoints_delegate_to_the_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _service = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        posts = [
            "/api/sessions/nope/static/open",
            "/api/sessions/nope/dynamic/open",
            "/api/sessions/nope/dynamic/resume",
            "/api/sessions/nope/dynamic/pause",
            "/api/sessions/nope/apk/open",
        ]
        for url in posts:
            response = client.post(url, headers=_HEADERS)
            assert response.status_code == 200, url
            assert response.json()["ok"] is False, url

        # Closing a web session that never existed is idempotent success.
        closed = client.post("/api/sessions/nope/web/close", headers=_HEADERS)
        assert closed.status_code == 200 and closed.json()["ok"] is True

        opened = client.post(
            "/api/sessions/nope/web/open",
            headers=_HEADERS,
            json={"url": "https://example.invalid", "headless": True},
        )
        assert opened.status_code == 200 and opened.json()["ok"] is False
        bodyless = client.post("/api/sessions/nope/web/open", headers=_HEADERS)
        assert bodyless.status_code == 200 and bodyless.json()["ok"] is False

        no_url = client.post("/api/sessions/nope/web/navigate", headers=_HEADERS, json={})
        assert no_url.status_code == 400
        navigated = client.post(
            "/api/sessions/nope/web/navigate",
            headers=_HEADERS,
            json={"url": "https://example.invalid"},
        )
        assert navigated.status_code == 200 and navigated.json()["ok"] is False

        gets = [
            "/api/sessions/nope/web/network",
            "/api/sessions/nope/web/console",
            "/api/sessions/nope/web/scripts",
            "/api/sessions/nope/static/functions",
            "/api/sessions/nope/static/strings",
            "/api/sessions/nope/static/decompile?address=4096",
            "/api/sessions/nope/dynamic/state",
            "/api/sessions/nope/dynamic/registers",
            "/api/sessions/nope/modules",
            "/api/sessions/nope/breakpoints",
            "/api/sessions/nope/workflow",
            "/api/sessions/nope/virtual-desktop",
            "/api/sessions/nope/knowledge",
            "/api/sessions/nope/unpack",
            "/api/sessions/nope/unpack/artifacts",
        ]
        for url in gets:
            response = client.get(url, headers=_HEADERS)
            assert response.status_code == 200, url
            assert response.json()["ok"] is False, url

        # An unknown session has an empty-but-valid timeline.
        timeline = client.get("/api/sessions/nope/timeline", headers=_HEADERS)
        assert timeline.status_code == 200 and timeline.json()["ok"] is True

        preview = client.get("/api/sessions/nope/web/preview", headers=_HEADERS)
        assert preview.status_code == 409

        report = client.post("/api/sessions/nope/report", headers=_HEADERS, json={"title": "T"})
        assert report.status_code == 200 and report.json()["ok"] is False

        listed = client.get("/api/artifacts", headers=_HEADERS)
        assert listed.status_code == 200 and listed.json()["ok"] is True
        audited = client.get("/api/audit", headers=_HEADERS)
        assert audited.status_code == 200 and audited.json()["ok"] is True


def test_monitor_stream_emits_frames_and_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _service = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        response = client.get(
            "/api/sessions/nope/monitor/stream?max_frames=2&interval_ms=250",
            headers=_HEADERS,
        )
        assert response.status_code == 200
        assert response.text.count("event: monitor") == 2
        assert "event: end" in response.text


def test_preview_and_frame_edge_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app, service = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        monkeypatch.setattr(
            AnalysisService, "web_preview", lambda self, session_id: _success({"nope": 1})
        )
        missing_path = client.get("/api/sessions/s1/web/preview", headers=_HEADERS)
        assert missing_path.status_code == 500
        assert missing_path.json()["detail"] == "preview_path_missing"

        failed = client.get("/api/sessions/s1/virtual-desktop/frame", headers=_HEADERS)
        assert failed.status_code == 409

        monkeypatch.setattr(
            AnalysisService,
            "virtual_desktop_capture",
            lambda self, session_id, hwnd=None: _success({"backend": "gdi"}),
        )
        no_path = client.get("/api/sessions/s1/virtual-desktop/frame", headers=_HEADERS)
        assert no_path.status_code == 500
        assert no_path.json()["detail"] == "capture_path_missing"

        frame = service.settings.artifact_root / "frames" / "window.bmp"
        frame.parent.mkdir(parents=True, exist_ok=True)
        frame.write_bytes(b"BM fake bitmap")
        monkeypatch.setattr(
            AnalysisService,
            "virtual_desktop_capture",
            lambda self, session_id, hwnd=None: _success(
                {
                    "path": str(frame),
                    "hwnd": 66,
                    "backend": "print_window",
                    "degraded": True,
                    "degraded_reason": "gdi fallback",
                }
            ),
        )
        served = client.get("/api/sessions/s1/virtual-desktop/frame", headers=_HEADERS)
        assert served.status_code == 200
        assert served.headers["X-Capture-Degraded"] == "1"
        assert served.headers["X-Capture-Degraded-Reason"] == "gdi fallback"
        assert served.content == b"BM fake bitmap"


def test_artifact_file_requires_a_stored_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _service = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        monkeypatch.setattr(
            AnalysisService,
            "artifacts_describe",
            lambda self, artifact_id: _success({"artifact": {"id": artifact_id}}),
        )
        response = client.get("/api/artifacts/a1/file", headers=_HEADERS)
        assert response.status_code == 404
        assert response.json()["detail"] == "artifact_path_missing"


def test_write_action_maps_an_unknown_method_key_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, service = _build_app(tmp_path, monkeypatch)
    action = sorted(WebCommandAdapter(service).write_methods)[0]

    def invoke(self: WebCommandAdapter, name: str, body: Any) -> Any:
        raise KeyError(name)

    monkeypatch.setattr(WebCommandAdapter, "invoke_write", invoke)
    with TestClient(app) as client:
        response = client.post(f"/api/write/{action}", headers=_HEADERS, json={"confirm": True})
        assert response.status_code == 400
        assert response.json()["detail"] == "unknown_or_disallowed_write"
