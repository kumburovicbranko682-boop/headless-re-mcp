"""Branch coverage for the legacy console REST surface (web/routes/legacy.py).

These routes are the shared control plane every track (web, android, proxy)
drives from the browser console, so their guard branches deserve real tests:
loopback enforcement for exotic hosts, bootstrap-cookie fallbacks, MCP config
export shapes, setup-wizard input validation, and the artifact/write guards.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app
from headless_re_mcp.web.commands import WebCommandAdapter
from headless_re_mcp.web.routes import legacy as legacy_module

TOKEN = "test-token-value-0123456789abcdef"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


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


@pytest.fixture()
def console(tmp_path: Path) -> tuple[TestClient, AnalysisService]:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    app = create_app(service, token=TOKEN, settings=settings)
    return TestClient(app), service


class TestLoopbackGuard:
    def test_a_client_host_that_is_not_even_an_ip_is_refused(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path)
        service = AnalysisService(settings)
        app = create_app(service, token=TOKEN, settings=settings)

        async def fetch() -> httpx.Response:
            transport = httpx.ASGITransport(app=app, client=("evil.example", 4444))
            async with httpx.AsyncClient(transport=transport, base_url="http://web") as client:
                return await client.get("/api/meta", headers=AUTH)

        response = asyncio.run(fetch())
        assert response.status_code == 403
        assert response.json()["detail"] == "loopback_only"


class TestBootstrapCookie:
    def test_a_valid_cookie_authorizes_index_even_with_a_non_bearer_header(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        first = client.get("/", params={"token": TOKEN})
        assert first.status_code == 200
        assert "headless_re_bootstrap" in client.cookies
        # A Basic header is present so the promote middleware stays out of the
        # way, and _require_token must fall through to the cookie branch.
        again = client.get("/", headers={"Authorization": "Basic bm9wZTpub3Bl"})
        assert again.status_code == 200

    def test_bootstrap_sessions_are_evicted_once_thirty_two_pile_up(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        for _ in range(33):
            client.cookies.clear()
            assert client.get("/", params={"token": TOKEN}).status_code == 200
        sessions: set[str] = client.app.state.bootstrap_sessions  # type: ignore[attr-defined]
        assert len(sessions) <= 32


class TestMetaAndMetrics:
    def test_meta_reports_host_port_and_artifact_root(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        body = client.get("/api/meta", headers=AUTH).json()
        assert body["ok"] is True
        assert body["port"] == 8765
        assert body["loopback_only"] is True

    def test_tool_metrics_artifacts_and_audit_listings_answer(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        assert client.get("/api/metrics", headers=AUTH).json()["ok"] is True
        assert client.get("/api/artifacts", headers=AUTH).json()["ok"] is True
        assert client.get("/api/audit", headers=AUTH).json()["ok"] is True


class TestMcpExport:
    def test_an_unknown_client_kind_is_a_400(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        response = client.get("/api/mcp/export", params={"client": "sublime"}, headers=AUTH)
        assert response.status_code == 400
        assert response.json()["detail"] == "unknown_client"

    def test_claude_is_an_alias_for_claude_desktop(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        body = client.get("/api/mcp/export", params={"client": "claude"}, headers=AUTH).json()
        assert body["client"] == "claude_desktop"
        assert "config" in body

    def test_all_returns_stdio_plus_examples(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        body = client.get("/api/mcp/export", headers=AUTH).json()
        assert "stdio" in body
        assert "examples" in body

    def test_stdio_returns_the_raw_launch_config(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        body = client.get("/api/mcp/export", params={"client": "stdio"}, headers=AUTH).json()
        assert body["config"] == body["stdio"]


class TestSetupWizard:
    def test_configure_ida_without_a_home_is_a_400(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        response = client.post(
            "/api/setup/ida", json={"confirm": True, "ida_home": "   "}, headers=AUTH
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "ida_home_required"

    def test_a_saved_ida_home_hot_swaps_the_live_settings(
        self,
        console: tuple[TestClient, AnalysisService],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, service = console
        ida_dir = tmp_path / "ida-pro"
        ida_dir.mkdir()
        monkeypatch.setattr(
            legacy_module,
            "configure_ida",
            lambda **kwargs: {"ok": True, "saved": True, "ida_home": str(ida_dir)},
        )
        response = client.post(
            "/api/setup/ida", json={"confirm": True, "ida_home": str(ida_dir)}, headers=AUTH
        )
        assert response.status_code == 200
        assert service.settings.ida_home == ida_dir

    def test_a_failed_ida_configure_leaves_the_live_settings_alone(
        self,
        console: tuple[TestClient, AnalysisService],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, service = console
        monkeypatch.setattr(
            legacy_module,
            "configure_ida",
            lambda **kwargs: {"ok": False, "error": "not_an_ida_home"},
        )
        response = client.post(
            "/api/setup/ida", json={"confirm": True, "ida_home": "/tmp/nowhere"}, headers=AUTH
        )
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert service.settings.ida_home is None

    def test_run_step_without_a_step_name_is_a_400(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        response = client.post("/api/setup/run", json={"confirm": True, "step": " "}, headers=AUTH)
        assert response.status_code == 400
        assert response.json()["detail"] == "step_required"

    def test_a_config_writing_step_reloads_settings_and_keeps_the_new_ida_home(
        self,
        console: tuple[TestClient, AnalysisService],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, service = console
        ida_dir = tmp_path / "ida-after-step"
        ida_dir.mkdir()
        monkeypatch.setattr(
            legacy_module,
            "run_setup_step",
            lambda *args, **kwargs: {"ok": True, "ida_home": str(ida_dir)},
        )
        response = client.post(
            "/api/setup/run", json={"confirm": True, "step": "configure_ida"}, headers=AUTH
        )
        assert response.status_code == 200
        assert response.json()["settings_reloaded"] is True
        assert service.settings.ida_home == ida_dir


class TestPickFile:
    def test_on_a_posix_host_the_dialog_reports_unavailable_instead_of_crashing(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        body = client.post("/api/ui/pick-file", headers=AUTH).json()
        assert body["ok"] is True
        assert body["data"]["available"] is False
        assert body["data"]["path"] is None


class TestSessionScopedEnvelopes:
    """Every per-session route must answer an envelope, never a 500."""

    GET_ROUTES = (
        "/api/sessions/nope/web/status",
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
        "/api/sessions/nope/timeline",
        "/api/sessions/nope/unpack",
        "/api/sessions/nope/unpack/artifacts",
    )

    POST_ROUTES = (
        "/api/sessions/nope/static/open",
        "/api/sessions/nope/dynamic/open",
        "/api/sessions/nope/dynamic/resume",
        "/api/sessions/nope/dynamic/pause",
        "/api/sessions/nope/web/open",
        "/api/sessions/nope/web/close",
        "/api/sessions/nope/apk/open",
    )

    def test_get_routes_answer_a_json_envelope_for_an_unknown_session(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        for route in self.GET_ROUTES:
            response = client.get(route, headers=AUTH)
            assert response.status_code == 200, route
            assert "ok" in response.json(), route

    def test_post_routes_answer_a_json_envelope_for_an_unknown_session(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        for route in self.POST_ROUTES:
            response = client.post(route, headers=AUTH)
            assert response.status_code == 200, route
            # web/close is idempotent and succeeds; the rest refuse politely.
            assert "ok" in response.json(), route

    def test_navigate_requires_a_url_and_rejects_a_numeric_one(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        missing = client.post("/api/sessions/nope/web/navigate", json={}, headers=AUTH)
        assert missing.status_code == 400
        numeric = client.post(
            "/api/sessions/nope/web/navigate", json={"url": 123}, headers=AUTH
        )
        assert numeric.status_code == 400
        given = client.post(
            "/api/sessions/nope/web/navigate",
            json={"url": "https://example.test"},
            headers=AUTH,
        )
        assert given.status_code == 200
        assert given.json()["ok"] is False

    def test_a_report_title_is_forwarded_to_the_service(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, service = console
        seen: dict[str, Any] = {}

        def fake_report(session_id: str, *, title: str | None = None) -> Result[dict[str, Any]]:
            seen["title"] = title
            return Result(ok=True, data={"path": "x"})

        service.report_generate = fake_report  # type: ignore[method-assign]
        response = client.post(
            "/api/sessions/nope/report", json={"title": "Findings"}, headers=AUTH
        )
        assert response.status_code == 200
        assert seen["title"] == "Findings"


class TestPreviewAndDesktopFrames:
    def test_a_preview_whose_payload_lost_its_path_is_a_500(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, service = console
        service.web_preview = lambda sid: Result(ok=True, data={"path": 123})  # type: ignore[method-assign]
        response = client.get("/api/sessions/nope/web/preview", headers=AUTH)
        assert response.status_code == 500
        assert response.json()["detail"] == "preview_path_missing"

    def test_a_failed_desktop_capture_is_a_409_with_the_error(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        response = client.get("/api/sessions/nope/virtual-desktop/frame", headers=AUTH)
        assert response.status_code == 409
        assert response.json()["ok"] is False

    def test_a_capture_without_a_path_is_a_500(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, service = console
        service.virtual_desktop_capture = (  # type: ignore[method-assign]
            lambda sid, hwnd=None: Result(ok=True, data={"hwnd": 7})
        )
        response = client.get("/api/sessions/nope/virtual-desktop/frame", headers=AUTH)
        assert response.status_code == 500
        assert response.json()["detail"] == "capture_path_missing"

    def test_a_degraded_capture_reports_its_reason_in_a_header(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, service = console
        frame = service.settings.artifact_root / "frame.bmp"
        frame.parent.mkdir(parents=True, exist_ok=True)
        frame.write_bytes(b"BM fake bitmap")
        service.virtual_desktop_capture = (  # type: ignore[method-assign]
            lambda sid, hwnd=None: Result(
                ok=True,
                data={
                    "path": str(frame),
                    "hwnd": 7,
                    "degraded": True,
                    "degraded_reason": "print_window_fallback",
                    "backend": "gdi",
                },
            )
        )
        response = client.get("/api/sessions/nope/virtual-desktop/frame", headers=AUTH)
        assert response.status_code == 200
        assert response.headers["X-Capture-Degraded"] == "1"
        assert response.headers["X-Capture-Degraded-Reason"] == "print_window_fallback"


class TestMonitorStream:
    def test_the_sse_feed_emits_frames_then_a_clean_end_event(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, _ = console
        response = client.get(
            "/api/sessions/nope/monitor/stream",
            params={"interval_ms": 250, "max_frames": 2},
            headers=AUTH,
        )
        assert response.status_code == 200
        assert response.text.count("event: monitor") == 2
        assert "event: end" in response.text


class TestArtifactFile:
    def test_an_artifact_record_without_a_path_is_a_404(
        self, console: tuple[TestClient, AnalysisService]
    ) -> None:
        client, service = console
        service.artifacts_describe = (  # type: ignore[method-assign]
            lambda artifact_id: Result(ok=True, data={"artifact": {"id": artifact_id}})
        )
        response = client.get("/api/artifacts/a1/file", headers=AUTH)
        assert response.status_code == 404
        assert response.json()["detail"] == "artifact_path_missing"


class TestWriteAdapter:
    def test_an_adapter_key_error_maps_to_a_400_not_a_500(
        self,
        console: tuple[TestClient, AnalysisService],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, _ = console

        def raise_key_error(self: WebCommandAdapter, action: str, body: dict[str, Any]) -> Any:
            raise KeyError(action)

        monkeypatch.setattr(WebCommandAdapter, "invoke_write", raise_key_error)
        response = client.post(
            "/api/write/session.close",
            json={"confirm": True, "session_id": "nope"},
            headers=AUTH,
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "unknown_or_disallowed_write"
