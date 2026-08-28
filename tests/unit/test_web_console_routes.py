"""Route-body coverage for the legacy web console.

The existing suite pins the security-critical routes (auth, loopback, path
escape, write policy). These fill in the plain read/write handlers and the
small validation branches that no other test reaches with a valid token: every
session-scoped route answers its envelope for an unknown session, the metadata
and export routes cover their client variants, and the setup routes reject the
bodies that omit a required field.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

_TOKEN = "test-token-value-0123456789abcdef"
_HEADERS = {"Authorization": f"Bearer {_TOKEN}"}


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


def _client(tmp_path: Path) -> TestClient:
    service = AnalysisService(_settings(tmp_path))
    return TestClient(create_app(service, token=_TOKEN, settings=service.settings))


_READ_ROUTES = [
    "/api/sessions/{sid}/web/network",
    "/api/sessions/{sid}/web/console",
    "/api/sessions/{sid}/web/scripts",
    "/api/sessions/{sid}/last-known",
    "/api/sessions/{sid}/static/functions",
    "/api/sessions/{sid}/static/strings",
    "/api/sessions/{sid}/static/decompile?address=4096",
    "/api/sessions/{sid}/dynamic/state",
    "/api/sessions/{sid}/dynamic/registers",
    "/api/sessions/{sid}/modules",
    "/api/sessions/{sid}/breakpoints",
    "/api/sessions/{sid}/workflow",
    "/api/sessions/{sid}/virtual-desktop",
    "/api/sessions/{sid}/knowledge",
    "/api/sessions/{sid}/timeline",
    "/api/sessions/{sid}/unpack",
    "/api/sessions/{sid}/unpack/artifacts",
]


@pytest.mark.parametrize("route", _READ_ROUTES)
def test_session_read_routes_answer_the_envelope_for_an_unknown_session(
    tmp_path: Path, route: str
) -> None:
    client = _client(tmp_path)
    response = client.get(route.format(sid="ghost"), headers=_HEADERS)
    assert response.status_code == 200, route
    assert response.json()["ok"] is False, route


_WRITE_ROUTES = [
    "/api/sessions/{sid}/apk/open",
    "/api/sessions/{sid}/static/open",
    "/api/sessions/{sid}/dynamic/open",
    "/api/sessions/{sid}/dynamic/resume",
    "/api/sessions/{sid}/dynamic/pause",
    "/api/sessions/{sid}/web/close",
    "/api/sessions/{sid}/web/open",
    "/api/sessions/{sid}/report",
]


@pytest.mark.parametrize("route", _WRITE_ROUTES)
def test_session_write_routes_answer_the_envelope_for_an_unknown_session(
    tmp_path: Path, route: str
) -> None:
    client = _client(tmp_path)
    response = client.post(route.format(sid="ghost"), headers=_HEADERS, json={})
    assert response.status_code == 200, route
    # An unknown session yields an ``ok:false`` envelope for most routes; a few
    # writes (e.g. closing an already-absent web view) are idempotent successes.
    assert isinstance(response.json()["ok"], bool), route


def test_web_navigate_requires_a_url_then_answers_the_envelope(tmp_path: Path) -> None:
    client = _client(tmp_path)
    missing = client.post("/api/sessions/ghost/web/navigate", headers=_HEADERS, json={})
    assert missing.status_code == 400
    assert missing.json()["detail"] == "url_required"

    navigated = client.post(
        "/api/sessions/ghost/web/navigate",
        headers=_HEADERS,
        json={"url": "https://example.com/app"},
    )
    assert navigated.status_code == 200
    assert navigated.json()["ok"] is False


def test_metadata_and_inventory_routes_serve(tmp_path: Path) -> None:
    client = _client(tmp_path)

    meta = client.get("/api/meta", headers=_HEADERS)
    assert meta.status_code == 200
    body = meta.json()
    assert body["ok"] is True
    assert body["loopback_only"] is True
    assert body["claims_universal_unpack"] is False

    for route in ("/api/metrics", "/api/artifacts", "/api/audit"):
        response = client.get(route, headers=_HEADERS)
        assert response.status_code == 200, route
        assert response.json()["ok"] is True, route


def test_mcp_export_covers_each_client_variant(tmp_path: Path) -> None:
    client = _client(tmp_path)

    everything = client.get("/api/mcp/export?client=all", headers=_HEADERS)
    assert everything.status_code == 200
    all_body = everything.json()
    assert "stdio" in all_body
    assert "examples" in all_body

    stdio = client.get("/api/mcp/export?client=stdio", headers=_HEADERS)
    assert stdio.status_code == 200
    assert stdio.json()["config"] == stdio.json()["stdio"]

    claude = client.get("/api/mcp/export?client=claude", headers=_HEADERS)
    assert claude.status_code == 200
    assert claude.json()["client"] == "claude_desktop"

    bogus = client.get("/api/mcp/export?client=bogus", headers=_HEADERS)
    assert bogus.status_code == 400
    assert bogus.json()["detail"] == "unknown_client"


def test_setup_routes_reject_bodies_missing_a_required_field(tmp_path: Path) -> None:
    client = _client(tmp_path)

    # Confirmed, but no IDA path.
    no_home = client.post("/api/setup/ida", headers=_HEADERS, json={"confirm": True})
    assert no_home.status_code == 400
    assert no_home.json()["detail"] == "ida_home_required"

    # Confirmed, but no step named.
    no_step = client.post("/api/setup/run", headers=_HEADERS, json={"confirm": True})
    assert no_step.status_code == 400
    assert no_step.json()["detail"] == "step_required"


def test_pick_file_reports_unavailable_off_windows(tmp_path: Path) -> None:
    """On a non-Windows host the native dialog is simply unavailable, not an error."""
    client = _client(tmp_path)
    picked = client.post("/api/ui/pick-file", headers=_HEADERS)
    assert picked.status_code == 200
    data = picked.json()["data"]
    assert data["available"] is False
    assert data["path"] is None


def test_bootstrap_session_set_is_capped(tmp_path: Path) -> None:
    """Each ?token= open mints a bootstrap cookie; the server keeps a bounded set."""
    service = AnalysisService(_settings(tmp_path))
    app = create_app(service, token=_TOKEN, settings=service.settings)
    client = TestClient(app)
    for _ in range(40):
        assert client.get(f"/?token={_TOKEN}").status_code == 200
    assert len(app.state.bootstrap_sessions) <= 32


def test_monitor_stream_emits_multiple_frames_before_the_end(tmp_path: Path) -> None:
    """A max_frames above one exercises the inter-frame sleep, not just one shot."""
    client = _client(tmp_path)
    response = client.get(
        "/api/sessions/ghost/monitor/stream?interval_ms=250&max_frames=2",
        headers=_HEADERS,
    )
    assert response.status_code == 200
    assert response.text.count("event: monitor") == 2
    assert "event: end" in response.text


def test_virtual_desktop_frame_maps_capture_failure_and_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)

    monkeypatch.setattr(
        AnalysisService,
        "virtual_desktop_capture",
        lambda self, sid, hwnd=None: Result(
            ok=False, error=RpcError(code="no_capture", message="none")
        ),
    )
    conflict = client.get("/api/sessions/s1/virtual-desktop/frame", headers=_HEADERS)
    assert conflict.status_code == 409
    assert conflict.json()["ok"] is False

    monkeypatch.setattr(
        AnalysisService,
        "virtual_desktop_capture",
        lambda self, sid, hwnd=None: Result(ok=True, data={"path": 123}),
    )
    broken = client.get("/api/sessions/s1/virtual-desktop/frame", headers=_HEADERS)
    assert broken.status_code == 500
    assert broken.json()["detail"] == "capture_path_missing"


def test_web_open_tolerates_a_request_with_no_body(tmp_path: Path) -> None:
    """The optional-body helper must treat a missing body as empty, not crash."""
    client = _client(tmp_path)
    response = client.post("/api/sessions/ghost/web/open", headers=_HEADERS)
    assert response.status_code == 200
    assert isinstance(response.json()["ok"], bool)


def test_web_preview_reports_a_capture_without_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(
        AnalysisService,
        "web_preview",
        lambda self, sid: Result(ok=True, data={"path": 123}),
    )
    broken = client.get("/api/sessions/s1/web/preview", headers=_HEADERS)
    assert broken.status_code == 500
    assert broken.json()["detail"] == "preview_path_missing"


def test_artifact_file_reports_a_row_without_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(
        AnalysisService,
        "artifacts_describe",
        lambda self, artifact_id: Result(ok=True, data={"artifact": {"id": artifact_id}}),
    )
    missing = client.get("/api/artifacts/any/file", headers=_HEADERS)
    assert missing.status_code == 404
    assert missing.json()["detail"] == "artifact_path_missing"
