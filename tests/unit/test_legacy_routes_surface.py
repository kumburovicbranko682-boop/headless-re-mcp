"""Exercise the legacy /api surface: delegation routes, guards, and capture edges."""

from __future__ import annotations

import asyncio
from collections import deque
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

import headless_re_mcp.config_generate as config_generate
import headless_re_mcp.web.routes.legacy as legacy
from headless_re_mcp.config import Settings
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import _MAX_BOOTSTRAP_SESSIONS, create_app
from headless_re_mcp.web.commands import WebCommandAdapter

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


@pytest.fixture
def console(tmp_path: Path) -> tuple[TestClient, AnalysisService]:
    service = AnalysisService(_settings(tmp_path))
    app = create_app(service, token=TOKEN, settings=service.settings)
    return TestClient(app), service


GET_ROUTES = [
    "/api/sessions/nosuch/static/functions",
    "/api/sessions/nosuch/static/strings",
    "/api/sessions/nosuch/static/decompile?address=4096",
    "/api/sessions/nosuch/dynamic/state",
    "/api/sessions/nosuch/dynamic/registers",
    "/api/sessions/nosuch/modules",
    "/api/sessions/nosuch/breakpoints",
    "/api/sessions/nosuch/workflow",
    "/api/sessions/nosuch/timeline",
    "/api/sessions/nosuch/unpack",
    "/api/sessions/nosuch/unpack/artifacts",
    "/api/sessions/nosuch/web/status",
    "/api/sessions/nosuch/web/network",
    "/api/sessions/nosuch/web/console",
    "/api/sessions/nosuch/web/scripts",
    "/api/sessions/nosuch/knowledge?kind=finding",
    "/api/sessions/nosuch/virtual-desktop",
]

POST_ROUTES = [
    "/api/sessions/nosuch/static/open",
    "/api/sessions/nosuch/dynamic/open",
    "/api/sessions/nosuch/dynamic/resume",
    "/api/sessions/nosuch/dynamic/pause",
    "/api/sessions/nosuch/close",
    "/api/sessions/nosuch/apk/open",
    "/api/sessions/nosuch/web/open",
    "/api/sessions/nosuch/report",
]


@pytest.mark.parametrize("route", GET_ROUTES)
def test_every_session_get_route_answers_an_envelope_not_a_crash(
    console: tuple[TestClient, AnalysisService], route: str
) -> None:
    response = console[0].get(route, headers=AUTH)

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False, "an unknown session must be a refusal envelope"
    assert body["error"]["code"]


@pytest.mark.parametrize("route", POST_ROUTES)
def test_every_session_post_route_answers_an_envelope_not_a_crash(
    console: tuple[TestClient, AnalysisService], route: str
) -> None:
    response = console[0].post(route, headers=AUTH)

    assert response.status_code == 200
    assert response.json()["ok"] is False


def test_closing_a_never_opened_web_session_is_idempotent(
    console: tuple[TestClient, AnalysisService],
) -> None:
    response = console[0].post("/api/sessions/nosuch/web/close", headers=AUTH)

    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_meta_and_metrics_and_listings_answer_with_the_token(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, _ = console

    meta = client.get("/api/meta", headers=AUTH).json()
    assert meta["ok"] is True and meta["loopback_only"] is True

    assert client.get("/api/metrics", headers=AUTH).json()["ok"] is True
    assert client.get("/api/artifacts", headers=AUTH).json()["ok"] is True
    assert client.get("/api/audit", headers=AUTH).json()["ok"] is True


def test_web_open_reads_headless_and_url_from_the_body(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, service = console
    seen: list[tuple[str, str, bool]] = []

    def spy(session_id: str, *, url: str, headless: bool) -> Any:
        seen.append((session_id, url, headless))
        return _success({"opened": True}, backend="web")

    service.web_open = spy  # type: ignore[method-assign, assignment]

    body = {"url": "https://example.test", "headless": False}
    assert client.post("/api/sessions/s1/web/open", headers=AUTH, json=body).json()["ok"]

    assert seen == [("s1", "https://example.test", False)]


def test_web_navigate_requires_a_url(console: tuple[TestClient, AnalysisService]) -> None:
    client, _ = console
    refused = client.post("/api/sessions/s1/web/navigate", headers=AUTH, json={"url": " "})
    assert refused.status_code == 400
    assert refused.json()["detail"] == "url_required"

    routed = client.post(
        "/api/sessions/s1/web/navigate", headers=AUTH, json={"url": "https://example.test"}
    )
    assert routed.status_code == 200
    assert routed.json()["ok"] is False


def test_report_title_is_used_only_when_it_is_a_real_string(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, service = console
    titles: list[str | None] = []

    def spy(session_id: str, *, title: str | None = None) -> Any:
        titles.append(title)
        return _success({"generated": True}, backend="core")

    service.report_generate = spy  # type: ignore[method-assign, assignment]

    client.post("/api/sessions/s1/report", headers=AUTH, json={"title": "  "})
    client.post("/api/sessions/s1/report", headers=AUTH, json={"title": "Findings"})

    assert titles == [None, "Findings"]


# ---------------------------------------------------------------------------
# loopback and token guards


def _get_as(app: Any, host: str, path: str) -> httpx.Response:
    """One request whose ASGI client address is `host` instead of `testclient`."""

    async def _run() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, client=(host, 9))
        async with httpx.AsyncClient(transport=transport, base_url="http://console") as probe:
            return await probe.get(path, headers=AUTH)

    return asyncio.run(_run())


def test_a_client_whose_host_is_not_an_ip_is_refused(
    console: tuple[TestClient, AnalysisService],
) -> None:
    response = _get_as(console[0].app, "gateway.lan", "/api/meta")

    assert response.status_code == 403
    assert response.json()["detail"] == "loopback_only"


def test_a_routable_client_address_is_refused(
    console: tuple[TestClient, AnalysisService],
) -> None:
    assert _get_as(console[0].app, "203.0.113.7", "/api/meta").status_code == 403


def test_a_bootstrap_cookie_authenticates_when_the_bearer_scheme_is_foreign(
    console: tuple[TestClient, AnalysisService],
) -> None:
    """A `Basic` header must not shadow a valid HttpOnly session cookie."""
    client, _ = console
    assert client.get("/", params={"token": TOKEN}).status_code == 200
    assert client.cookies.get("headless_re_bootstrap")

    page = client.get("/", headers={"Authorization": "Basic Zm9vOmJhcg=="})

    assert page.status_code == 200
    assert "legacy-monitor-contract" in page.text


def test_bootstrap_sessions_are_capped_at_32(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, _ = console
    for _ in range(33):
        client.cookies.clear()
        assert client.get("/", params={"token": TOKEN}).status_code == 200

    assert len(client.app.state.bootstrap_sessions) == 32  # type: ignore[attr-defined]


def test_the_asset_mount_is_skipped_when_no_static_dir_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(legacy, "_SPA_DIR", tmp_path / "no-spa")
    monkeypatch.setattr(legacy, "_STATIC_DIR", tmp_path / "no-static")

    service = AnalysisService(_settings(tmp_path))
    app = create_app(service, token=TOKEN, settings=service.settings)

    assert all(getattr(route, "name", "") != "assets" for route in app.routes)


# ---------------------------------------------------------------------------
# /api/mcp/export client shaping


_EXPORT = {
    "ok": True,
    "python": "python.exe",
    "config_path": "cfg.json",
    "repo_root": "repo",
    "package_importable": True,
    "env_inventory": {},
    "embedded_env_keys": [],
    "doctor": {},
    "doctor_ready": True,
    "notes": [],
    "stdio": {"command": "python.exe"},
    "examples": {"cursor": {"mcp": 1}, "claude_desktop": {"mcp": 2}},
}


@pytest.fixture
def canned_export(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_generate, "merge_live_settings", lambda settings: settings)
    monkeypatch.setattr(config_generate, "export_mcp_environment", lambda *a, **k: dict(_EXPORT))


def test_mcp_export_refuses_an_unknown_client(
    console: tuple[TestClient, AnalysisService], canned_export: None
) -> None:
    response = console[0].get("/api/mcp/export", params={"client": "emacs"}, headers=AUTH)
    assert response.status_code == 400
    assert response.json()["detail"] == "unknown_client"


def test_mcp_export_shapes_all_stdio_and_claude_aliases(
    console: tuple[TestClient, AnalysisService], canned_export: None
) -> None:
    client, _ = console

    everything = client.get("/api/mcp/export", headers=AUTH).json()
    assert everything["stdio"] == _EXPORT["stdio"]
    assert everything["examples"] == _EXPORT["examples"]

    stdio = client.get("/api/mcp/export", params={"client": "stdio"}, headers=AUTH).json()
    assert stdio["config"] == _EXPORT["stdio"]

    claude = client.get("/api/mcp/export", params={"client": "claude"}, headers=AUTH).json()
    assert claude["client"] == "claude_desktop"
    assert claude["config"] == {"mcp": 2}


# ---------------------------------------------------------------------------
# setup wizard


def test_setup_ida_requires_a_home_path(console: tuple[TestClient, AnalysisService]) -> None:
    response = console[0].post(
        "/api/setup/ida", headers=AUTH, json={"confirm": True, "ida_home": "  "}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "ida_home_required"


def test_a_failed_ida_configure_does_not_mutate_live_settings(
    console: tuple[TestClient, AnalysisService], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = console
    monkeypatch.setattr(
        legacy, "configure_ida", lambda **kw: {"ok": False, "error": "not an IDA home"}
    )

    body = {"confirm": True, "ida_home": "/nowhere/ida"}
    response = client.post("/api/setup/ida", headers=AUTH, json=body)

    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert service.settings.ida_home is None


def test_setup_run_requires_a_step(console: tuple[TestClient, AnalysisService]) -> None:
    response = console[0].post("/api/setup/run", headers=AUTH, json={"confirm": True})
    assert response.status_code == 400
    assert response.json()["detail"] == "step_required"


def test_a_config_writing_step_hot_reloads_settings_with_the_new_ida_home(
    console: tuple[TestClient, AnalysisService],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client, service = console
    ida_home = tmp_path / "ida-pro"
    monkeypatch.setattr(
        legacy,
        "run_setup_step",
        lambda settings, step, **kw: {"ok": True, "ida_home": str(ida_home)},
    )

    body = {"confirm": True, "step": "configure_ida"}
    result = client.post("/api/setup/run", headers=AUTH, json=body).json()

    assert result["settings_reloaded"] is True
    assert service.settings.ida_home == ida_home


def test_pick_file_reports_unavailable_off_windows(
    console: tuple[TestClient, AnalysisService], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(legacy, "is_windows_host", lambda: False)

    data = console[0].post("/api/ui/pick-file", headers=AUTH).json()["data"]

    assert data == {"path": None, "cancelled": False, "available": False, "busy": False}


# ---------------------------------------------------------------------------
# capture file responses


def test_a_preview_whose_backend_lost_the_path_is_a_500_not_a_file(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, service = console
    service.web_preview = lambda session_id: _success({"path": 123}, backend="web")  # type: ignore[method-assign]

    response = client.get("/api/sessions/s1/web/preview", headers=AUTH)

    assert response.status_code == 500
    assert response.json()["detail"] == "preview_path_missing"


def test_a_desktop_frame_for_an_unknown_session_is_a_409_envelope(
    console: tuple[TestClient, AnalysisService],
) -> None:
    response = console[0].get("/api/sessions/nosuch/virtual-desktop/frame", headers=AUTH)

    assert response.status_code == 409
    assert response.json()["ok"] is False


def test_a_desktop_frame_without_a_path_is_a_500(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, service = console
    capture = _success({"hwnd": 42}, backend="win32_ui")
    service.virtual_desktop_capture = lambda sid, hwnd=None: capture  # type: ignore[method-assign, misc]

    response = client.get("/api/sessions/s1/virtual-desktop/frame", headers=AUTH)

    assert response.status_code == 500
    assert response.json()["detail"] == "capture_path_missing"


def test_a_degraded_desktop_frame_discloses_the_reason_in_headers(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, service = console
    root = service.settings.artifact_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    frame = root / "desk.bmp"
    frame.write_bytes(b"BM fake bitmap")
    capture = _success(
        {
            "path": str(frame),
            "hwnd": 42,
            "backend": "gdi",
            "degraded": True,
            "degraded_reason": "printwindow-fallback",
        },
        backend="win32_ui",
    )
    service.virtual_desktop_capture = lambda sid, hwnd=None: capture  # type: ignore[method-assign, misc]

    response = client.get("/api/sessions/s1/virtual-desktop/frame", headers=AUTH)

    assert response.status_code == 200
    assert response.headers["X-Capture-Degraded"] == "1"
    assert response.headers["X-Capture-Degraded-Reason"] == "printwindow-fallback"
    assert response.content == b"BM fake bitmap"


def test_an_artifact_row_without_a_path_is_a_404(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, service = console
    described = _success({"artifact": {"id": "a-1"}}, backend="core")
    service.artifacts_describe = lambda artifact_id: described  # type: ignore[method-assign]

    response = client.get("/api/artifacts/a-1/file", headers=AUTH)

    assert response.status_code == 404
    assert response.json()["detail"] == "artifact_path_missing"


# ---------------------------------------------------------------------------
# writes and streaming


def test_a_write_the_adapter_no_longer_knows_is_a_400(
    console: tuple[TestClient, AnalysisService], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The route allow-list and the adapter registry can drift; disclose, don't 500."""
    client, service = console
    action = sorted(WebCommandAdapter(service).write_methods)[0]

    def vanished(self: WebCommandAdapter, name: str, body: dict[str, Any]) -> Any:
        raise KeyError(name)

    monkeypatch.setattr(WebCommandAdapter, "invoke_write", vanished)

    response = client.post(f"/api/write/{action}", headers=AUTH, json={"confirm": True})

    assert response.status_code == 400
    assert response.json()["detail"] == "unknown_or_disallowed_write"


def test_the_monitor_stream_yields_frames_and_a_final_end_event(
    console: tuple[TestClient, AnalysisService],
) -> None:
    client, _ = console
    url = "/api/sessions/nosuch/monitor/stream?max_frames=2&interval_ms=250"

    with client.stream("GET", url, headers=AUTH) as response:
        assert response.status_code == 200
        body = b"".join(response.iter_bytes())

    assert body.count(b"event: monitor") == 2
    assert b"event: end" in body


def test_a_disconnected_monitor_stream_stops_polling_immediately(
    console: tuple[TestClient, AnalysisService], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closed tab must not keep the snapshot builder running for max_frames."""
    from starlette.requests import Request

    async def gone(self: Request) -> bool:
        return True

    monkeypatch.setattr(Request, "is_disconnected", gone)
    client, _ = console
    url = "/api/sessions/nosuch/monitor/stream?max_frames=2000&interval_ms=250"

    with client.stream("GET", url, headers=AUTH) as response:
        body = b"".join(response.iter_bytes())

    assert b"event: monitor" not in body
    assert b"event: end" in body


def test_bootstrap_session_store_is_bounded_and_evicts_oldest_first(
    tmp_path: Path,
) -> None:
    """A full bootstrap store must drop its OLDEST session, never a random one.

    The store was a plain set, and ``set.pop()`` removes an arbitrary member: a
    burst of more than the cap in ``/?token=`` opens could invalidate a session
    issued moments earlier while an older, idle one survived -- the active user
    then 401s on their next /api call. It is now a bounded deque, so appending
    when full evicts the oldest and every more-recent session lives on.
    """
    service = AnalysisService(_settings(tmp_path))
    app = create_app(service, token=TOKEN, settings=service.settings)
    store = app.state.bootstrap_sessions

    assert isinstance(store, deque)
    assert store.maxlen == _MAX_BOOTSTRAP_SESSIONS

    store.extend(f"t{index}" for index in range(store.maxlen))
    assert len(store) == store.maxlen

    store.append("newest")
    assert "t0" not in store  # the oldest was pushed out
    assert "t1" in store  # everything after it survived
    assert f"t{store.maxlen - 1}" in store
    assert "newest" in store
    assert len(store) == store.maxlen


def test_a_token_open_when_full_evicts_the_oldest_bootstrap_session(
    tmp_path: Path,
) -> None:
    """Driving the real /?token= route when the store is full drops the oldest.

    Proves the route appends rather than doing a set-style arbitrary pop: with
    the store pre-filled to capacity, one more token open evicts only the oldest
    sentinel and keeps the most recent one.
    """
    service = AnalysisService(_settings(tmp_path))
    app = create_app(service, token=TOKEN, settings=service.settings)
    client = TestClient(app)
    store = app.state.bootstrap_sessions
    store.extend(f"t{index}" for index in range(store.maxlen))

    reply = client.get(f"/?token={TOKEN}")
    assert reply.status_code == 200
    assert reply.cookies.get("headless_re_bootstrap")

    assert "t0" not in store
    assert f"t{store.maxlen - 1}" in store
    assert len(store) == store.maxlen
