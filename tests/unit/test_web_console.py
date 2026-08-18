from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app
from headless_re_mcp.web.auth import load_or_create_web_token


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


def test_web_token_persists(tmp_path: Path) -> None:
    path = tmp_path / "web_token.json"
    first = load_or_create_web_token(path=path)
    second = load_or_create_web_token(path=path)
    assert first == second
    assert len(first) >= 24


def test_web_requires_token_and_serves_sessions(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    app = create_app(service, token="test-token-value-0123456789abcdef", settings=settings)
    client = TestClient(app)

    denied = client.get("/api/sessions")
    assert denied.status_code == 401

    ok = client.get(
        "/api/sessions",
        headers={"Authorization": "Bearer test-token-value-0123456789abcdef"},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    assert body["data"]["count"] == 0


def test_token_query_cookie_authorizes_later_api_calls(tmp_path: Path) -> None:
    """SPA strips ?token= from the URL; refresh must still reach /api via cookie."""
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))

    assert client.get("/api/sessions").status_code == 401
    page = client.get("/?token=" + token)
    assert page.status_code == 200
    assert client.cookies.get("headless_re_bootstrap")
    ok = client.get("/api/sessions")
    assert ok.status_code == 200
    assert ok.json()["ok"] is True


def test_percent_encoded_token_equals_still_opens_the_console(tmp_path: Path) -> None:
    from headless_re_mcp.web.routes.legacy import repair_encoded_token_query

    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))

    assert repair_encoded_token_query(f"token%3D{token}".encode()) == f"token={token}".encode()
    missing = client.get("/")
    assert missing.status_code == 401
    assert "需要访问令牌" in missing.text
    page = client.get(f"/?token%3D{token}")
    assert page.status_code == 200
    assert '<div id="root"></div>' in page.text


def test_web_workspace_mode_get_and_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Redirect config persistence to a temp path so the gate never writes the
    # real user config (which would leak workspace_profile into other tests).
    monkeypatch.setattr(
        "headless_re_mcp.config.default_config_path", lambda: tmp_path / "config.json"
    )
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    app = create_app(service, token="test-token-value-0123456789abcdef", settings=settings)
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token-value-0123456789abcdef"}

    got = client.get("/api/workspace/mode", headers=headers)
    assert got.status_code == 200
    body = got.json()
    assert body["ok"] is True
    assert body["data"]["profile"] == "full"

    missing = client.post("/api/workspace/mode", headers=headers, json={})
    assert missing.status_code == 400

    changed = client.post("/api/workspace/mode", headers=headers, json={"profile": "android"})
    assert changed.status_code == 200
    changed_body = changed.json()
    assert changed_body["ok"] is True
    assert changed_body["data"]["profile"] == "android"
    assert service.settings.workspace_profile == "android"


def test_web_write_requires_confirm(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    missing = client.post("/api/write/artifacts.gc", headers=headers, json={})
    assert missing.status_code == 400
    assert missing.json()["detail"] == "confirm_required"

    confirmed = client.post(
        "/api/write/artifacts.gc",
        headers=headers,
        json={"confirm": True, "max_total_bytes": 1024},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["ok"] is True


def test_web_monitor_endpoint(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    missing = client.get("/api/sessions/does-not-exist/monitor", headers=headers)
    assert missing.status_code == 200
    body = missing.json()
    assert body["ok"] is False
    assert body["data"]["ok"] is False
    assert body["data"]["session_id"] == "does-not-exist"
    assert body["data"]["error"]["code"]


def test_web_monitor_stream_sends_sse_frames(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(
        "/api/sessions/does-not-exist/monitor/stream?interval_ms=250&max_frames=1",
        headers=headers,
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")
    text = response.text
    assert "event: monitor" in text
    assert "does-not-exist" in text
    assert "event: end" in text


def test_web_index_is_monitor_shell(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    page = client.get("/", headers={"Authorization": f"Bearer {token}"})
    assert page.status_code == 200
    html = page.text
    assert "实时工作流监控" in html
    assert "wizard-backdrop" in html
    assert "跳过向导" in html
    assert "/api/setup/run" in html
    assert "安装向导" in html
    assert "ida_setup" in html
    assert "/api/sessions/" in html
    assert "monitor/stream" in html
    assert "/api/mcp/export" in html
    assert "MCP 配置导出" in html
    assert "识别环境并生成" in html


def test_web_deps_inventory(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}
    denied = client.get("/api/deps")
    assert denied.status_code == 401
    ok = client.get("/api/deps", headers=headers)
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    assert body["claims_universal_unpack"] is False
    assert "external" in body["external_root"].replace("\\", "/")
    ids = {item["id"] for item in body["items"]}
    assert "x64dbg_headless_x64" in ids
    assert "ida_home" in ids
    ida = next(i for i in body["items"] if i["id"] == "ida_home")
    assert ida["packable"] is False
    assert ida["never_bundle"] is True
    dbg = next(i for i in body["items"] if i["id"] == "x64dbg_headless_x64")
    assert dbg["packable"] is True


def test_discover_x64dbg_headless_external(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp import config as cfg

    monkeypatch.setattr(cfg, "repo_root", lambda: tmp_path)
    target = tmp_path / "external" / "x64dbg-x64"
    target.mkdir(parents=True)
    exe = target / "headless.exe"
    exe.write_bytes(b"MZ")
    found = cfg.discover_x64dbg_headless("x64")
    assert found == exe.resolve()
    assert cfg.discover_x64dbg_headless("x86") is None


def test_web_setup_ida_writes_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp import config as cfgmod

    fake_ida = tmp_path / "IDA Professional 9.9"
    fake_ida.mkdir()
    (fake_ida / "idalib.dll").write_bytes(b"MZ")
    act = fake_ida / "idalib" / "python"
    act.mkdir(parents=True)
    (act / "py-activate-idalib.py").write_text(
        "import sys\nprint('activated')\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "user-config.json"
    monkeypatch.setattr(cfgmod, "default_config_path", lambda: config_path)

    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    status = client.get("/api/setup/status", headers=headers)
    assert status.status_code == 200
    assert status.json()["never_bundle_ida"] is True

    missing = client.post(
        "/api/setup/ida",
        headers=headers,
        json={"ida_home": str(fake_ida)},
    )
    assert missing.status_code == 400
    assert missing.json()["detail"] == "confirm_required"

    ok = client.post(
        "/api/setup/ida",
        headers=headers,
        json={"confirm": True, "ida_home": str(fake_ida), "activate": True},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    assert body["saved"] is True
    assert body["never_bundle_ida"] is True
    saved = __import__("json").loads(config_path.read_text(encoding="utf-8"))
    assert Path(saved["ida_home"]) == fake_ida.resolve()
    assert service.settings.ida_home == fake_ida.resolve()


def test_validate_ida_home_rejects_missing_idalib(tmp_path: Path) -> None:
    from headless_re_mcp.config import validate_ida_home

    empty = tmp_path / "not-ida"
    empty.mkdir()
    result = validate_ida_home(empty)
    assert result["ok"] is False
    assert result["code"] == "idalib_missing"


def test_web_setup_run_environment(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}
    denied = client.post("/api/setup/run", headers=headers, json={"step": "environment"})
    assert denied.status_code == 400
    ok = client.post(
        "/api/setup/run",
        headers=headers,
        json={"confirm": True, "step": "environment"},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["step"] == "environment"
    assert body["python"]["ok"] is True
    assert body["paths"]["repo_root"]


def test_web_setup_run_persist_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp import config as cfgmod

    config_path = tmp_path / "cfg.json"
    monkeypatch.setattr(cfgmod, "default_config_path", lambda: config_path)
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}
    ok = client.post(
        "/api/setup/run",
        headers=headers,
        json={"confirm": True, "step": "persist_defaults"},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    saved = json.loads(config_path.read_text(encoding="utf-8"))
    assert saved["http_host"] == "127.0.0.1"
    assert "artifact_root" in saved


def test_web_pick_file_returns_a_local_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.core import windows as winmod
    from headless_re_mcp.web.routes import legacy as legacy_mod

    chosen = str(tmp_path / "sample.exe")
    monkeypatch.setattr(winmod, "pick_open_file_status", lambda **_kwargs: {
        "path": chosen,
        "cancelled": False,
        "available": True,
        "busy": False,
        "error": None,
    })
    monkeypatch.setattr(legacy_mod.os, "name", "nt")
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}
    picked = client.post("/api/ui/pick-file", headers=headers)
    assert picked.status_code == 200
    body = picked.json()
    assert body["ok"] is True
    assert body["data"]["path"] == chosen
    assert body["data"]["cancelled"] is False
    assert body["data"]["available"] is True
    assert body["data"]["busy"] is False

    monkeypatch.setattr(winmod, "pick_open_file_status", lambda **_kwargs: {
        "path": None,
        "cancelled": True,
        "available": True,
        "busy": False,
        "error": None,
    })
    cancelled = client.post("/api/ui/pick-file", headers=headers)
    assert cancelled.json()["data"]["cancelled"] is True
    assert cancelled.json()["data"]["path"] is None

    monkeypatch.setattr(winmod, "pick_open_file_status", lambda **_kwargs: {
        "path": None,
        "cancelled": False,
        "available": True,
        "busy": True,
        "error": None,
    })
    busy = client.post("/api/ui/pick-file", headers=headers)
    assert busy.json()["data"]["busy"] is True
    assert busy.json()["data"]["cancelled"] is False

def test_web_mcp_export_embeds_discovered_paths(tmp_path: Path) -> None:
    headless = tmp_path / "x64" / "headless.exe"
    headless.parent.mkdir(parents=True)
    headless.write_bytes(b"MZ")
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=headless,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    denied = client.get("/api/mcp/export")
    assert denied.status_code == 401

    ok = client.get("/api/mcp/export?client=cursor", headers=headers)
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    assert body["never_bundle_ida"] is True
    cfg = body["config"]["mcpServers"]["headless-re-mcp"]
    assert cfg["env"]["HEADLESS_RE_X64DBG_HEADLESS_X64"] == str(headless.resolve())
    assert "python" in body

    bad = client.post("/api/mcp/export", headers=headers, json={})
    assert bad.status_code == 400
    assert bad.json()["detail"] == "confirm_required"

    persisted = client.post(
        "/api/mcp/export",
        headers=headers,
        json={"confirm": True, "persist": True},
    )
    assert persisted.status_code == 200
    pout = persisted.json()
    assert pout["ok"] is True
    assert pout["written"].get("cursor") or pout["written"].get("bundle")


def test_web_can_create_a_session_from_the_console(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    missing = client.post("/api/sessions", headers=headers, json={})
    assert missing.status_code == 400
    missing_file = client.post(
        "/api/sessions",
        headers=headers,
        json={"binary": str(tmp_path / "nope.exe")},
    )
    assert missing_file.status_code == 200
    assert missing_file.json()["ok"] is False

    sample = tmp_path / "tiny.exe"
    from tests.unit.test_session import _write_minimal_pe

    _write_minimal_pe(sample, 0x8664)
    created = client.post("/api/sessions", headers=headers, json={"binary": str(sample)})
    assert created.status_code == 200
    body = created.json()
    assert body["ok"] is True
    session_id = body["data"]["session"]["id"]
    listed = client.get("/api/sessions", headers=headers)
    ids = [item["id"] for item in listed.json()["data"]["sessions"]]
    assert session_id in ids
    closed = client.post(f"/api/sessions/{session_id}/close", headers=headers)
    assert closed.status_code == 200


def test_run_web_rejects_non_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp.web import app as web_app

    settings = _settings(tmp_path)
    settings_non = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="0.0.0.0",
        http_port=8765,
    )
    code = web_app.run_web(settings_non)
    assert code == 2
    _ = settings
    _ = monkeypatch


def test_the_monitor_timeline_follows_the_session_instead_of_its_first_frames(
    tmp_path: Path,
) -> None:
    """A live view has to show the live end.

    timeline.list pages from the oldest entry, which suits a caller walking the
    history. The monitor asked for offset 0 on every frame, so once a session
    had done more than `timeline_limit` things it showed the first 48 of them
    and never moved again -- at 750ms per frame, for the rest of the session.
    An operator or an agent watching that panel to decide what is happening is
    reading the start of the run as if it were the present.
    """
    from headless_re_mcp.core.store.timeline import append_session_timeline, list_session_timeline
    from headless_re_mcp.web.monitor import _timeline_tail

    path = tmp_path / "timeline.jsonl"

    class Result:
        def __init__(self, data: dict[str, object]) -> None:
            self.ok = True
            self.data = data

    class Service:
        def __init__(self) -> None:
            self.reads = 0

        def timeline_list(self, session_id: str, offset: int = 0, limit: int = 100) -> Result:
            self.reads += 1
            return Result(list_session_timeline(path, offset=offset, limit=limit))

    for step in range(1, 11):
        append_session_timeline(path, event="tool.call", message=f"step {step}")
    short = Service()
    frame = _timeline_tail(short, "s", 48).data
    assert [e["message"] for e in frame["events"]][-1] == "step 10"
    assert short.reads == 1, "a session inside the window needs only one read"

    for step in range(11, 301):
        append_session_timeline(path, event="tool.call", message=f"step {step}")
    long_running = Service()
    frame = _timeline_tail(long_running, "s", 48).data
    shown = [e["message"] for e in frame["events"]]
    assert frame["total"] == 300
    assert len(shown) == 48
    assert shown[-1] == "step 300", "the newest entry must be in the frame"
    assert shown[0] == "step 253"


def test_web_exposes_dynamic_resume_and_pause(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    app = create_app(service, token="test-token-value-0123456789abcdef", settings=settings)
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/api/sessions/{session_id}/dynamic/resume" in paths
    assert "/api/sessions/{session_id}/dynamic/pause" in paths
    resume = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/api/sessions/{session_id}/dynamic/resume"
    )
    assert "POST" in (resume.methods or set())


def test_web_sessions_survive_a_console_restart(tmp_path: Path) -> None:
    from tests.unit.test_session import _write_minimal_pe

    sample = tmp_path / "keep.exe"
    _write_minimal_pe(sample, 0x8664)
    first = AnalysisService(_settings(tmp_path))
    created = first.create_session(str(sample))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    token = "test-token-value-0123456789abcdef"
    # Simulate a process death: do not close_all on first before the next
    # service boots from the same artifact root.
    second = AnalysisService(_settings(tmp_path))
    try:
        client = TestClient(create_app(second, token=token, settings=_settings(tmp_path)))
        headers = {"Authorization": f"Bearer {token}"}
        listed = client.get("/api/sessions", headers=headers).json()
        ids = [item["id"] for item in listed["data"]["sessions"]]
        assert session_id in ids
        live = client.get(f"/api/sessions/{session_id}", headers=headers).json()
        assert live["ok"] is True
        session = live["data"]["session"]
        assert session["id"] == session_id
        assert session["state"] == "created"
        assert session["metadata"]["restored"] is True
        assert Path(session["locator"] or session["binary"]) == sample.resolve()
        known = client.get(f"/api/sessions/{session_id}/last-known", headers=headers)
        body = known.json()
        assert known.status_code == 200
        assert body["ok"] is True
        assert body["data"]["live"] is True
        assert Path(body["data"]["binary"]) == sample.resolve()
        unclean = client.get("/api/sessions/unclean", headers=headers).json()
        unclean_ids = [item["id"] for item in unclean["data"]["sessions"]]
        assert session_id in unclean_ids
    finally:
        second.close_all()
        first.close_all()


def test_web_closed_sessions_are_not_hydrated_after_restart(tmp_path: Path) -> None:
    from tests.unit.test_session import _write_minimal_pe

    sample = tmp_path / "done.exe"
    _write_minimal_pe(sample, 0x8664)
    first = AnalysisService(_settings(tmp_path))
    created = first.create_session(str(sample))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    closed = first.close_session(session_id)
    assert closed.ok
    second = AnalysisService(_settings(tmp_path))
    try:
        listed = second.list_sessions()
        assert listed.ok and listed.data is not None
        ids = [item["id"] for item in listed.data["sessions"]]
        assert session_id not in ids
        known = second.peek_session_record(session_id)
        assert known.ok and known.data is not None
        assert known.data["live"] is False
        assert known.data["state"] == "closed"
    finally:
        second.close_all()
        first.close_all()


def test_web_session_http_skips_x64dbg_and_exposes_browser_status(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}
    try:
        created = client.post(
            "/api/sessions",
            headers=headers,
            json={"binary": "https://example.com/app", "target": "web"},
        )
        body = created.json()
        assert created.status_code == 200
        assert body["ok"] is True
        assert body["data"]["session"]["target"] == "web"
        session_id = body["data"]["session"]["id"]

        monitor = client.get(f"/api/sessions/{session_id}/monitor", headers=headers).json()
        assert monitor["ok"] is True
        dynamic_error = (monitor["data"].get("dynamic") or {}).get("error") or {}
        assert "x64dbg" not in str(dynamic_error).lower()
        assert monitor["data"]["web"]["open"] is False

        status = client.get(f"/api/sessions/{session_id}/web/status", headers=headers).json()
        assert status["ok"] is True
        assert status["data"]["open"] is False
        assert status["data"]["locator"] == "https://example.com/app"
    finally:
        service.close_all()