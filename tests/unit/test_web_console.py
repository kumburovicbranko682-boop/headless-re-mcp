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
