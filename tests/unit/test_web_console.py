from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import httpx
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


def test_the_spa_fallback_serves_deep_links_but_never_api_paths(tmp_path: Path) -> None:
    """The catch-all route must behave like a router, not a wildcard.

    Refreshing a client-side deep link (/threads/x) must return the SPA shell,
    or every bookmark 404s. But the same catch-all sits behind the API routers,
    so an *unknown* /api/... path falls through to it -- if it answered with
    HTML, an API client with a typo would try to parse the console page as
    JSON. Pin both halves, plus 401 for an unauthenticated deep link and 404
    for a missing asset (a stale asset hash must fail, not load HTML as JS).
    """
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/threads/some-thread-id").status_code == 401

    deep_link = client.get("/threads/some-thread-id", headers=headers)
    assert deep_link.status_code == 200
    assert '<div id="root"></div>' in deep_link.text

    for path in ("/api/no/such/route", "/assets/stale-build-hash.js"):
        fell_through = client.get(path, headers=headers)
        assert fell_through.status_code == 404, path
        assert "root" not in fell_through.text, path


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


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (b"", b""),
        (b"foo=bar", b"foo=bar"),
        (b"token=already-plain", b"token=already-plain"),
        (b"token%3Dsecret", b"token=secret"),
        (b"TOKEN%3Dsecret", b"token=secret"),
        (b"token%3dsecret", b"token=secret"),
        (b"token%3Dsecret&next=/x", b"token=secret&next=/x"),
        (b"foo=bar&token%3Dsecret", b"foo=bar&token=secret"),
    ],
)
def test_repair_encoded_token_query_covers_position_case_and_passthrough(
    query: bytes, expected: bytes
) -> None:
    """The console falls over if ?token%3D... is not repaired before routing.

    Chat clients percent-encode the ``=`` and Starlette then reads the whole
    thing as a parameter name, so the bearer never arrives and every open 401s.
    Cover the shapes that actually occur -- no marker (untouched), the marker
    mid-query, a trailing parameter that must survive, and upper/lower case.
    """
    from headless_re_mcp.web.routes.legacy import repair_encoded_token_query

    assert repair_encoded_token_query(query) == expected


def test_a_wrong_token_is_rejected_like_a_missing_one(tmp_path: Path) -> None:
    """Presenting the wrong secret must not fare better than presenting none."""
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))

    wrong_bearer = client.get(
        "/api/sessions", headers={"Authorization": "Bearer " + token[:-1] + "X"}
    )
    assert wrong_bearer.status_code == 401
    wrong_query = client.get("/?token=" + token[:-1] + "X")
    assert wrong_query.status_code == 401
    # And the failed attempts must not have minted a bootstrap cookie.
    assert client.get("/api/sessions").status_code == 401


def test_a_forged_bootstrap_cookie_does_not_authenticate(tmp_path: Path) -> None:
    """The cookie shortcut only accepts values the server actually issued.

    A valid ?token= mints an HttpOnly bootstrap cookie that later /api calls
    ride, so a client-supplied cookie value that was never issued must be
    ignored rather than promoted to an Authorization header.
    """
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))

    client.cookies.set("headless_re_bootstrap", "forged-cookie-value-0123456789")
    assert client.get("/api/sessions").status_code == 401


def _get_off_loopback(
    app: object, client_addr: tuple[str, int], path: str, headers: dict[str, str] | None = None
) -> httpx.Response:
    """GET as a specific client address; TestClient cannot spoof one."""

    async def call() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, client=client_addr)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="http://console") as client:
            return await client.get(path, headers=headers)

    return asyncio.run(call())


def test_non_loopback_clients_are_refused_even_with_the_right_token(tmp_path: Path) -> None:
    """The console promises loopback-only; a stolen token must not undo that.

    SECURITY.md counts "listening beyond loopback" as a vulnerability. The bind
    address enforces most of it, but the middleware is the guard that holds when
    the port gets forwarded -- so it must refuse a public source address even
    when the request carries the correct bearer token.
    """
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    app = create_app(service, token=token, settings=settings)
    public = ("203.0.113.9", 40000)
    bearer = {"Authorization": f"Bearer {token}"}

    for path in ("/api/sessions", "/", "/readyz"):
        refused = _get_off_loopback(app, public, path, headers=bearer)
        assert refused.status_code == 403, f"{path} answered off-loopback"
        assert refused.json()["detail"] == "loopback_only"


def test_healthz_is_the_only_route_reachable_off_loopback(tmp_path: Path) -> None:
    """Liveness stays probeable, and it must not hand out anything secret."""
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    app = create_app(service, token=token, settings=settings)

    alive = _get_off_loopback(app, ("203.0.113.9", 40000), "/healthz")

    assert alive.status_code == 200
    assert alive.json()["ok"] is True
    assert token not in alive.text


def test_ipv6_loopback_passes_the_host_guard(tmp_path: Path) -> None:
    """::1 is loopback too; it must hit the token check (401), not the host 403."""
    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    app = create_app(service, token=token, settings=settings)

    refused = _get_off_loopback(app, ("::1", 40000), "/api/sessions")
    assert refused.status_code == 401

    ok = _get_off_loopback(
        app, ("::1", 40000), "/api/sessions", headers={"Authorization": f"Bearer {token}"}
    )
    assert ok.status_code == 200


def test_artifact_download_never_serves_a_file_outside_the_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SECURITY.md counts path escape as a vulnerability; this route is the guard.

    ``artifacts_describe`` answers straight from the store, so a tampered or
    migrated DB row can point anywhere on disk. Whatever the row says, the
    download route must refuse anything that resolves outside the configured
    artifact root -- including a root-prefixed path that climbs back out.
    """
    from headless_re_mcp.core.models import Result

    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    loot = tmp_path / "outside" / "loot.txt"
    loot.parent.mkdir(parents=True)
    loot.write_text("keep out", encoding="utf-8")
    escapes = [
        str(loot),
        str(settings.artifact_root / ".." / "outside" / "loot.txt"),
    ]

    for escape in escapes:
        monkeypatch.setattr(
            AnalysisService,
            "artifacts_describe",
            lambda self, artifact_id, _path=escape: Result(
                ok=True, data={"artifact": {"id": artifact_id, "path": _path}}
            ),
        )
        refused = client.get("/api/artifacts/any/file", headers=headers)
        assert refused.status_code == 403, f"served {escape}"
        assert refused.json()["detail"] == "artifact_outside_root"


def test_artifact_download_serves_only_real_files_under_the_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.core.models import Result

    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    # An unknown id is a 404 through the real service, not an error page.
    unknown = client.get("/api/artifacts/does-not-exist/file", headers=headers)
    assert unknown.status_code == 404
    assert unknown.json()["detail"] == "artifact_not_found"

    inside = settings.artifact_root / "dump.bin"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_bytes(b"artifact bytes")

    def describe(self: AnalysisService, artifact_id: str) -> Result:
        return Result(ok=True, data={"artifact": {"id": artifact_id, "path": str(inside)}})

    monkeypatch.setattr(AnalysisService, "artifacts_describe", describe)
    served = client.get("/api/artifacts/dump/file", headers=headers)
    assert served.status_code == 200
    assert served.content == b"artifact bytes"

    # A row whose file is gone is a clean 404, not a traceback.
    inside.unlink()
    missing = client.get("/api/artifacts/dump/file", headers=headers)
    assert missing.status_code == 404
    assert missing.json()["detail"] == "artifact_missing"


def test_web_preview_refuses_a_path_outside_the_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The preview PNG route serves a file off disk, so it guards the root too."""
    from headless_re_mcp.core.models import Result, RpcError

    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    outside = tmp_path / "outside" / "leak.png"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"\x89PNG\r\n\x1a\n")
    monkeypatch.setattr(
        AnalysisService,
        "web_preview",
        lambda self, sid: Result(ok=True, data={"path": str(outside)}),
    )
    refused = client.get("/api/sessions/s1/web/preview", headers=headers)
    assert refused.status_code == 404
    assert refused.json()["detail"] == "preview_not_found"

    inside = settings.artifact_root / "web" / "s1" / "preview.png"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_bytes(b"\x89PNG\r\n\x1a\nreal")
    monkeypatch.setattr(
        AnalysisService,
        "web_preview",
        lambda self, sid: Result(ok=True, data={"path": str(inside)}),
    )
    served = client.get("/api/sessions/s1/web/preview", headers=headers)
    assert served.status_code == 200
    assert served.headers["content-type"] == "image/png"
    assert served.content == b"\x89PNG\r\n\x1a\nreal"

    monkeypatch.setattr(
        AnalysisService,
        "web_preview",
        lambda self, sid: Result(ok=False, error=RpcError(code="no_preview", message="none")),
    )
    failed = client.get("/api/sessions/s1/web/preview", headers=headers)
    assert failed.status_code == 409


def test_virtual_desktop_frame_refuses_a_path_outside_the_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.core.models import Result

    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    outside = tmp_path / "outside" / "frame.bmp"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"BMx")
    monkeypatch.setattr(
        AnalysisService,
        "virtual_desktop_capture",
        lambda self, sid, hwnd=None: Result(ok=True, data={"path": str(outside)}),
    )
    refused = client.get("/api/sessions/s1/virtual-desktop/frame", headers=headers)
    assert refused.status_code == 404
    assert refused.json()["detail"] == "capture_not_found"

    inside = settings.artifact_root / "ui" / "s1" / "frame.bmp"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_bytes(b"BMreal")
    monkeypatch.setattr(
        AnalysisService,
        "virtual_desktop_capture",
        lambda self, sid, hwnd=None: Result(ok=True, data={"artifact": str(inside)}),
    )
    served = client.get("/api/sessions/s1/virtual-desktop/frame", headers=headers)
    assert served.status_code == 200
    assert served.content == b"BMreal"


def test_a_weak_token_file_is_replaced_with_a_strong_private_one(tmp_path: Path) -> None:
    """A truncated or tampered token file must not become the accepted secret."""
    path = tmp_path / "web_token.json"
    path.write_text(json.dumps({"token": "short"}), encoding="utf-8")

    token = load_or_create_web_token(path=path)

    assert token != "short"
    assert len(token) >= 24
    assert json.loads(path.read_text(encoding="utf-8"))["token"] == token
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "damaged",
    [
        pytest.param('{"token": "test-token-value-0123456789', id="truncated-json"),
        pytest.param("not json at all", id="garbage"),
        pytest.param('"a-bare-string-not-an-object"', id="non-dict-json"),
        pytest.param("[1, 2, 3]", id="list-json"),
    ],
)
def test_a_corrupt_token_file_regenerates_instead_of_crashing(
    tmp_path: Path, damaged: str
) -> None:
    """A half-written token file must not make the console unbootable.

    write_text is not atomic, so a crash mid-write leaves truncated JSON; the
    loader used to feed that straight to json.loads (or call .get on a
    non-dict) and raise, and the console then failed at startup until someone
    deleted the file by hand. config.json already treats corruption as
    replace-not-fatal; the token file must match, and regenerating is safe
    because this is the server's own credential.
    """
    path = tmp_path / "web_token.json"
    path.write_text(damaged, encoding="utf-8")

    token = load_or_create_web_token(path=path)

    assert len(token) >= 24
    assert json.loads(path.read_text(encoding="utf-8"))["token"] == token
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


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


def test_a_read_only_deployment_refuses_web_writes(tmp_path: Path) -> None:
    """local_full_access=false must make /api/write answer 403, not 500.

    The Web adapter bypasses the per-handler write_disabled guard and leans on
    the catalog's write_allowed flag, which bind_all_tools (run inside
    create_app via agent route registration) sets from local_full_access -- so
    the write was refused, but as an unhandled PermissionError the route turned
    into a 500 instead of the promised 403 write_disabled.
    """
    from dataclasses import replace

    settings = replace(_settings(tmp_path), local_full_access=False)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    refused = client.post(
        "/api/write/artifacts.gc",
        headers=headers,
        json={"confirm": True, "max_total_bytes": 1024},
    )
    assert refused.status_code == 403
    assert refused.json()["detail"] == "write_disabled"

    # The whitelist and confirm gate still apply and answer before the adapter.
    unknown = client.post(
        "/api/write/not.a.real.write", headers=headers, json={"confirm": True}
    )
    assert unknown.status_code == 400
    assert unknown.json()["detail"] == "unknown_or_disallowed_write"


def test_the_web_write_surface_is_self_consistent() -> None:
    """/api/write depends on confirm_required == spec.write on the WEB transport.

    The route whitelists actions by write_names() (confirm_required WEB tools),
    while invoke_write independently requires spec.write and WEB transport. If a
    WEB tool were confirm_required but not a write, the route would accept it and
    invoke_write would 400 it; if it were a write but not confirm_required, the
    write would never be reachable through the console. Pin them equal.
    """
    from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandTransport

    web = list(COMMAND_CATALOG.for_transport(CommandTransport.WEB))
    confirm = {spec.name for spec in web if spec.confirm_required}
    write = {spec.name for spec in web if spec.write}
    assert confirm == write, {
        "confirm_but_not_write": sorted(confirm - write),
        "write_but_not_confirm": sorted(write - confirm),
    }


def test_full_access_deployment_still_allows_web_writes(tmp_path: Path) -> None:
    """The default (local_full_access=true) path must be unchanged by the guard."""
    from dataclasses import replace

    settings = replace(_settings(tmp_path), local_full_access=True)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    client = TestClient(create_app(service, token=token, settings=settings))
    headers = {"Authorization": f"Bearer {token}"}

    ok = client.post(
        "/api/write/artifacts.gc",
        headers=headers,
        json={"confirm": True, "max_total_bytes": 1024},
    )
    assert ok.status_code == 200
    assert ok.json()["ok"] is True


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


def test_every_route_refuses_an_unauthenticated_request_except_the_probe_trio(
    tmp_path: Path,
) -> None:
    """Auth is enforced per-route by hand, so one forgotten call is an open door.

    _require_token/authorize appear at 50+ call sites rather than as a global
    dependency; nothing structural stops a new route from shipping without one.
    Walk every registered route unauthenticated (from loopback) and require 401,
    pinning the deliberate exceptions -- /healthz (liveness), /readyz and
    /metrics (supervisor probes, unauthenticated by design so an operator does
    not have to hand the console token to a supervisor) -- and that none of the
    three leaks the token.
    """
    import re

    from fastapi.routing import APIRoute

    settings = _settings(tmp_path)
    service = AnalysisService(settings)
    token = "test-token-value-0123456789abcdef"
    app = create_app(service, token=token, settings=settings)
    client = TestClient(app, raise_server_exceptions=False)

    unauthenticated_by_design = {"/healthz", "/readyz", "/metrics"}
    checked = 0
    offenders: list[tuple[str, str, int]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path in unauthenticated_by_design:
            continue
        path = re.sub(r"\{[^}]+\}", "x", route.path)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            response = client.request(method, path, json={})
            if response.status_code == 422:
                # A required query param fails validation before the handler
                # (and its auth check) runs; fill the params and ask again so
                # the verdict is about authentication, not about the schema.
                missing = {
                    item["loc"][1]: "0"
                    for item in response.json()["detail"]
                    if item.get("type") == "missing" and item["loc"][0] == "query"
                }
                response = client.request(method, path, json={}, params=missing)
            checked += 1
            if response.status_code != 401:
                offenders.append((method, route.path, response.status_code))
    assert checked >= 80, f"route walk looks broken, only checked {checked}"
    assert not offenders, f"routes answering without a token: {offenders}"

    # The three deliberate exceptions serve, and none of them leaks the token.
    for path in sorted(unauthenticated_by_design):
        response = client.get(path)
        assert response.status_code == 200, path
        assert token not in response.text, path


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