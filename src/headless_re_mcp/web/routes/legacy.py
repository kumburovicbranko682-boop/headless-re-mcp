"""Legacy monitor/setup/API routes separated from the Web composition root."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.readiness import build_info
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.metrics_exposition import CONTENT_TYPE as EXPOSITION_CONTENT_TYPE
from headless_re_mcp.metrics_exposition import render as render_exposition
from headless_re_mcp.platform_support import is_windows_host
from headless_re_mcp.web.auth import tokens_match
from headless_re_mcp.web.commands import WebCommandAdapter
from headless_re_mcp.web.deps import build_deps_snapshot
from headless_re_mcp.web.monitor import build_monitor_snapshot
from headless_re_mcp.web.setup import configure_ida, run_setup_step, setup_status

try:
    from starlette.requests import Request
except ImportError:  # pragma: no cover - optional web extra
    Request = Any  # type: ignore[misc,assignment]

JsonObject = dict[str, Any]
_STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
_SPA_DIR = Path(__file__).resolve().parents[1] / "spa"
_WEB_STARTED_AT = datetime.now(UTC).isoformat()
_LEGACY_MONITOR_MARKERS = (
    '<meta name="legacy-monitor-contract" content="'
    "\u5b9e\u65f6\u5de5\u4f5c\u6d41\u76d1\u63a7 wizard-backdrop "
    "\u8df3\u8fc7\u5411\u5bfc /api/setup/run \u5b89\u88c5\u5411\u5bfc ida_setup "
    "/api/sessions/ monitor/stream /api/mcp/export MCP \u914d\u7f6e\u5bfc\u51fa "
    "\u8bc6\u522b\u73af\u5883\u5e76\u751f\u6210"
    '" />'
)


def _result_payload(result: Result[Any]) -> JsonObject:
    return result.model_dump(mode="json")


def repair_encoded_token_query(query_string: bytes) -> bytes:
    """Turn ``token%3DSECRET`` back into ``token=SECRET``.

    Chat and some JSON viewers encode the ``=`` so the address bar shows
    ``?token%3D…``. Starlette then treats the whole ``token=SECRET`` as the
    parameter *name*, ``Query(alias='token')`` is empty, and ``/`` answers
    ``{"detail":"unauthorized"}``.
    """
    if not query_string or b"token%3d" not in query_string.lower():
        return query_string
    raw = query_string.decode("ascii", errors="replace")
    lower = raw.lower()
    marker = "token%3d"
    idx = lower.find(marker)
    if idx < 0:
        return query_string
    prefix = raw[:idx]
    rest = raw[idx + len(marker) :]
    amp = rest.find("&")
    secret, tail = (rest[:amp], rest[amp:]) if amp >= 0 else (rest, "")
    return f"{prefix}token={secret}{tail}".encode("ascii", errors="replace")


def register_legacy_routes(
    app: FastAPI,
    service: AnalysisService,
    *,
    token: str,
    settings: Settings,
) -> None:
    try:
        from fastapi import Header, HTTPException, Query
        from fastapi.responses import (
            FileResponse,
            HTMLResponse,
            JSONResponse,
            PlainTextResponse,
            StreamingResponse,
        )
        from fastapi.staticfiles import StaticFiles
        from starlette.datastructures import MutableHeaders
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("web extra required: pip install 'headless-re-mcp[web]'") from exc

    commands = WebCommandAdapter(service)

    def _settings() -> Settings:
        return app.state.settings  # type: ignore[no-any-return]

    def _require_loopback(request: Request) -> None:
        host = request.client.host if request.client else ""
        # Starlette TestClient reports host "testclient"; treat as loopback for unit tests.
        if host in {"testclient", "localhost"}:
            return
        try:
            addr = ipaddress.ip_address(host)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="loopback_only") from exc
        if not addr.is_loopback:
            raise HTTPException(status_code=403, detail="loopback_only")

    def _bootstrap_cookie_ok(token_cookie: str | None) -> bool:
        if not token_cookie:
            return False
        sessions: set[str] = app.state.bootstrap_sessions
        # compare_digest over bytes handles unequal lengths safely and in
        # constant time, so the earlier len() pre-check is dropped: it added
        # nothing but a length-dependent short-circuit, and on a str cookie it
        # was also the gate that let a same-length non-ASCII value reach the
        # crashing comparison.
        return any(tokens_match(token_cookie, session_token) for session_token in tuple(sessions))

    def _require_token(
        authorization: str | None,
        token_query: str | None,
        token_cookie: str | None = None,
    ) -> None:
        provided: str | None = None
        if authorization and authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        elif token_query:
            provided = token_query.strip()
        elif _bootstrap_cookie_ok(token_cookie):
            return
        if not provided or not tokens_match(provided, token):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.middleware("http")
    async def repair_token_query(request: Request, call_next: Callable[..., Any]) -> Any:
        repaired = repair_encoded_token_query(request.scope.get("query_string", b""))
        if repaired != request.scope.get("query_string", b""):
            request.scope["query_string"] = repaired
        return await call_next(request)

    @app.middleware("http")
    async def loopback_guard(request: Request, call_next: Callable[..., Any]) -> Any:
        if request.url.path == "/healthz":
            return await call_next(request)
        try:
            _require_loopback(request)
        except HTTPException as exc:
            # An HTTPException raised in middleware never reaches FastAPI's
            # handler (that wraps only the router), so without this conversion
            # an off-loopback client got a 500 internal_error and every probe
            # wrote an incident to the log, instead of the promised plain 403.
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        return await call_next(request)

    @app.middleware("http")
    async def promote_bootstrap_cookie(request: Request, call_next: Callable[..., Any]) -> Any:
        """Let the HttpOnly session cookie authenticate APIs after /?token= is stripped.

        The SPA removes the token from the visible URL so it is not copied or
        logged. Refresh then loads HTML via this cookie but used to 401 every
        /api call because those routes only accepted Bearer. Promote a valid
        bootstrap cookie to an internal Authorization header so the existing
        per-route checks keep working without sending the master token back to JS.
        """
        if request.url.path in {"/healthz", "/readyz", "/metrics"}:
            return await call_next(request)
        if _bootstrap_cookie_ok(request.cookies.get("headless_re_bootstrap")) and not request.headers.get(
            "authorization"
        ):
            headers = MutableHeaders(scope=request.scope)
            headers["authorization"] = f"Bearer {token}"
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> JsonObject:
        """Liveness only: this process is up and serving.

        Deliberately touches nothing else, so a restart loop can never be caused
        by a slow backend. Readiness is a separate question, answered by /readyz.
        """
        return {
            "ok": True,
            "service": "headless-re-mcp-web",
            "build": build_info(),
            "started_at": _WEB_STARTED_AT,
        }

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        """Readiness: 503 once the store or artifact directory stops working.

        Loopback-guarded but unauthenticated, so a local supervisor can probe it
        without being given the console token.
        """
        result = service.readiness()
        data = result.data if isinstance(result.data, dict) else {}
        ready = bool(result.ok and data.get("ready"))
        return JSONResponse(_result_payload(result), status_code=200 if ready else 503)

    @app.get("/metrics")
    def metrics_exposition() -> Any:
        """Prometheus scrape endpoint for this process.

        Unauthenticated for the same reason as /readyz, and loopback-guarded for
        the same reason as everything else.
        """
        collected = service.tool_metrics(limit=0)
        readiness = service.readiness()
        return PlainTextResponse(
            render_exposition(
                collected.data if isinstance(collected.data, dict) else {},
                build_info(),
                readiness.data if isinstance(readiness.data, dict) else None,
            ),
            media_type=EXPOSITION_CONTENT_TYPE,
        )

    @app.get("/", response_class=HTMLResponse)
    def index(
        request: Request,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> HTMLResponse:
        try:
            _require_token(authorization, token_q, request.cookies.get("headless_re_bootstrap"))
        except HTTPException as exc:
            if exc.status_code != 401:
                raise
            return HTMLResponse(
                "<!doctype html><meta charset=utf-8><title>需要访问令牌</title>"
                "<p>请用启动日志里的完整链接打开本机工作台。"
                "地址必须是 <code>?token=…</code>，不要把等号编成 <code>%3D</code>。</p>",
                status_code=401,
            )
        selected_static = _SPA_DIR if (_SPA_DIR / "index.html").is_file() else _STATIC_DIR
        index_path = selected_static / "index.html"
        html = index_path.read_text(encoding="utf-8")
        response = HTMLResponse(
            html.replace("</head>", f"{_LEGACY_MONITOR_MARKERS}</head>")
        )
        if token_q:
            bootstrap_session = secrets.token_urlsafe(32)
            sessions: set[str] = app.state.bootstrap_sessions
            if len(sessions) >= 32:
                sessions.pop()
            sessions.add(bootstrap_session)
            response.set_cookie(
                "headless_re_bootstrap",
                bootstrap_session,
                httponly=True,
                secure=False,
                samesite="strict",
                path="/",
            )
        return response

    asset_dir = _SPA_DIR / "assets" if (_SPA_DIR / "assets").is_dir() else _STATIC_DIR
    if asset_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(asset_dir)), name="assets")

    @app.get("/api/meta")
    def meta(
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JsonObject:
        _require_token(authorization, token_q)
        current = _settings()
        return {
            "ok": True,
            "host": current.http_host,
            "port": current.http_port,
            "artifact_root": str(current.artifact_root),
            "loopback_only": True,
            "write_confirm_required": True,
            "external_root": str(build_deps_snapshot(current).get("external_root")),
            "ida_home": str(current.ida_home) if current.ida_home else None,
            "claims_universal_unpack": False,
        }

    @app.get("/api/deps")
    def deps(
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """External dependency inventory (packable dbg vs never-bundle IDA)."""
        _require_token(authorization, token_q)
        return JSONResponse(build_deps_snapshot(_settings()))

    @app.get("/api/workspace/mode")
    def workspace_mode_get(
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Return the active startup work direction (full/pe/android/web)."""
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.workspace_mode_get()))

    @app.post("/api/workspace/mode")
    def workspace_mode_set(
        body: JsonObject,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Set the startup work direction; persists and mutates the live settings."""
        _require_token(authorization, token_q)
        profile = body.get("profile")
        if not isinstance(profile, str) or not profile.strip():
            raise HTTPException(status_code=400, detail="profile_required")
        result = service.workspace_mode_set(profile.strip())
        # workspace_mode_set mutates the shared Settings in place; keep the web
        # app's view pointed at the same object so /api/meta reflects it too.
        app.state.settings = service.settings
        return JSONResponse(_result_payload(result))

    @app.get("/api/mcp/export")
    def mcp_export_get(
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
        client: str = Query(default="all"),
    ) -> JSONResponse:
        """Discover local backends and return MCP JSON matching this machine."""
        _require_token(authorization, token_q)
        from headless_re_mcp.config_generate import (
            export_mcp_environment,
            merge_live_settings,
        )

        merged = merge_live_settings(_settings())
        export = export_mcp_environment(merged, persist=False, refresh_discovery=False)
        app.state.settings = merged
        service.settings = merged
        allowed = {"all", "cursor", "vscode", "claude", "claude_desktop", "stdio"}
        kind = (client or "all").strip().lower()
        if kind not in allowed:
            raise HTTPException(status_code=400, detail="unknown_client")
        if kind == "claude":
            kind = "claude_desktop"
        payload: JsonObject = {
            "ok": export.get("ok"),
            "python": export.get("python"),
            "config_path": export.get("config_path"),
            "repo_root": export.get("repo_root"),
            "package_importable": export.get("package_importable"),
            "env_inventory": export.get("env_inventory"),
            "embedded_env_keys": export.get("embedded_env_keys"),
            "doctor": export.get("doctor"),
            "doctor_ready": export.get("doctor_ready"),
            "notes": export.get("notes"),
            "never_bundle_ida": True,
            "claims_universal_unpack": False,
        }
        if kind == "all":
            payload["stdio"] = export.get("stdio")
            payload["examples"] = export.get("examples")
        elif kind == "stdio":
            payload["stdio"] = export.get("stdio")
            payload["config"] = export.get("stdio")
        else:
            examples = export.get("examples") or {}
            snippet = examples.get(kind) if isinstance(examples, dict) else None
            payload["client"] = kind
            payload["config"] = snippet
            payload["examples"] = {kind: snippet} if snippet is not None else {}
        return JSONResponse(payload)

    @app.post("/api/mcp/export")
    def mcp_export_post(
        body: JsonObject,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Re-discover environment and optionally persist MCP JSON under config dir."""
        _require_token(authorization, token_q)
        if body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail="confirm_required")
        from headless_re_mcp.config_generate import (
            export_mcp_environment,
            merge_live_settings,
        )

        persist = body.get("persist", True) is not False
        merged = merge_live_settings(_settings())
        export = export_mcp_environment(merged, persist=persist, refresh_discovery=False)
        app.state.settings = merged
        service.settings = merged
        return JSONResponse({**export, "persisted": persist})

    @app.get("/api/setup/status")
    def setup_status_api(
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(setup_status(_settings()))

    @app.post("/api/setup/ida")
    def setup_ida_api(
        body: JsonObject,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Wizard: save IDA path to config.json and optionally activate idalib."""
        _require_token(authorization, token_q)
        if body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail="confirm_required")
        ida_home = body.get("ida_home")
        if not isinstance(ida_home, str) or not ida_home.strip():
            raise HTTPException(status_code=400, detail="ida_home_required")
        activate = body.get("activate", True) is not False
        result = configure_ida(ida_home=ida_home.strip(), activate=activate)
        if result.get("ok") and result.get("saved"):
            from dataclasses import replace

            new_settings = replace(_settings(), ida_home=Path(str(result["ida_home"])))
            app.state.settings = new_settings
            service.settings = new_settings
        return JSONResponse(result)

    @app.post("/api/setup/run")
    def setup_run_api(
        body: JsonObject,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Run one install-wizard step (environment / sync / doctor / mcp / …)."""
        _require_token(authorization, token_q)
        if body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail="confirm_required")
        step = body.get("step")
        if not isinstance(step, str) or not step.strip():
            raise HTTPException(status_code=400, detail="step_required")
        ida_home = body.get("ida_home")
        ida_arg = ida_home.strip() if isinstance(ida_home, str) and ida_home.strip() else None
        activate = body.get("activate", True) is not False
        result = run_setup_step(
            _settings(),
            step.strip(),
            ida_home=ida_arg,
            activate=activate,
        )
        # Hot-reload settings after steps that rewrite config.json.
        if (
            step.strip() in {"configure_ida", "persist_defaults", "sync_x64dbg"}
            and result.get("ok")
        ):
            reloaded = Settings.load()
            if result.get("ida_home"):
                from dataclasses import replace

                reloaded = replace(reloaded, ida_home=Path(str(result["ida_home"])))
            app.state.settings = reloaded
            service.settings = reloaded
            result = {**result, "settings_reloaded": True}
        return JSONResponse(result)

    @app.get("/api/sessions")
    def sessions(
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.list_sessions()))

    @app.get("/api/sessions/unclean")
    def sessions_unclean(
        offset: int = 0,
        limit: int = 20,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Sample paths left behind when this process died, newest first."""
        _require_token(authorization, token_q)
        cap = max(1, min(int(limit), 100))
        start = max(0, int(offset))
        return JSONResponse(_result_payload(service.sessions_unclean(offset=start, limit=cap)))

    @app.post("/api/sessions")
    def sessions_create(
        body: JsonObject,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        binary = body.get("binary")
        if not isinstance(binary, str) or not binary.strip():
            raise HTTPException(status_code=400, detail="binary_required")
        target = body.get("target")
        kind = target.strip() if isinstance(target, str) and target.strip() else None
        result = service.create_session(binary.strip(), kind)
        return JSONResponse(_result_payload(result))

    @app.post("/api/ui/pick-file")
    def pick_file(
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Native open-file dialog on this machine (loopback console only)."""
        _require_token(authorization, token_q)
        from headless_re_mcp.core.windows import pick_open_file_status

        if not is_windows_host():
            return JSONResponse(
                {
                    "ok": True,
                    "data": {
                        "path": None,
                        "cancelled": False,
                        "available": False,
                        "busy": False,
                    },
                }
            )
        picked = pick_open_file_status()
        path = picked.get("path") if isinstance(picked, dict) else None
        return JSONResponse(
            {
                "ok": True,
                "data": {
                    "path": path if isinstance(path, str) and path.strip() else None,
                    "cancelled": bool(picked.get("cancelled")) if isinstance(picked, dict) else False,
                    "available": bool(picked.get("available", True)) if isinstance(picked, dict) else True,
                    "busy": bool(picked.get("busy")) if isinstance(picked, dict) else False,
                    "error": picked.get("error") if isinstance(picked, dict) else None,
                },
            }
        )

    @app.post("/api/sessions/{session_id}/static/open")
    def session_open_static(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.open_static(session_id)))

    @app.post("/api/sessions/{session_id}/dynamic/open")
    def session_open_dynamic(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.open_dynamic(session_id)))

    @app.post("/api/sessions/{session_id}/dynamic/resume")
    def session_dynamic_resume(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.dynamic_resume(session_id)))

    @app.post("/api/sessions/{session_id}/dynamic/pause")
    def session_dynamic_pause(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.dynamic_pause(session_id)))

    @app.post("/api/sessions/{session_id}/close")
    def session_close(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.close_session(session_id)))

    def _body_text(body: JsonObject | None, key: str) -> str:
        if not isinstance(body, dict):
            return ""
        value = body.get(key)
        return value.strip() if isinstance(value, str) else ""

    @app.post("/api/sessions/{session_id}/web/open")
    def session_web_open(
        session_id: str,
        body: JsonObject | None = None,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        headless = True if not isinstance(body, dict) or "headless" not in body else bool(body.get("headless"))
        return JSONResponse(
            _result_payload(service.web_open(session_id, url=_body_text(body, "url"), headless=headless))
        )

    @app.post("/api/sessions/{session_id}/web/navigate")
    def session_web_navigate(
        session_id: str,
        body: JsonObject | None = None,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        url = _body_text(body, "url")
        if not url:
            raise HTTPException(status_code=400, detail="url_required")
        return JSONResponse(_result_payload(service.web_navigate(session_id, url)))

    @app.post("/api/sessions/{session_id}/web/close")
    def session_web_close(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.web_close(session_id)))

    @app.get("/api/sessions/{session_id}/web/status")
    def session_web_status(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.web_status(session_id)))

    @app.get("/api/sessions/{session_id}/web/network")
    def session_web_network(
        session_id: str,
        offset: int = 0,
        limit: int = 40,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(service.web_network_list(session_id, offset=offset, limit=limit))
        )

    @app.get("/api/sessions/{session_id}/web/console")
    def session_web_console(
        session_id: str,
        limit: int = 40,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.web_console(session_id, limit=limit)))

    @app.get("/api/sessions/{session_id}/web/scripts")
    def session_web_scripts(
        session_id: str,
        offset: int = 0,
        limit: int = 40,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(service.web_scripts(session_id, offset=offset, limit=limit))
        )

    @app.get("/api/sessions/{session_id}/web/preview")
    def session_web_preview(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> Any:
        """Capture the current page to a stable PNG for the inspector."""
        _require_token(authorization, token_q)
        captured = service.web_preview(session_id)
        if not captured.ok or captured.data is None:
            error = captured.error.model_dump(mode="json") if captured.error else None
            return JSONResponse({"ok": False, "error": error}, status_code=409)
        path_value = captured.data.get("path")
        if not isinstance(path_value, str):
            raise HTTPException(status_code=500, detail="preview_path_missing")
        path = Path(path_value).resolve()
        artifact_root = service.settings.artifact_root.expanduser().resolve()
        if not path.is_file() or not path.is_relative_to(artifact_root):
            raise HTTPException(status_code=404, detail="preview_not_found")
        return FileResponse(
            path,
            media_type="image/png",
            filename=f"web-{session_id}.png",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.post("/api/sessions/{session_id}/apk/open")
    def session_apk_open(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.apk_open(session_id)))

    @app.get("/api/sessions/{session_id}")
    def session_get(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.get_session(session_id)))

    @app.get("/api/sessions/{session_id}/last-known")
    def session_last_known(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Live session, or the stored binary path after a console restart."""
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.peek_session_record(session_id)))

    @app.get("/api/sessions/{session_id}/static/functions")
    def static_functions(
        session_id: str,
        offset: int = 0,
        limit: int = 50,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(service.static_functions(session_id, offset=offset, limit=limit))
        )

    @app.get("/api/sessions/{session_id}/static/strings")
    def static_strings(
        session_id: str,
        offset: int = 0,
        limit: int = 50,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(service.static_strings(session_id, offset=offset, limit=limit))
        )

    @app.get("/api/sessions/{session_id}/static/decompile")
    def static_decompile(
        session_id: str,
        address: int,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(service.static_decompile(session_id, address=address))
        )

    @app.get("/api/sessions/{session_id}/dynamic/state")
    def dynamic_state(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.dynamic_state(session_id)))

    @app.get("/api/sessions/{session_id}/dynamic/registers")
    def dynamic_registers(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.dynamic_registers_read(session_id)))

    @app.get("/api/sessions/{session_id}/modules")
    def modules(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.dynamic_modules(session_id)))

    @app.get("/api/sessions/{session_id}/breakpoints")
    def breakpoints(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.dynamic_breakpoints(session_id)))

    @app.get("/api/sessions/{session_id}/workflow")
    def workflow(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.workflow_status(session_id)))

    @app.get("/api/sessions/{session_id}/monitor")
    def monitor(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
        timeline_limit: int = Query(default=48, ge=1, le=200),
        events_limit: int = Query(default=24, ge=1, le=100),
    ) -> JSONResponse:
        """One-shot aggregated workflow monitor snapshot."""
        _require_token(authorization, token_q)
        payload = build_monitor_snapshot(
            service,
            session_id,
            timeline_limit=timeline_limit,
            events_limit=events_limit,
        )
        return JSONResponse({"ok": bool(payload.get("ok")), "data": payload})

    @app.get("/api/sessions/{session_id}/monitor/stream")
    async def monitor_stream(
        request: Request,
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
        interval_ms: int = Query(default=750, ge=250, le=5000),
        timeline_limit: int = Query(default=48, ge=1, le=200),
        events_limit: int = Query(default=24, ge=1, le=100),
        max_frames: int = Query(default=800, ge=1, le=2000),
    ) -> StreamingResponse:
        """SSE live monitor feed (loopback + token)."""
        _require_token(authorization, token_q)

        async def event_gen() -> AsyncIterator[bytes]:
            # Bound stream lifetime so clients reconnect cleanly.
            # Snapshot build is sync/blocking — run off the event loop.
            for index in range(max_frames):
                if await request.is_disconnected():
                    break
                payload = await asyncio.to_thread(
                    build_monitor_snapshot,
                    service,
                    session_id,
                    timeline_limit=timeline_limit,
                    events_limit=events_limit,
                )
                frame = json.dumps(
                    {"ok": bool(payload.get("ok")), "data": payload},
                    ensure_ascii=False,
                    default=str,
                )
                yield f"event: monitor\ndata: {frame}\n\n".encode()
                if index + 1 >= max_frames:
                    break
                await asyncio.sleep(float(interval_ms) / 1000.0)
            yield b"event: end\ndata: {\"ok\": true}\n\n"

        return StreamingResponse(
            event_gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/sessions/{session_id}/virtual-desktop")
    def virtual_desktop(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Passive hidden-desktop window inventory; never switches desktops."""
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.virtual_desktop_snapshot(session_id)))

    @app.get("/api/sessions/{session_id}/virtual-desktop/frame")
    def virtual_desktop_frame(
        session_id: str,
        hwnd: int | None = Query(default=None, gt=0),
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> Any:
        """Capture one target-owned window on demand without changing input desktop."""
        _require_token(authorization, token_q)
        captured = service.virtual_desktop_capture(session_id, hwnd=hwnd)
        if not captured.ok or captured.data is None:
            error = captured.error.model_dump(mode="json") if captured.error else None
            return JSONResponse(
                {"ok": False, "error": error},
                status_code=409,
            )
        path_value = captured.data.get("path") or captured.data.get("artifact")
        if not isinstance(path_value, str):
            raise HTTPException(status_code=500, detail="capture_path_missing")
        path = Path(path_value).resolve()
        artifact_root = service.settings.artifact_root.expanduser().resolve()
        if not path.is_file() or not path.is_relative_to(artifact_root):
            raise HTTPException(status_code=404, detail="capture_not_found")
        degraded = bool(captured.data.get("degraded"))
        frame_headers = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Capture-Degraded": "1" if degraded else "0",
            "X-Capture-Backend": str(captured.data.get("backend") or ""),
        }
        degraded_reason = captured.data.get("degraded_reason")
        if isinstance(degraded_reason, str) and degraded_reason:
            frame_headers["X-Capture-Degraded-Reason"] = degraded_reason
        return FileResponse(
            path,
            media_type="image/bmp",
            filename=f"desktop-{session_id}-{captured.data.get('hwnd')}.bmp",
            headers=frame_headers,
        )

    @app.get("/api/sessions/{session_id}/knowledge")
    def session_knowledge(
        session_id: str,
        kind: str | None = Query(default=None),
        limit: int = Query(default=200, ge=1, le=500),
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Accumulated analysis findings for one session, optionally one kind."""
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(
                service.knowledge_query(session_id, kind=kind, limit=limit)
            )
        )

    @app.post("/api/sessions/{session_id}/report")
    def session_report(
        session_id: str,
        body: JsonObject | None = None,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Render a Markdown analysis report and persist it as an artifact."""
        _require_token(authorization, token_q)
        title = (body or {}).get("title")
        return JSONResponse(
            _result_payload(
                service.report_generate(
                    session_id,
                    title=str(title) if isinstance(title, str) and title.strip() else None,
                )
            )
        )

    @app.get("/api/metrics")
    def tool_metrics(
        limit: int = Query(default=20, ge=0, le=200),
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        """Per-tool call counts, failures and latency percentiles for this process."""
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.tool_metrics(limit=limit)))

    @app.get("/api/sessions/{session_id}/timeline")
    def timeline(
        session_id: str,
        offset: int = 0,
        limit: int = 100,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(service.timeline_list(session_id, offset=offset, limit=limit))
        )

    @app.get("/api/sessions/{session_id}/unpack")
    def unpack_status(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.unpack_status(session_id)))

    @app.get("/api/sessions/{session_id}/unpack/artifacts")
    def unpack_artifacts(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.unpack_artifacts(session_id)))

    @app.get("/api/artifacts")
    def artifacts(
        session_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(
                service.artifacts_list(session_id=session_id, offset=offset, limit=limit)
            )
        )

    @app.get("/api/artifacts/{artifact_id}/file")
    def artifact_file(
        artifact_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> FileResponse:
        _require_token(authorization, token_q)
        described = service.artifacts_describe(artifact_id)
        if not described.ok or described.data is None:
            raise HTTPException(status_code=404, detail="artifact_not_found")
        artifact = described.data.get("artifact")
        path_value = artifact.get("path") if isinstance(artifact, dict) else None
        if not isinstance(path_value, str):
            raise HTTPException(status_code=404, detail="artifact_path_missing")
        path = Path(path_value)
        root = _settings().artifact_root.resolve()
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=403, detail="artifact_outside_root") from exc
        if not resolved.is_file():
            raise HTTPException(status_code=404, detail="artifact_missing")
        # Artifact bytes are hostile by definition in this console: script
        # sources and response bodies captured from a malicious page, files
        # pulled out of a malicious APK, deobfuscated malware. A bare
        # FileResponse guesses the media type from the extension and sets no
        # disposition, so the legacy UI's <a href> download link *navigated*
        # into the bytes -- and the first artifact kind to carry a renderable
        # type (an HTML report, an exported .html asset) would execute in the
        # console's authenticated origin, with the bearer token sitting in its
        # own query string. Serve every artifact as an opaque download instead:
        # the fixed octet-stream type plus nosniff means no browser renders or
        # executes it, and the attachment disposition (via filename=) matches
        # what the download links want anyway. The SPA fetches into a blob and
        # ignores all three headers, so nothing inline breaks.
        return FileResponse(
            resolved,
            media_type="application/octet-stream",
            filename=resolved.name,
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/api/audit")
    def audit(
        session_id: str | None = None,
        offset: int = 0,
        limit: int = 100,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(
            _result_payload(
                service.audit_list(session_id=session_id, offset=offset, limit=limit)
            )
        )

    @app.post("/api/write/{action}")
    def write_action(
        action: str,
        body: JsonObject,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        if action not in commands.write_methods:
            raise HTTPException(status_code=400, detail="unknown_or_disallowed_write")
        if body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail="confirm_required")
        try:
            result = commands.invoke_write(action, body)
        except KeyError as exc:
            raise HTTPException(
                status_code=400,
                detail="unknown_or_disallowed_write",
            ) from exc
        except PermissionError:
            # A read-only deployment refusing a write is policy, not a defect.
            # Uncaught, this fell through to the generic exception boundary and
            # came back as a 500 internal_error with a logged incident; return
            # the same write_disabled envelope the MCP transport uses instead.
            return JSONResponse(commands.write_refusal(action), status_code=403)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(_result_payload(result))

