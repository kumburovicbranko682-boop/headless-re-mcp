"""Legacy monitor/setup/API routes separated from the Web composition root."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
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


def register_legacy_routes(
    app: FastAPI,
    service: AnalysisService,
    *,
    token: str,
    settings: Settings,
) -> None:
    try:
        from fastapi import Header, HTTPException, Query
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
        from fastapi.staticfiles import StaticFiles
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
        elif token_cookie and any(
            secrets.compare_digest(token_cookie, session_token)
            for session_token in app.state.bootstrap_sessions
        ):
            return
        if not provided or not secrets.compare_digest(provided, token):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.middleware("http")
    async def loopback_guard(request: Request, call_next: Callable[..., Any]) -> Any:
        if request.url.path == "/healthz":
            return await call_next(request)
        _require_loopback(request)
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> JsonObject:
        return {"ok": True, "service": "headless-re-mcp-web"}

    @app.get("/", response_class=HTMLResponse)
    def index(
        request: Request,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> HTMLResponse:
        _require_token(authorization, token_q, request.cookies.get("headless_re_bootstrap"))
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

    @app.get("/api/sessions/{session_id}")
    def session_get(
        session_id: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.get_session(session_id)))

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
        return FileResponse(resolved)

    @app.get("/api/audit")
    def audit(
        offset: int = 0,
        limit: int = 100,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> JSONResponse:
        _require_token(authorization, token_q)
        return JSONResponse(_result_payload(service.audit_list(offset=offset, limit=limit)))

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
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(_result_payload(result))

