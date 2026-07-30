"""Agent, provider and replayable SSE routes."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from headless_re_mcp.agent import (
    AgentOrchestrator,
    AgentStore,
    ProviderConfigStore,
    ProviderProfile,
)
from headless_re_mcp.agent.models import TERMINAL_RUN_STATUSES
from headless_re_mcp.agent.providers import OpenAICompatibleProvider
from headless_re_mcp.config import Settings, default_config_path
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandCatalog

JsonObject = dict[str, Any]


def register_agent_routes(
    app: FastAPI,
    service: AnalysisService,
    *,
    token: str,
    settings: Settings,
    catalog: CommandCatalog = COMMAND_CATALOG,
) -> None:
    from fastapi import Header, HTTPException, Query
    from fastapi.responses import JSONResponse, StreamingResponse

    # Bind handlers and schemas directly from protocol-independent tool domains.
    bind_all_tools(service, catalog)
    store = AgentStore(settings.artifact_root / "meta" / "agent.db")
    configured_path = os.environ.get("HEADLESS_RE_PROVIDER_CONFIG")
    config_path = (
        Path(configured_path)
        if configured_path
        else default_config_path().parent / "providers.json"
    )
    configs = ProviderConfigStore(config_path)
    orchestrator = AgentOrchestrator(store, catalog, configs)
    app.state.agent_store = store
    app.state.provider_configs = configs
    app.state.agent_orchestrator = orchestrator
    app.state.tool_catalog = catalog

    def authorize(authorization: str | None) -> None:
        provided = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else None
        if not provided or not secrets.compare_digest(provided, token):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/api/agent/threads")
    def list_threads(authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        return JSONResponse({"ok": True, "threads": [item.dump() for item in store.list_threads()]})

    @app.post("/api/agent/threads", status_code=201)
    def create_thread(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        title = str(body.get("title") or "New analysis")
        session_id = body.get("session_id")
        if session_id is not None and not isinstance(session_id, str):
            raise HTTPException(status_code=400, detail="invalid_session_id")
        item = store.create_thread(title=title, session_id=session_id)
        return JSONResponse({"ok": True, "thread": item.dump()}, status_code=201)

    @app.get("/api/agent/threads/{thread_id}")
    def get_thread(thread_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        item = store.get_thread(thread_id)
        if item is None:
            raise HTTPException(status_code=404, detail="thread_not_found")
        return JSONResponse({"ok": True, "thread": item.dump(), "messages": [message.dump() for message in store.list_messages(thread_id)]})

    @app.post("/api/agent/threads/{thread_id}/messages", status_code=201)
    def add_message(thread_id: str, body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        content = body.get("content")
        if not isinstance(content, str) or not content.strip():
            raise HTTPException(status_code=400, detail="message_required")
        try:
            message = store.add_message(thread_id, "user", content.strip())
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="thread_not_found") from exc
        return JSONResponse({"ok": True, "message": message.dump()}, status_code=201)

    @app.post("/api/agent/runs", status_code=202)
    async def create_run(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        thread_id = body.get("thread_id")
        if not isinstance(thread_id, str):
            raise HTTPException(status_code=400, detail="thread_id_required")
        message = body.get("message")
        if isinstance(message, str) and message.strip():
            try:
                store.add_message(thread_id, "user", message.strip())
            except KeyError as exc:
                raise HTTPException(status_code=404, detail="thread_not_found") from exc
        try:
            run = await orchestrator.start_run(thread_id, profile_id=body.get("profile_id") if isinstance(body.get("profile_id"), str) else None, model=body.get("model") if isinstance(body.get("model"), str) else None)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="thread_or_profile_not_found") from exc
        return JSONResponse({"ok": True, "run_id": run["id"], "run": run}, status_code=202)

    @app.get("/api/agent/runs/{run_id}")
    def get_run(run_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run_not_found")
        return JSONResponse({"ok": True, "run": run.dump()})

    @app.post("/api/agent/runs/{run_id}/cancel", status_code=202)
    async def cancel_run(run_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            run = await orchestrator.cancel(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run_not_found") from exc
        return JSONResponse({"ok": True, "run": run}, status_code=202)

    async def _decision(run_id: str, tool_call_id: str, body: JsonObject, approved: bool) -> JSONResponse:
        value = body.get("args_sha256")
        if not isinstance(value, str) or len(value) != 64:
            raise HTTPException(status_code=400, detail="args_sha256_required")
        try:
            decision = await orchestrator.decide(run_id, tool_call_id, value, approved=approved)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="tool_call_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse({"ok": True, "tool_call": decision})

    @app.post("/api/agent/runs/{run_id}/tool-calls/{tool_call_id}/approve")
    async def approve(run_id: str, tool_call_id: str, body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        return await _decision(run_id, tool_call_id, body, True)

    @app.post("/api/agent/runs/{run_id}/tool-calls/{tool_call_id}/reject")
    async def reject(run_id: str, tool_call_id: str, body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        return await _decision(run_id, tool_call_id, body, False)

    @app.get("/api/agent/runs/{run_id}/events")
    async def events(
        run_id: str,
        authorization: str | None = Header(default=None),
        after: int = Query(default=0, ge=0),
    ) -> StreamingResponse:
        authorize(authorization)
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run_not_found")

        async def generate() -> AsyncIterator[bytes]:
            cursor = after
            idle = 0
            while True:
                batch = await asyncio.to_thread(store.list_events, run_id, after=cursor)
                for event in batch:
                    cursor = event.seq
                    payload = json.dumps(event.dump(), ensure_ascii=False, separators=(",", ":"), default=str)
                    yield f"id: {event.seq}\nevent: {event.type}\ndata: {payload}\n\n".encode()
                run = await asyncio.to_thread(store.get_run, run_id)
                if run is None:
                    break
                if run.status in TERMINAL_RUN_STATUSES and not batch:
                    break
                if not batch:
                    idle += 1
                    if idle >= 10:
                        heartbeat = json.dumps({"run_id": run_id, "after": cursor})
                        yield f"event: heartbeat\ndata: {heartbeat}\n\n".encode()
                        idle = 0
                else:
                    idle = 0
                await asyncio.sleep(0.25)

        return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/agent/runs/{run_id}/events/history")
    def event_history(
        run_id: str,
        authorization: str | None = Header(default=None),
        after: int = Query(default=0, ge=0),
    ) -> JSONResponse:
        authorize(authorization)
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run_not_found")
        return JSONResponse(
            {"ok": True, "events": [event.dump() for event in store.list_events(run_id, after=after)]}
        )

    @app.get("/api/providers")
    def providers(authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        return JSONResponse({"ok": True, **configs.list_public()})

    @app.put("/api/providers/{profile_id}")
    def save_provider(profile_id: str, body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            profile = ProviderProfile(
                id=profile_id,
                base_url=str(body.get("base_url") or ""),
                model=str(body.get("model") or ""),
                api_key=str(body["api_key"]) if body.get("api_key") else None,
                known_models=[str(x) for x in body.get("known_models", []) if isinstance(x, str)],
                model_catalogs=[dict(x) for x in body.get("model_catalogs", []) if isinstance(x, dict)],
                enable_thinking=bool(body.get("enable_thinking", False)),
                reasoning_effort=str(body["reasoning_effort"]) if body.get("reasoning_effort") else None,
                context_compression_threshold_percent=int(body.get("context_compression_threshold_percent", 75)),
            )
            public = configs.save(profile, make_current=body.get("make_current", True) is not False)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse({"ok": True, "profile": public})

    @app.post("/api/providers/{profile_id}/models")
    async def probe_models(profile_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            provider = OpenAICompatibleProvider(configs.get(profile_id), timeout=30.0)
            models = await provider.list_models()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="profile_not_found") from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"provider_probe_failed:{type(exc).__name__}") from exc
        return JSONResponse({"ok": True, "models": models})

    @app.post("/api/providers/zerofall/preview")
    def zerofall_preview(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        return JSONResponse({"ok": True, "preview": configs.preview_zerofall(body)})

    @app.post("/api/providers/zerofall/import")
    def zerofall_import(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        source = body.get("config")
        if not isinstance(source, dict):
            raise HTTPException(status_code=400, detail="config_required")
        try:
            profile = configs.import_zerofall(source, confirm=body.get("confirm") is True, profile_id=str(body.get("profile_id") or "zerofall"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse({"ok": True, "profile": profile})
