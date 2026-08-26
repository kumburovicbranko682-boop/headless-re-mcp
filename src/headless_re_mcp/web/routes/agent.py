"""Agent, provider and replayable SSE routes."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from headless_re_mcp.agent import (
    AgentOrchestrator,
    AgentStore,
    ProviderConfigStore,
    ProviderProfile,
)
from headless_re_mcp.agent.autonomy import AutonomyPolicy
from headless_re_mcp.agent.models import TERMINAL_RUN_STATUSES, MissionStatus
from headless_re_mcp.agent.personas import PersonaStore
from headless_re_mcp.agent.providers import OpenAICompatibleProvider
from headless_re_mcp.agent.scheduler import MissionScheduler
from headless_re_mcp.config import Settings, default_config_path, update_config_values
from headless_re_mcp.core.isolation import IsolationPolicy, IsolationRunner
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.watchdog import Watchdog, WatchdogPolicy
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import (
    COMMAND_CATALOG,
    CommandCatalog,
    CommandTransport,
    ToolEffect,
)

JsonObject = dict[str, Any]


def _attach_scheduler_lifespan(app: FastAPI, scheduler: MissionScheduler) -> None:
    """Run the scheduler for as long as the app is serving.

    Chained onto any existing lifespan rather than replacing it, because the
    router does not own the app and must not silently drop someone else's
    startup work.
    """
    previous = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(instance: FastAPI) -> AsyncIterator[None]:
        scheduler.start()
        try:
            async with previous(instance):
                yield
        finally:
            await scheduler.stop()

    app.router.lifespan_context = lifespan


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
    # This process is taking ownership of the database, so anything the previous
    # one left mid-flight is dead and its missions belong back in the queue.
    store.recover_after_restart()
    configured_path = os.environ.get("HEADLESS_RE_PROVIDER_CONFIG")
    config_path = (
        Path(configured_path)
        if configured_path
        else default_config_path().parent / "providers.json"
    )
    configs = ProviderConfigStore(config_path)
    autonomy = AutonomyPolicy.from_settings(settings)
    personas = PersonaStore(settings.artifact_root / "meta" / "personas")
    orchestrator = AgentOrchestrator(
        store,
        catalog,
        configs,
        autonomy=autonomy,
        # Read the live profile each run: workspace_mode_set mutates the shared
        # Settings in place, so the web agent focuses on the chosen direction
        # without recreating the orchestrator.
        tool_profile_provider=lambda: getattr(service.settings, "workspace_profile", "full"),
        persona_provider=personas.current_prompt,
    )
    watchdog_policy = WatchdogPolicy.from_settings(settings)
    watchdog = Watchdog(service, policy=watchdog_policy)
    isolation_policy = IsolationPolicy.from_settings(settings)
    scheduler = MissionScheduler(
        store,
        orchestrator.start_run,
        watchdog=watchdog if watchdog_policy.enabled else None,
        watchdog_interval_s=watchdog_policy.interval_s,
        isolation=IsolationRunner(isolation_policy) if isolation_policy.configured else None,
    )
    app.state.agent_store = store
    app.state.provider_configs = configs
    app.state.agent_orchestrator = orchestrator
    app.state.persona_store = personas
    app.state.mission_scheduler = scheduler
    app.state.watchdog = watchdog
    app.state.tool_catalog = catalog

    # Bound to the app lifespan rather than started at import, so the loop
    # attaches to the server's event loop and a test client that never enters
    # the lifespan does not leave one running.
    _attach_scheduler_lifespan(app, scheduler)

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
        try:
            item = store.create_thread(title=title, session_id=session_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse({"ok": True, "thread": item.dump()}, status_code=201)

    @app.get("/api/agent/threads/{thread_id}")
    def get_thread(thread_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        item = store.get_thread(thread_id)
        if item is None:
            raise HTTPException(status_code=404, detail="thread_not_found")
        return JSONResponse(
            {
                "ok": True,
                "thread": item.dump(),
                "messages": [message.dump() for message in store.list_messages(thread_id)],
                "events": [event.dump() for event in store.list_thread_events(thread_id)],
            }
        )

    @app.patch("/api/agent/threads/{thread_id}")
    def bind_thread(thread_id: str, body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        if "session_id" not in body:
            raise HTTPException(status_code=400, detail="session_id_required")
        session_id = body.get("session_id")
        if session_id is not None and not isinstance(session_id, str):
            raise HTTPException(status_code=400, detail="invalid_session_id")
        bound_id = session_id.strip() if isinstance(session_id, str) and session_id.strip() else None
        try:
            item = store.bind_thread_session(thread_id, bound_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="thread_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse({"ok": True, "thread": item.dump()})

    @app.delete("/api/agent/threads/{thread_id}")
    def delete_thread(thread_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            store.delete_thread(thread_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="thread_not_found") from exc
        return JSONResponse({"ok": True})

    @app.get("/api/agent/personas")
    def list_personas(authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        return JSONResponse({"ok": True, **personas.list_public()})

    @app.post("/api/agent/personas/select")
    def select_persona(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        persona_id = body.get("id")
        if not isinstance(persona_id, str) or not persona_id.strip():
            raise HTTPException(status_code=400, detail="persona_id_required")
        try:
            listed = personas.select(persona_id.strip())
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="persona_not_found") from exc
        return JSONResponse({"ok": True, **listed})

    @app.post("/api/agent/personas/import")
    def import_persona(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            path = body.get("path")
            content = body.get("content")
            title = body.get("title")
            if isinstance(path, str) and path.strip():
                listed = personas.import_path(Path(path.strip()))
            elif isinstance(content, str):
                listed = personas.import_markdown(
                    title=str(title or "imported"),
                    body=content,
                    source="upload",
                )
            else:
                raise HTTPException(status_code=400, detail="persona_source_required")
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse({"ok": True, **listed})

    @app.delete("/api/agent/personas/{persona_id}")
    def delete_persona(persona_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            listed = personas.delete(persona_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="persona_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse({"ok": True, **listed})

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
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
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
                # Off the loop: the store serialises on a lock and waits up to
                # busy_timeout (30s) for SQLite, and the scheduler writes to the
                # same database continuously. Inline, a contended write freezes
                # every other request and SSE stream for as long as it waits.
                await asyncio.to_thread(store.add_message, thread_id, "user", message.strip())
            except KeyError as exc:
                raise HTTPException(status_code=404, detail="thread_not_found") from exc
            except ValueError as exc:
                raise HTTPException(status_code=413, detail=str(exc)) from exc
        try:
            run = await orchestrator.start_run(thread_id, profile_id=body.get("profile_id") if isinstance(body.get("profile_id"), str) else None, model=body.get("model") if isinstance(body.get("model"), str) else None)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="thread_or_profile_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
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

    def _persist_autonomy(policy: AutonomyPolicy) -> None:
        update_config_values(
            {
                "agent_auto_approve_effects": sorted(item.value for item in policy.auto_approve_effects),
                "agent_auto_approve_tools": sorted(policy.auto_approve_tools),
                "agent_never_auto_approve": sorted(policy.never_auto_approve),
            }
        )

    def _autonomy_body(policy: AutonomyPolicy) -> dict[str, object]:
        unattended = sorted(
            spec.name
            for spec in catalog.for_transport(CommandTransport.AGENT)
            if spec.write and policy.decide(spec).approved
        )
        return {
            "ok": True,
            "mode": policy.mode.value,
            "policy": policy.describe(),
            "auto_executable_writes": unattended,
            "auto_executable_write_count": len(unattended),
        }

    def _remember_approval(run_id: str, tool_call_id: str, remember: str) -> AutonomyPolicy:
        call = store.get_tool_call(run_id, tool_call_id)
        name = str(call["name"])
        spec = catalog.require(name)
        if remember == "tool":
            policy = orchestrator.autonomy.grant(tools=(name,))
        elif remember == "effect":
            policy = orchestrator.autonomy.grant(
                effects=tuple(item.value for item in spec.effects if item is not ToolEffect.READ_ONLY)
            )
        else:
            raise ValueError("remember must be 'tool' or 'effect'")
        orchestrator.autonomy = policy
        _persist_autonomy(policy)
        return policy

    async def _decision(run_id: str, tool_call_id: str, body: JsonObject, approved: bool) -> JSONResponse:
        value = body.get("args_sha256")
        if not isinstance(value, str) or len(value) != 64:
            raise HTTPException(status_code=400, detail="args_sha256_required")
        remember = body.get("remember")
        if remember not in (None, "", "tool", "effect"):
            raise HTTPException(status_code=400, detail="remember_invalid")
        policy = None
        try:
            decision = await orchestrator.decide(run_id, tool_call_id, value, approved=approved)
            if approved and remember in {"tool", "effect"}:
                policy = _remember_approval(run_id, tool_call_id, str(remember)).describe()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="tool_call_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        payload: dict[str, object] = {"ok": True, "tool_call": decision}
        if policy is not None:
            payload["policy"] = policy
        return JSONResponse(payload)

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
        if await asyncio.to_thread(store.get_run, run_id) is None:
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

    @app.post("/api/agent/missions", status_code=201)
    def create_mission(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        """Queue a durable objective for the scheduler to carry out.

        This is the unattended entry point: unlike a run, nobody has to be
        present when it starts, and it survives the run deadline and a restart.
        """
        authorize(authorization)
        objective = body.get("objective")
        if not isinstance(objective, str) or not objective.strip():
            raise HTTPException(status_code=400, detail="objective_required")
        thread_id = body.get("thread_id")
        if thread_id is not None and not isinstance(thread_id, str):
            raise HTTPException(status_code=400, detail="invalid_thread_id")
        profile = body.get("profile_id") if isinstance(body.get("profile_id"), str) else None
        model = body.get("model") if isinstance(body.get("model"), str) else None
        try:
            text, profile, model, max_runs = store.validate_mission(
                objective,
                provider_profile=profile,
                model=model,
                max_runs=int(body.get("max_runs", 8)),
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if thread_id is None:
            thread_id = store.create_thread(title=text[:80]).id
        try:
            mission = store.create_mission(
                thread_id,
                text,
                provider_profile=profile,
                model=model,
                max_runs=max_runs,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="thread_not_found") from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse({"ok": True, "mission": mission.dump()}, status_code=201)

    @app.get("/api/agent/missions")
    def list_missions(
        status: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        authorize(authorization)
        try:
            wanted = MissionStatus(status) if status else None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid_status") from exc
        items = [item.dump() for item in store.list_missions(status=wanted, limit=limit)]
        return JSONResponse(
            {"ok": True, "missions": items, "count": len(items), "scheduler_running": scheduler.running}
        )

    @app.get("/api/agent/missions/{mission_id}")
    def get_mission(mission_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        mission = store.get_mission(mission_id)
        if mission is None:
            raise HTTPException(status_code=404, detail="mission_not_found")
        return JSONResponse({"ok": True, "mission": mission.dump()})

    @app.post("/api/agent/missions/{mission_id}/cancel", status_code=202)
    def cancel_mission(mission_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            mission = store.cancel_mission(mission_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="mission_not_found") from exc
        return JSONResponse({"ok": True, "mission": mission.dump()}, status_code=202)

    @app.get("/api/agent/watchdog")
    def agent_watchdog(
        limit: int = Query(default=50, ge=1, le=128),
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Recent alerts and what the watchdog is permitted to fix by itself."""
        authorize(authorization)
        return JSONResponse(
            {
                "ok": True,
                "policy": {
                    "enabled": watchdog_policy.enabled,
                    "interval_s": watchdog_policy.interval_s,
                    "auto_recover_backends": watchdog_policy.auto_recover_backends,
                },
                "recovered_total": watchdog.recovered,
                "alerts_total": watchdog.raised,
                "alerts": watchdog.recent_alerts(limit),
            }
        )

    @app.get("/api/agent/autonomy")
    def agent_autonomy(authorization: str | None = Header(default=None)) -> JSONResponse:
        """Report which tools may run unattended, and why.

        An operator running this unattended needs to be able to read the policy
        back rather than infer it from config files, and a reviewer needs to see
        exactly which write tools were opened up.
        """
        authorize(authorization)
        return JSONResponse(_autonomy_body(orchestrator.autonomy))

    @app.put("/api/agent/autonomy")
    def update_autonomy(body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        """Switch the two-mode policy, or grant/revoke individual rules.

        ``mode`` is the Web UI switch: ``request`` restores the fail-closed
        default, ``full_access`` auto-approves every write effect class. It
        replaces the current grants rather than stacking on them. The older
        add/remove lists stay for remembered tools and for scripts.
        """
        authorize(authorization)
        if body.get("mode") not in (None, ""):
            try:
                policy = orchestrator.autonomy.with_mode(str(body["mode"]))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            orchestrator.autonomy = policy
            _persist_autonomy(policy)
            return JSONResponse(_autonomy_body(policy))
        add_tools = body.get("add_tools") or []
        add_effects = body.get("add_effects") or []
        remove_tools = body.get("remove_tools") or []
        if not isinstance(add_tools, list) or not isinstance(add_effects, list) or not isinstance(remove_tools, list):
            raise HTTPException(status_code=400, detail="autonomy_lists_required")
        try:
            policy = orchestrator.autonomy.grant(
                tools=[str(item) for item in add_tools],
                effects=[str(item) for item in add_effects],
            )
            if remove_tools:
                policy = policy.revoke_tools(str(item) for item in remove_tools)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        orchestrator.autonomy = policy
        _persist_autonomy(policy)
        return JSONResponse(_autonomy_body(policy))

    @app.get("/api/providers")
    def providers(authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        return JSONResponse({"ok": True, **configs.list_public()})

    @app.put("/api/providers/{profile_id}")
    def save_provider(profile_id: str, body: JsonObject, authorization: str | None = Header(default=None)) -> JSONResponse:
        authorize(authorization)
        try:
            try:
                existing = configs.get(profile_id)
            except KeyError:
                existing = None
            incoming_key = body.get("api_key")
            api_key = str(incoming_key) if isinstance(incoming_key, str) and incoming_key.strip() else (existing.api_key if existing else None)
            profile = ProviderProfile(
                id=profile_id,
                base_url=str(body.get("base_url") or (existing.base_url if existing else "")),
                model=str(body.get("model") or (existing.model if existing else "")),
                api_key=api_key,
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
            if models:
                current = configs.get(profile_id)
                current.known_models = models
                configs.save(current, make_current=False)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="profile_not_found") from exc
        except Exception as exc:
            # Type name alone made 401/403/404/429/500 look identical.
            # Keep a bounded str(exc) so a quota body or a refused key
            # survives the 502.
            detail = " ".join(str(exc).split())
            if len(detail) > 500:
                detail = detail[:500]
            raise HTTPException(
                status_code=502,
                detail=f"provider_probe_failed:{type(exc).__name__}:{detail}",
            ) from exc
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
