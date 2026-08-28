"""Additional agent/provider HTTP route branches.

These reach arms the existing agent-web suites leave dark: a successful run
start (the 202 return), the approve-with-remember path that grants and persists
an autonomy policy, saving a brand-new provider profile, and the provider-probe
missing/empty-model branches. Everything drives the real FastAPI app through a
TestClient so the HTTPException-to-status wiring is covered too.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headless_re_mcp.agent import AgentOrchestrator
from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

TOKEN = "web-secret"


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: Any) -> Iterator[tuple[TestClient, FastAPI]]:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        agent_auto_approve_tools=(),
        agent_auto_approve_effects=(),
    )
    app = create_app(AnalysisService(settings), token=TOKEN, settings=settings)
    with TestClient(app) as client:
        client.headers.update({"Authorization": f"Bearer {TOKEN}"})
        yield client, app


def _thread(client: TestClient) -> str:
    created = client.post("/api/agent/threads", json={"title": "T"})
    assert created.status_code == 201, created.text
    return str(created.json()["thread"]["id"])


def _save_provider(client: TestClient, profile_id: str = "default") -> None:
    saved = client.put(
        f"/api/providers/{profile_id}",
        json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
    )
    assert saved.status_code == 200, saved.text


# --- run start --------------------------------------------------------------


def test_start_run_returns_202_with_the_run(app_client: Any, monkeypatch: Any) -> None:
    client, app = app_client

    async def noop(self: AgentOrchestrator, run_id: str) -> None:
        return None

    # The run executor would try to reach the LLM; neutralise it so the route's
    # 202 accept path is what we measure, not a real turn.
    monkeypatch.setattr(AgentOrchestrator, "_execute", noop)
    _save_provider(client)
    thread_id = _thread(client)
    reply = client.post("/api/agent/runs", json={"thread_id": thread_id, "profile_id": "default"})
    assert reply.status_code == 202, reply.text
    body = reply.json()
    assert body["ok"] is True
    assert body["run_id"] == body["run"]["id"]


# --- approve with remember --------------------------------------------------


def _seed_pending_tool_call(app: FastAPI, name: str) -> tuple[str, str]:
    store = app.state.agent_store
    thread = store.create_thread(title="tc")
    run = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    call = store.propose_tool_call(run.id, "tc1", name, {"path": "sample.bin"}, [])
    return run.id, str(call["args_sha256"])


def test_approve_remember_tool_grants_and_persists(app_client: Any, monkeypatch: Any) -> None:
    client, app = app_client
    written: dict[str, Any] = {}

    def fake_update(updates: Any, *, config_path: Any = None) -> Path:
        written.update(updates)
        return Path("/cfg.json")

    monkeypatch.setattr("headless_re_mcp.web.routes.agent.update_config_values", fake_update)
    run_id, args_hash = _seed_pending_tool_call(app, "dynamic.open")
    reply = client.post(
        f"/api/agent/runs/{run_id}/tool-calls/tc1/approve",
        json={"args_sha256": args_hash, "remember": "tool"},
    )
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert body["tool_call"]["status"] == "approved"
    assert "dynamic.open" in body["policy"]["auto_approve_tools"]
    assert "dynamic.open" in written["agent_auto_approve_tools"]


def test_approve_remember_effect_grants_effects(app_client: Any, monkeypatch: Any) -> None:
    client, app = app_client
    written: dict[str, Any] = {}

    def fake_update(updates: Any, *, config_path: Any = None) -> Path:
        written.update(updates)
        return Path("/cfg.json")

    monkeypatch.setattr("headless_re_mcp.web.routes.agent.update_config_values", fake_update)
    run_id, args_hash = _seed_pending_tool_call(app, "dynamic.launch")
    reply = client.post(
        f"/api/agent/runs/{run_id}/tool-calls/tc1/approve",
        json={"args_sha256": args_hash, "remember": "effect"},
    )
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert body["tool_call"]["status"] == "approved"
    assert "policy" in body
    assert "agent_auto_approve_effects" in written


def test_approve_without_remember_omits_policy(app_client: Any) -> None:
    client, app = app_client
    run_id, args_hash = _seed_pending_tool_call(app, "dynamic.open")
    reply = client.post(
        f"/api/agent/runs/{run_id}/tool-calls/tc1/approve",
        json={"args_sha256": args_hash},
    )
    assert reply.status_code == 200, reply.text
    assert "policy" not in reply.json()


# --- providers --------------------------------------------------------------


def test_save_a_brand_new_provider_profile(app_client: Any) -> None:
    client, _ = app_client
    reply = client.put(
        "/api/providers/brand-new",
        json={"base_url": "https://example.invalid/v1", "model": "m", "api_key": "k"},
    )
    assert reply.status_code == 200, reply.text
    assert reply.json()["profile"]["id"] == "brand-new"


def test_probe_models_on_a_corrupt_profile_is_404(app_client: Any, tmp_path: Path) -> None:
    # A missing id resolves to a default profile; only a non-dict stored value
    # makes ProviderConfigStore.get raise the KeyError the route maps to 404.
    client, _ = app_client
    (tmp_path / "providers.json").write_text(json.dumps({"profiles": {"ghost": "corrupt"}}))
    reply = client.post("/api/providers/ghost/models")
    assert reply.status_code == 404
    assert reply.json()["detail"] == "profile_not_found"


def test_probe_models_failure_maps_to_502_with_bounded_detail(
    app_client: Any, monkeypatch: Any
) -> None:
    client, _ = app_client
    _save_provider(client, "p2")

    async def boom(self: OpenAICompatibleProvider) -> list[str]:
        raise RuntimeError("quota   exhausted " + "x" * 600)

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", boom)
    reply = client.post("/api/providers/p2/models")
    assert reply.status_code == 502
    detail = reply.json()["detail"]
    assert detail.startswith("provider_probe_failed:RuntimeError:quota exhausted")
    assert len(detail) == len("provider_probe_failed:RuntimeError:") + 500


def test_probe_models_empty_result_returns_ok(app_client: Any, monkeypatch: Any) -> None:
    client, _ = app_client
    _save_provider(client, "p1")

    async def empty(self: OpenAICompatibleProvider) -> list[str]:
        return []

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", empty)
    reply = client.post("/api/providers/p1/models")
    assert reply.status_code == 200, reply.text
    assert reply.json()["models"] == []


def test_probe_models_short_failure_detail_is_kept_whole(app_client: Any, monkeypatch: Any) -> None:
    client, _ = app_client
    _save_provider(client, "p3")

    async def boom(self: OpenAICompatibleProvider) -> list[str]:
        raise RuntimeError("key refused")

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", boom)
    reply = client.post("/api/providers/p3/models")
    assert reply.status_code == 502
    assert reply.json()["detail"] == "provider_probe_failed:RuntimeError:key refused"


def test_save_provider_over_a_corrupt_entry_treats_it_as_new(
    app_client: Any, tmp_path: Path
) -> None:
    # A non-dict stored profile makes configs.get raise KeyError; the save
    # route swallows that and writes a fresh profile in its place.
    client, _ = app_client
    (tmp_path / "providers.json").write_text(json.dumps({"profiles": {"broken": 7}}))
    reply = client.put(
        "/api/providers/broken",
        json={"base_url": "https://example.invalid/v1", "model": "m", "api_key": "k"},
    )
    assert reply.status_code == 200, reply.text
    assert reply.json()["profile"]["id"] == "broken"


# --- personas ----------------------------------------------------------------


def test_list_personas_returns_the_catalog(app_client: Any) -> None:
    client, _ = app_client
    reply = client.get("/api/agent/personas")
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert body["ok"] is True
    assert any(item["id"] == "default" for item in body["personas"])


def test_select_persona_switches_current(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/personas/select", json={"id": "default"})
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert body["ok"] is True
    assert any(item["id"] == "default" and item["current"] for item in body["personas"])


# --- missions ----------------------------------------------------------------


def test_create_mission_with_unparsable_max_runs_is_400(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post(
        "/api/agent/missions", json={"objective": "look around", "max_runs": "many"}
    )
    assert reply.status_code == 400


def test_create_mission_store_rejection_is_400(app_client: Any, monkeypatch: Any) -> None:
    client, app = app_client

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("mission_rejected")

    monkeypatch.setattr(app.state.agent_store, "create_mission", refuse)
    reply = client.post("/api/agent/missions", json={"objective": "look around"})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "mission_rejected"


# --- event stream ------------------------------------------------------------


def _seed_run(app: FastAPI) -> str:
    store = app.state.agent_store
    thread = store.create_thread(title="sse")
    run = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    return str(run.id)


def test_event_stream_stops_when_the_run_vanishes(app_client: Any, monkeypatch: Any) -> None:
    # TestClient buffers the whole response, so the stream must terminate on
    # its own; here the run disappearing mid-stream is what ends it.
    client, app = app_client
    run_id = _seed_run(app)
    store = app.state.agent_store
    real_get_run = store.get_run
    calls = {"n": 0}

    def vanishing(requested: str) -> Any:
        calls["n"] += 1
        # First lookup is the 404 gate; afterwards the run is gone mid-stream.
        return real_get_run(requested) if calls["n"] == 1 else None

    monkeypatch.setattr(store, "get_run", vanishing)
    reply = client.get(f"/api/agent/runs/{run_id}/events")
    assert reply.status_code == 200
    assert calls["n"] >= 2
    assert b"heartbeat" not in reply.content


def test_event_stream_emits_a_heartbeat_after_idling(app_client: Any, monkeypatch: Any) -> None:
    client, app = app_client
    run_id = _seed_run(app)
    store = app.state.agent_store
    real_get_run = store.get_run
    real_sleep = asyncio.sleep
    calls = {"n": 0}

    async def fast_sleep(delay: float) -> None:
        await real_sleep(0)

    def eventually_terminal(requested: str) -> Any:
        # Call 1 is the 404 gate and call 2 drains the run.started event; calls
        # 3-12 keep the loop idling long enough for ten empty polls (the
        # heartbeat threshold); call 13 completes the run so the otherwise
        # endless stream can finish for the buffering TestClient.
        calls["n"] += 1
        run = real_get_run(requested)
        if calls["n"] >= 13:
            return replace(run, status=RunStatus.COMPLETED)
        return run

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    monkeypatch.setattr(store, "get_run", eventually_terminal)
    reply = client.get(f"/api/agent/runs/{run_id}/events")
    assert reply.status_code == 200
    assert b"event: heartbeat" in reply.content
