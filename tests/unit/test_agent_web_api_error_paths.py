"""Error, validation and edge branches of the agent/provider HTTP routes.

The happy paths of these routes are exercised elsewhere (test_agent_web_api,
test_probe_models_error_body). This module reaches the arms those tests skip:
the 400/404/409/413 rejections, the persona import/delete surface, the
autonomy grant/revoke lists, and the SSE event stream draining to a terminal
run. Every test drives the real FastAPI app through a TestClient so the wiring
that maps a raised HTTPException to a status code is covered too, not just the
handler bodies.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

TOKEN = "web-secret"


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: Any) -> Iterator[tuple[TestClient, FastAPI]]:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token=TOKEN, settings=settings)
    with TestClient(app) as client:
        client.headers.update({"Authorization": f"Bearer {TOKEN}"})
        yield client, app


def _thread(client: TestClient, **body: Any) -> str:
    created = client.post("/api/agent/threads", json={"title": "T", **body})
    assert created.status_code == 201, created.text
    return str(created.json()["thread"]["id"])


# --- threads ----------------------------------------------------------------


def test_create_thread_rejects_a_non_string_session_id(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/threads", json={"title": "T", "session_id": 123})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "invalid_session_id"


def test_bind_thread_requires_the_session_id_key(app_client: Any) -> None:
    client, _ = app_client
    thread_id = _thread(client)
    reply = client.patch(f"/api/agent/threads/{thread_id}", json={})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "session_id_required"


def test_bind_thread_rejects_a_non_string_session_id(app_client: Any) -> None:
    client, _ = app_client
    thread_id = _thread(client)
    reply = client.patch(f"/api/agent/threads/{thread_id}", json={"session_id": 5})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "invalid_session_id"


def test_bind_thread_on_a_missing_thread_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.patch("/api/agent/threads/nope", json={"session_id": "s"})
    assert reply.status_code == 404
    assert reply.json()["detail"] == "thread_not_found"


def test_bind_thread_surfaces_the_store_bound_as_a_400(app_client: Any) -> None:
    client, _ = app_client
    thread_id = _thread(client)
    reply = client.patch(f"/api/agent/threads/{thread_id}", json={"session_id": "x" * 1024})
    assert reply.status_code == 400
    assert "session_id" in reply.json()["detail"]


def test_delete_a_missing_thread_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.delete("/api/agent/threads/nope")
    assert reply.status_code == 404
    assert reply.json()["detail"] == "thread_not_found"


# --- messages & runs --------------------------------------------------------


def test_add_message_requires_non_blank_content(app_client: Any) -> None:
    client, _ = app_client
    thread_id = _thread(client)
    reply = client.post(f"/api/agent/threads/{thread_id}/messages", json={"content": "   "})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "message_required"


def test_add_message_on_a_missing_thread_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/threads/nope/messages", json={"content": "hi"})
    assert reply.status_code == 404
    assert reply.json()["detail"] == "thread_not_found"


def test_create_run_requires_a_thread_id(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/runs", json={})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "thread_id_required"


def test_create_run_with_a_message_to_a_missing_thread_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/runs", json={"thread_id": "nope", "message": "hi"})
    assert reply.status_code == 404
    assert reply.json()["detail"] == "thread_not_found"


def test_create_run_on_a_missing_thread_is_a_404(app_client: Any) -> None:
    """No provider is configured, so start_run cannot even build a run for a
    thread that does not exist; the KeyError comes back as thread_or_profile."""
    client, _ = app_client
    reply = client.post("/api/agent/runs", json={"thread_id": "nope"})
    assert reply.status_code == 404
    assert reply.json()["detail"] == "thread_or_profile_not_found"


# --- run reads / cancel -----------------------------------------------------


def test_get_a_missing_run_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    assert client.get("/api/agent/runs/nope").status_code == 404


def test_get_a_run_created_directly_in_the_store(app_client: Any) -> None:
    client, app = app_client
    thread_id = _thread(client)
    run = app.state.agent_store.create_run(
        thread_id, provider_profile="default", model="fake", deadline_seconds=30
    )
    reply = client.get(f"/api/agent/runs/{run.id}")
    assert reply.status_code == 200
    assert reply.json()["run"]["id"] == run.id


def test_cancel_a_missing_run_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    assert client.post("/api/agent/runs/nope/cancel").status_code == 404


def test_cancel_a_queued_run_requests_cancellation(app_client: Any) -> None:
    client, app = app_client
    thread_id = _thread(client)
    run = app.state.agent_store.create_run(
        thread_id, provider_profile="default", model="fake", deadline_seconds=30
    )
    reply = client.post(f"/api/agent/runs/{run.id}/cancel")
    assert reply.status_code == 202
    assert reply.json()["run"]["cancel_requested"] is True


# --- approvals --------------------------------------------------------------


def test_approve_requires_a_64_char_args_hash(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/runs/r/tool-calls/t/approve", json={})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "args_sha256_required"


def test_approve_rejects_an_unknown_remember_mode(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post(
        "/api/agent/runs/r/tool-calls/t/approve",
        json={"args_sha256": "a" * 64, "remember": "forever"},
    )
    assert reply.status_code == 400
    assert reply.json()["detail"] == "remember_invalid"


def test_reject_on_a_missing_run_is_a_409(app_client: Any) -> None:
    """decide() finds no run, calls it terminal-or-missing, which is a conflict."""
    client, _ = app_client
    reply = client.post("/api/agent/runs/nope/tool-calls/t/reject", json={"args_sha256": "a" * 64})
    assert reply.status_code == 409


def test_approve_on_a_live_run_with_an_unknown_tool_call_is_a_404(app_client: Any) -> None:
    client, app = app_client
    thread_id = _thread(client)
    run = app.state.agent_store.create_run(
        thread_id, provider_profile="default", model="fake", deadline_seconds=30
    )
    reply = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/ghost/approve",
        json={"args_sha256": "a" * 64},
    )
    assert reply.status_code == 404
    assert reply.json()["detail"] == "tool_call_not_found"


# --- event stream & history -------------------------------------------------


def test_event_history_on_a_missing_run_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    assert client.get("/api/agent/runs/nope/events/history").status_code == 404


def test_event_history_returns_the_recorded_events(app_client: Any) -> None:
    client, app = app_client
    thread_id = _thread(client)
    run = app.state.agent_store.create_run(
        thread_id, provider_profile="default", model="fake", deadline_seconds=30
    )
    app.state.agent_store.append_event(run.id, "llm.started", {"round": 1})
    reply = client.get(f"/api/agent/runs/{run.id}/events/history")
    assert reply.status_code == 200
    assert any(event["type"] == "llm.started" for event in reply.json()["events"])


def test_event_stream_on_a_missing_run_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    assert client.get("/api/agent/runs/nope/events").status_code == 404


def test_event_stream_drains_then_closes_on_a_terminal_run(app_client: Any) -> None:
    """A finished run's stream must emit its backlog and then end on its own.

    The generator polls once, sees the run terminal with an empty follow-up
    batch, and breaks -- so a plain GET returns the whole SSE body rather than
    hanging. QUEUED cannot jump straight to COMPLETED, so fail it (a terminal
    state reachable from QUEUED) to trip the same break.
    """
    client, app = app_client
    thread_id = _thread(client)
    store = app.state.agent_store
    run = store.create_run(thread_id, provider_profile="default", model="fake", deadline_seconds=30)
    store.append_event(run.id, "llm.started", {"round": 1})
    store.transition(run.id, RunStatus.FAILED, error="boom")

    reply = client.get(f"/api/agent/runs/{run.id}/events")
    assert reply.status_code == 200
    assert "event: llm.started" in reply.text


# --- personas ---------------------------------------------------------------


def test_select_persona_requires_an_id(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/personas/select", json={})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "persona_id_required"


def test_select_an_unknown_persona_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/personas/select", json={"id": "does-not-exist"})
    assert reply.status_code == 404
    assert reply.json()["detail"] == "persona_not_found"


def test_import_persona_requires_a_source(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/personas/import", json={})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "persona_source_required"


def test_import_persona_from_a_missing_path_is_a_400(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/personas/import", json={"path": "/no/such/persona.md"})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "persona_path_missing"


def test_import_persona_from_content_then_delete_it(app_client: Any) -> None:
    client, _ = app_client
    imported = client.post(
        "/api/agent/personas/import",
        json={"title": "Custom", "content": "You are a focused analyst."},
    )
    assert imported.status_code == 200
    persona_id = imported.json()["current"]
    assert any(p["id"] == persona_id and not p["builtin"] for p in imported.json()["personas"])

    removed = client.delete(f"/api/agent/personas/{persona_id}")
    assert removed.status_code == 200
    assert all(p["id"] != persona_id for p in removed.json()["personas"])


def test_import_persona_from_a_file_path(app_client: Any, tmp_path: Path) -> None:
    client, _ = app_client
    persona_file = tmp_path / "analyst.md"
    persona_file.write_text("Focus on the unpacking stub first.\n", encoding="utf-8")
    reply = client.post("/api/agent/personas/import", json={"path": str(persona_file)})
    assert reply.status_code == 200
    assert reply.json()["current"]


def test_delete_a_missing_persona_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.delete("/api/agent/personas/custom-missing")
    assert reply.status_code == 404
    assert reply.json()["detail"] == "persona_not_found"


def test_delete_a_builtin_persona_is_a_400(app_client: Any) -> None:
    client, _ = app_client
    reply = client.delete("/api/agent/personas/default")
    assert reply.status_code == 400
    assert reply.json()["detail"] == "persona_builtin"


# --- missions ---------------------------------------------------------------


def test_create_mission_rejects_a_non_string_thread_id(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/missions", json={"objective": "recover key", "thread_id": 7})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "invalid_thread_id"


def test_create_mission_for_a_missing_thread_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post(
        "/api/agent/missions",
        json={"objective": "recover key", "thread_id": "no-such-thread"},
    )
    assert reply.status_code == 404
    assert reply.json()["detail"] == "thread_not_found"


def test_list_missions_rejects_an_unknown_status_filter(app_client: Any) -> None:
    client, _ = app_client
    reply = client.get("/api/agent/missions", params={"status": "napping"})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "invalid_status"


def test_cancel_a_missing_mission_is_a_404(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/agent/missions/nope/cancel")
    assert reply.status_code == 404
    assert reply.json()["detail"] == "mission_not_found"


# --- watchdog & autonomy ----------------------------------------------------


def test_watchdog_reports_policy_and_alert_counters(app_client: Any) -> None:
    client, _ = app_client
    body = client.get("/api/agent/watchdog").json()
    assert body["ok"] is True
    assert "policy" in body
    assert body["alerts_total"] >= 0
    assert isinstance(body["alerts"], list)


def test_update_autonomy_rejects_non_list_grants(app_client: Any) -> None:
    client, _ = app_client
    reply = client.put("/api/agent/autonomy", json={"add_tools": "dynamic.open"})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "autonomy_lists_required"


def test_update_autonomy_rejects_an_unknown_effect(app_client: Any) -> None:
    client, _ = app_client
    reply = client.put("/api/agent/autonomy", json={"add_effects": ["telepathy"]})
    assert reply.status_code == 400
    assert "telepathy" in reply.json()["detail"]


def test_update_autonomy_grants_then_revokes_a_tool(app_client: Any) -> None:
    client, _ = app_client
    reply = client.put(
        "/api/agent/autonomy",
        json={"add_tools": ["dynamic.open"], "remove_tools": ["dynamic.open"]},
    )
    assert reply.status_code == 200
    assert "dynamic.open" not in reply.json()["policy"]["auto_approve_tools"]


# --- providers --------------------------------------------------------------


def test_save_a_brand_new_provider_profile(app_client: Any) -> None:
    client, _ = app_client
    reply = client.put(
        "/api/providers/fresh",
        json={"base_url": "https://example.invalid/v1", "model": "m"},
    )
    assert reply.status_code == 200
    assert reply.json()["profile"]["id"] == "fresh"


def test_save_provider_rejects_a_non_numeric_threshold(app_client: Any) -> None:
    client, _ = app_client
    reply = client.put(
        "/api/providers/bad",
        json={
            "base_url": "https://example.invalid/v1",
            "model": "m",
            "context_compression_threshold_percent": "lots",
        },
    )
    assert reply.status_code == 400


def test_probe_models_stores_a_returned_catalog(app_client: Any, monkeypatch: Any) -> None:
    client, _ = app_client
    saved = client.put(
        "/api/providers/probe",
        json={"base_url": "https://example.invalid/v1", "model": "m", "api_key": "k"},
    )
    assert saved.status_code == 200

    async def models(self: OpenAICompatibleProvider) -> list[str]:
        return ["m1", "m2"]

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", models)
    reply = client.post("/api/providers/probe/models")
    assert reply.status_code == 200
    assert reply.json()["models"] == ["m1", "m2"]
    listed = client.get("/api/providers").json()["profiles"]
    assert any("m1" in p.get("known_models", []) for p in listed)


def test_probe_models_truncates_a_huge_provider_error(app_client: Any, monkeypatch: Any) -> None:
    client, _ = app_client
    client.put(
        "/api/providers/probe",
        json={"base_url": "https://example.invalid/v1", "model": "m", "api_key": "k"},
    )

    async def boom(self: OpenAICompatibleProvider) -> list[str]:
        raise RuntimeError("x" * 5000)

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", boom)
    reply = client.post("/api/providers/probe/models")
    assert reply.status_code == 502
    detail = reply.json()["detail"]
    assert detail.startswith("provider_probe_failed:RuntimeError:")
    # 500-char body cap plus the fixed prefix; never the whole 5000-char blast.
    assert len(detail) < 600


def test_zerofall_import_requires_a_config_object(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/providers/zerofall/import", json={"config": "nope"})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "config_required"


def test_zerofall_import_requires_explicit_confirmation(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post("/api/providers/zerofall/import", json={"config": {"apiKey": "k"}})
    assert reply.status_code == 400
    assert reply.json()["detail"] == "confirm_required"


@pytest.mark.parametrize(
    "field,value",
    [
        ("contextCompressionThresholdPercent", None),
        ("contextCompressionThresholdPercent", [1, 2]),
        ("knownModels", None),
        ("modelCatalogs", 5),
    ],
)
def test_zerofall_import_rejects_a_wrongly_typed_field_with_a_400(
    app_client: Any, field: str, value: Any
) -> None:
    """A pasted config with a wrong field type is the client's error, not ours.

    import_zerofall coerces these fields (int() on the threshold, iteration on
    the model lists), so a null or scalar raises TypeError rather than
    ValueError -- and the route used to let that escape as a 500.
    """
    client, _ = app_client
    reply = client.post(
        "/api/providers/zerofall/import",
        json={"config": {"apiKey": "k", field: value}, "confirm": True},
    )
    assert reply.status_code == 400


def test_zerofall_import_saves_a_confirmed_profile(app_client: Any) -> None:
    client, _ = app_client
    reply = client.post(
        "/api/providers/zerofall/import",
        json={
            "config": {"apiKey": "secret", "model": "gpt-x", "ai.apiBaseUrl": "https://x/v1"},
            "confirm": True,
        },
    )
    assert reply.status_code == 200
    assert reply.json()["profile"]["id"] == "zerofall"
    assert "secret" not in reply.text
