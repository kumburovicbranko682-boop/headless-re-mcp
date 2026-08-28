"""Degradation and guard branches of the agent web control-plane routes.

The happy paths live in test_agent_web_api.py. These tests pin the client-error
contracts: malformed bodies come back as 4xx with stable details, provider
probe failures surface bounded diagnostics instead of a blank 500, and the
approval endpoints refuse stale or mismatched decisions.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

HEADERS = {"Authorization": "Bearer web-secret"}


def _build_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(
        Settings.load(), artifact_root=tmp_path / "artifacts", **overrides
    )
    service = AnalysisService(settings)
    return create_app(service, token="web-secret", settings=settings)


def test_thread_and_message_guards_reject_malformed_bodies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad_session = client.post(
            "/api/agent/threads", headers=HEADERS, json={"title": "T", "session_id": 5}
        )
        assert bad_session.status_code == 400
        assert bad_session.json()["detail"] == "invalid_session_id"

        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "T"})
        thread_id = created.json()["thread"]["id"]

        no_key = client.patch(
            f"/api/agent/threads/{thread_id}", headers=HEADERS, json={}
        )
        assert no_key.status_code == 400
        assert no_key.json()["detail"] == "session_id_required"

        bad_type = client.patch(
            f"/api/agent/threads/{thread_id}", headers=HEADERS, json={"session_id": 5}
        )
        assert bad_type.status_code == 400
        assert bad_type.json()["detail"] == "invalid_session_id"

        missing = client.patch(
            "/api/agent/threads/not-a-thread", headers=HEADERS, json={"session_id": "s"}
        )
        assert missing.status_code == 404

        oversized = client.patch(
            f"/api/agent/threads/{thread_id}",
            headers=HEADERS,
            json={"session_id": "x" * 1024},
        )
        assert oversized.status_code == 400

        assert (
            client.delete("/api/agent/threads/not-a-thread", headers=HEADERS).status_code
            == 404
        )

        not_text = client.post(
            f"/api/agent/threads/{thread_id}/messages",
            headers=HEADERS,
            json={"content": 5},
        )
        assert not_text.status_code == 400
        assert not_text.json()["detail"] == "message_required"

        orphan = client.post(
            "/api/agent/threads/not-a-thread/messages",
            headers=HEADERS,
            json={"content": "hello"},
        )
        assert orphan.status_code == 404


def test_persona_routes_cover_selection_import_and_delete_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        listed = client.get("/api/agent/personas", headers=HEADERS)
        assert listed.status_code == 200
        assert any(item["builtin"] for item in listed.json()["personas"])

        assert (
            client.post(
                "/api/agent/personas/select", headers=HEADERS, json={}
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/api/agent/personas/select", headers=HEADERS, json={"id": "ghost"}
            ).status_code
            == 404
        )

        source = tmp_path / "persona.md"
        source.write_text("# Sharp analyst\nBe curt.\n", encoding="utf-8")
        imported = client.post(
            "/api/agent/personas/import", headers=HEADERS, json={"path": str(source)}
        )
        assert imported.status_code == 200
        items = imported.json()["personas"]
        custom = next(item["id"] for item in items if not item["builtin"])

        no_source = client.post("/api/agent/personas/import", headers=HEADERS, json={})
        assert no_source.status_code == 400
        assert no_source.json()["detail"] == "persona_source_required"

        empty_body = client.post(
            "/api/agent/personas/import", headers=HEADERS, json={"content": "   "}
        )
        assert empty_body.status_code == 400

        selected = client.post(
            "/api/agent/personas/select", headers=HEADERS, json={"id": custom}
        )
        assert selected.status_code == 200

        assert (
            client.delete("/api/agent/personas/ghost", headers=HEADERS).status_code
            == 404
        )
        assert (
            client.delete("/api/agent/personas/default", headers=HEADERS).status_code
            == 400
        )
        removed = client.delete(f"/api/agent/personas/{custom}", headers=HEADERS)
        assert removed.status_code == 200


def test_run_creation_lookup_and_cancel_cover_missing_and_live_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        no_thread = client.post("/api/agent/runs", headers=HEADERS, json={})
        assert no_thread.status_code == 400
        assert no_thread.json()["detail"] == "thread_id_required"

        # The inline message write is the first thing to notice a bad thread.
        ghost_message = client.post(
            "/api/agent/runs",
            headers=HEADERS,
            json={"thread_id": "ghost", "message": "hi"},
        )
        assert ghost_message.status_code == 404

        ghost_run = client.post(
            "/api/agent/runs", headers=HEADERS, json={"thread_id": "ghost"}
        )
        assert ghost_run.status_code == 404

        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "T"})
        thread_id = created.json()["thread"]["id"]

        from headless_re_mcp.agent.orchestrator import AgentOrchestrator

        async def fake_start_run(self, thread_id, *, profile_id=None, model=None):  # type: ignore[no-untyped-def]
            return {"id": "r-fake", "thread_id": thread_id, "status": "queued"}

        monkeypatch.setattr(AgentOrchestrator, "start_run", fake_start_run)
        accepted = client.post(
            "/api/agent/runs",
            headers=HEADERS,
            json={"thread_id": thread_id, "profile_id": "default", "model": "m"},
        )
        assert accepted.status_code == 202
        assert accepted.json()["run_id"] == "r-fake"
        monkeypatch.undo()

        assert client.get("/api/agent/runs/ghost", headers=HEADERS).status_code == 404
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        fetched = client.get(f"/api/agent/runs/{run.id}", headers=HEADERS)
        assert fetched.status_code == 200
        assert fetched.json()["run"]["id"] == run.id

        assert (
            client.post("/api/agent/runs/ghost/cancel", headers=HEADERS).status_code
            == 404
        )
        cancelled = client.post(f"/api/agent/runs/{run.id}/cancel", headers=HEADERS)
        assert cancelled.status_code == 202


def test_approvals_validate_shas_remember_grants_and_refuse_stale_decisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: dict[str, object] = {}

    def fake_update(updates, *, config_path=None):  # type: ignore[no-untyped-def]
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.update_config_values", fake_update
    )
    # Hosted machines preload the packed preset; pin empty grants so the test
    # measures exactly what the remember flow persisted.
    app = _build_app(
        tmp_path,
        monkeypatch,
        agent_auto_approve_tools=(),
        agent_auto_approve_effects=(),
    )
    with TestClient(app) as client:
        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "T"})
        thread_id = created.json()["thread"]["id"]
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        first = store.propose_tool_call(
            run.id, "call-1", "dynamic.launch", {"arguments": "-h"}, ["state_change"]
        )
        base = f"/api/agent/runs/{run.id}/tool-calls"

        short_sha = client.post(
            f"{base}/call-1/approve", headers=HEADERS, json={"args_sha256": "short"}
        )
        assert short_sha.status_code == 400
        assert short_sha.json()["detail"] == "args_sha256_required"

        bad_remember = client.post(
            f"{base}/call-1/approve",
            headers=HEADERS,
            json={"args_sha256": first["args_sha256"], "remember": "always"},
        )
        assert bad_remember.status_code == 400
        assert bad_remember.json()["detail"] == "remember_invalid"

        unknown_call = client.post(
            f"{base}/nope/approve",
            headers=HEADERS,
            json={"args_sha256": "a" * 64},
        )
        assert unknown_call.status_code == 404

        remembered_tool = client.post(
            f"{base}/call-1/approve",
            headers=HEADERS,
            json={"args_sha256": first["args_sha256"], "remember": "tool"},
        )
        assert remembered_tool.status_code == 200
        assert "dynamic.launch" in remembered_tool.json()["policy"]["auto_approve_tools"]
        assert written["agent_auto_approve_tools"] == ["dynamic.launch"]

        stale = client.post(
            f"{base}/call-1/approve",
            headers=HEADERS,
            json={"args_sha256": first["args_sha256"]},
        )
        assert stale.status_code == 409

        second = store.propose_tool_call(
            run.id, "call-2", "report.generate", {"session_id": "s"}, ["file_write"]
        )
        remembered_effect = client.post(
            f"{base}/call-2/approve",
            headers=HEADERS,
            json={"args_sha256": second["args_sha256"], "remember": "effect"},
        )
        assert remembered_effect.status_code == 200
        assert remembered_effect.json()["policy"]["auto_approve_effects"]

        third = store.propose_tool_call(
            run.id, "call-3", "dynamic.launch", {"arguments": "-x"}, ["state_change"]
        )
        rejected = client.post(
            f"{base}/call-3/reject",
            headers=HEADERS,
            json={"args_sha256": third["args_sha256"]},
        )
        assert rejected.status_code == 200
        assert rejected.json()["tool_call"]["status"] == "rejected"


def test_run_event_streams_replay_history_and_close_on_terminal_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        assert (
            client.get("/api/agent/runs/ghost/events", headers=HEADERS).status_code
            == 404
        )
        assert (
            client.get(
                "/api/agent/runs/ghost/events/history", headers=HEADERS
            ).status_code
            == 404
        )

        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "T"})
        thread_id = created.json()["thread"]["id"]
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        store.append_event(run.id, "llm.started", {"round": 1})
        store.append_event(run.id, "llm.completed", {"round": 1})
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.COMPLETED)

        streamed = client.get(f"/api/agent/runs/{run.id}/events", headers=HEADERS)
        assert streamed.status_code == 200
        assert "event: llm.started" in streamed.text
        assert "event: llm.completed" in streamed.text

        history = client.get(
            f"/api/agent/runs/{run.id}/events/history", headers=HEADERS
        )
        assert history.status_code == 200
        types = [event["type"] for event in history.json()["events"]]
        assert types == ["run.started", "llm.started", "llm.completed"]


def test_an_idle_live_stream_heartbeats_and_a_vanished_run_closes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SSE consumers need liveness signals, not a silently wedged socket."""
    import threading

    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "T"})
        thread_id = created.json()["thread"]["id"]
        store = app.state.agent_store

        idle_run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )

        def finish() -> None:
            store.transition(idle_run.id, RunStatus.STREAMING)
            store.transition(idle_run.id, RunStatus.COMPLETED)

        # Ten empty polls at 0.25s each earn a heartbeat around 2.5s; end the
        # run shortly after so the stream closes on the terminal status.
        finisher = threading.Timer(3.2, finish)
        finisher.start()
        try:
            streamed = client.get(f"/api/agent/runs/{idle_run.id}/events", headers=HEADERS)
        finally:
            finisher.join()
        assert streamed.status_code == 200
        assert "event: heartbeat" in streamed.text

        doomed_run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )

        def vanish() -> None:
            with store.transaction() as con:
                con.execute("DELETE FROM runs WHERE id=?", (doomed_run.id,))

        eraser = threading.Timer(0.6, vanish)
        eraser.start()
        try:
            gone = client.get(f"/api/agent/runs/{doomed_run.id}/events", headers=HEADERS)
        finally:
            eraser.join()
        assert gone.status_code == 200
        assert "event: heartbeat" not in gone.text


def test_mission_routes_reject_bad_threads_and_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad_thread_type = client.post(
            "/api/agent/missions",
            headers=HEADERS,
            json={"objective": "obj", "thread_id": 5},
        )
        assert bad_thread_type.status_code == 400
        assert bad_thread_type.json()["detail"] == "invalid_thread_id"

        ghost_thread = client.post(
            "/api/agent/missions",
            headers=HEADERS,
            json={"objective": "obj", "thread_id": "ghost"},
        )
        assert ghost_thread.status_code == 404

        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "T"})
        thread_id = created.json()["thread"]["id"]
        onto_existing = client.post(
            "/api/agent/missions",
            headers=HEADERS,
            json={"objective": "reuse this thread", "thread_id": thread_id},
        )
        assert onto_existing.status_code == 201
        assert onto_existing.json()["mission"]["thread_id"] == thread_id

        assert (
            client.get(
                "/api/agent/missions?status=bogus", headers=HEADERS
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/api/agent/missions/ghost/cancel", headers=HEADERS
            ).status_code
            == 404
        )

        watchdog = client.get("/api/agent/watchdog", headers=HEADERS)
        assert watchdog.status_code == 200
        body = watchdog.json()
        assert set(body["policy"]) == {"enabled", "interval_s", "auto_recover_backends"}
        assert body["alerts"] == []


def test_autonomy_updates_validate_lists_and_support_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: dict[str, object] = {}

    def fake_update(updates, *, config_path=None):  # type: ignore[no-untyped-def]
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.update_config_values", fake_update
    )
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        not_lists = client.put(
            "/api/agent/autonomy", headers=HEADERS, json={"add_tools": "dynamic.open"}
        )
        assert not_lists.status_code == 400
        assert not_lists.json()["detail"] == "autonomy_lists_required"

        bogus_effect = client.put(
            "/api/agent/autonomy", headers=HEADERS, json={"add_effects": ["bogus"]}
        )
        assert bogus_effect.status_code == 400

        granted = client.put(
            "/api/agent/autonomy", headers=HEADERS, json={"add_tools": ["dynamic.open"]}
        )
        assert granted.status_code == 200
        assert "dynamic.open" in granted.json()["policy"]["auto_approve_tools"]

        revoked = client.put(
            "/api/agent/autonomy",
            headers=HEADERS,
            json={"remove_tools": ["dynamic.open"]},
        )
        assert revoked.status_code == 200
        assert "dynamic.open" not in revoked.json()["policy"]["auto_approve_tools"]


def test_provider_saves_and_probes_report_bounded_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    providers_path = tmp_path / "providers.json"
    providers_path.write_text(
        json.dumps({"profiles": {"bad": 5}, "current": "default"}), encoding="utf-8"
    )
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        # A corrupt (non-dict) profile entry reads as "no existing profile":
        # the save still succeeds from the body alone.
        repaired = client.put(
            "/api/providers/bad",
            headers=HEADERS,
            json={"base_url": "https://example.invalid/v1", "model": "m"},
        )
        assert repaired.status_code == 200
        assert repaired.json()["profile"]["id"] == "bad"

        providers_path.write_text(
            json.dumps({"profiles": {"bad": 5}, "current": "default"}),
            encoding="utf-8",
        )
        unusable = client.put(
            "/api/providers/bad",
            headers=HEADERS,
            json={"base_url": "https://example.invalid/v1"},
        )
        assert unusable.status_code == 400

        probe_corrupt = client.post("/api/providers/bad/models", headers=HEADERS)
        assert probe_corrupt.status_code == 404

        import headless_re_mcp.web.routes.agent as agent_routes

        class _Listing:
            def __init__(self, profile, timeout=30.0):  # type: ignore[no-untyped-def]
                del profile, timeout

            async def list_models(self) -> list[str]:
                return ["model-b", "model-a"]

        monkeypatch.setattr(agent_routes, "OpenAICompatibleProvider", _Listing)
        listed = client.post("/api/providers/default/models", headers=HEADERS)
        assert listed.status_code == 200
        assert listed.json()["models"] == ["model-b", "model-a"]

        class _Empty(_Listing):
            async def list_models(self) -> list[str]:
                return []

        monkeypatch.setattr(agent_routes, "OpenAICompatibleProvider", _Empty)
        empty = client.post("/api/providers/default/models", headers=HEADERS)
        assert empty.status_code == 200
        assert empty.json()["models"] == []

        class _Refused(_Listing):
            async def list_models(self) -> list[str]:
                raise RuntimeError("quota exceeded " * 100)

        monkeypatch.setattr(agent_routes, "OpenAICompatibleProvider", _Refused)
        refused = client.post("/api/providers/default/models", headers=HEADERS)
        assert refused.status_code == 502
        detail = refused.json()["detail"]
        assert detail.startswith("provider_probe_failed:RuntimeError:")
        assert len(detail) <= len("provider_probe_failed:RuntimeError:") + 500


def test_zerofall_import_requires_a_config_object_and_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        not_dict = client.post(
            "/api/providers/zerofall/import", headers=HEADERS, json={"config": 5}
        )
        assert not_dict.status_code == 400
        assert not_dict.json()["detail"] == "config_required"

        unconfirmed = client.post(
            "/api/providers/zerofall/import",
            headers=HEADERS,
            json={"config": {"apiKey": "sk-zero"}},
        )
        assert unconfirmed.status_code == 400
        assert unconfirmed.json()["detail"] == "confirm_required"

        confirmed = client.post(
            "/api/providers/zerofall/import",
            headers=HEADERS,
            json={"config": {"apiKey": "sk-zero", "model": "m"}, "confirm": True},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["profile"]["id"] == "zerofall"
        assert "sk-zero" not in confirmed.text
