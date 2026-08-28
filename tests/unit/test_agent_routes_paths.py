"""Coverage for the agent web routes' validation and error arms.

Drives ``register_agent_routes`` through a real FastAPI ``TestClient``:
thread/persona/message guards, run lifecycle over the store, tool-call
approval arms (including remembered grants), the replayable SSE stream,
missions, autonomy edge arms, and the provider endpoints with a faked
OpenAI-compatible provider.
"""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.orchestrator import AgentOrchestrator
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

_TOKEN = "web-secret"
_HEADERS = {"Authorization": f"Bearer {_TOKEN}"}
_SHA = "0" * 64


def _build_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.update_config_values",
        lambda updates, *, config_path=None: tmp_path / "config.json",
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app: FastAPI = create_app(AnalysisService(settings), token=_TOKEN, settings=settings)
    return app


def _thread(client: TestClient) -> str:
    created = client.post("/api/agent/threads", headers=_HEADERS, json={"title": "T"})
    assert created.status_code == 201
    return str(created.json()["thread"]["id"])


async def _noop_execute(self: AgentOrchestrator, run_id: str) -> None:
    return None


def test_thread_and_message_validation_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad_create = client.post(
            "/api/agent/threads", headers=_HEADERS, json={"title": "T", "session_id": 7}
        )
        assert bad_create.status_code == 400

        thread_id = _thread(client)
        no_key = client.patch(f"/api/agent/threads/{thread_id}", headers=_HEADERS, json={})
        assert no_key.status_code == 400
        assert no_key.json()["detail"] == "session_id_required"
        bad_type = client.patch(
            f"/api/agent/threads/{thread_id}", headers=_HEADERS, json={"session_id": 7}
        )
        assert bad_type.status_code == 400
        missing = client.patch(
            "/api/agent/threads/nope", headers=_HEADERS, json={"session_id": "s"}
        )
        assert missing.status_code == 404
        overlong = client.patch(
            f"/api/agent/threads/{thread_id}",
            headers=_HEADERS,
            json={"session_id": "x" * 1024},
        )
        assert overlong.status_code == 400

        assert client.delete("/api/agent/threads/nope", headers=_HEADERS).status_code == 404

        empty = client.post(
            f"/api/agent/threads/{thread_id}/messages", headers=_HEADERS, json={"content": "  "}
        )
        assert empty.status_code == 400
        orphan = client.post(
            "/api/agent/threads/nope/messages", headers=_HEADERS, json={"content": "hello"}
        )
        assert orphan.status_code == 404


def test_persona_selection_import_and_delete_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        blank = client.post("/api/agent/personas/select", headers=_HEADERS, json={"id": "  "})
        assert blank.status_code == 400
        unknown = client.post(
            "/api/agent/personas/select", headers=_HEADERS, json={"id": "no-such-persona"}
        )
        assert unknown.status_code == 404

        markdown = tmp_path / "persona.md"
        markdown.write_text("# Analyst\nBe thorough.\n")
        imported = client.post(
            "/api/agent/personas/import", headers=_HEADERS, json={"path": str(markdown)}
        )
        assert imported.status_code == 200
        assert any(not item["builtin"] for item in imported.json()["personas"])

        sourceless = client.post("/api/agent/personas/import", headers=_HEADERS, json={})
        assert sourceless.status_code == 400
        assert sourceless.json()["detail"] == "persona_source_required"
        empty = client.post("/api/agent/personas/import", headers=_HEADERS, json={"content": "   "})
        assert empty.status_code == 400

        assert (
            client.delete("/api/agent/personas/no-such-persona", headers=_HEADERS).status_code
            == 404
        )
        builtin = client.delete("/api/agent/personas/default", headers=_HEADERS)
        assert builtin.status_code == 400
        assert builtin.json()["detail"] == "persona_builtin"


def test_run_creation_lookup_and_cancel_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(AgentOrchestrator, "_execute", _noop_execute)
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad_thread = client.post("/api/agent/runs", headers=_HEADERS, json={"thread_id": 7})
        assert bad_thread.status_code == 400

        with_message = client.post(
            "/api/agent/runs",
            headers=_HEADERS,
            json={"thread_id": "nope", "message": "look at this"},
        )
        assert with_message.status_code == 404

        without_message = client.post(
            "/api/agent/runs", headers=_HEADERS, json={"thread_id": "nope"}
        )
        assert without_message.status_code == 404

        thread_id = _thread(client)
        accepted = client.post(
            "/api/agent/runs",
            headers=_HEADERS,
            json={"thread_id": thread_id, "message": "go"},
        )
        assert accepted.status_code == 202
        run_id = accepted.json()["run_id"]

        assert client.get("/api/agent/runs/nope", headers=_HEADERS).status_code == 404
        fetched = client.get(f"/api/agent/runs/{run_id}", headers=_HEADERS)
        assert fetched.status_code == 200
        assert fetched.json()["run"]["id"] == run_id

        assert client.post("/api/agent/runs/nope/cancel", headers=_HEADERS).status_code == 404
        cancelled = client.post(f"/api/agent/runs/{run_id}/cancel", headers=_HEADERS)
        assert cancelled.status_code == 202
        assert cancelled.json()["run"]["cancel_requested"] is True


def test_tool_call_decisions_and_remembered_grants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        thread_id = _thread(client)
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        base = f"/api/agent/runs/{run.id}/tool-calls"

        missing_sha = client.post(f"{base}/call-x/approve", headers=_HEADERS, json={})
        assert missing_sha.status_code == 400
        assert missing_sha.json()["detail"] == "args_sha256_required"
        bad_remember = client.post(
            f"{base}/call-x/approve",
            headers=_HEADERS,
            json={"args_sha256": _SHA, "remember": "forever"},
        )
        assert bad_remember.status_code == 400
        unknown_call = client.post(
            f"{base}/call-x/approve", headers=_HEADERS, json={"args_sha256": _SHA}
        )
        assert unknown_call.status_code == 404

        first = store.propose_tool_call(
            run.id, "call-1", "dynamic.launch", {"path": "C:/x.exe"}, ["process_spawn"]
        )
        mismatch = client.post(
            f"{base}/call-1/approve", headers=_HEADERS, json={"args_sha256": _SHA}
        )
        assert mismatch.status_code == 409

        remembered_tool = client.post(
            f"{base}/call-1/approve",
            headers=_HEADERS,
            json={"args_sha256": first["args_sha256"], "remember": "tool"},
        )
        assert remembered_tool.status_code == 200
        body = remembered_tool.json()
        assert body["tool_call"]["approved"] is True
        assert "dynamic.launch" in body["policy"]["auto_approve_tools"]

        second = store.propose_tool_call(
            run.id, "call-2", "dynamic.launch", {"path": "C:/y.exe"}, ["process_spawn"]
        )
        remembered_effect = client.post(
            f"{base}/call-2/approve",
            headers=_HEADERS,
            json={"args_sha256": second["args_sha256"], "remember": "effect"},
        )
        assert remembered_effect.status_code == 200
        assert remembered_effect.json()["policy"]["auto_approve_effects"]

        third = store.propose_tool_call(
            run.id, "call-3", "dynamic.launch", {"path": "C:/z.exe"}, ["process_spawn"]
        )
        rejected = client.post(
            f"{base}/call-3/reject",
            headers=_HEADERS,
            json={"args_sha256": third["args_sha256"]},
        )
        assert rejected.status_code == 200
        assert rejected.json()["tool_call"]["approved"] is False


def test_event_stream_replays_and_stops_on_a_terminal_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        assert client.get("/api/agent/runs/nope/events", headers=_HEADERS).status_code == 404

        thread_id = _thread(client)
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        store.append_event(run.id, "llm.started", {"round": 1})
        store.append_event(run.id, "llm.completed", {"round": 1})
        store.transition(run.id, RunStatus.FAILED, error="stopped for the test")

        with client.stream("GET", f"/api/agent/runs/{run.id}/events", headers=_HEADERS) as sse:
            assert sse.status_code == 200
            text = "".join(chunk for chunk in sse.iter_text())
        assert "event: llm.started" in text
        assert "event: llm.completed" in text
        assert "event: run.started" in text

        assert (
            client.get("/api/agent/runs/nope/events/history", headers=_HEADERS).status_code == 404
        )
        history = client.get(f"/api/agent/runs/{run.id}/events/history", headers=_HEADERS)
        assert history.status_code == 200
        assert [event["type"] for event in history.json()["events"]][-1] == "llm.completed"


def test_event_stream_emits_a_heartbeat_while_idle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        thread_id = _thread(client)
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        # The run stays queued (non-terminal) and quiet, so after ten idle
        # polls (2.5s) the stream must emit a heartbeat instead of new events.
        # The generator only stops on a terminal run and the test client
        # buffers the body, so fail the run from a timer once the heartbeat
        # has certainly been emitted, then assert on the completed stream.
        timer = threading.Timer(
            4.0, store.transition, args=(run.id, RunStatus.FAILED), kwargs={"error": "stop"}
        )
        timer.start()
        try:
            response = client.get(f"/api/agent/runs/{run.id}/events?after=1", headers=_HEADERS)
        finally:
            timer.cancel()
        assert response.status_code == 200
        assert "event: heartbeat" in response.text


def test_mission_validation_watchdog_and_status_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad_thread = client.post(
            "/api/agent/missions",
            headers=_HEADERS,
            json={"objective": "map the packer", "thread_id": 7},
        )
        assert bad_thread.status_code == 400
        orphan = client.post(
            "/api/agent/missions",
            headers=_HEADERS,
            json={"objective": "map the packer", "thread_id": "nope"},
        )
        assert orphan.status_code == 404

        thread_id = _thread(client)
        queued = client.post(
            "/api/agent/missions",
            headers=_HEADERS,
            json={"objective": "map the packer", "thread_id": thread_id},
        )
        assert queued.status_code == 201
        assert queued.json()["mission"]["thread_id"] == thread_id

        bad_status = client.get("/api/agent/missions?status=bogus", headers=_HEADERS)
        assert bad_status.status_code == 400

        assert client.post("/api/agent/missions/nope/cancel", headers=_HEADERS).status_code == 404

        watchdog = client.get("/api/agent/watchdog", headers=_HEADERS)
        assert watchdog.status_code == 200
        assert "policy" in watchdog.json()


def test_autonomy_update_edge_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        not_lists = client.put(
            "/api/agent/autonomy", headers=_HEADERS, json={"add_tools": "dynamic.open"}
        )
        assert not_lists.status_code == 400
        assert not_lists.json()["detail"] == "autonomy_lists_required"

        revoked = client.put(
            "/api/agent/autonomy",
            headers=_HEADERS,
            json={"add_tools": ["dynamic.open"], "remove_tools": ["dynamic.open"]},
        )
        assert revoked.status_code == 200
        assert "dynamic.open" not in revoked.json()["policy"]["auto_approve_tools"]

        bad_effect = client.put(
            "/api/agent/autonomy", headers=_HEADERS, json={"add_effects": ["bogus_effect"]}
        )
        assert bad_effect.status_code == 400


class _FakeProvider:
    models: list[str] = ["m-b", "m-a"]
    error: Exception | None = None

    def __init__(self, profile: Any, timeout: float) -> None:
        self.profile = profile

    async def list_models(self) -> list[str]:
        error = type(self).error
        if error is not None:
            raise error
        return list(type(self).models)


def test_provider_save_probe_and_zerofall_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "providers.json").write_text(
        json.dumps({"current": "default", "profiles": {"broken": "junk"}})
    )
    app = _build_app(tmp_path, monkeypatch)
    monkeypatch.setattr("headless_re_mcp.web.routes.agent.OpenAICompatibleProvider", _FakeProvider)
    with TestClient(app) as client:
        # The stored profile entry is not an object, so the lookup raises and
        # the route must treat it as a brand-new profile.
        repaired = client.put(
            "/api/providers/broken",
            headers=_HEADERS,
            json={"base_url": "https://example.invalid/v1", "model": "m"},
        )
        assert repaired.status_code == 200

        bad_threshold = client.put(
            "/api/providers/default",
            headers=_HEADERS,
            json={
                "base_url": "https://example.invalid/v1",
                "model": "m",
                "context_compression_threshold_percent": "lots",
            },
        )
        assert bad_threshold.status_code == 400

        _FakeProvider.error = None
        probed = client.post("/api/providers/broken/models", headers=_HEADERS)
        assert probed.status_code == 200
        assert probed.json()["models"] == ["m-b", "m-a"]
        listed = client.get("/api/providers", headers=_HEADERS).json()
        stored = next(item for item in listed["profiles"] if item["id"] == "broken")
        assert stored["known_models"] == ["m-b", "m-a"]

        _FakeProvider.error = KeyError("broken")
        assert client.post("/api/providers/broken/models", headers=_HEADERS).status_code == 404

        _FakeProvider.error = RuntimeError("quota exceeded " * 60)
        failed = client.post("/api/providers/broken/models", headers=_HEADERS)
        _FakeProvider.error = None
        assert failed.status_code == 502
        detail = failed.json()["detail"]
        assert detail.startswith("provider_probe_failed:RuntimeError:")
        assert len(detail) <= len("provider_probe_failed:RuntimeError:") + 500

        not_dict = client.post(
            "/api/providers/zerofall/import", headers=_HEADERS, json={"config": "x"}
        )
        assert not_dict.status_code == 400
        unconfirmed = client.post(
            "/api/providers/zerofall/import", headers=_HEADERS, json={"config": {}}
        )
        assert unconfirmed.status_code == 400
        assert unconfirmed.json()["detail"] == "confirm_required"
        imported = client.post(
            "/api/providers/zerofall/import",
            headers=_HEADERS,
            json={"config": {"model": "gpt-x"}, "confirm": True},
        )
        assert imported.status_code == 200
        assert imported.json()["profile"]["id"] == "zerofall"
