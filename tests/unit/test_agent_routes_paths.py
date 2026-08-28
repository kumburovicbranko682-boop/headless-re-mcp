"""Branch coverage for the agent/provider HTTP routes.

The existing test_agent_web_api.py drives the happy REST paths; this file fills
the error arms and a few narrow success paths (persona lifecycle, tool-call
decisions with remembered grants, the SSE replay loop, provider probing and
zerofall import) that were otherwise unexercised.

TestClient is used without its lifespan context on purpose: entering the
lifespan starts the MissionScheduler, and several tests here poke the store
directly (proposing tool calls, transitioning runs). Keeping the scheduler off
makes those deterministic. The lifespan wiring itself is covered elsewhere.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

TOKEN = "web-secret"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def _build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides: Any
) -> tuple[Any, TestClient]:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    # Keep grants pinned so autonomy assertions do not inherit host presets.
    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        agent_auto_approve_tools=(),
        agent_auto_approve_effects=(),
        **overrides,
    )
    service = AnalysisService(settings)
    app = create_app(service, token=TOKEN, settings=settings)
    return app, TestClient(app)


def _silence_config_writes(monkeypatch: pytest.MonkeyPatch, sink: dict[str, Any]) -> None:
    def fake_update(updates: dict[str, Any], *, config_path: Any = None) -> Path:
        sink.update(updates)
        return Path("/tmp/config.json")

    monkeypatch.setattr("headless_re_mcp.web.routes.agent.update_config_values", fake_update)


# ---------------------------------------------------------------------------
# thread validation arms
# ---------------------------------------------------------------------------


def test_thread_validation_and_not_found_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, client = _build(tmp_path, monkeypatch)

    bad_type = client.post(
        "/api/agent/threads", headers=HEADERS, json={"title": "t", "session_id": 5}
    )
    assert bad_type.status_code == 400
    assert bad_type.json()["detail"] == "invalid_session_id"

    thread_id = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"}).json()[
        "thread"
    ]["id"]

    missing_key = client.patch(f"/api/agent/threads/{thread_id}", headers=HEADERS, json={})
    assert missing_key.status_code == 400
    assert missing_key.json()["detail"] == "session_id_required"

    wrong_type = client.patch(
        f"/api/agent/threads/{thread_id}", headers=HEADERS, json={"session_id": 7}
    )
    assert wrong_type.status_code == 400
    assert wrong_type.json()["detail"] == "invalid_session_id"

    unknown = client.patch("/api/agent/threads/ghost", headers=HEADERS, json={"session_id": "s"})
    assert unknown.status_code == 404

    oversized = client.patch(
        f"/api/agent/threads/{thread_id}",
        headers=HEADERS,
        json={"session_id": "x" * 4096},
    )
    assert oversized.status_code == 400

    assert client.delete("/api/agent/threads/ghost", headers=HEADERS).status_code == 404


# ---------------------------------------------------------------------------
# persona lifecycle
# ---------------------------------------------------------------------------


def test_persona_import_select_delete_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, client = _build(tmp_path, monkeypatch)

    assert client.get("/api/agent/personas", headers=HEADERS).status_code == 200

    imported = client.post(
        "/api/agent/personas/import",
        headers=HEADERS,
        json={"title": "Focus", "content": "Stay on the unpacking objective."},
    )
    assert imported.status_code == 200
    new_id = imported.json()["current"]
    assert new_id not in {"default"}

    selected = client.post("/api/agent/personas/select", headers=HEADERS, json={"id": new_id})
    assert selected.status_code == 200

    # import via a real file path branch
    md = tmp_path / "extra.md"
    md.write_text("# From disk\nDrive the trace.", encoding="utf-8")
    from_path = client.post("/api/agent/personas/import", headers=HEADERS, json={"path": str(md)})
    assert from_path.status_code == 200

    deleted = client.delete(f"/api/agent/personas/{new_id}", headers=HEADERS)
    assert deleted.status_code == 200

    # error arms
    assert client.post("/api/agent/personas/select", headers=HEADERS, json={}).status_code == 400
    assert (
        client.post("/api/agent/personas/select", headers=HEADERS, json={"id": "nope"}).status_code
        == 404
    )
    assert client.post("/api/agent/personas/import", headers=HEADERS, json={}).status_code == 400
    empty = client.post("/api/agent/personas/import", headers=HEADERS, json={"content": "   "})
    assert empty.status_code == 400
    builtin = client.delete("/api/agent/personas/default", headers=HEADERS)
    assert builtin.status_code == 400
    assert client.delete("/api/agent/personas/ghost", headers=HEADERS).status_code == 404


# ---------------------------------------------------------------------------
# messages + runs
# ---------------------------------------------------------------------------


def test_add_message_and_run_lifecycle_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, client = _build(tmp_path, monkeypatch)
    store = app.state.agent_store
    orchestrator = app.state.agent_orchestrator

    thread_id = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"}).json()[
        "thread"
    ]["id"]

    blank = client.post(
        f"/api/agent/threads/{thread_id}/messages", headers=HEADERS, json={"content": " "}
    )
    assert blank.status_code == 400

    missing_thread = client.post(
        "/api/agent/threads/ghost/messages", headers=HEADERS, json={"content": "hi"}
    )
    assert missing_thread.status_code == 404

    # create_run: thread_id must be a string
    assert client.post("/api/agent/runs", headers=HEADERS, json={"thread_id": 9}).status_code == 400
    # create_run: message to a missing thread -> 404 from add_message
    assert (
        client.post(
            "/api/agent/runs",
            headers=HEADERS,
            json={"thread_id": "ghost", "message": "hi"},
        ).status_code
        == 404
    )
    # create_run: unknown thread without a message -> start_run's create_run
    # raises KeyError (the provider store synthesises a default profile, so the
    # miss surfaces from the thread lookup instead).
    assert (
        client.post("/api/agent/runs", headers=HEADERS, json={"thread_id": "ghost"}).status_code
        == 404
    )

    async def fake_start_run(tid: str, **kwargs: Any) -> dict[str, Any]:
        return {"id": "run-fake", "thread_id": tid, "status": "queued"}

    monkeypatch.setattr(orchestrator, "start_run", fake_start_run)
    ok = client.post(
        "/api/agent/runs",
        headers=HEADERS,
        json={"thread_id": thread_id, "message": "go", "model": "m", "profile_id": "p"},
    )
    assert ok.status_code == 202
    assert ok.json()["run_id"] == "run-fake"

    # get_run: unknown then real
    assert client.get("/api/agent/runs/ghost", headers=HEADERS).status_code == 404
    run = store.create_run(thread_id, provider_profile="default", model="m", deadline_seconds=30)
    fetched = client.get(f"/api/agent/runs/{run.id}", headers=HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["run"]["id"] == run.id

    # cancel_run: unknown -> 404, then a stubbed success
    assert client.post("/api/agent/runs/ghost/cancel", headers=HEADERS).status_code == 404

    async def fake_cancel(run_id: str) -> dict[str, Any]:
        return {"id": run_id, "status": "cancelled"}

    monkeypatch.setattr(orchestrator, "cancel", fake_cancel)
    cancelled = client.post(f"/api/agent/runs/{run.id}/cancel", headers=HEADERS)
    assert cancelled.status_code == 202
    assert cancelled.json()["run"]["status"] == "cancelled"


# ---------------------------------------------------------------------------
# tool-call decisions
# ---------------------------------------------------------------------------


def test_tool_call_decisions_and_remembered_grants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: dict[str, Any] = {}
    _silence_config_writes(monkeypatch, written)
    app, client = _build(tmp_path, monkeypatch)
    store = app.state.agent_store

    thread_id = store.create_thread(title="decisions").id
    run = store.create_run(thread_id, provider_profile="default", model="m", deadline_seconds=30)

    def _propose(call_id: str) -> str:
        call = store.propose_tool_call(
            run.id, call_id, "dynamic.launch", {"path": "sample.exe"}, ["state_change"]
        )
        return str(call["args_sha256"])

    # validation arms come before the orchestrator is touched
    short_sha = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/call-1/approve",
        headers=HEADERS,
        json={"args_sha256": "abc"},
    )
    assert short_sha.status_code == 400
    assert short_sha.json()["detail"] == "args_sha256_required"

    bad_remember = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/call-1/approve",
        headers=HEADERS,
        json={"args_sha256": "a" * 64, "remember": "sometimes"},
    )
    assert bad_remember.status_code == 400
    assert bad_remember.json()["detail"] == "remember_invalid"

    # unknown tool call on a live run -> KeyError -> 404
    not_found = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/ghost/approve",
        headers=HEADERS,
        json={"args_sha256": "a" * 64},
    )
    assert not_found.status_code == 404
    assert not_found.json()["detail"] == "tool_call_not_found"

    # approve remembering the tool
    sha1 = _propose("call-1")
    approved = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/call-1/approve",
        headers=HEADERS,
        json={"args_sha256": sha1, "remember": "tool"},
    )
    assert approved.status_code == 200
    assert "dynamic.launch" in approved.json()["policy"]["auto_approve_tools"]
    assert written["agent_auto_approve_tools"] == ["dynamic.launch"]

    # deciding the same call again is a conflict
    conflict = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/call-1/approve",
        headers=HEADERS,
        json={"args_sha256": sha1},
    )
    assert conflict.status_code == 409

    # approve remembering the effect class
    sha2 = _propose("call-2")
    effect_grant = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/call-2/approve",
        headers=HEADERS,
        json={"args_sha256": sha2, "remember": "effect"},
    )
    assert effect_grant.status_code == 200
    assert "state_change" in effect_grant.json()["policy"]["auto_approve_effects"]

    # reject path
    sha3 = _propose("call-3")
    rejected = client.post(
        f"/api/agent/runs/{run.id}/tool-calls/call-3/reject",
        headers=HEADERS,
        json={"args_sha256": sha3},
    )
    assert rejected.status_code == 200
    assert rejected.json()["tool_call"]["approved"] is False


# ---------------------------------------------------------------------------
# SSE events + history
# ---------------------------------------------------------------------------


def test_event_history_and_terminal_stream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app, client = _build(tmp_path, monkeypatch)
    store = app.state.agent_store

    thread_id = store.create_thread(title="events").id
    run = store.create_run(thread_id, provider_profile="default", model="m", deadline_seconds=30)
    store.append_event(run.id, "llm.started", {"round": 1})
    store.append_event(run.id, "llm.completed", {"round": 1})
    store.transition(run.id, RunStatus.FAILED, error="boom")

    assert client.get("/api/agent/runs/ghost/events/history", headers=HEADERS).status_code == 404
    history = client.get(f"/api/agent/runs/{run.id}/events/history", headers=HEADERS)
    assert history.status_code == 200
    types = [event["type"] for event in history.json()["events"]]
    assert "llm.started" in types

    assert client.get("/api/agent/runs/ghost/events", headers=HEADERS).status_code == 404

    # Terminal run: the generator emits the backlog then breaks, so the whole
    # body is finite and TestClient can read it to completion.
    streamed = client.get(f"/api/agent/runs/{run.id}/events", headers=HEADERS)
    assert streamed.status_code == 200
    assert "event: llm.started" in streamed.text
    assert "event: llm.completed" in streamed.text


def test_event_stream_ends_when_the_run_row_vanishes_mid_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After each batch the stream re-resolves the run to decide whether to
    keep waiting. A row that stops resolving mid-stream -- a purged store, a
    swapped database file -- must end the stream, not park the client on
    heartbeats for a run nobody can look up anymore."""
    app, client = _build(tmp_path, monkeypatch)
    store = app.state.agent_store

    thread_id = store.create_thread(title="vanish").id
    run = store.create_run(thread_id, provider_profile="default", model="m", deadline_seconds=30)
    store.append_event(run.id, "llm.started", {"round": 1})
    # The run stays non-terminal: only the vanish can end this stream.

    real_get_run = store.get_run
    lookups = {"count": 0}

    def vanishing(run_id: str) -> Any:
        lookups["count"] += 1
        if lookups["count"] == 1:
            return real_get_run(run_id)  # the route's own 404 pre-check
        return None  # gone by the first in-stream poll

    monkeypatch.setattr(store, "get_run", vanishing)

    streamed = client.get(f"/api/agent/runs/{run.id}/events", headers=HEADERS)

    assert streamed.status_code == 200, "the run still existed at the pre-check"
    assert "event: llm.started" in streamed.text, "the backlog was delivered first"
    assert "event: heartbeat" not in streamed.text
    assert lookups["count"] == 2, "the stream ended at the first failed poll"


def test_event_stream_emits_a_heartbeat_while_idle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    app, client = _build(tmp_path, monkeypatch)
    store = app.state.agent_store

    thread_id = store.create_thread(title="idle").id
    # A live, event-less run never terminates on its own. The loop must emit a
    # heartbeat after ~10 idle ticks (~2.5s). TestClient buffers the streamed
    # body, so make the stream finite by transitioning the run to a terminal
    # state after the heartbeat is due; the body then contains exactly one
    # heartbeat and the read completes.
    run = store.create_run(thread_id, provider_profile="default", model="m", deadline_seconds=30)
    timer = threading.Timer(4.0, lambda: store.transition(run.id, RunStatus.FAILED))
    timer.start()
    try:
        streamed = client.get(f"/api/agent/runs/{run.id}/events", headers=HEADERS)
    finally:
        timer.cancel()
    assert streamed.status_code == 200
    assert "event: heartbeat" in streamed.text


# ---------------------------------------------------------------------------
# missions extra arms
# ---------------------------------------------------------------------------


def test_mission_validation_and_lookup_arms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, client = _build(tmp_path, monkeypatch)
    store = app.state.agent_store

    bad_thread = client.post(
        "/api/agent/missions",
        headers=HEADERS,
        json={"objective": "do", "thread_id": 5},
    )
    assert bad_thread.status_code == 400
    assert bad_thread.json()["detail"] == "invalid_thread_id"

    # a provided, valid thread id takes the false arm of the auto-create check
    thread_id = store.create_thread(title="mission-thread").id
    with_thread = client.post(
        "/api/agent/missions",
        headers=HEADERS,
        json={"objective": "recover key", "thread_id": thread_id, "max_runs": 2},
    )
    assert with_thread.status_code == 201
    assert with_thread.json()["mission"]["thread_id"] == thread_id

    # a valid-but-unknown thread id reaches create_mission's KeyError -> 404
    unknown_thread = client.post(
        "/api/agent/missions",
        headers=HEADERS,
        json={"objective": "recover key", "thread_id": "ghost"},
    )
    assert unknown_thread.status_code == 404

    # a non-numeric max_runs fails validation (int() raises) -> 400
    bad_max = client.post(
        "/api/agent/missions",
        headers=HEADERS,
        json={"objective": "do", "max_runs": "lots"},
    )
    assert bad_max.status_code == 400

    bad_status = client.get("/api/agent/missions", headers=HEADERS, params={"status": "bogus"})
    assert bad_status.status_code == 400
    assert bad_status.json()["detail"] == "invalid_status"

    assert client.post("/api/agent/missions/ghost/cancel", headers=HEADERS).status_code == 404


# ---------------------------------------------------------------------------
# watchdog + autonomy lists
# ---------------------------------------------------------------------------


def test_watchdog_and_autonomy_list_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    written: dict[str, Any] = {}
    _silence_config_writes(monkeypatch, written)
    app, client = _build(tmp_path, monkeypatch)

    watchdog = client.get("/api/agent/watchdog", headers=HEADERS)
    assert watchdog.status_code == 200
    body = watchdog.json()
    assert body["ok"] is True
    assert "enabled" in body["policy"]
    assert "alerts" in body

    # add_tools must be a list
    bad_lists = client.put(
        "/api/agent/autonomy", headers=HEADERS, json={"add_tools": "dynamic.open"}
    )
    assert bad_lists.status_code == 400
    assert bad_lists.json()["detail"] == "autonomy_lists_required"

    # grant then revoke via the list form
    client.put("/api/agent/autonomy", headers=HEADERS, json={"add_tools": ["dynamic.open"]})
    revoked = client.put(
        "/api/agent/autonomy",
        headers=HEADERS,
        json={"add_tools": [], "remove_tools": ["dynamic.open"]},
    )
    assert revoked.status_code == 200
    assert "dynamic.open" not in revoked.json()["policy"]["auto_approve_tools"]

    # an unknown effect class is a 400 from grant()
    bad_effect = client.put(
        "/api/agent/autonomy", headers=HEADERS, json={"add_effects": ["not-an-effect"]}
    )
    assert bad_effect.status_code == 400


# ---------------------------------------------------------------------------
# providers: save, probe, zerofall
# ---------------------------------------------------------------------------


class _FakeProvider:
    def __init__(self, models: list[str] | None = None, error: Exception | None = None) -> None:
        self._models = models or []
        self._error = error

    async def list_models(self) -> list[str]:
        if self._error is not None:
            raise self._error
        return self._models


def test_save_provider_rejects_invalid_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, client = _build(tmp_path, monkeypatch)

    # An out-of-range compression threshold fails ProviderProfile validation
    # (base_url/model fall back to the store's synthesised defaults) -> 400.
    invalid = client.put(
        "/api/providers/fresh",
        headers=HEADERS,
        json={"context_compression_threshold_percent": 5},
    )
    assert invalid.status_code == 400


def test_probe_models_success_missing_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, client = _build(tmp_path, monkeypatch)

    saved = client.put(
        "/api/providers/default",
        headers=HEADERS,
        json={"base_url": "https://api.example.invalid/v1", "model": "m"},
    )
    assert saved.status_code == 200

    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider",
        lambda profile, timeout=30.0: _FakeProvider(models=["m1", "m2"]),
    )
    ok = client.post("/api/providers/default/models", headers=HEADERS)
    assert ok.status_code == 200
    assert ok.json()["models"] == ["m1", "m2"]

    # an empty model list skips the write-back and still answers ok
    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider",
        lambda profile, timeout=30.0: _FakeProvider(models=[]),
    )
    empty = client.post("/api/providers/default/models", headers=HEADERS)
    assert empty.status_code == 200
    assert empty.json()["models"] == []

    # a short failure keeps its whole message (no truncation)
    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider",
        lambda profile, timeout=30.0: _FakeProvider(error=RuntimeError("boom")),
    )
    short = client.post("/api/providers/default/models", headers=HEADERS)
    assert short.status_code == 502
    assert short.json()["detail"] == "provider_probe_failed:RuntimeError:boom"

    long_error = RuntimeError("401 unauthorized " + "x" * 800)
    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider",
        lambda profile, timeout=30.0: _FakeProvider(error=long_error),
    )
    failed = client.post("/api/providers/default/models", headers=HEADERS)
    assert failed.status_code == 502
    detail = failed.json()["detail"]
    assert detail.startswith("provider_probe_failed:RuntimeError:")
    # bounded to 500 chars of message after the prefix
    assert len(detail) < 600


def test_zerofall_import_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _build(tmp_path, monkeypatch)

    missing = client.post(
        "/api/providers/zerofall/import", headers=HEADERS, json={"config": "nope"}
    )
    assert missing.status_code == 400
    assert missing.json()["detail"] == "config_required"

    unconfirmed = client.post(
        "/api/providers/zerofall/import",
        headers=HEADERS,
        json={"config": {"apiKey": "sk-x", "model": "m"}},
    )
    assert unconfirmed.status_code == 400

    imported = client.post(
        "/api/providers/zerofall/import",
        headers=HEADERS,
        json={
            "config": {
                "apiKey": "sk-secret-value",
                "model": "gpt-x",
                "ai": {"apiBaseUrl": "https://api.example.invalid/v1"},
            },
            "confirm": True,
        },
    )
    assert imported.status_code == 200
    assert imported.json()["profile"]["id"] == "zerofall"
    assert "sk-secret-value" not in imported.text
