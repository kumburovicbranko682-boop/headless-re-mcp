"""Error contracts and less-travelled branches of the agent HTTP routes.

test_agent_web_api.py pins the happy paths (create a thread, save a provider,
queue a mission, read autonomy). What is covered here is the guard lattice
around them -- the 400/404/409/413/502 an unattended caller must be able to tell
apart -- plus the persona, decision, SSE-events and provider-probe endpoints
that the happy-path file does not exercise. Every test drives the real app
through a TestClient with a fake service; no provider network call succeeds.
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

_HEADERS = {"Authorization": "Bearer web-secret"}


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, TestClient]:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    return app, TestClient(app)


def _thread(client: TestClient, title: str = "T") -> str:
    created = client.post("/api/agent/threads", headers=_HEADERS, json={"title": title})
    assert created.status_code == 201
    return created.json()["thread"]["id"]


# --------------------------------------------------------------------------
# thread guards
# --------------------------------------------------------------------------
def test_thread_endpoints_reject_bad_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _client(tmp_path, monkeypatch)
    # A non-string session_id on create is a client error.
    bad_create = client.post(
        "/api/agent/threads", headers=_HEADERS, json={"title": "x", "session_id": 123}
    )
    assert bad_create.status_code == 400

    thread_id = _thread(client)
    # bind without the key, with a bad type, and against a missing thread.
    assert client.patch(f"/api/agent/threads/{thread_id}", headers=_HEADERS, json={}).status_code == 400
    assert (
        client.patch(
            f"/api/agent/threads/{thread_id}", headers=_HEADERS, json={"session_id": 5}
        ).status_code
        == 400
    )
    assert (
        client.patch(
            "/api/agent/threads/missing", headers=_HEADERS, json={"session_id": "s"}
        ).status_code
        == 404
    )
    # delete of a missing thread is a 404, not a silent success.
    assert client.delete("/api/agent/threads/missing", headers=_HEADERS).status_code == 404


# --------------------------------------------------------------------------
# personas
# --------------------------------------------------------------------------
def test_persona_endpoints_import_select_and_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, client = _client(tmp_path, monkeypatch)
    assert client.get("/api/agent/personas", headers=_HEADERS).status_code == 200

    # select guards: blank id -> 400, unknown id -> 404.
    assert client.post("/api/agent/personas/select", headers=_HEADERS, json={}).status_code == 400
    assert (
        client.post(
            "/api/agent/personas/select", headers=_HEADERS, json={"id": "nope"}
        ).status_code
        == 404
    )

    # import guards: no source -> 400, empty body -> 400.
    assert client.post("/api/agent/personas/import", headers=_HEADERS, json={}).status_code == 400
    assert (
        client.post(
            "/api/agent/personas/import", headers=_HEADERS, json={"content": ""}
        ).status_code
        == 400
    )

    # import from a real file path (the path branch of import_persona).
    persona_file = tmp_path / "from_disk.md"
    persona_file.write_text("# On Disk\nStay focused.")
    from_path = client.post(
        "/api/agent/personas/import",
        headers=_HEADERS,
        json={"path": str(persona_file)},
    )
    assert from_path.status_code == 200

    # import a real persona from inline markdown, then select and delete it.
    imported = client.post(
        "/api/agent/personas/import",
        headers=_HEADERS,
        json={"title": "Custom", "content": "# Custom\nBe careful."},
    )
    assert imported.status_code == 200
    new_id = next(
        item["id"]
        for item in imported.json()["personas"]
        if item["id"] not in {"default", "seagull"}
    )
    assert client.post(
        "/api/agent/personas/select", headers=_HEADERS, json={"id": new_id}
    ).status_code == 200
    assert client.delete(f"/api/agent/personas/{new_id}", headers=_HEADERS).status_code == 200

    # delete guards: unknown -> 404, built-in -> 400.
    assert client.delete("/api/agent/personas/nope", headers=_HEADERS).status_code == 404
    assert client.delete("/api/agent/personas/default", headers=_HEADERS).status_code == 400


# --------------------------------------------------------------------------
# messages and runs
# --------------------------------------------------------------------------
def test_message_and_run_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _client(tmp_path, monkeypatch)
    thread_id = _thread(client)
    # blank content -> 400, missing thread -> 404.
    assert (
        client.post(
            f"/api/agent/threads/{thread_id}/messages", headers=_HEADERS, json={"content": " "}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/agent/threads/missing/messages", headers=_HEADERS, json={"content": "hi"}
        ).status_code
        == 404
    )
    # run without a thread_id -> 400 (thread_id_required).
    assert client.post("/api/agent/runs", headers=_HEADERS, json={}).status_code == 400
    # a message for a missing thread -> 404 from add_message (thread_not_found).
    assert (
        client.post(
            "/api/agent/runs", headers=_HEADERS, json={"thread_id": "missing", "message": "hi"}
        ).status_code
        == 404
    )
    # a missing thread with no message -> 404 from start_run
    # (thread_or_profile_not_found).
    assert (
        client.post(
            "/api/agent/runs", headers=_HEADERS, json={"thread_id": "missing"}
        ).status_code
        == 404
    )
    # a real thread with the seeded default profile starts -> 202.
    assert (
        client.post(
            "/api/agent/runs", headers=_HEADERS, json={"thread_id": thread_id}
        ).status_code
        == 202
    )


def test_run_read_and_cancel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app, client = _client(tmp_path, monkeypatch)
    store = app.state.agent_store
    thread_id = _thread(client)
    run = store.create_run(thread_id, provider_profile="default", model="fake", deadline_seconds=30)

    fetched = client.get(f"/api/agent/runs/{run.id}", headers=_HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["run"]["id"] == run.id
    assert client.get("/api/agent/runs/missing", headers=_HEADERS).status_code == 404

    cancelled = client.post(f"/api/agent/runs/{run.id}/cancel", headers=_HEADERS)
    assert cancelled.status_code == 202
    assert client.post("/api/agent/runs/missing/cancel", headers=_HEADERS).status_code == 404


# --------------------------------------------------------------------------
# approve / reject
# --------------------------------------------------------------------------
def test_decision_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app, client = _client(tmp_path, monkeypatch)
    store = app.state.agent_store
    thread_id = _thread(client)
    run = store.create_run(thread_id, provider_profile="default", model="fake", deadline_seconds=30)
    sha = "a" * 64

    # missing / short args_sha256 -> 400.
    assert (
        client.post(
            f"/api/agent/runs/{run.id}/tool-calls/tc/approve", headers=_HEADERS, json={}
        ).status_code
        == 400
    )
    # invalid remember value -> 400.
    assert (
        client.post(
            f"/api/agent/runs/{run.id}/tool-calls/tc/approve",
            headers=_HEADERS,
            json={"args_sha256": sha, "remember": "sometimes"},
        ).status_code
        == 400
    )
    # a real, non-terminal run but an unknown tool call -> 404.
    assert (
        client.post(
            f"/api/agent/runs/{run.id}/tool-calls/missing/approve",
            headers=_HEADERS,
            json={"args_sha256": sha},
        ).status_code
        == 404
    )
    # a run that does not exist is terminal-or-missing -> 409.
    assert (
        client.post(
            "/api/agent/runs/missing/tool-calls/tc/reject",
            headers=_HEADERS,
            json={"args_sha256": sha},
        ).status_code
        == 409
    )


def test_approve_with_remember_grants_and_returns_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, client = _client(tmp_path, monkeypatch)
    store = app.state.agent_store
    thread_id = _thread(client)

    # remember="tool" records the approval and folds the tool into the policy.
    run_tool = store.create_run(
        thread_id, provider_profile="default", model="fake", deadline_seconds=30
    )
    proposed = store.propose_tool_call(
        run_tool.id, "call-1", "dynamic.open", {"path": "/tmp/x"}, ["read_only"]
    )
    approved = client.post(
        f"/api/agent/runs/{run_tool.id}/tool-calls/call-1/approve",
        headers=_HEADERS,
        json={"args_sha256": proposed["args_sha256"], "remember": "tool"},
    )
    assert approved.status_code == 200
    assert "dynamic.open" in approved.json()["policy"]["auto_approve_tools"]

    # remember="effect" walks the effect branch of the same helper.
    run_effect = store.create_run(
        thread_id, provider_profile="default", model="fake", deadline_seconds=30
    )
    proposed_effect = store.propose_tool_call(
        run_effect.id, "call-2", "dynamic.open", {"path": "/tmp/y"}, ["read_only"]
    )
    remembered = client.post(
        f"/api/agent/runs/{run_effect.id}/tool-calls/call-2/approve",
        headers=_HEADERS,
        json={"args_sha256": proposed_effect["args_sha256"], "remember": "effect"},
    )
    assert remembered.status_code == 200
    assert "policy" in remembered.json()

    # A plain approve (no remember) records the decision but leaves the policy
    # out of the payload.
    run_plain = store.create_run(
        thread_id, provider_profile="default", model="fake", deadline_seconds=30
    )
    proposed_plain = store.propose_tool_call(
        run_plain.id, "call-3", "dynamic.open", {"path": "/tmp/z"}, ["read_only"]
    )
    plain = client.post(
        f"/api/agent/runs/{run_plain.id}/tool-calls/call-3/approve",
        headers=_HEADERS,
        json={"args_sha256": proposed_plain["args_sha256"]},
    )
    assert plain.status_code == 200
    assert "policy" not in plain.json()


# --------------------------------------------------------------------------
# events + history
# --------------------------------------------------------------------------
def test_event_history_and_stream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app, client = _client(tmp_path, monkeypatch)
    store = app.state.agent_store
    thread_id = _thread(client)
    run = store.create_run(thread_id, provider_profile="default", model="fake", deadline_seconds=30)
    store.append_event(run.id, "llm.started", {"round": 1})
    # A terminal run makes the SSE generator drain and stop instead of hanging.
    store.transition(run.id, RunStatus.CANCELLED)

    assert client.get("/api/agent/runs/missing/events/history", headers=_HEADERS).status_code == 404
    history = client.get(f"/api/agent/runs/{run.id}/events/history", headers=_HEADERS)
    assert history.status_code == 200
    assert any(e["type"] == "llm.started" for e in history.json()["events"])

    assert client.get("/api/agent/runs/missing/events", headers=_HEADERS).status_code == 404
    stream = client.get(f"/api/agent/runs/{run.id}/events", headers=_HEADERS)
    assert stream.status_code == 200
    assert "llm.started" in stream.text


# --------------------------------------------------------------------------
# missions
# --------------------------------------------------------------------------
def test_mission_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _client(tmp_path, monkeypatch)
    # non-string thread_id -> 400.
    assert (
        client.post(
            "/api/agent/missions", headers=_HEADERS, json={"objective": "x", "thread_id": 5}
        ).status_code
        == 400
    )
    # a max_runs that is not a number -> 400 from validate_mission.
    assert (
        client.post(
            "/api/agent/missions",
            headers=_HEADERS,
            json={"objective": "x", "max_runs": "lots"},
        ).status_code
        == 400
    )
    # a valid objective but a thread that does not exist -> 404.
    assert (
        client.post(
            "/api/agent/missions",
            headers=_HEADERS,
            json={"objective": "recover the key", "thread_id": "missing"},
        ).status_code
        == 404
    )
    # an invalid status filter on the list -> 400.
    assert (
        client.get("/api/agent/missions?status=weird", headers=_HEADERS).status_code == 400
    )
    # cancel of a missing mission -> 404.
    assert (
        client.post("/api/agent/missions/missing/cancel", headers=_HEADERS).status_code == 404
    )


# --------------------------------------------------------------------------
# watchdog + autonomy list validation
# --------------------------------------------------------------------------
def test_watchdog_and_autonomy_list_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.update_config_values",
        lambda updates, *, config_path=None: tmp_path / "config.json",
    )
    _, client = _client(tmp_path, monkeypatch)
    assert client.get("/api/agent/watchdog", headers=_HEADERS).status_code == 200

    # A non-list where a list is required is a client error.
    assert (
        client.put(
            "/api/agent/autonomy", headers=_HEADERS, json={"add_tools": "not-a-list"}
        ).status_code
        == 400
    )
    # An unknown effect class is rejected by the policy as a 400.
    assert (
        client.put(
            "/api/agent/autonomy", headers=_HEADERS, json={"add_effects": ["not-an-effect"]}
        ).status_code
        == 400
    )
    # Grant then revoke a tool to exercise the revoke branch.
    granted = client.put(
        "/api/agent/autonomy", headers=_HEADERS, json={"add_tools": ["dynamic.open"]}
    )
    assert granted.status_code == 200
    revoked = client.put(
        "/api/agent/autonomy",
        headers=_HEADERS,
        json={"add_tools": [], "remove_tools": ["dynamic.open"]},
    )
    assert revoked.status_code == 200
    assert "dynamic.open" not in revoked.json()["policy"]["auto_approve_tools"]


# --------------------------------------------------------------------------
# providers: save update, probe, zerofall import
# --------------------------------------------------------------------------
def test_provider_save_update_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _client(tmp_path, monkeypatch)
    first = client.put(
        "/api/providers/default",
        headers=_HEADERS,
        json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
    )
    assert first.status_code == 200
    # A second save with no api_key reuses the stored one (the existing branch).
    second = client.put(
        "/api/providers/default",
        headers=_HEADERS,
        json={"base_url": "https://example.invalid/v1", "model": "fake2"},
    )
    assert second.status_code == 200
    # A malformed base_url is rejected by ProviderProfile as a 400.
    bad = client.put(
        "/api/providers/broken",
        headers=_HEADERS,
        json={"base_url": "not-a-url", "model": "fake"},
    )
    assert bad.status_code == 400


def test_save_provider_over_corrupt_profile_starts_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json as _json

    _, client = _client(tmp_path, monkeypatch)
    # A stored profile that is not a mapping makes configs.get raise KeyError;
    # the save treats it as absent and writes a fresh profile rather than 500.
    (tmp_path / "providers.json").write_text(
        _json.dumps({"profiles": {"corrupt": "not-a-mapping"}})
    )
    saved = client.put(
        "/api/providers/corrupt",
        headers=_HEADERS,
        json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
    )
    assert saved.status_code == 200
    assert saved.json()["profile"]["id"] == "corrupt"


def test_probe_models_persists_discovered_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FakeProvider:
        def __init__(self, profile: Any, timeout: float | None = None) -> None:
            self._profile = profile

        async def list_models(self) -> list[str]:
            return ["m-b", "m-a"]

    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider", _FakeProvider
    )
    _, client = _client(tmp_path, monkeypatch)
    client.put(
        "/api/providers/good",
        headers=_HEADERS,
        json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
    )
    probed = client.post("/api/providers/good/models", headers=_HEADERS)
    assert probed.status_code == 200
    assert probed.json()["models"] == ["m-b", "m-a"]
    # The discovered ids are folded back into the stored profile.
    listed = client.get("/api/providers", headers=_HEADERS)
    profiles = listed.json()["profiles"]
    good = next(p for p in profiles if p["id"] == "good")
    assert good["known_models"] == ["m-b", "m-a"]


def test_probe_models_with_empty_result_reports_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _EmptyProvider:
        def __init__(self, profile: Any, timeout: float | None = None) -> None:
            self._profile = profile

        async def list_models(self) -> list[str]:
            return []

    monkeypatch.setattr(
        "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider", _EmptyProvider
    )
    _, client = _client(tmp_path, monkeypatch)
    client.put(
        "/api/providers/empty",
        headers=_HEADERS,
        json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
    )
    # An empty catalogue is still a 200 -- the probe reached the server, there
    # was simply nothing to persist.
    probed = client.post("/api/providers/empty/models", headers=_HEADERS)
    assert probed.status_code == 200
    assert probed.json()["models"] == []


def test_probe_models_reports_missing_profile_and_provider_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json as _json

    _, client = _client(tmp_path, monkeypatch)
    # A profile stored as a non-dict value cannot be built -> KeyError -> 404.
    config_path = tmp_path / "providers.json"
    config_path.write_text(_json.dumps({"profiles": {"broken": "not-a-mapping"}}))
    assert client.post("/api/providers/broken/models", headers=_HEADERS).status_code == 404
    # A saved profile pointing nowhere reachable becomes a bounded 502.
    client.put(
        "/api/providers/unreachable",
        headers=_HEADERS,
        json={"base_url": "http://127.0.0.1:1/v1", "model": "fake", "api_key": "k"},
    )
    probed = client.post("/api/providers/unreachable/models", headers=_HEADERS)
    assert probed.status_code == 502
    assert probed.json()["detail"].startswith("provider_probe_failed:")


def test_zerofall_import_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = _client(tmp_path, monkeypatch)
    # A missing config object is a client error.
    assert (
        client.post("/api/providers/zerofall/import", headers=_HEADERS, json={}).status_code == 400
    )
    # A config dict without confirmation is refused as a 400.
    refused = client.post(
        "/api/providers/zerofall/import",
        headers=_HEADERS,
        json={"config": {"apiKey": "k", "model": "fake"}},
    )
    assert refused.status_code == 400

    # The same config, confirmed, imports into a saved profile.
    imported = client.post(
        "/api/providers/zerofall/import",
        headers=_HEADERS,
        json={"config": {"apiKey": "k", "model": "fake"}, "confirm": True},
    )
    assert imported.status_code == 200
    assert imported.json()["profile"]["id"] == "zerofall"
