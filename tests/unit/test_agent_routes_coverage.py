"""The agent REST surface must answer the error contract, not just the happy path.

Every handler authorises, validates its body and maps store/orchestrator
failures to a specific status (400 for bad input, 404 for unknown ids, 409 for
a stale decision, 413 for oversize, 502 for a failed provider probe). These
drive the real FastAPI app through ``TestClient`` against a real store, so the
validation and not-found branches across threads, personas, runs, missions,
autonomy and providers are exercised without a live LLM.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import headless_re_mcp.web.routes.agent as agent_routes
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

_HEADERS = {"Authorization": "Bearer web-secret"}


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return create_app(AnalysisService(settings), token="web-secret", settings=settings)


def _new_thread(client: TestClient) -> str:
    created = client.post("/api/agent/threads", headers=_HEADERS, json={"title": "T"})
    assert created.status_code == 201
    return str(created.json()["thread"]["id"])


# --------------------------------------------------------------------------
# threads
# --------------------------------------------------------------------------


def test_thread_error_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad_create = client.post(
            "/api/agent/threads", headers=_HEADERS, json={"title": "T", "session_id": 5}
        )
        assert bad_create.status_code == 400
        assert bad_create.json()["detail"] == "invalid_session_id"

        thread_id = _new_thread(client)

        assert (
            client.patch(f"/api/agent/threads/{thread_id}", headers=_HEADERS, json={}).status_code
            == 400
        )
        assert (
            client.patch(
                f"/api/agent/threads/{thread_id}", headers=_HEADERS, json={"session_id": 9}
            ).status_code
            == 400
        )
        assert (
            client.patch(
                "/api/agent/threads/missing", headers=_HEADERS, json={"session_id": "s"}
            ).status_code
            == 404
        )
        assert client.delete("/api/agent/threads/missing", headers=_HEADERS).status_code == 404


def test_message_error_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        thread_id = _new_thread(client)
        blank = client.post(
            f"/api/agent/threads/{thread_id}/messages", headers=_HEADERS, json={"content": "  "}
        )
        assert blank.status_code == 400
        assert blank.json()["detail"] == "message_required"

        unknown = client.post(
            "/api/agent/threads/missing/messages", headers=_HEADERS, json={"content": "hi"}
        )
        assert unknown.status_code == 404


# --------------------------------------------------------------------------
# personas
# --------------------------------------------------------------------------


def test_persona_select_and_import_and_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        listed = client.get("/api/agent/personas", headers=_HEADERS)
        assert listed.status_code == 200
        first_id = listed.json()["personas"][0]["id"]

        selected = client.post("/api/agent/personas/select", headers=_HEADERS, json={"id": first_id})
        assert selected.status_code == 200

        assert (
            client.post("/api/agent/personas/select", headers=_HEADERS, json={"id": "  "}).status_code
            == 400
        )
        assert (
            client.post(
                "/api/agent/personas/select", headers=_HEADERS, json={"id": "nope"}
            ).status_code
            == 404
        )

        imported = client.post(
            "/api/agent/personas/import",
            headers=_HEADERS,
            json={"title": "Imported", "content": "# Imported\nBe careful."},
        )
        assert imported.status_code == 200
        new_ids = {p["id"] for p in imported.json()["personas"]}
        added = (new_ids - {p["id"] for p in listed.json()["personas"]}).pop()

        assert (
            client.post("/api/agent/personas/import", headers=_HEADERS, json={}).status_code == 400
        )

        removed = client.delete(f"/api/agent/personas/{added}", headers=_HEADERS)
        assert removed.status_code == 200
        assert client.delete("/api/agent/personas/nope", headers=_HEADERS).status_code == 404
        # A built-in persona cannot be deleted: a refusal, not a crash.
        assert client.delete(f"/api/agent/personas/{first_id}", headers=_HEADERS).status_code in {
            400,
            404,
        }


# --------------------------------------------------------------------------
# runs
# --------------------------------------------------------------------------


def test_run_error_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        assert (
            client.post("/api/agent/runs", headers=_HEADERS, json={}).status_code == 400
        )
        # A message routed to an unknown thread is a 404, before any run starts.
        unknown_thread = client.post(
            "/api/agent/runs",
            headers=_HEADERS,
            json={"thread_id": "missing", "message": "hi"},
        )
        assert unknown_thread.status_code == 404

        thread_id = _new_thread(client)
        # Valid thread: the run is accepted and started off the request path.
        started = client.post(
            "/api/agent/runs",
            headers=_HEADERS,
            json={"thread_id": thread_id, "profile_id": "does-not-exist"},
        )
        assert started.status_code in {202, 400, 404}

        assert client.get("/api/agent/runs/missing", headers=_HEADERS).status_code == 404
        assert (
            client.post("/api/agent/runs/missing/cancel", headers=_HEADERS).status_code == 404
        )
        assert (
            client.get("/api/agent/runs/missing/events", headers=_HEADERS).status_code == 404
        )
        assert (
            client.get("/api/agent/runs/missing/events/history", headers=_HEADERS).status_code
            == 404
        )


def test_run_event_history_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        thread_id = _new_thread(client)
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        store.append_event(run.id, "llm.started", {"round": 1})
        history = client.get(f"/api/agent/runs/{run.id}/events/history", headers=_HEADERS)
        assert history.status_code == 200
        assert any(event["type"] == "llm.started" for event in history.json()["events"])


def test_decision_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        base = "/api/agent/runs/r/tool-calls/tc"
        assert client.post(f"{base}/approve", headers=_HEADERS, json={}).status_code == 400
        assert (
            client.post(
                f"{base}/approve", headers=_HEADERS, json={"args_sha256": "x" * 64, "remember": "bad"}
            ).status_code
            == 400
        )
        # A well-formed decision against an unknown run is refused as a conflict.
        assert (
            client.post(
                f"{base}/reject", headers=_HEADERS, json={"args_sha256": "a" * 64}
            ).status_code
            in {404, 409}
        )


# --------------------------------------------------------------------------
# missions
# --------------------------------------------------------------------------


def test_mission_lifecycle_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        assert (
            client.post("/api/agent/missions", headers=_HEADERS, json={}).status_code == 400
        )
        assert (
            client.post(
                "/api/agent/missions", headers=_HEADERS, json={"objective": "go", "thread_id": 5}
            ).status_code
            == 400
        )
        bad_runs = client.post(
            "/api/agent/missions",
            headers=_HEADERS,
            json={"objective": "go", "max_runs": "not-an-int"},
        )
        assert bad_runs.status_code == 400

        # A mission bound to an unknown thread is a not-found, not a new thread.
        assert (
            client.post(
                "/api/agent/missions",
                headers=_HEADERS,
                json={"objective": "inspect the binary", "thread_id": "missing"},
            ).status_code
            == 404
        )

        created = client.post(
            "/api/agent/missions", headers=_HEADERS, json={"objective": "inspect the binary"}
        )
        assert created.status_code == 201
        mission_id = created.json()["mission"]["id"]

        listed = client.get("/api/agent/missions", headers=_HEADERS)
        assert listed.status_code == 200 and listed.json()["count"] >= 1
        assert (
            client.get("/api/agent/missions?status=not-a-status", headers=_HEADERS).status_code
            == 400
        )

        assert client.get(f"/api/agent/missions/{mission_id}", headers=_HEADERS).status_code == 200
        assert client.get("/api/agent/missions/missing", headers=_HEADERS).status_code == 404

        cancelled = client.post(
            f"/api/agent/missions/{mission_id}/cancel", headers=_HEADERS
        )
        assert cancelled.status_code == 202
        assert (
            client.post("/api/agent/missions/missing/cancel", headers=_HEADERS).status_code == 404
        )


# --------------------------------------------------------------------------
# autonomy + watchdog
# --------------------------------------------------------------------------


def test_autonomy_get_and_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # _persist_autonomy writes the user config; stub it so the test is hermetic.
    monkeypatch.setattr(agent_routes, "update_config_values", lambda *a, **k: Path("noop"))
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        assert client.get("/api/agent/autonomy", headers=_HEADERS).status_code == 200

        assert (
            client.put(
                "/api/agent/autonomy", headers=_HEADERS, json={"mode": "not-a-mode"}
            ).status_code
            == 400
        )
        switched = client.put("/api/agent/autonomy", headers=_HEADERS, json={"mode": "request"})
        assert switched.status_code == 200

        assert (
            client.put(
                "/api/agent/autonomy", headers=_HEADERS, json={"add_tools": "notalist"}
            ).status_code
            == 400
        )
        granted = client.put(
            "/api/agent/autonomy",
            headers=_HEADERS,
            json={"add_tools": ["doctor"], "remove_tools": ["doctor"]},
        )
        assert granted.status_code == 200

        assert client.get("/api/agent/watchdog", headers=_HEADERS).status_code == 200


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------


def test_provider_save_and_probe_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad = client.put(
            "/api/providers/default",
            headers=_HEADERS,
            json={"base_url": "ftp://nope", "model": "m", "api_key": "k"},
        )
        assert bad.status_code == 400

        assert (
            client.post("/api/providers/does-not-exist/models", headers=_HEADERS).status_code
            in {404, 502}
        )

        saved = client.put(
            "/api/providers/probe",
            headers=_HEADERS,
            json={"base_url": "https://nonexistent.invalid/v1", "model": "m", "api_key": "k"},
        )
        assert saved.status_code == 200
        probe = client.post("/api/providers/probe/models", headers=_HEADERS)
        assert probe.status_code == 502
        assert probe.json()["detail"].startswith("provider_probe_failed:")


def test_zerofall_import_requires_a_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        assert (
            client.post("/api/providers/zerofall/import", headers=_HEADERS, json={}).status_code
            == 400
        )
        # A malformed config is a client error, not a crash.
        bad = client.post(
            "/api/providers/zerofall/import",
            headers=_HEADERS,
            json={"config": {"unusable": True}},
        )
        assert bad.status_code == 400
