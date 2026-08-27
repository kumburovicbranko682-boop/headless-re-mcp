from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app


def test_agent_rest_spa_and_provider_secret_boundary(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    with TestClient(app) as client:
        page = client.get("/?token=web-secret")
        assert page.status_code == 200
        assert '<div id="root"></div>' in page.text
        assert "web-secret" not in page.text
        deep_link = client.get("/analysis/thread/demo", headers=headers)
        assert deep_link.status_code == 200
        assert '<div id="root"></div>' in deep_link.text
        assert client.get("/api/not-real", headers=headers).status_code == 404
        assert client.get("/assets/not-real.js", headers=headers).status_code == 404

        created = client.post("/api/agent/threads", headers=headers, json={"title": "T"})
        assert created.status_code == 201
        thread_id = created.json()["thread"]["id"]
        bound = client.patch(
            f"/api/agent/threads/{thread_id}",
            headers=headers,
            json={"session_id": "analysis-session"},
        )
        assert bound.status_code == 200
        assert bound.json()["thread"]["session_id"] == "analysis-session"
        cleared = client.patch(
            f"/api/agent/threads/{thread_id}",
            headers=headers,
            json={"session_id": None},
        )
        assert cleared.status_code == 200
        assert cleared.json()["thread"]["session_id"] is None
        message = client.post(
            f"/api/agent/threads/{thread_id}/messages",
            headers=headers,
            json={"content": "inspect"},
        )
        assert message.status_code == 201
        store = app.state.agent_store
        run = store.create_run(thread_id, provider_profile="default", model="fake", deadline_seconds=30)
        store.append_event(run.id, "llm.started", {"round": 1})
        fetched = client.get(f"/api/agent/threads/{thread_id}", headers=headers)
        assert fetched.status_code == 200
        assert any(event["type"] == "llm.started" for event in fetched.json()["events"])
        removed = client.delete(f"/api/agent/threads/{thread_id}", headers=headers)
        assert removed.status_code == 200
        assert client.get(f"/api/agent/threads/{thread_id}", headers=headers).status_code == 404
        leftover = client.post("/api/agent/threads", headers=headers, json={"title": "T"})
        thread_id = leftover.json()["thread"]["id"]

        secret = "provider-super-secret-value"
        saved = client.put(
            "/api/providers/default",
            headers=headers,
            json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": secret},
        )
        assert saved.status_code == 200
        assert secret not in saved.text
        listed = client.get("/api/providers", headers=headers)
        assert listed.status_code == 200
        assert secret not in listed.text
        assert listed.json()["profiles"][0]["configured"] is True

        preview = client.post(
            "/api/providers/zerofall/preview",
            headers=headers,
            json={"apiKey": secret, "localHttpAccessToken": "must-not-import", "model": "fake"},
        )
        assert preview.status_code == 200
        assert secret not in preview.text
        assert "must-not-import" not in preview.text
        assert "localHttpAccessToken" in preview.json()["preview"]["ignored"]

        assert client.get("/api/agent/threads").status_code == 200
        client.cookies.clear()
        assert client.get("/api/agent/threads").status_code == 401
        assert client.get("/api/agent/threads", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_decision_endpoints_distinguish_missing_run_from_missing_call(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """approve/reject must 404 a gone run, 404 a gone call, and 409 a stopped run.

    A missing run and a terminal run used to share one 409 "run is terminal or
    missing", so approving on a run that never existed looked like a transient
    conflict rather than the plain 404 the cancel endpoint already gives.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    sha = "0" * 64

    with TestClient(app) as client:
        gone = client.post(
            "/api/agent/runs/no-such-run/tool-calls/no-such-call/approve",
            headers=headers,
            json={"args_sha256": sha},
        )
        assert gone.status_code == 404
        assert gone.json()["detail"] == "run_not_found"

        store = app.state.agent_store
        thread = store.create_thread()
        run = store.create_run(
            thread.id, provider_profile="default", model="fake", deadline_seconds=30
        )

        missing_call = client.post(
            f"/api/agent/runs/{run.id}/tool-calls/no-such-call/reject",
            headers=headers,
            json={"args_sha256": sha},
        )
        assert missing_call.status_code == 404
        assert missing_call.json()["detail"] == "tool_call_not_found"

        store.request_cancel(run.id)
        conflict = client.post(
            f"/api/agent/runs/{run.id}/tool-calls/no-such-call/approve",
            headers=headers,
            json={"args_sha256": sha},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"] == "run is terminal"


def test_agent_message_limits_are_client_errors_not_incidents(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        invalid_thread = client.post(
            "/api/agent/threads",
            headers=headers,
            json={"title": "bounded", "session_id": "x" * 1024},
        )
        assert invalid_thread.status_code == 400
        assert "thread session_id" in invalid_thread.json()["detail"]

        created = client.post(
            "/api/agent/threads", headers=headers, json={"title": "bounded"}
        )
        thread_id = created.json()["thread"]["id"]
        oversized = "x" * (1024 * 1024 + 1)

        message = client.post(
            f"/api/agent/threads/{thread_id}/messages",
            headers=headers,
            json={"content": oversized},
        )
        assert message.status_code == 413
        assert message.json()["detail"] == "message exceeds 1 MiB"

        run = client.post(
            "/api/agent/runs",
            headers=headers,
            json={"thread_id": thread_id, "message": oversized},
        )
        assert run.status_code == 413
        assert run.json()["detail"] == "message exceeds 1 MiB"

        invalid_model = client.post(
            "/api/agent/runs",
            headers=headers,
            json={"thread_id": thread_id, "model": "x" * 2048},
        )
        assert invalid_model.status_code == 400
        assert "run model" in invalid_model.json()["detail"]


def test_missions_are_queued_over_http_and_the_scheduler_runs(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The unattended entry point, over the wire.

    A run needs a caller present when it starts and dies at its deadline. A
    mission is queued once and the scheduler carries it, so this checks the
    endpoint exists, is authenticated like everything else, and that the loop is
    actually attached to the app lifespan rather than only constructed.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    assert app.state.mission_scheduler.running is False

    with TestClient(app) as client:
        assert client.post("/api/agent/missions", json={"objective": "x"}).status_code == 401

        created = client.post(
            "/api/agent/missions",
            headers=headers,
            json={"objective": "recover the serial", "max_runs": 3},
        )
        assert created.status_code == 201
        mission = created.json()["mission"]
        assert mission["objective"] == "recover the serial"
        assert mission["max_runs"] == 3
        # A thread is created for it, so a caller can queue work with one call.
        assert mission["thread_id"]

        assert client.post("/api/agent/missions", headers=headers, json={"objective": "  "}).status_code == 400

        listed = client.get("/api/agent/missions", headers=headers).json()
        assert listed["count"] == 1
        assert listed["scheduler_running"] is True

        fetched = client.get(f"/api/agent/missions/{mission['id']}", headers=headers)
        assert fetched.status_code == 200
        assert client.get("/api/agent/missions/nope", headers=headers).status_code == 404

        cancelled = client.post(f"/api/agent/missions/{mission['id']}/cancel", headers=headers)
        assert cancelled.status_code == 202
        assert cancelled.json()["mission"]["status"] == "cancelled"

    # The lifespan has to stop the loop, or the process cannot exit cleanly.
    assert app.state.mission_scheduler.running is False


def test_the_autonomy_policy_is_readable_over_http(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        agent_auto_approve_effects=("state_change",),
    )
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        assert client.get("/api/agent/autonomy").status_code == 401
        body = client.get("/api/agent/autonomy", headers=headers).json()

    assert body["mode"] == "request"
    assert body["policy"]["mode"] == "request"
    assert body["policy"]["unattended"] is True
    assert body["policy"]["auto_approve_effects"] == ["state_change"]
    # The point of the endpoint: see exactly which writes were opened up.
    assert body["auto_executable_write_count"] > 0
    assert "dynamic.launch" in body["auto_executable_writes"]


def test_autonomy_can_be_granted_over_http(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    written: dict[str, object] = {}

    def fake_update(updates, *, config_path=None):  # type: ignore[no-untyped-def]
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr("headless_re_mcp.web.routes.agent.update_config_values", fake_update)
    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        # Hosted quality has no config.json, so Settings.load() fills the packed
        # PE-analysis preset. Pin an empty grant so this test measures add_tools
        # instead of whatever the machine already auto-approves.
        agent_auto_approve_tools=(),
        agent_auto_approve_effects=(),
    )
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        granted = client.put(
            "/api/agent/autonomy",
            headers=headers,
            json={"add_tools": ["dynamic.open", "dynamic.launch"]},
        )
        assert granted.status_code == 200
        body = granted.json()
        assert "dynamic.open" in body["policy"]["auto_approve_tools"]
        assert "dynamic.launch" in body["auto_executable_writes"]
        listed = client.get("/api/agent/autonomy", headers=headers).json()
        assert listed["policy"]["auto_approve_tools"] == body["policy"]["auto_approve_tools"]

    assert written["agent_auto_approve_tools"] == ["dynamic.launch", "dynamic.open"]


def test_autonomy_mode_can_be_switched_over_http(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    written: dict[str, object] = {}

    def fake_update(updates, *, config_path=None):  # type: ignore[no-untyped-def]
        written.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr("headless_re_mcp.web.routes.agent.update_config_values", fake_update)
    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        agent_auto_approve_tools=("dynamic.open",),
    )
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        opened = client.put("/api/agent/autonomy", headers=headers, json={"mode": "full_access"})
        assert opened.status_code == 200
        body = opened.json()
        assert body["mode"] == "full_access"
        assert body["policy"]["auto_approve_effects"] == ["file_write", "state_change"]
        assert body["policy"]["auto_approve_tools"] == []
        assert "dynamic.launch" in body["auto_executable_writes"]
        assert "report.generate" in body["auto_executable_writes"]

        asked = client.put("/api/agent/autonomy", headers=headers, json={"mode": "request"})
        assert asked.status_code == 200
        reset = asked.json()
        assert reset["mode"] == "request"
        assert reset["policy"]["auto_approve_effects"] == []
        assert reset["policy"]["auto_approve_tools"] == []
        assert reset["auto_executable_write_count"] == 0

        bad = client.put("/api/agent/autonomy", headers=headers, json={"mode": "approve_for_me"})
        assert bad.status_code == 400

    assert written["agent_auto_approve_effects"] == []
    assert written["agent_auto_approve_tools"] == []


def test_a_granted_autonomy_survives_a_restart_through_the_config_file(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """The writer and the reader of the grant keys must not drift apart.

    PUT /api/agent/autonomy persists through update_config_values, and the next
    process reads the keys back via Settings.load -> AutonomyPolicy.from_settings.
    Both sides name the agent_* keys independently; if either renamed, grants
    would silently vanish on restart with nothing failing. Round-trip through a
    real file, only redirecting the config path away from the user's home.
    """
    from functools import partial

    import headless_re_mcp.web.routes.agent as agent_routes
    from headless_re_mcp.agent.autonomy import AutonomyPolicy
    from headless_re_mcp.config import update_config_values

    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    for var in (
        "HEADLESS_RE_AGENT_AUTO_APPROVE_EFFECTS",
        "HEADLESS_RE_AGENT_AUTO_APPROVE_TOOLS",
        "HEADLESS_RE_AGENT_NEVER_AUTO_APPROVE",
    ):
        monkeypatch.delenv(var, raising=False)
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(
        agent_routes,
        "update_config_values",
        partial(update_config_values, config_path=config_path),
    )

    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        agent_auto_approve_tools=(),
        agent_auto_approve_effects=(),
    )
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        granted = client.put(
            "/api/agent/autonomy", headers=headers, json={"add_tools": ["dynamic.open"]}
        )
        assert granted.status_code == 200
        reported = granted.json()["policy"]

    # "The restart": a fresh Settings from that file, a fresh policy from it.
    reloaded = AutonomyPolicy.from_settings(Settings.load(config_path))
    assert "dynamic.open" in reloaded.auto_approve_tools
    assert sorted(reloaded.auto_approve_tools) == reported["auto_approve_tools"]
    # The explicit empty effects list persisted by the grant stays fail-closed
    # on reload, rather than being repopulated by the packed-analysis preset.
    assert reloaded.auto_approve_effects == frozenset()