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
        body = fetched.json()
        assert any(event["type"] == "llm.started" for event in body["events"])
        # A short thread is shown whole, and the view says so rather than
        # leaving a reader to guess whether more exists.
        assert body["messages_total"] == len(body["messages"])
        assert body["messages_truncated"] is False
        assert body["events_total"] == len(body["events"])
        assert body["events_truncated"] is False
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


def test_thread_view_says_when_it_shows_only_the_recent_window(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """The thread view is a most-recent window; a partial one must say so.

    list_messages returns the tail that fits its count and byte budgets, so a
    long thread hands back its latest turns with the earliest dropped. Without
    a total and a truncated flag that tail reads as the whole conversation --
    the same misread the report sections were fixed to avoid.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        created = client.post("/api/agent/threads", headers=headers, json={"title": "long"})
        thread_id = created.json()["thread"]["id"]
        store = app.state.agent_store
        # Squeeze the read window to its floor and write past it, so the window
        # returns fewer messages than the thread retains without needing to
        # insert hundreds. The write-time retention bounds are far larger, so
        # every message written here is still counted.
        store.message_page_max_bytes = 1024
        for index in range(5):
            store.add_message(thread_id, "user", f"{index}:" + "x" * 400)

        body = client.get(f"/api/agent/threads/{thread_id}", headers=headers).json()

        assert body["messages_total"] == 5
        assert len(body["messages"]) < 5
        assert body["messages_truncated"] is True
        # The window keeps the newest end, so the last message is present.
        assert body["messages"][-1]["content"].startswith("4:")


def test_event_history_hands_back_a_cursor_when_a_page_hides_more(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """A one-shot history page must say when it is not the whole run.

    /events/history returns a forward page bounded by a count and a byte
    budget. Without has_more and a cursor, a full-looking first page reads as
    the entire run history and a reader never fetches the rest.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        created = client.post("/api/agent/threads", headers=headers, json={"title": "run"})
        thread_id = created.json()["thread"]["id"]
        store = app.state.agent_store
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        # Squeeze the read window to its byte floor so a handful of events pages
        # rather than needing to append a thousand.
        store.event_page_max_bytes = 1024
        for index in range(5):
            store.append_event(run.id, "message.delta", {"blob": f"{index}:" + "x" * 400})

        first = client.get(
            f"/api/agent/runs/{run.id}/events/history?after=0", headers=headers
        ).json()
        assert first["has_more"] is True
        assert first["count"] < 5
        assert first["next_after"] == first["events"][-1]["seq"]

        # Draining via the cursor terminates and the last page says so, without
        # any page repeating a sequence it already returned.
        seen: list[int] = [event["seq"] for event in first["events"]]
        cursor = first["next_after"]
        has_more = first["has_more"]
        for _ in range(20):
            if not has_more:
                break
            page = client.get(
                f"/api/agent/runs/{run.id}/events/history?after={cursor}", headers=headers
            ).json()
            assert all(seq > cursor for seq in [event["seq"] for event in page["events"]])
            seen.extend(event["seq"] for event in page["events"])
            cursor = page["next_after"]
            has_more = page["has_more"]
        assert has_more is False, "draining the cursor must reach a final page"
        assert len(seen) == len(set(seen)), "no page may repeat an event"
        assert seen == sorted(seen)
        assert len(seen) >= 5


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