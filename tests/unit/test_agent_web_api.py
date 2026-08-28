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


def test_capped_thread_pages_disclose_their_totals(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """A newest-capped thread page must say it is a window, not the history.

    list_messages and list_thread_events page the newest 500/4,000 items under
    an 8 MiB byte cap while retention goes much further (2,000 messages /
    64 MiB; 5,000 events per retained run). The thread view returned those
    windows bare, so a long thread read as a conversation that began mid-way
    -- indistinguishable from one that actually did. The page now carries
    messages_total/messages_truncated and events_total/events_truncated when
    it is a subset, and stays unchanged when it is the whole history.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        created = client.post("/api/agent/threads", headers=headers, json={"title": "T"})
        thread_id = created.json()["thread"]["id"]
        store = app.state.agent_store
        store.add_message(thread_id, "user", "short and complete")

        whole = client.get(f"/api/agent/threads/{thread_id}", headers=headers).json()
        assert len(whole["messages"]) == 1
        assert "messages_total" not in whole
        assert "messages_truncated" not in whole
        assert "events_total" not in whole
        assert "events_truncated" not in whole

        # Byte caps are instance attributes read per call; the floor is 1024.
        store.message_page_max_bytes = 1024
        store.event_page_max_bytes = 1024
        for index in range(3):
            store.add_message(thread_id, "assistant", f"m{index} " + "x" * 700)
        # create_run itself appends a run.started event, hence 3 + 1 below.
        run = store.create_run(
            thread_id, provider_profile="default", model="fake", deadline_seconds=30
        )
        for _ in range(3):
            store.append_event(run.id, "llm.delta", {"text": "y" * 700})

        capped = client.get(f"/api/agent/threads/{thread_id}", headers=headers).json()
        assert capped["messages_truncated"] is True
        assert capped["messages_total"] == 4
        assert len(capped["messages"]) < capped["messages_total"]
        assert capped["events_truncated"] is True
        assert capped["events_total"] == 4
        assert len(capped["events"]) < capped["events_total"]


def test_a_capped_thread_listing_discloses_the_true_count(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """The sidebar page holds 100 threads while the store retains up to 2,000.

    Returned bare, the page reads as the complete set and the threads past the
    cap are unfindable. A capped listing now carries threads_total and
    threads_truncated; a complete one stays unchanged.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        store = app.state.agent_store
        store.create_thread(title="only one")
        complete = client.get("/api/agent/threads", headers=headers).json()
        assert len(complete["threads"]) == 1
        assert "threads_total" not in complete
        assert "threads_truncated" not in complete

        for index in range(101):
            store.create_thread(title=f"t{index}")

        capped = client.get("/api/agent/threads", headers=headers).json()
        assert len(capped["threads"]) == 100
        assert capped["threads_total"] == 102
        assert capped["threads_truncated"] is True


def test_a_capped_mission_listing_discloses_the_true_count(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """"count" is the page length; past the cap it silently diverged from the
    number of missions that actually match, so a capped page now says so.

    Unfiltered totals only: the live scheduler may flip mission statuses while
    the test runs, but creating and never deleting missions keeps the overall
    count stable.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        store = app.state.agent_store
        thread = store.create_thread(title="missions")
        for index in range(3):
            store.create_mission(thread.id, f"objective {index}")

        complete = client.get("/api/agent/missions", headers=headers).json()
        assert complete["count"] == 3
        assert "missions_total" not in complete
        assert "missions_truncated" not in complete

        capped = client.get("/api/agent/missions?limit=1", headers=headers).json()
        assert capped["count"] == 1
        assert capped["missions_total"] == 3
        assert capped["missions_truncated"] is True


def test_event_history_says_when_a_page_is_not_the_whole_tail(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """A full cursor page must say the tail continues, not read as the end.

    /events/history returns one page cut at 1,000 events or 8 MiB, and a
    streamed run is deltas, so it routinely holds more. Returned bare, a full
    page read as "everything after `after`" and a client rebuilding history
    saw a run that just stops mid-way. A cut page now carries has_more and
    next_after; following next_after to the end yields every event exactly
    once, and the final page carries neither key.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        store = app.state.agent_store
        thread = store.create_thread(title="history")
        run = store.create_run(
            thread.id, provider_profile="default", model="fake", deadline_seconds=30
        )

        whole = client.get(f"/api/agent/runs/{run.id}/events/history", headers=headers).json()
        assert [event["type"] for event in whole["events"]] == ["run.started"]
        assert "has_more" not in whole
        assert "next_after" not in whole

        store.event_page_max_bytes = 1024
        for _ in range(3):
            store.append_event(run.id, "message.delta", {"delta": "y" * 700})

        first = client.get(f"/api/agent/runs/{run.id}/events/history", headers=headers).json()
        assert first["has_more"] is True
        assert first["next_after"] == first["events"][-1]["seq"]
        assert len(first["events"]) < 4

        collected = list(first["events"])
        page = first
        for _ in range(10):
            if "has_more" not in page:
                break
            page = client.get(
                f"/api/agent/runs/{run.id}/events/history?after={page['next_after']}",
                headers=headers,
            ).json()
            collected.extend(page["events"])
        assert "has_more" not in page, "cursor never reached the end of the tail"
        seqs = [event["seq"] for event in collected]
        assert seqs == sorted(set(seqs)), "following next_after must not repeat or skip"
        assert len(collected) == 4  # run.started + three deltas


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