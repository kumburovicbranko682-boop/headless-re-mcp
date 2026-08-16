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
        message = client.post(
            f"/api/agent/threads/{thread_id}/messages",
            headers=headers,
            json={"content": "inspect"},
        )
        assert message.status_code == 201

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

        assert client.get("/api/agent/threads").status_code == 401
        assert client.get("/api/agent/threads", headers={"Authorization": "Bearer wrong"}).status_code == 401


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

    assert body["policy"]["unattended"] is True
    assert body["policy"]["auto_approve_effects"] == ["state_change"]
    # The point of the endpoint: see exactly which writes were opened up.
    assert body["auto_executable_write_count"] > 0
    assert "dynamic.launch" in body["auto_executable_writes"]


def test_event_history_says_when_it_stopped(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The history endpoint stopped at 1000 events and said the run was complete.

    Measured: 1500 events came back as 1000 with ok=True and no has_more, so
    an overnight run's later tool.completed events disappeared.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    store = app.state.agent_store
    thread = store.create_thread(session_id="analysis-session")
    run = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=30
    )
    for index in range(1001):
        store.append_event(run.id, "message.delta", {"n": index})

    with TestClient(app) as client:
        first = client.get(
            f"/api/agent/runs/{run.id}/events/history", headers=headers
        ).json()
        assert first["ok"] is True
        assert first["count"] == 1000
        assert first["has_more"] is True
        assert first["events"][-1]["seq"] == 1000

        tail = client.get(
            f"/api/agent/runs/{run.id}/events/history",
            headers=headers,
            params={"after": 1000},
        ).json()
        assert tail["has_more"] is False
        assert tail["count"] >= 1
        assert tail["events"][0]["seq"] == 1001


def test_a_long_thread_says_when_older_messages_were_dropped(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """GET thread returned the recent 500 messages as if that was the whole chat.

    Measured: 600 messages came back as 500 (starting at m100) with no
    has_more, so an overnight conversation looked like it started mid-thread.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    store = app.state.agent_store
    thread = store.create_thread(session_id="analysis-session")
    for index in range(600):
        store.add_message(thread.id, "user", f"m{index}")

    with TestClient(app) as client:
        body = client.get(f"/api/agent/threads/{thread.id}", headers=headers).json()
    assert body["ok"] is True
    assert body["count"] == 500
    assert body["has_more"] is True
    assert body["messages"][0]["content"] == "m100"
    assert body["messages"][-1]["content"] == "m599"


def test_thread_list_says_when_it_stopped(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """GET /threads stopped at 100 rows and said that was every thread.

    Measured: 150 threads came back as 100 with ok=True and no has_more, so
    overnight missions' older threads disappeared.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    store = app.state.agent_store
    for index in range(150):
        store.create_thread(title=f"t{index}", session_id="analysis-session")

    with TestClient(app) as client:
        body = client.get("/api/agent/threads", headers=headers).json()
    assert body["ok"] is True
    assert body["count"] == 100
    assert body["has_more"] is True
    assert len(body["threads"]) == 100


def test_mission_list_says_when_it_stopped(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """GET /missions stopped at 100 rows and said that was every mission.

    Measured: 150 missions with limit=100 came back as count=100 with no
    has_more, so overnight queued work looked complete.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    store = app.state.agent_store
    thread = store.create_thread(session_id="analysis-session")
    for index in range(150):
        store.create_mission(thread.id, f"obj {index}")

    with TestClient(app) as client:
        body = client.get(
            "/api/agent/missions", headers=headers, params={"limit": 100}
        ).json()
    assert body["ok"] is True
    assert body["count"] == 100
    assert body["has_more"] is True
    assert len(body["missions"]) == 100


def test_watchdog_alerts_say_when_they_stopped(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """GET /watchdog stopped at 50 alerts and said that was every alert.

    Measured: 80 alerts with limit=50 came back as 50 and alerts_total=80
    with no has_more, so overnight backend deaths disappeared.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    watchdog = app.state.watchdog
    for index in range(80):
        watchdog._alert("test", n=index)

    with TestClient(app) as client:
        body = client.get(
            "/api/agent/watchdog", headers=headers, params={"limit": 50}
        ).json()
    assert body["ok"] is True
    assert body["alerts_total"] == 80
    assert len(body["alerts"]) == 50
    assert body["has_more"] is True

    with TestClient(app) as client:
        complete = client.get(
            "/api/agent/watchdog", headers=headers, params={"limit": 128}
        ).json()
    assert complete["has_more"] is False
    assert len(complete["alerts"]) == 80


def test_mission_create_says_when_the_objective_was_cut(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """POST /missions sliced the objective at 8000 and said nothing.

    Measured: a 9000-character objective came back as 8000 with no
    truncated, so an unattended agent treated a cut brief as the whole
    overnight job.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    store = app.state.agent_store
    thread = store.create_thread(session_id="analysis-session")

    with TestClient(app) as client:
        cut = client.post(
            "/api/agent/missions",
            headers=headers,
            json={"thread_id": thread.id, "objective": "X" * 9000},
        ).json()
        intact = client.post(
            "/api/agent/missions",
            headers=headers,
            json={"thread_id": thread.id, "objective": "short job"},
        ).json()
    assert cut["ok"] is True
    assert len(cut["mission"]["objective"]) == 8000
    assert cut["mission"]["truncated"] is True
    assert intact["mission"]["truncated"] is False


def test_run_get_says_when_the_error_was_cut(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """_finish_failure sliced the error at 1000 and said nothing.

    Measured: a 1500-character failure reason was stored as 1000 with
    no error_truncated, so an unattended GET treated a cut cause as
    the whole overnight failure.
    """
    import asyncio

    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    store = app.state.agent_store
    orch = app.state.agent_orchestrator
    thread = store.create_thread(session_id="analysis-session")
    cut = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=30
    )
    intact = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=30
    )
    asyncio.run(orch._finish_failure(cut.id, "R" * 1500, event="run.failed"))
    asyncio.run(orch._finish_failure(intact.id, "provider exploded", event="run.failed"))

    with TestClient(app) as client:
        cut_body = client.get(f"/api/agent/runs/{cut.id}", headers=headers).json()
        intact_body = client.get(f"/api/agent/runs/{intact.id}", headers=headers).json()
    assert cut_body["ok"] is True
    assert len(cut_body["run"]["error"]) == 1000
    assert cut_body["run"]["error_truncated"] is True
    assert intact_body["run"]["error_truncated"] is False
    assert intact_body["run"]["error"] == "provider exploded"


def test_mission_get_says_when_the_error_was_cut(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """set_mission_status sliced the error at 1000 and said nothing.

    Measured: a 1500-character failure reason was stored as 1000 with
    no error_truncated, so an unattended GET treated a cut cause as
    the whole overnight failure.
    """
    from headless_re_mcp.agent.models import MissionStatus

    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    store = app.state.agent_store
    thread = store.create_thread(session_id="analysis-session")
    cut = store.create_mission(thread.id, "long failure")
    intact = store.create_mission(thread.id, "short failure")
    store.set_mission_status(cut.id, MissionStatus.FAILED, error="E" * 1500)
    store.set_mission_status(intact.id, MissionStatus.FAILED, error="provider exploded")

    with TestClient(app) as client:
        cut_body = client.get(f"/api/agent/missions/{cut.id}", headers=headers).json()
        intact_body = client.get(f"/api/agent/missions/{intact.id}", headers=headers).json()
    assert cut_body["ok"] is True
    assert len(cut_body["mission"]["error"]) == 1000
    assert cut_body["mission"]["error_truncated"] is True
    assert intact_body["mission"]["error_truncated"] is False
    assert intact_body["mission"]["error"] == "provider exploded"


def test_thread_create_says_when_the_title_was_cut(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """POST /threads sliced the title at 200 and said nothing.

    Measured: a 250-character title came back as 200 with no truncated,
    so an unattended agent treated a cut name as the whole thread title.
    """
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}

    with TestClient(app) as client:
        cut = client.post(
            "/api/agent/threads",
            headers=headers,
            json={"title": "T" * 250},
        ).json()
        intact = client.post(
            "/api/agent/threads",
            headers=headers,
            json={"title": "short"},
        ).json()
    assert cut["ok"] is True
    assert len(cut["thread"]["title"]) == 200
    assert cut["thread"]["truncated"] is True
    assert intact["thread"]["truncated"] is False