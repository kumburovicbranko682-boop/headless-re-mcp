"""Fail-closed and edge branches of the agent/provider HTTP surface.

The happy paths and the secret boundary are covered elsewhere; this file
drives the guard clauses -- the 400/404/409/413/502 arms and the less-common
success branches (tool-call approval memory, provider probe, SSE heartbeat)
that the broad integration tests never reach.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

HEADERS = {"Authorization": "Bearer web-secret"}


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> FastAPI:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts", **overrides)
    service = AnalysisService(settings)
    return cast(FastAPI, create_app(service, token="web-secret", settings=settings))


def test_thread_endpoints_reject_bad_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        bad_type = client.post(
            "/api/agent/threads", headers=HEADERS, json={"title": "t", "session_id": 123}
        )
        assert bad_type.status_code == 400
        assert bad_type.json()["detail"] == "invalid_session_id"

        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"})
        tid = created.json()["thread"]["id"]

        missing = client.patch(f"/api/agent/threads/{tid}", headers=HEADERS, json={})
        assert missing.status_code == 400
        assert missing.json()["detail"] == "session_id_required"

        wrong_type = client.patch(
            f"/api/agent/threads/{tid}", headers=HEADERS, json={"session_id": 5}
        )
        assert wrong_type.status_code == 400
        assert wrong_type.json()["detail"] == "invalid_session_id"

        unknown = client.patch("/api/agent/threads/nope", headers=HEADERS, json={"session_id": "s"})
        assert unknown.status_code == 404
        assert unknown.json()["detail"] == "thread_not_found"

        oversized = client.patch(
            f"/api/agent/threads/{tid}", headers=HEADERS, json={"session_id": "x" * 8192}
        )
        assert oversized.status_code == 400

        gone = client.delete("/api/agent/threads/nope", headers=HEADERS)
        assert gone.status_code == 404
        assert gone.json()["detail"] == "thread_not_found"


def test_persona_endpoints_error_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        listed = client.get("/api/agent/personas", headers=HEADERS)
        assert listed.status_code == 200
        builtin_id = next(item["id"] for item in listed.json()["personas"] if item["builtin"])
        chosen = client.post("/api/agent/personas/select", headers=HEADERS, json={"id": builtin_id})
        assert chosen.status_code == 200
        assert chosen.json()["current"] == builtin_id

        blank = client.post("/api/agent/personas/select", headers=HEADERS, json={})
        assert blank.status_code == 400
        assert blank.json()["detail"] == "persona_id_required"

        ghost = client.post("/api/agent/personas/select", headers=HEADERS, json={"id": "ghost"})
        assert ghost.status_code == 404
        assert ghost.json()["detail"] == "persona_not_found"

        sourceless = client.post("/api/agent/personas/import", headers=HEADERS, json={})
        assert sourceless.status_code == 400
        assert sourceless.json()["detail"] == "persona_source_required"

        md = tmp_path / "custom.md"
        md.write_text("# Persona\nBe precise.\n", encoding="utf-8")
        imported = client.post(
            "/api/agent/personas/import", headers=HEADERS, json={"path": str(md)}
        )
        assert imported.status_code == 200
        custom_ids = [item["id"] for item in imported.json()["personas"] if not item["builtin"]]
        assert custom_ids

        empty = client.post("/api/agent/personas/import", headers=HEADERS, json={"content": "   "})
        assert empty.status_code == 400

        builtin = client.delete("/api/agent/personas/default", headers=HEADERS)
        assert builtin.status_code == 400

        missing = client.delete("/api/agent/personas/nosuchpersona", headers=HEADERS)
        assert missing.status_code == 404

        removed = client.delete(f"/api/agent/personas/{custom_ids[0]}", headers=HEADERS)
        assert removed.status_code == 200
        assert all(item["id"] != custom_ids[0] for item in removed.json()["personas"])


def test_message_and_run_guard_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        created = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"})
        tid = created.json()["thread"]["id"]

        blank = client.post(
            f"/api/agent/threads/{tid}/messages", headers=HEADERS, json={"content": "  "}
        )
        assert blank.status_code == 400
        assert blank.json()["detail"] == "message_required"

        no_thread = client.post(
            "/api/agent/threads/nope/messages", headers=HEADERS, json={"content": "hi"}
        )
        assert no_thread.status_code == 404
        assert no_thread.json()["detail"] == "thread_not_found"

        no_id = client.post("/api/agent/runs", headers=HEADERS, json={})
        assert no_id.status_code == 400
        assert no_id.json()["detail"] == "thread_id_required"

        msg_no_thread = client.post(
            "/api/agent/runs", headers=HEADERS, json={"thread_id": "nope", "message": "hi"}
        )
        assert msg_no_thread.status_code == 404
        assert msg_no_thread.json()["detail"] == "thread_not_found"

        start_no_thread = client.post(
            "/api/agent/runs", headers=HEADERS, json={"thread_id": "nope"}
        )
        assert start_no_thread.status_code == 404
        assert start_no_thread.json()["detail"] == "thread_or_profile_not_found"

        async def fake_start_run(
            thread_id: str, *, profile_id: str | None = None, model: str | None = None
        ) -> dict[str, Any]:
            return {"id": "run-xyz", "thread_id": thread_id, "status": "queued"}

        app.state.agent_orchestrator.start_run = fake_start_run
        ok = client.post(
            "/api/agent/runs",
            headers=HEADERS,
            json={"thread_id": tid, "profile_id": "p", "model": "m"},
        )
        assert ok.status_code == 202
        assert ok.json()["run_id"] == "run-xyz"


def test_run_and_event_history_endpoints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        store = app.state.agent_store
        tid = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"}).json()[
            "thread"
        ]["id"]
        run = store.create_run(tid, provider_profile="default", model="fake", deadline_seconds=60)

        got = client.get(f"/api/agent/runs/{run.id}", headers=HEADERS)
        assert got.status_code == 200
        assert got.json()["run"]["id"] == run.id
        assert client.get("/api/agent/runs/nope", headers=HEADERS).status_code == 404

        cancelled = client.post(f"/api/agent/runs/{run.id}/cancel", headers=HEADERS)
        assert cancelled.status_code == 202
        assert client.post("/api/agent/runs/nope/cancel", headers=HEADERS).status_code == 404

        assert client.get("/api/agent/runs/nope/events/history", headers=HEADERS).status_code == 404
        store.append_event(run.id, "llm.started", {"round": 1})
        history = client.get(f"/api/agent/runs/{run.id}/events/history", headers=HEADERS)
        assert history.status_code == 200
        assert any(event["type"] == "llm.started" for event in history.json()["events"])


def test_event_stream_drains_a_terminal_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        store = app.state.agent_store
        tid = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"}).json()[
            "thread"
        ]["id"]
        run = store.create_run(tid, provider_profile="default", model="fake", deadline_seconds=60)
        store.append_event(run.id, "llm.completed", {"round": 1})
        store.transition(run.id, RunStatus.FAILED, error="boom")

        assert client.get("/api/agent/runs/nope/events", headers=HEADERS).status_code == 404

        streamed = client.get(f"/api/agent/runs/{run.id}/events", headers=HEADERS)
        assert streamed.status_code == 200
        assert "event: llm.completed" in streamed.text


def test_event_stream_emits_a_heartbeat_while_idle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import contextlib
    import threading

    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        store = app.state.agent_store
        tid = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"}).json()[
            "thread"
        ]["id"]
        # A live (non-terminal) run with no fresh events: the loop idles and
        # must send a keep-alive rather than sit silent behind a proxy. The
        # TestClient buffers the whole SSE body, so a background timer retires
        # the run to a terminal state after the first keep-alive is due, letting
        # the generator finish instead of looping forever.
        run = store.create_run(tid, provider_profile="default", model="fake", deadline_seconds=120)

        def _retire() -> None:
            # A transition that raced the loop's own terminal break is fine.
            with contextlib.suppress(Exception):
                store.transition(run.id, RunStatus.FAILED, error="idle test done")

        timer = threading.Timer(3.25, _retire)
        timer.start()
        try:
            streamed = client.get(f"/api/agent/runs/{run.id}/events?after=999999", headers=HEADERS)
        finally:
            timer.cancel()
        assert streamed.status_code == 200
        assert "event: heartbeat" in streamed.text


def test_tool_call_decision_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    persisted: dict[str, object] = {}

    def fake_update(updates: dict[str, Any], *, config_path: Path | None = None) -> Path:
        persisted.update(updates)
        return tmp_path / "config.json"

    monkeypatch.setattr("headless_re_mcp.web.routes.agent.update_config_values", fake_update)
    app = _app(
        tmp_path,
        monkeypatch,
        agent_auto_approve_tools=(),
        agent_auto_approve_effects=(),
    )
    with TestClient(app) as client:
        store = app.state.agent_store
        tid = client.post("/api/agent/threads", headers=HEADERS, json={"title": "t"}).json()[
            "thread"
        ]["id"]

        def _proposed(run_suffix: str, call_id: str) -> tuple[str, str]:
            run = store.create_run(
                tid, provider_profile="default", model="fake", deadline_seconds=120
            )
            call = store.propose_tool_call(
                run.id, call_id, "apk.decode", {"path": run_suffix}, ["file_write", "state_change"]
            )
            return run.id, str(call["args_sha256"])

        run_id, sha = _proposed("a", "call-1")
        base = f"/api/agent/runs/{run_id}/tool-calls/call-1"

        short = client.post(f"{base}/approve", headers=HEADERS, json={"args_sha256": "z"})
        assert short.status_code == 400
        assert short.json()["detail"] == "args_sha256_required"

        bad_remember = client.post(
            f"{base}/approve", headers=HEADERS, json={"args_sha256": sha, "remember": "sometimes"}
        )
        assert bad_remember.status_code == 400
        assert bad_remember.json()["detail"] == "remember_invalid"

        remember_tool = client.post(
            f"{base}/approve", headers=HEADERS, json={"args_sha256": sha, "remember": "tool"}
        )
        assert remember_tool.status_code == 200
        body = remember_tool.json()
        assert body["ok"] is True
        assert "apk.decode" in body["policy"]["auto_approve_tools"]
        assert persisted["agent_auto_approve_tools"] == ["apk.decode"]

        run_id2, sha2 = _proposed("b", "call-2")
        remember_effect = client.post(
            f"/api/agent/runs/{run_id2}/tool-calls/call-2/approve",
            headers=HEADERS,
            json={"args_sha256": sha2, "remember": "effect"},
        )
        assert remember_effect.status_code == 200
        effects = remember_effect.json()["policy"]["auto_approve_effects"]
        assert "file_write" in effects and "state_change" in effects

        run_id3, sha3 = _proposed("c", "call-3")
        rejected = client.post(
            f"/api/agent/runs/{run_id3}/tool-calls/call-3/reject",
            headers=HEADERS,
            json={"args_sha256": sha3},
        )
        assert rejected.status_code == 200
        assert rejected.json()["tool_call"]["status"] == "rejected"
        assert "policy" not in rejected.json()

        missing_call = client.post(
            f"/api/agent/runs/{run_id3}/tool-calls/ghost/approve",
            headers=HEADERS,
            json={"args_sha256": "a" * 64},
        )
        assert missing_call.status_code == 404
        assert missing_call.json()["detail"] == "tool_call_not_found"

        run_id4, _ = _proposed("d", "call-4")
        mismatch = client.post(
            f"/api/agent/runs/{run_id4}/tool-calls/call-4/approve",
            headers=HEADERS,
            json={"args_sha256": "b" * 64},
        )
        assert mismatch.status_code == 409


def test_mission_watchdog_and_autonomy_guard_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_update(updates: dict[str, Any], *, config_path: Path | None = None) -> Path:
        return tmp_path / "config.json"

    monkeypatch.setattr("headless_re_mcp.web.routes.agent.update_config_values", fake_update)
    app = _app(
        tmp_path,
        monkeypatch,
        agent_auto_approve_tools=(),
        agent_auto_approve_effects=(),
    )
    with TestClient(app) as client:
        bad_thread = client.post(
            "/api/agent/missions", headers=HEADERS, json={"objective": "do", "thread_id": 5}
        )
        assert bad_thread.status_code == 400
        assert bad_thread.json()["detail"] == "invalid_thread_id"

        bad_runs = client.post(
            "/api/agent/missions",
            headers=HEADERS,
            json={"objective": "do", "max_runs": "not-a-number"},
        )
        assert bad_runs.status_code == 400

        no_thread = client.post(
            "/api/agent/missions",
            headers=HEADERS,
            json={"objective": "do", "thread_id": "ghost"},
        )
        assert no_thread.status_code == 404
        assert no_thread.json()["detail"] == "thread_not_found"

        bad_status = client.get("/api/agent/missions?status=bogus", headers=HEADERS)
        assert bad_status.status_code == 400
        assert bad_status.json()["detail"] == "invalid_status"

        cancel_ghost = client.post("/api/agent/missions/ghost/cancel", headers=HEADERS)
        assert cancel_ghost.status_code == 404

        watchdog = client.get("/api/agent/watchdog", headers=HEADERS)
        assert watchdog.status_code == 200
        assert watchdog.json()["ok"] is True

        not_lists = client.put(
            "/api/agent/autonomy", headers=HEADERS, json={"add_tools": "notalist"}
        )
        assert not_lists.status_code == 400
        assert not_lists.json()["detail"] == "autonomy_lists_required"

        bad_effect = client.put(
            "/api/agent/autonomy", headers=HEADERS, json={"add_effects": ["not_an_effect"]}
        )
        assert bad_effect.status_code == 400

        toggled = client.put(
            "/api/agent/autonomy",
            headers=HEADERS,
            json={"add_tools": ["apk.decode"], "remove_tools": ["apk.decode"]},
        )
        assert toggled.status_code == 200
        assert "apk.decode" not in toggled.json()["policy"]["auto_approve_tools"]


def test_provider_endpoints_guard_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(tmp_path, monkeypatch)
    # A corrupt (non-object) profile entry: get() must fail closed with KeyError
    # so the routes report "not found" rather than crash on a bad config.
    (tmp_path / "providers.json").write_text(
        json.dumps({"profiles": {"corrupt1": 1, "corrupt2": 2}}), encoding="utf-8"
    )

    class FakeProvider:
        def __init__(self, profile: Any, timeout: float = 0.0) -> None:
            self.profile = profile

        async def list_models(self) -> list[str]:
            return ["m1", "m2"]

    class EmptyProvider:
        def __init__(self, profile: Any, timeout: float = 0.0) -> None:
            pass

        async def list_models(self) -> list[str]:
            return []

    class BoomProvider:
        def __init__(self, profile: Any, timeout: float = 0.0) -> None:
            pass

        async def list_models(self) -> list[str]:
            raise RuntimeError("q" * 800)

    class ShortBoomProvider:
        def __init__(self, profile: Any, timeout: float = 0.0) -> None:
            pass

        async def list_models(self) -> list[str]:
            raise RuntimeError("no models here")

    with TestClient(app) as client:
        # Saving onto a corrupt id takes the existing=None arm, then succeeds.
        saved = client.put(
            "/api/providers/corrupt1",
            headers=HEADERS,
            json={"base_url": "https://x.invalid/v1", "model": "some-model"},
        )
        assert saved.status_code == 200
        assert saved.json()["profile"]["id"] == "corrupt1"

        bad_threshold = client.put(
            "/api/providers/p2",
            headers=HEADERS,
            json={
                "base_url": "https://x.invalid/v1",
                "model": "some-model",
                "context_compression_threshold_percent": 5,
            },
        )
        assert bad_threshold.status_code == 400

        not_found = client.post("/api/providers/corrupt2/models", headers=HEADERS)
        assert not_found.status_code == 404
        assert not_found.json()["detail"] == "profile_not_found"

        monkeypatch.setattr(
            "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider", FakeProvider
        )
        listed = client.post("/api/providers/corrupt1/models", headers=HEADERS)
        assert listed.status_code == 200
        assert listed.json()["models"] == ["m1", "m2"]

        monkeypatch.setattr(
            "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider", EmptyProvider
        )
        empty = client.post("/api/providers/corrupt1/models", headers=HEADERS)
        assert empty.status_code == 200
        assert empty.json()["models"] == []

        monkeypatch.setattr(
            "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider", BoomProvider
        )
        failed = client.post("/api/providers/corrupt1/models", headers=HEADERS)
        assert failed.status_code == 502
        assert failed.json()["detail"].startswith("provider_probe_failed:RuntimeError:")
        # The bounded detail keeps the body without letting it run away.
        assert len(failed.json()["detail"]) < 600

        monkeypatch.setattr(
            "headless_re_mcp.web.routes.agent.OpenAICompatibleProvider", ShortBoomProvider
        )
        short_fail = client.post("/api/providers/corrupt1/models", headers=HEADERS)
        assert short_fail.status_code == 502
        assert short_fail.json()["detail"] == ("provider_probe_failed:RuntimeError:no models here")

        missing_config = client.post("/api/providers/zerofall/import", headers=HEADERS, json={})
        assert missing_config.status_code == 400
        assert missing_config.json()["detail"] == "config_required"

        unconfirmed = client.post(
            "/api/providers/zerofall/import",
            headers=HEADERS,
            json={"config": {"apiKey": "k", "model": "some-model"}},
        )
        assert unconfirmed.status_code == 400

        confirmed = client.post(
            "/api/providers/zerofall/import",
            headers=HEADERS,
            json={"config": {"apiKey": "k", "model": "some-model"}, "confirm": True},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["profile"]["id"] == "zerofall"
