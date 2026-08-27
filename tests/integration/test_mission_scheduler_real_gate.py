"""Mission scheduler gate: an unattended objective spans real runs to completion.

The scheduler has thorough unit coverage, but every one of those tests drives
a ``FakeRunner`` that fakes ``start_run`` -- none exercise the real
composition an unattended deployment runs: ``MissionScheduler`` feeding runs
to the real ``AgentOrchestrator``, which drives the real tool catalog bound to
a real ``AnalysisService``, until the model declares the objective met.

This gate builds exactly that stack with a scripted, backend-free provider
(the orchestrator's ``provider_factory`` seam) and pins the long-running
objective contract:

* nobody presses start -- a PENDING mission is claimed and driven by
  ``scheduler.tick()`` alone;
* one objective is carried across several bounded runs -- run one opens the
  sample, run two records a finding using the session id the first run learned
  from a real tool result, run three writes the report and declares
  ``MISSION_COMPLETE``; between runs the mission returns to PENDING and the
  next tick resumes it, and each run appends the continuation contract to the
  same thread;
* completion is the model's word, not a guess -- the mission flips to
  COMPLETED only on the run whose final reply begins with the marker, and the
  real service then shows the session, the finding and the report the runs
  actually produced.

Pure Python end to end: no network (provider injected) and no analysis backend
opened (session.create only classifies and binds). Runs on every platform.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.autonomy import ApprovalMode, AutonomyPolicy
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.models import MISSION_COMPLETE_MARKER, MissionStatus
from headless_re_mcp.agent.orchestrator import AgentOrchestrator
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.agent.scheduler import MissionScheduler
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog

JsonObject = dict[str, Any]

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _session_id_from(messages: Sequence[JsonObject]) -> str | None:
    for message in reversed(list(messages)):
        if message.get("role") != "tool":
            continue
        try:
            payload = json.loads(str(message.get("content", "")))
        except json.JSONDecodeError:
            continue
        data = payload.get("data") if isinstance(payload, dict) else None
        session = data.get("session") if isinstance(data, dict) else None
        if isinstance(session, dict) and session.get("id"):
            return str(session["id"])
    return None


class _MissionAnalyst:
    """A backend-free provider that works one objective across several runs.

    ``turn`` counts LLM turns, not runs: a run is several turns and ends when a
    turn returns no tool calls. The turns are paired so each run does one piece
    of real work and then hands off with a next-step summary, except the last,
    which declares the objective met.
    """

    def __init__(self, binary: str) -> None:
        self.binary = binary
        self.turn = 0
        self.session_id: str | None = None

    def stream_chat(
        self,
        *,
        messages: Sequence[JsonObject],
        tools: Sequence[JsonObject],
        model: str,
        enable_thinking: bool = False,
        reasoning_effort: str | None = None,
    ) -> AsyncIterator[ProviderEvent]:
        del tools, model, enable_thinking, reasoning_effort
        found = _session_id_from(messages)
        if found:
            self.session_id = found
        return self._events()

    async def _events(self) -> AsyncIterator[ProviderEvent]:
        turn = self.turn
        self.turn += 1
        if turn == 0:  # run 1: open the sample
            yield ProviderEvent("text_delta", text="Opening the sample.")
            yield ProviderEvent(
                "completed",
                tool_calls=(ProviderToolCall("open", "session.create", {"binary": self.binary}),),
            )
            return
        if turn == 1:  # run 1: end without the marker, hand off
            yield ProviderEvent("text_delta", text="Sample open. Next: record a finding.")
            yield ProviderEvent("completed", tool_calls=())
            return
        if turn == 2:  # run 2: record a finding with the id learned earlier
            assert self.session_id, "the first run's tool result never reached the model"
            yield ProviderEvent("text_delta", text="Recording a finding.")
            yield ProviderEvent(
                "completed",
                tool_calls=(
                    ProviderToolCall(
                        "note",
                        "knowledge.record",
                        {
                            "session_id": self.session_id,
                            "kind": "function",
                            "key": "licence_check",
                            "value": {"note": "carried across runs by the scheduler gate"},
                        },
                    ),
                ),
            )
            return
        if turn == 3:  # run 2: end without the marker, hand off
            yield ProviderEvent("text_delta", text="Finding recorded. Next: write the report.")
            yield ProviderEvent("completed", tool_calls=())
            return
        if turn == 4:  # run 3: write the report
            assert self.session_id
            yield ProviderEvent("text_delta", text="Writing the report.")
            yield ProviderEvent(
                "completed",
                tool_calls=(
                    ProviderToolCall("report", "report.generate", {"session_id": self.session_id}),
                ),
            )
            return
        # run 3: declare the objective met -- the marker must begin the reply.
        yield ProviderEvent(
            "text_delta", text=f"{MISSION_COMPLETE_MARKER}: sample analysed and reported."
        )
        yield ProviderEvent("completed", tool_calls=())

    async def list_models(self) -> list[str]:
        return ["mission-analyst"]


def _stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provider: _MissionAnalyst
) -> tuple[AnalysisService, AgentStore, MissionScheduler]:
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("HEADLESS_RE_LOCAL_FULL_ACCESS", "1")
    service = AnalysisService(Settings.load())
    catalog = CommandCatalog()
    bind_all_tools(service, catalog)
    store = AgentStore(tmp_path / "agent.db")
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(ProviderProfile("default", "https://example.invalid", "mission-analyst"))
    orchestrator = AgentOrchestrator(
        store,
        catalog,
        configs,
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy().with_mode(ApprovalMode.FULL_ACCESS),
    )
    scheduler = MissionScheduler(
        store, orchestrator.start_run, interval_s=0.01, cancel_run=orchestrator.cancel
    )
    return service, store, scheduler


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_mission_is_carried_across_real_runs_to_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _PE_FIXTURE.is_file(), f"committed fixture missing: {_PE_FIXTURE}"
    provider = _MissionAnalyst(str(_PE_FIXTURE))
    service, store, scheduler = _stack(tmp_path, monkeypatch, provider)
    try:
        thread = store.create_thread()
        mission = store.create_mission(thread.id, "analyse the sample and report", max_runs=6)

        runs_driven = 0
        for _ in range(20):
            current = store.get_mission(mission.id)
            assert current is not None
            if current.status in {
                MissionStatus.COMPLETED,
                MissionStatus.FAILED,
                MissionStatus.EXHAUSTED,
            }:
                break
            if await scheduler.tick():
                runs_driven += 1
        else:
            raise AssertionError("mission never settled")

        settled = store.get_mission(mission.id)
        assert settled.status is MissionStatus.COMPLETED, settled
        # Three runs of real work: open, record, report -- not one, not the cap.
        assert runs_driven == 3
        assert settled.runs_used == 3

        # Each run appended the continuation contract to the same thread.
        messages = store.list_messages(thread.id)
        contracts = [
            message
            for message in messages
            if message.role == "user"
            and "Run" in message.content
            and "objective" in message.content
        ]
        assert len(contracts) == 3
        assert messages[-1].role == "assistant"
        assert messages[-1].content.lstrip().startswith(MISSION_COMPLETE_MARKER)

        # The real service carries the effects those runs produced.
        sessions = service.list_sessions().data["sessions"]
        assert len(sessions) == 1
        session_id = str(sessions[0]["id"])
        assert sessions[0]["target"] == "pe"

        findings = service.knowledge_query(session_id, kind="function", limit=10)
        assert {item["key"] for item in findings.data["entries"]} == {"licence_check"}

        artifacts = service.artifacts_list(session_id)
        assert "report_markdown" in {item["kind"] for item in artifacts.data["artifacts"]}
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_scheduler_starts_a_pending_mission_without_a_human(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gap that made unattended operation impossible: nobody to press start."""
    assert _PE_FIXTURE.is_file()

    class _OneShot(_MissionAnalyst):
        async def _events(self) -> AsyncIterator[ProviderEvent]:
            turn = self.turn
            self.turn += 1
            if turn == 0:
                yield ProviderEvent(
                    "completed",
                    tool_calls=(
                        ProviderToolCall("open", "session.create", {"binary": self.binary}),
                    ),
                )
                return
            yield ProviderEvent("text_delta", text=f"{MISSION_COMPLETE_MARKER}: opened.")
            yield ProviderEvent("completed", tool_calls=())

    provider = _OneShot(str(_PE_FIXTURE))
    service, store, scheduler = _stack(tmp_path, monkeypatch, provider)
    try:
        thread = store.create_thread()
        mission = store.create_mission(thread.id, "just open the sample", max_runs=3)
        assert store.get_mission(mission.id).status is MissionStatus.PENDING

        progressed = await scheduler.tick()

        assert progressed is True
        assert store.get_mission(mission.id).status is MissionStatus.COMPLETED
        assert len(service.list_sessions().data["sessions"]) == 1
    finally:
        service.close_all()
