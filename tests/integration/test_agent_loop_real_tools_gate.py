"""Agent loop gate: the orchestrator drives the real tool catalog to real effect.

The orchestrator has thorough unit coverage, but every one of those tests
binds a synthetic one-tool ``CommandCatalog`` with a lambda handler. Nothing
proves the loop against the *real* catalog bound to a real ``AnalysisService``
-- the composition that ``register_agent_routes`` actually builds and the
conversation-centred workbench actually runs.

This gate closes that gap with a scripted, backend-free LLM provider (the
orchestrator's ``provider_factory`` seam) driving the genuine 265-tool surface:

* a full tool round-trip with real side effects -- the model calls
  ``session.create`` against the committed PE fixture, reads the created
  session id back out of the tool-result message the loop feeds it, records a
  finding, generates a report, then summarizes; afterwards the *service* shows
  a bound PE session, the finding is queryable, and the report is a registered
  artifact. Full-access autonomy is audited as auto-approved with the rule
  that allowed each write, not silently;
* a failed real tool call stays in the envelope -- a ``session.create`` for a
  path that does not exist comes back ``ok=False`` as a tool result the model
  reads, so the run still completes with a summary and no session is left
  behind, instead of the loop crashing on the backend's refusal.

Pure Python end to end: no network (the provider is injected) and no analysis
backend is opened (session.create only classifies and binds). Runs on every
platform.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.autonomy import ApprovalMode, AutonomyPolicy
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.orchestrator import AgentOrchestrator
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog

JsonObject = dict[str, Any]

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _latest_session_id(messages: Sequence[JsonObject]) -> str | None:
    """Pull the session id out of the most recent tool-result message.

    This is exactly how a real model learns the id: session.create's envelope
    is fed back as a ``role=tool`` message and the next turn uses it.
    """
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


class _ScriptedAnalyst:
    """A backend-free provider that plays a real analysis conversation.

    Each turn is driven by what the loop has fed back so far, so the tool
    results genuinely round-trip through the provider the way they would with
    a live model -- the session id used in later calls is read from the
    earlier tool result, never hardcoded.
    """

    def __init__(self, binary: str) -> None:
        self.binary = binary
        self.round = 0
        self.models = ["scripted-analyst"]

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
        session_id = _latest_session_id(messages)
        return self._events(session_id)

    async def _events(self, session_id: str | None) -> AsyncIterator[ProviderEvent]:
        current = self.round
        self.round += 1
        if current == 0:
            yield ProviderEvent("text_delta", text="Opening the sample.")
            yield ProviderEvent(
                "completed",
                tool_calls=(
                    ProviderToolCall("call-open", "session.create", {"binary": self.binary}),
                ),
            )
            return
        if current == 1:
            assert session_id, "the loop did not feed session.create's result back"
            yield ProviderEvent("text_delta", text="Recording a finding.")
            yield ProviderEvent(
                "completed",
                tool_calls=(
                    ProviderToolCall(
                        "call-note",
                        "knowledge.record",
                        {
                            "session_id": session_id,
                            "kind": "function",
                            "key": "entrypoint",
                            "value": {"note": "driven by the agent loop gate"},
                        },
                    ),
                ),
            )
            return
        if current == 2:
            assert session_id
            yield ProviderEvent("text_delta", text="Writing the report.")
            yield ProviderEvent(
                "completed",
                tool_calls=(
                    ProviderToolCall("call-report", "report.generate", {"session_id": session_id}),
                ),
            )
            return
        yield ProviderEvent("text_delta", text="Analysis complete.")
        yield ProviderEvent("completed", tool_calls=())

    async def list_models(self) -> list[str]:
        return list(self.models)


class _MissingBinaryAnalyst:
    """Calls session.create on a path that does not exist, then summarizes."""

    def __init__(self, missing: str) -> None:
        self.missing = missing
        self.round = 0

    def stream_chat(
        self,
        *,
        messages: Sequence[JsonObject],
        tools: Sequence[JsonObject],
        model: str,
        enable_thinking: bool = False,
        reasoning_effort: str | None = None,
    ) -> AsyncIterator[ProviderEvent]:
        del messages, tools, model, enable_thinking, reasoning_effort
        return self._events()

    async def _events(self) -> AsyncIterator[ProviderEvent]:
        current = self.round
        self.round += 1
        if current == 0:
            yield ProviderEvent(
                "completed",
                tool_calls=(
                    ProviderToolCall("call-open", "session.create", {"binary": self.missing}),
                ),
            )
            return
        yield ProviderEvent("text_delta", text="That path does not exist; nothing opened.")
        yield ProviderEvent("completed", tool_calls=())


def _service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AnalysisService, CommandCatalog]:
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("HEADLESS_RE_LOCAL_FULL_ACCESS", "1")
    settings = Settings.load()
    service = AnalysisService(settings)
    catalog = CommandCatalog()
    bind_all_tools(service, catalog)
    return service, catalog


def _configs(tmp_path: Path) -> ProviderConfigStore:
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(ProviderProfile("default", "https://example.invalid", "scripted-analyst"))
    return configs


async def _wait_status(store: AgentStore, run_id: str, wanted: set[RunStatus]) -> RunStatus:
    for _ in range(1000):
        run = store.get_run(run_id)
        assert run is not None
        if run.status in wanted:
            return run.status
        await asyncio.sleep(0.01)
    raise AssertionError("run status never settled")


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_agent_loop_drives_real_tools_to_real_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _PE_FIXTURE.is_file(), f"committed fixture missing: {_PE_FIXTURE}"
    service, catalog = _service(tmp_path, monkeypatch)
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "Open the sample, note a finding, and report.")
    provider = _ScriptedAnalyst(str(_PE_FIXTURE))
    orchestrator = AgentOrchestrator(
        store,
        catalog,
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy().with_mode(ApprovalMode.FULL_ACCESS),
    )
    try:
        run = await orchestrator.start_run(thread.id)
        status = await _wait_status(
            store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.REJECTED}
        )
        assert status is RunStatus.COMPLETED, store.get_run(run["id"])

        # The real service carries the effects the loop drove.
        listed = service.list_sessions()
        assert listed.ok, listed.model_dump(mode="json")
        sessions = listed.data["sessions"]
        assert len(sessions) == 1
        session_id = str(sessions[0]["id"])
        assert sessions[0]["target"] == "pe"

        findings = service.knowledge_query(session_id, kind="function", limit=10)
        assert findings.ok, findings.model_dump(mode="json")
        keys = {item["key"] for item in findings.data["entries"]}
        assert "entrypoint" in keys

        artifacts = service.artifacts_list(session_id)
        assert artifacts.ok, artifacts.model_dump(mode="json")
        kinds = {item["kind"] for item in artifacts.data["artifacts"]}
        assert "report_markdown" in kinds

        # The transcript ends with the model's summary, after real tool messages.
        messages = store.list_messages(thread.id)
        roles = [message.role for message in messages]
        assert roles.count("tool") == 3
        assert messages[-1].role == "assistant"
        assert "complete" in messages[-1].content.lower()

        # Every unattended write is audited with the rule that allowed it.
        events = store.list_events(run["id"])
        auto = {
            event.data.get("name"): event.data.get("reason")
            for event in events
            if event.type == "approval.auto"
        }
        assert set(auto) == {"session.create", "knowledge.record", "report.generate"}
        assert all(str(reason).startswith("allowlisted_effects") for reason in auto.values())
        assert not any(event.type == "approval.required" for event in events)
        completed = [
            event.data.get("name")
            for event in events
            if event.type == "tool.completed" and event.data.get("ok")
        ]
        assert completed == ["session.create", "knowledge.record", "report.generate"]
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_agent_loop_keeps_a_failed_real_tool_in_the_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, catalog = _service(tmp_path, monkeypatch)
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "Open a binary that is not there.")
    missing = str(tmp_path / "does-not-exist.bin")
    provider = _MissingBinaryAnalyst(missing)
    orchestrator = AgentOrchestrator(
        store,
        catalog,
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy().with_mode(ApprovalMode.FULL_ACCESS),
    )
    try:
        run = await orchestrator.start_run(thread.id)
        status = await _wait_status(
            store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.REJECTED}
        )
        # A backend refusal is a tool result, not a crashed run.
        assert status is RunStatus.COMPLETED, store.get_run(run["id"])

        assert service.list_sessions().data["sessions"] == []

        events = store.list_events(run["id"])
        failed = [
            event
            for event in events
            if event.type == "tool.completed"
            and event.data.get("name") == "session.create"
            and event.data.get("ok") is False
        ]
        assert len(failed) == 1

        messages = store.list_messages(thread.id)
        tool_messages = [message for message in messages if message.role == "tool"]
        assert len(tool_messages) == 1
        envelope = json.loads(tool_messages[0].content)
        assert envelope["ok"] is False
        assert envelope["error"]["code"]
        assert messages[-1].role == "assistant"
    finally:
        service.close_all()
