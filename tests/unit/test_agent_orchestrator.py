from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import AsyncIterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.autonomy import AutonomyPolicy
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.context import compact_messages
from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.orchestrator import AgentOrchestrator
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.agent.redaction import redact
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ResourcePolicy,
    ToolEffect,
)

JsonObject = dict[str, Any]


class FakeProvider:
    def __init__(self, calls: list[tuple[ProviderToolCall, ...]]) -> None:
        self.calls = calls
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
        yield ProviderEvent("text_delta", text=f"round-{self.round}")
        calls = self.calls[self.round] if self.round < len(self.calls) else ()
        self.round += 1
        yield ProviderEvent("completed", tool_calls=calls)

    async def list_models(self) -> list[str]:
        return ["fake"]


async def _wait_status(store: AgentStore, run_id: str, wanted: set[RunStatus]) -> RunStatus:
    for _ in range(300):
        run = store.get_run(run_id)
        assert run is not None
        if run.status in wanted:
            return run.status
        await asyncio.sleep(0.01)
    raise AssertionError("run status timeout")


def _configs(tmp_path: Path) -> ProviderConfigStore:
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(ProviderProfile("default", "https://example.invalid", "fake", api_key="never-exposed"))
    return configs


@pytest.mark.asyncio
async def test_read_only_auto_executes_and_multiple_calls_complete(tmp_path: Path) -> None:
    observed: list[int] = []

    def read(value: int) -> JsonObject:
        observed.append(value)
        return {"ok": True, "data": {"value": value}}

    spec = CommandSpec(
        "test.read",
        "test_read",
        frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=read,
        input_schema={"type": "object", "properties": {"value": {"type": "integer"}}},
    )
    catalog = CommandCatalog([spec])
    provider = FakeProvider([
        (
            ProviderToolCall("c1", "test.read", {"value": 1}),
            ProviderToolCall("c2", "test.read", {"value": 2}),
        ),
        (),
    ])
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "read twice")
    runner = AgentOrchestrator(store, catalog, _configs(tmp_path), provider_factory=lambda _: provider)
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED
    assert observed == [1, 2]
    assert not any(event.type == "approval.required" for event in store.list_events(run["id"]))


@pytest.mark.asyncio
async def test_dangerous_call_requires_bound_single_approval(tmp_path: Path) -> None:
    observed: list[str] = []

    def mutate(session_id: str) -> JsonObject:
        observed.append(session_id)
        return {"ok": True, "data": {"changed": True}}

    spec = CommandSpec(
        "test.mutate",
        "test_mutate",
        frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({ToolEffect.STATE_CHANGE}),
        handler=mutate,
        input_schema={"type": "object", "properties": {"session_id": {"type": "string"}}, "required": ["session_id"]},
    )
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "mutate")
    provider = FakeProvider(
        [(ProviderToolCall("danger", "test.mutate", {"session_id": "s"}),), ()]
    )
    runner = AgentOrchestrator(store, CommandCatalog([spec]), _configs(tmp_path), provider_factory=lambda _: provider)
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.AWAITING_APPROVAL}) is RunStatus.AWAITING_APPROVAL
    event = next(item for item in store.list_events(run["id"]) if item.type == "approval.required")
    await runner.decide(run["id"], "danger", str(event.data["args_sha256"]), approved=True)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED
    assert observed == ["s"]


def _single_spec(
    handler: Any,
    *,
    effect: ToolEffect = ToolEffect.READ_ONLY,
    max_result_bytes: int = 262_144,
) -> CommandSpec:
    return CommandSpec(
        "test.tool",
        "test_tool",
        frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({effect}),
        handler=handler,
        input_schema={"type": "object", "properties": {}},
        resource_policy=ResourcePolicy(max_result_bytes=max_result_bytes),
    )


@pytest.mark.asyncio
async def test_a_write_runs_unattended_only_once_the_policy_grants_it(
    tmp_path: Path,
) -> None:
    """The unattended path, end to end: policy in, write executed, no human.

    The policy object being right is not the same as it being wired in. Without
    a grant this same run parks in AWAITING_APPROVAL until the approval timeout
    fails it, which is what makes 24/7 operation impossible today.
    """
    executed: list[str] = []

    def mutate() -> JsonObject:
        executed.append("ran")
        return {"ok": True, "data": {"changed": True}}

    store = AgentStore(tmp_path / "granted.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "do the write")
    provider = FakeProvider([(ProviderToolCall("w1", "test.tool", {}),), ()])
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(mutate, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy(auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE})),
    )

    run = await runner.start_run(thread.id)
    status = await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED})

    assert status is RunStatus.COMPLETED
    assert executed == ["ran"]
    events = store.list_events(run["id"])
    assert not any(event.type == "approval.required" for event in events)
    # A write that ran without a human must be auditable as exactly that.
    auto = next(event for event in events if event.type == "approval.auto")
    assert auto.data["name"] == "test.tool"
    assert auto.data["reason"] == "allowlisted_effects:state_change"
    assert auto.data["effects"] == ["state_change"]


@pytest.mark.asyncio
async def test_a_denied_tool_still_waits_even_when_its_effects_are_granted(
    tmp_path: Path,
) -> None:
    """never_auto_approve has to be an unconditional stop, not a default."""
    store = AgentStore(tmp_path / "denied.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "do the write")
    provider = FakeProvider([(ProviderToolCall("w1", "test.tool", {}),), ()])
    runner = AgentOrchestrator(
        store,
        CommandCatalog(
            [_single_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]
        ),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy(
            auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE}),
            never_auto_approve=frozenset({"test.tool"}),
        ),
    )

    run = await runner.start_run(thread.id)
    status = await _wait_status(store, run["id"], {RunStatus.AWAITING_APPROVAL})

    assert status is RunStatus.AWAITING_APPROVAL
    events = store.list_events(run["id"])
    assert any(event.type == "approval.required" for event in events)
    assert not any(event.type == "approval.auto" for event in events)
    await runner.cancel(run["id"])
    await _wait_status(store, run["id"], {RunStatus.CANCELLED})


@pytest.mark.asyncio
async def test_read_only_auto_execution_is_not_announced_as_a_policy_grant(
    tmp_path: Path,
) -> None:
    """Read-only always ran on its own; it must not look like a widened policy."""
    store = AgentStore(tmp_path / "readonly.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "read")
    provider = FakeProvider([(ProviderToolCall("r1", "test.tool", {}),), ()])
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
    )

    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED}) is RunStatus.COMPLETED
    events = store.list_events(run["id"])
    assert not any(event.type == "approval.auto" for event in events)
    assert not any(event.type == "approval.required" for event in events)


@pytest.mark.asyncio
async def test_rejection_is_terminal_and_tool_never_executes(tmp_path: Path) -> None:
    executed = False

    def mutate() -> JsonObject:
        nonlocal executed
        executed = True
        return {"ok": True}

    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    provider = FakeProvider([(ProviderToolCall("danger", "test.tool", {}),), ()])
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(mutate, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.AWAITING_APPROVAL}) is RunStatus.AWAITING_APPROVAL
    required = next(
        event for event in store.list_events(run["id"]) if event.type == "approval.required"
    )
    await runner.decide(
        run["id"],
        "danger",
        str(required.data["args_sha256"]),
        approved=False,
    )
    assert await _wait_status(store, run["id"], {RunStatus.REJECTED}) is RunStatus.REJECTED
    assert executed is False
    assert any(event.type == "run.rejected" for event in store.list_events(run["id"]))


@pytest.mark.asyncio
async def test_cancel_while_awaiting_approval_is_terminal(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    provider = FakeProvider([(ProviderToolCall("danger", "test.tool", {}),)])
    runner = AgentOrchestrator(
        store,
        CommandCatalog(
            [_single_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]
        ),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.AWAITING_APPROVAL}) is RunStatus.AWAITING_APPROVAL
    await runner.cancel(run["id"])
    assert await _wait_status(store, run["id"], {RunStatus.CANCELLED}) is RunStatus.CANCELLED
    assert any(event.type == "run.cancelled" for event in store.list_events(run["id"]))


@pytest.mark.asyncio
async def test_a_wedged_tool_cannot_starve_the_default_thread_pool(
    tmp_path: Path,
) -> None:
    """A tool that outlives its timeout must not take the event reader with it.

    Python cannot cancel the thread, so an abandoned call keeps its slot until
    the backend returns. Those used to be the same slots the SSE endpoint
    offloads its store reads onto, which left a stuck run unobservable as well
    as stuck. The default pool is shrunk to one worker here so that sharing it
    would be unmissable.
    """
    entered = threading.Event()
    release = threading.Event()

    def wedged_tool() -> JsonObject:
        entered.set()
        release.wait(30)
        return {"ok": True}

    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
    store = AgentStore(tmp_path / "wedged.db")
    thread = store.create_thread()
    provider = FakeProvider([(ProviderToolCall("stuck", "test.tool", {}),)])
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(wedged_tool)]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        tool_timeout=0.1,
    )
    run = await runner.start_run(thread.id)
    try:
        for _ in range(500):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert entered.is_set()
        assert await _wait_status(store, run["id"], {RunStatus.FAILED}) is RunStatus.FAILED

        # The tool thread is still wedged. Reading the run the way the SSE
        # endpoint does has to keep working while it is.
        events = await asyncio.wait_for(
            asyncio.to_thread(store.list_events, run["id"]),
            timeout=5.0,
        )
        assert any(event.type == "tool.completed" for event in events)
    finally:
        release.set()


@pytest.mark.asyncio
async def test_tool_timeout_and_total_deadline_fail_runs(tmp_path: Path) -> None:
    def slow_tool() -> JsonObject:
        time.sleep(0.3)
        return {"ok": True}

    store = AgentStore(tmp_path / "tool-timeout.db")
    thread = store.create_thread()
    provider = FakeProvider([(ProviderToolCall("slow", "test.tool", {}),)])
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(slow_tool)]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        tool_timeout=0.1,
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.FAILED}) is RunStatus.FAILED
    failed = store.get_run(run["id"])
    assert failed is not None and "tool timed out" in str(failed.error)

    class HangingProvider(FakeProvider):
        async def _events(self) -> AsyncIterator[ProviderEvent]:
            await asyncio.sleep(5)
            yield ProviderEvent("completed")

    deadline_store = AgentStore(tmp_path / "deadline.db")
    deadline_thread = deadline_store.create_thread()
    deadline_runner = AgentOrchestrator(
        deadline_store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path / "deadline-config"),
        provider_factory=lambda _: HangingProvider([]),
        run_deadline=1.0,
    )
    deadline_run = await deadline_runner.start_run(deadline_thread.id)
    assert await _wait_status(
        deadline_store, deadline_run["id"], {RunStatus.FAILED}
    ) is RunStatus.FAILED
    timed_out = deadline_store.get_run(deadline_run["id"])
    assert timed_out is not None and timed_out.error == "run deadline exceeded"


@pytest.mark.asyncio
async def test_max_rounds_and_oversized_tool_result_are_bounded(tmp_path: Path) -> None:
    calls = [
        (ProviderToolCall(f"call-{index}", "test.tool", {}),)
        for index in range(4)
    ]
    store = AgentStore(tmp_path / "rounds.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path / "round-config"),
        provider_factory=lambda _: FakeProvider(calls),
        max_tool_rounds=2,
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.FAILED}) is RunStatus.FAILED
    exhausted = store.get_run(run["id"])
    assert exhausted is not None and "maximum tool rounds" in str(exhausted.error)

    oversized_store = AgentStore(tmp_path / "oversized.db")
    oversized_thread = oversized_store.create_thread()
    oversized_provider = FakeProvider(
        [(ProviderToolCall("large", "test.tool", {}),), ()]
    )
    oversized_runner = AgentOrchestrator(
        oversized_store,
        CommandCatalog(
            [
                _single_spec(
                    lambda: {"ok": True, "data": {"blob": "x" * 10_000}},
                    max_result_bytes=512,
                )
            ]
        ),
        _configs(tmp_path / "oversized-config"),
        provider_factory=lambda _: oversized_provider,
    )
    oversized_run = await oversized_runner.start_run(oversized_thread.id)
    assert await _wait_status(
        oversized_store,
        oversized_run["id"],
        {RunStatus.COMPLETED, RunStatus.FAILED},
    ) is RunStatus.COMPLETED
    tool_message = next(
        message
        for message in oversized_store.list_messages(oversized_thread.id)
        if message.role == "tool"
    )
    assert '"truncated": true' in tool_message.content
    assert len(tool_message.content.encode("utf-8")) < 1000


def test_context_compaction_and_nested_redaction() -> None:
    messages: list[JsonObject] = [
        {"role": "system", "content": "system"},
        *[
            {"role": "user", "content": f"{index}:" + "x" * 4000}
            for index in range(40)
        ],
    ]
    compacted = compact_messages(messages, threshold_percent=10, max_chars=20_000)
    assert compacted[0] == messages[0]
    assert "compacted" in str(compacted[1]["content"])
    assert len(compacted) < len(messages)

    safe = redact(
        {
            "outer": [
                {"authorization": "Bearer top-secret"},
                {"nested": {"providerApiKeys": {"main": "secret"}}},
            ]
        }
    )
    assert safe == {
        "outer": [
            {"authorization": "***REDACTED***"},
            {"nested": {"providerApiKeys": "***REDACTED***"}},
        ]
    }
