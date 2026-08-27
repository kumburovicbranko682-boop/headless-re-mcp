from __future__ import annotations

import asyncio
import json
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
from headless_re_mcp.agent.orchestrator import AgentOrchestrator, thread_system_prompt
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


def test_linked_session_is_named_in_the_system_prompt() -> None:
    assert "session_id=abc" in thread_system_prompt("abc")
    assert "session_id=" not in thread_system_prompt(None)
    assert "blunt" in thread_system_prompt(None, "be blunt")
    assert "dynamic.resume" in thread_system_prompt(None)
    assert "dynamic.resume" in thread_system_prompt(None, "be blunt")
    assert "dynamic.stealth.set" in thread_system_prompt(None)
    assert "dynamic.stealth.set" in thread_system_prompt(None, "be blunt")
    assert "tmd" in thread_system_prompt(None)
    assert "without waiting" in thread_system_prompt(None)
    assert "without waiting" in thread_system_prompt(None, "be blunt")


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
    events = store.list_events(run["id"])
    assert not any(event.type == "approval.required" for event in events)
    assert [event.data.get("round") for event in events if event.type == "llm.started"] == [1, 2]
    assert [event.data.get("round") for event in events if event.type == "llm.completed"] == [1, 2]


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
async def test_a_runaway_argument_is_refused_rather_than_stored_and_run(
    tmp_path: Path,
) -> None:
    """Results are bounded before storage. Arguments were not.

    A model that lost its place mid-function-call wrote whatever it produced
    into the database and then had it executed. Refused rather than truncated:
    a shortened address or a clipped path is a different instruction from the
    one given, and running that is worse than running nothing. The refusal
    comes back as the tool result, which is what the model reads.
    """
    executed: list[str] = []

    def note(session_id: str = "") -> JsonObject:
        executed.append(session_id)
        return {"ok": True}

    store = AgentStore(tmp_path / "runaway.db")
    thread = store.create_thread()
    provider = FakeProvider(
        [[ProviderToolCall(id="big", name="test.tool", arguments={"session_id": "x" * 400_000})]]
    )
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(note)]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        max_argument_bytes=8_192,
    )

    run = await runner.start_run(thread.id)
    await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED})

    assert executed == [], "the tool must not run on arguments that were refused"
    messages = store.list_messages(thread.id)
    refusals = [item for item in messages if "arguments_too_large" in str(item.content)]
    assert refusals, "the model has to be told, or it just sends it again"
    assert "artifact_id" in str(refusals[0].content), "and told what to do instead"


@pytest.mark.asyncio
async def test_an_ordinary_argument_is_left_alone(tmp_path: Path) -> None:
    """The limit is far above anything the catalog actually takes."""
    executed: list[str] = []

    def note(session_id: str = "") -> JsonObject:
        executed.append(session_id)
        return {"ok": True}

    store = AgentStore(tmp_path / "ordinary.db")
    thread = store.create_thread()
    provider = FakeProvider(
        [[ProviderToolCall(id="ok", name="test.tool", arguments={"session_id": "abc123"})]]
    )
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(note)]),
        _configs(tmp_path / "ordinary-config"),
        provider_factory=lambda _: provider,
    )

    run = await runner.start_run(thread.id)
    await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED})

    assert executed == ["abc123"]


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
        assert await _wait_status(store, run["id"], {RunStatus.COMPLETED}) is RunStatus.COMPLETED

        # The tool thread is still wedged. Reading the run the way the SSE
        # endpoint does has to keep working while it is.
        events = await asyncio.wait_for(
            asyncio.to_thread(store.list_events, run["id"]),
            timeout=5.0,
        )
        assert any(event.type == "tool.completed" for event in events)
        assert any(
            event.type == "tool.completed" and event.data.get("error") == "tool_timeout"
            for event in events
        )
    finally:
        release.set()


@pytest.mark.asyncio
async def test_tool_timeout_returns_to_the_model_and_deadline_still_fails_runs(tmp_path: Path) -> None:
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
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED}) is RunStatus.COMPLETED
    finished = store.get_run(run["id"])
    assert finished is not None and finished.error is None
    assert any(
        event.type == "tool.completed" and event.data.get("error") == "tool_timeout"
        for event in store.list_events(run["id"])
    )

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
async def test_a_provider_stream_that_ends_without_completion_fails_the_run(
    tmp_path: Path,
) -> None:
    """EOF before the provider's terminal event is not a successful answer.

    Measured: a provider that yielded one partial token and then ended without
    a ``completed`` event left the run as completed and wrote a run.completed
    event. An unattended mission could therefore accept a cut-off answer as
    finished work.
    """

    class CutOffProvider(FakeProvider):
        async def _events(self) -> AsyncIterator[ProviderEvent]:
            yield ProviderEvent("text_delta", text="partial")

    store = AgentStore(tmp_path / "cut-off.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path / "cut-off-config"),
        provider_factory=lambda _: CutOffProvider([]),
    )

    run = await runner.start_run(thread.id)
    status = await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED})

    assert status is RunStatus.FAILED
    failed = store.get_run(run["id"])
    assert failed is not None and "without a completed event" in str(failed.error)
    assert not any(
        event.type == "run.completed" for event in store.list_events(run["id"])
    )


@pytest.mark.asyncio
async def test_max_rounds_and_oversized_tool_result_are_bounded(tmp_path: Path) -> None:
    calls = [
        (ProviderToolCall(f"call-{index}", "test.tool", {}),)
        for index in range(4)
    ]
    hits = {"n": 0}

    def counting_tool() -> dict[str, Any]:
        hits["n"] += 1
        return {"ok": True}

    store = AgentStore(tmp_path / "rounds.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(counting_tool)]),
        _configs(tmp_path / "round-config"),
        provider_factory=lambda _: FakeProvider(calls),
        max_tool_rounds=2,
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.FAILED}) is RunStatus.FAILED
    exhausted = store.get_run(run["id"])
    assert exhausted is not None
    assert exhausted.error == "maximum tool rounds exceeded"
    assert "incident" not in str(exhausted.error)
    assert "RuntimeError" not in str(exhausted.error)
    assert hits["n"] == 2
    assistants = [
        message.content
        for message in store.list_messages(thread.id)
        if message.role == "assistant"
    ]
    assert assistants[-1] == "round-2"

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


def test_compaction_never_orphans_a_tool_result_from_its_tool_call() -> None:
    """A cut between an assistant's tool_calls and its results is a provider 400.

    The tail kept by compaction is a suffix, so a role="tool" at its front is
    answering a tool_calls message the cut left behind. An OpenAI-compatible API
    rejects that outright, the run fails, and the scheduler counts a failed run
    as the mission failing -- so a thread that has grown past the budget starts
    losing missions to a malformed request rather than to anything about the
    work. It needs the assistant turns to carry text of their own, which is what
    a model that narrates before calling a tool produces.
    """
    conversation: list[JsonObject] = [{"role": "system", "content": "system prompt"}]
    for turn in range(60):
        conversation.append({"role": "user", "content": "x" * 600})
        conversation.append(
            {
                "role": "assistant",
                "content": "z" * 400,
                "tool_calls": [
                    {
                        "id": f"call{turn}",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{}"},
                    }
                ],
            }
        )
        conversation.append(
            {"role": "tool", "tool_call_id": f"call{turn}", "content": "y" * 1021}
        )

    compacted = compact_messages(conversation, threshold_percent=70)

    assert len(compacted) < len(conversation), "this input must actually compact"
    offered: set[str] = set()
    for message in compacted:
        if message.get("role") == "assistant":
            for call in message.get("tool_calls") or []:
                offered.add(str(call["id"]))
        elif message.get("role") == "tool":
            assert str(message["tool_call_id"]) in offered, (
                "a tool result survived without the tool_calls it answers, "
                "which the provider rejects with 400"
            )


def test_compaction_keeps_the_newest_turns_and_says_what_it_dropped() -> None:
    """Dropping the front is the point; dropping it silently is not."""
    conversation: list[JsonObject] = [{"role": "system", "content": "system prompt"}]
    conversation += [
        {"role": "user", "content": f"turn {index}: " + "x" * 4000} for index in range(40)
    ]

    compacted = compact_messages(conversation, threshold_percent=10, max_chars=20_000)

    assert compacted[0] == conversation[0], "the system prompt is not optional"
    assert "compacted" in str(compacted[1]["content"])
    assert str(compacted[-1]["content"]).startswith("turn 39"), "the newest turn must survive"

def test_a_tool_result_larger_than_the_budget_does_not_erase_the_conversation() -> None:
    """One oversized result must not leave the model with nothing to work from.

    Tool results are capped at 256 KiB, which is larger than the compaction
    budget, so a single large read makes a message no tail can hold. It was kept
    alone, then dropped as an orphan, and what reached the provider was the
    system prompt and a note that three messages had been omitted -- no task and
    no tool output. A model given that answers without calling anything, which
    the orchestrator reads as the run completing, so the run reports success
    having done nothing and every later run rebuilds the same context.
    """
    conversation: list[JsonObject] = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "unpack the sample and report the OEP"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call1",
                    "type": "function",
                    "function": {"name": "static.strings", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call1", "content": "s" * 200_000},
    ]

    compacted = compact_messages(conversation, threshold_percent=90)

    roles = [str(item.get("role")) for item in compacted]
    assert "user" in roles, "the task must survive, or the model has nothing to act on"
    assert "tool" in roles, "the result the model asked for must survive in some form"

    kept = next(item for item in compacted if item.get("role") == "tool")
    assert len(str(kept["content"])) < 200_000, "an oversized result must be trimmed, not dropped"
    offered = {
        str(call["id"])
        for item in compacted
        if item.get("role") == "assistant"
        for call in item.get("tool_calls") or []
    }
    assert str(kept["tool_call_id"]) in offered, "trimming must not orphan the result"


def test_compaction_counts_tool_call_arguments_not_just_spoken_text() -> None:
    """tool_calls go to the provider as part of the assistant message.

    Counting only content treated an 80 KB argument list as free: an 8 KB
    budget forwarded 80 KB and never dropped earlier turns. The arguments
    are what a model that lost its place mid-call produces, and they are
    already in the conversation before the size check refuses to run them.
    """
    conversation: list[JsonObject] = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "do the work"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call1",
                    "type": "function",
                    "function": {"name": "static.strings", "arguments": "A" * 80_000},
                }
            ],
        },
    ]

    compacted = compact_messages(conversation, threshold_percent=10, max_chars=20_000)
    budget = max(8_000, int(20_000 * 10 / 100))
    encoded = sum(
        len(str(item.get("content") or "")) + len(str(item.get("tool_calls") or ""))
        for item in compacted
    )

    assert encoded <= budget + 200, f"forwarded {encoded} characters against a {budget} budget"
    assistant = next(item for item in compacted if item.get("role") == "assistant")
    args = str(assistant["tool_calls"][0]["function"]["arguments"])
    assert len(args) < 80_000
    assert "dropped to fit the context" in args
    assert assistant["tool_calls"][0]["id"] == "call1"


def test_redaction_covers_the_configuration_secrets_it_missed() -> None:
    """Key names that are unambiguously credentials, and nothing more."""
    payload = {
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "credentials": "REALCRED",
        "passwd": "hunter2",
    }

    safe = redact(payload)

    assert all(value == "***REDACTED***" for value in safe.values()), safe


def test_redaction_leaves_the_analysis_result_it_also_runs_over() -> None:
    """This runs over tool results, so over-redacting destroys the deliverable.

    A credential hardcoded in a sample is the finding, not a leak. The rules are
    limited to key names for that reason, and "cookie" is deliberately not one
    of them: __security_cookie is a symbol in almost every Windows binary, and
    redacting it would blank a field the analysis is reporting on.
    """
    findings = {
        "ok": True,
        "data": {
            "symbols": [{"name": "__security_cookie", "address": "0x140021000"}],
            "strings": ["https://admin:hunter2@c2.example/beacon"],
            "cookie": "0x2b992ddfa232",
        },
    }

    safe = redact(findings)

    data = safe["data"]
    assert data["symbols"][0]["name"] == "__security_cookie"
    assert data["cookie"] == "0x2b992ddfa232"
    assert data["strings"][0] == "https://admin:hunter2@c2.example/beacon", (
        "a credential found in the target is the result, not a secret to hide"
    )


@pytest.mark.asyncio
async def test_arguments_too_deep_to_encode_are_refused_like_oversized_ones(
    tmp_path: Path,
) -> None:
    """The size check encodes the arguments, and encoding is what blows up first.

    Two thousand levels of nesting is 14 KB, well inside the byte limit, and
    json.dumps gives up before the limit is ever compared. Same answer as too
    large, since the model has to be told either way.
    """
    import sys

    store = AgentStore(tmp_path / "deep.db")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _: FakeProvider([]),
    )

    sys.setrecursionlimit(20_000)
    try:
        nested: Any = "leaf"
        for _ in range(5_000):
            nested = {"a": nested}
    finally:
        sys.setrecursionlimit(1_000)

    refusal = runner._arguments_too_large({"payload": nested})

    assert refusal is not None
    assert refusal["error"]["code"] == "arguments_too_large"
    assert "nested too deeply" in refusal["error"]["message"]
    assert runner._arguments_too_large({"session_id": "abc"}) is None


class _TinyDeltaProvider:
    def __init__(self, chunks: list[str]) -> None:
        self.chunks = chunks

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
        for chunk in self.chunks:
            yield ProviderEvent("text_delta", text=chunk)
        yield ProviderEvent("completed", tool_calls=())

    async def list_models(self) -> list[str]:
        return ["fake"]


@pytest.mark.asyncio
async def test_streamed_tokens_are_coalesced_before_they_become_sqlite_rows(
    tmp_path: Path,
) -> None:
    """Each token used to be its own event. 5 000 x 4 chars: 4.713s, 828 KiB.

    The UI concatenates message.delta, so a 256-character flush is the same
    text. Same 20 KB of speech becomes 79 rows.
    """
    chunks = ["abcd"] * 5000
    provider = _TinyDeltaProvider(chunks)
    store = AgentStore(tmp_path / "delta.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "talk")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED

    deltas = [event for event in store.list_events(run["id"], limit=5000) if event.type == "message.delta"]
    assert 1 <= len(deltas) <= 100, f"wrote {len(deltas)} delta rows for 20 KB of text"
    assert "".join(str(event.data.get("delta") or "") for event in deltas) == "".join(chunks)


class _ToolJsonProvider:
    def __init__(self) -> None:
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
        if self.round == 0:
            for piece in ("static", ".open", "{" + '"session_id":"x"' + "}"):
                yield ProviderEvent("output_delta", text=piece)
            yield ProviderEvent("completed", tool_calls=(ProviderToolCall("c1", "test.tool", {}),))
        else:
            yield ProviderEvent("text_delta", text="done")
            yield ProviderEvent("completed", tool_calls=())
        self.round += 1

    async def list_models(self) -> list[str]:
        return ["fake"]


@pytest.mark.asyncio
async def test_tool_only_rounds_emit_live_token_progress(tmp_path: Path) -> None:
    """RE turns often generate tool JSON and no chat text.

    tok/s used to stay 0 because the meter only counted message.delta, which
    this path never writes.
    """
    store = AgentStore(tmp_path / "progress.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "inspect")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _: _ToolJsonProvider(),
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED
    events = store.list_events(run["id"])
    first_completed = next(event for event in events if event.type == "llm.completed")
    assert int(first_completed.data.get("tokens") or 0) >= 1
    assert any(event.type == "llm.progress" for event in events)
    first_round_deltas = [
        event
        for event in events
        if event.type == "message.delta" and event.seq < first_completed.seq
    ]
    assert first_round_deltas == []


class _UsageOnlyProvider:
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
        yield ProviderEvent("usage", output_tokens=80)
        yield ProviderEvent("completed", tool_calls=(), output_tokens=80)

    async def list_models(self) -> list[str]:
        return ["fake"]


@pytest.mark.asyncio
async def test_provider_usage_becomes_llm_completed_tokens(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "usage.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "hi")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _: _UsageOnlyProvider(),
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED
    completed = next(event for event in store.list_events(run["id"]) if event.type == "llm.completed")
    assert int(completed.data.get("tokens") or 0) == 80


class _ReasoningProvider:
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
        yield ProviderEvent("reasoning_delta", text="hmm ")
        yield ProviderEvent("reasoning_delta", text="ok")
        yield ProviderEvent("text_delta", text="answer")
        yield ProviderEvent("completed", tool_calls=())

    async def list_models(self) -> list[str]:
        return ["fake"]


@pytest.mark.asyncio
async def test_reasoning_deltas_are_flushed_to_the_event_log(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "reason.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "think")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _: _ReasoningProvider(),
    )
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED
    events = store.list_events(run["id"])
    reasoning = [event for event in events if event.type == "reasoning.delta"]
    assert "".join(str(event.data.get("delta") or "") for event in reasoning) == "hmm ok"
    visible = [event for event in events if event.type == "message.delta"]
    assert "".join(str(event.data.get("delta") or "") for event in visible) == "answer"


class _CapturingProvider:
    """Scripted tool calls, and every request's messages kept for assertions."""

    def __init__(self, scripted: list[tuple[ProviderToolCall, ...]]) -> None:
        self.scripted = scripted
        self.round = 0
        self.requests: list[list[JsonObject]] = []

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
        self.requests.append([dict(message) for message in messages])
        return self._events()

    async def _events(self) -> AsyncIterator[ProviderEvent]:
        calls = self.scripted[self.round] if self.round < len(self.scripted) else ()
        self.round += 1
        yield ProviderEvent("text_delta", text=f"turn-{self.round}")
        yield ProviderEvent("completed", tool_calls=calls)

    async def list_models(self) -> list[str]:
        return ["fake"]


def _assert_tool_pairing_is_provider_valid(messages: list[JsonObject]) -> None:
    """Every role="tool" answers the immediately preceding assistant tool_calls.

    This is the invariant OpenAI-compatible endpoints enforce with a 400; a
    request that breaks it never reaches the model at all.
    """
    open_ids: set[str] = set()
    for message in messages:
        role = message.get("role")
        if role == "assistant":
            open_ids = {
                str(call.get("id"))
                for call in (message.get("tool_calls") or [])
            }
            assert all(open_ids), f"assistant tool_calls with a missing id: {message}"
        elif role == "tool":
            call_id = message.get("tool_call_id")
            assert call_id and str(call_id) in open_ids, (
                f"tool result {call_id!r} has no preceding assistant tool_calls, "
                "which an OpenAI-compatible endpoint rejects with 400"
            )
        else:
            open_ids = set()


@pytest.mark.asyncio
async def test_a_follow_up_run_replays_tool_history_a_provider_accepts(tmp_path: Path) -> None:
    """A thread whose history holds a tool call must stay usable on the next run.

    The store keeps the assistant's text and the tool result but not the
    tool_calls block between them, and the rebuild used to replay the rows
    verbatim: the second run's request carried a role="tool" message behind an
    assistant with no tool_calls, an OpenAI-compatible endpoint 400ed it, and
    every follow-up run on the thread -- including run two of any mission whose
    run one touched a tool -- died before its first token.
    """
    def read(value: int = 0) -> JsonObject:
        return {"ok": True, "data": {"value": value}}

    catalog = CommandCatalog([
        CommandSpec(
            "test.read",
            "test_read",
            frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
            frozenset({ToolEffect.READ_ONLY}),
            handler=read,
            input_schema={"type": "object", "properties": {"value": {"type": "integer"}}},
        )
    ])
    store = AgentStore(tmp_path / "replay.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "inspect the binary")
    first = _CapturingProvider([(ProviderToolCall("c1", "test.read", {"value": 7}),), ()])
    runner = AgentOrchestrator(store, catalog, _configs(tmp_path), provider_factory=lambda _: first)
    run_one = await runner.start_run(thread.id)
    assert await _wait_status(store, run_one["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED

    store.add_message(thread.id, "user", "now what?")
    second = _CapturingProvider([()])
    follow_up = AgentOrchestrator(store, catalog, _configs(tmp_path), provider_factory=lambda _: second)
    run_two = await follow_up.start_run(thread.id)
    assert await _wait_status(store, run_two["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED

    replayed = second.requests[0]
    _assert_tool_pairing_is_provider_valid(replayed)
    result_index = next(
        index for index, message in enumerate(replayed)
        if message.get("role") == "tool" and message.get("tool_call_id") == "c1"
    )
    anchor = replayed[result_index - 1]
    assert anchor["role"] == "assistant"
    stub = next(call for call in anchor["tool_calls"] if call["id"] == "c1")
    # Name and arguments come back from the tool_calls table while the run is
    # retained, so the model re-reads what it actually did, not a blank stub.
    assert stub["function"]["name"] == "test.read"
    assert json.loads(stub["function"]["arguments"]) == {"value": 7}


@pytest.mark.asyncio
async def test_an_id_less_tool_call_still_pairs_inside_its_own_run(tmp_path: Path) -> None:
    """A provider that omits the call id must not poison the next round.

    The minted id used to exist only inside _handle_tool_call while the
    conversation and the store kept the empty original, so round two of the
    same run paired a tool result with no call -- the same 400 shape.
    """
    def read() -> JsonObject:
        return {"ok": True}

    catalog = CommandCatalog([_single_spec(read)])
    store = AgentStore(tmp_path / "idless.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "go")
    provider = _CapturingProvider([(ProviderToolCall("", "test.tool", {}),), ()])
    runner = AgentOrchestrator(store, catalog, _configs(tmp_path), provider_factory=lambda _: provider)
    run = await runner.start_run(thread.id)
    assert await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED}) is RunStatus.COMPLETED

    _assert_tool_pairing_is_provider_valid(provider.requests[1])
    stored_tool = next(
        message for message in store.list_messages(thread.id) if message.role == "tool"
    )
    assert stored_tool.tool_call_id, "the minted id must be persisted, not the empty original"


def test_history_rebuild_survives_a_trimmed_tool_call_row(tmp_path: Path) -> None:
    """A result whose run was trimmed still replays as a valid, neutral pair.

    Message retention (2000 rows) outlives terminal-run retention (128 runs per
    thread), and deleting a run cascades its tool_calls rows, so old results
    legitimately outlive the table that knows their name and arguments.
    """
    from headless_re_mcp.agent.models import AgentMessage
    from headless_re_mcp.agent.orchestrator import _conversation_from_history

    def gone(_run_id: str, _tool_call_id: str) -> JsonObject | None:
        return None

    history = [
        AgentMessage("m1", "t", "user", "task", None, None, "2026-01-01T00:00:00+00:00"),
        AgentMessage("m2", "t", "assistant", "looking", "r1", None, "2026-01-01T00:00:01+00:00"),
        AgentMessage("m3", "t", "tool", '{"ok": true}', "r1", "dead1", "2026-01-01T00:00:02+00:00"),
        AgentMessage("m4", "t", "tool", '{"ok": true}', "r1", "dead2", "2026-01-01T00:00:03+00:00"),
        # A result from a different run must not attach to the earlier turn.
        AgentMessage("m5", "t", "tool", '{"ok": true}', "r2", "dead3", "2026-01-01T00:00:04+00:00"),
    ]

    rebuilt = _conversation_from_history(history, gone)

    _assert_tool_pairing_is_provider_valid(rebuilt)
    anchors = [message for message in rebuilt if message.get("role") == "assistant"]
    assert len(anchors) == 2, "run r2's orphan result needs its own synthesized turn"
    assert [call["id"] for call in anchors[0]["tool_calls"]] == ["dead1", "dead2"]
    assert anchors[0]["content"] == "looking", "the stored assistant text is the anchor"
    assert [call["id"] for call in anchors[1]["tool_calls"]] == ["dead3"]
    assert anchors[1]["content"] is None
