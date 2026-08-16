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
