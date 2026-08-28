"""Edges of the agent tool loop: meters, cancel checkpoints, approval failures."""

from __future__ import annotations

import asyncio
import time as real_time
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.agent.orchestrator as orchestrator_module
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.orchestrator import (
    _DESKTOP_RULE,
    _STEALTH_RULE,
    AgentOrchestrator,
    _arguments_too_deep,
    _LlmOutputMeter,
    estimate_output_tokens,
    thread_system_prompt,
)
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
)

JsonObject = dict[str, Any]

# ---------------------------------------------------------------------------
# pure helpers


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", 0),
        ("a", 1),
        ("abcd", 1),
        ("abcdefgh", 2),
        ("中", 1),
        ("中文字", 3),
        ("ab中", 2),
    ],
)
def test_estimate_output_tokens_matches_the_console_heuristic(text: str, expected: int) -> None:
    assert estimate_output_tokens(text) == expected


def test_a_persona_that_already_carries_the_rules_is_not_given_them_twice() -> None:
    persona = f"custom persona\n{_DESKTOP_RULE}\n{_STEALTH_RULE}"

    prompt = thread_system_prompt(None, persona)

    assert prompt.count(_DESKTOP_RULE) == 1
    assert prompt.count(_STEALTH_RULE) == 1


def test_deep_nesting_is_detected_through_lists_too() -> None:
    deep: Any = "leaf"
    for _ in range(300):
        deep = [deep]
    assert _arguments_too_deep(deep) is True
    assert _arguments_too_deep([[["shallow"]]]) is False


class _EventSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, JsonObject]] = []

    def append_event(self, run_id: str, event_type: str, data: JsonObject) -> None:
        self.events.append((event_type, data))


def test_the_output_meter_counts_cjk_and_prefers_provider_totals() -> None:
    sink = _EventSink()
    meter = _LlmOutputMeter(sink, "run-1")  # type: ignore[arg-type]

    meter.add("")
    assert meter.tokens == 0 and sink.events == []

    meter.add("中文中文")
    assert meter.other == 4 and meter.tokens == 4

    meter.set_provider_tokens(0)
    assert meter.tokens == 4, "a zero provider total must not shadow the estimate"

    meter.set_provider_tokens(7)
    assert meter.tokens == 7
    assert sink.events[-1] == ("llm.progress", {"tokens": 7})


# ---------------------------------------------------------------------------
# orchestrator plumbing


def _configs(tmp_path: Path) -> ProviderConfigStore:
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(ProviderProfile("default", "https://example.invalid", "fake", api_key="k"))
    return configs


class FakeProvider:
    def __init__(self, rounds: list[list[ProviderEvent]]) -> None:
        self.rounds = rounds
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
        if self.round < len(self.rounds):
            events = self.rounds[self.round]
        else:
            events = [ProviderEvent("completed")]
        self.round += 1
        for event in events:
            yield event

    async def list_models(self) -> list[str]:
        return ["fake"]


def _spec(handler: Any, *, effect: ToolEffect = ToolEffect.READ_ONLY) -> CommandSpec:
    return CommandSpec(
        "test.tool",
        "test_tool",
        frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({effect}),
        handler=handler,
        input_schema={"type": "object", "properties": {}},
    )


def _runner(
    tmp_path: Path,
    provider: FakeProvider | None = None,
    *,
    spec: CommandSpec | None = None,
    **kwargs: Any,
) -> tuple[AgentOrchestrator, AgentStore]:
    store = AgentStore(tmp_path / "agent.db")
    catalog = CommandCatalog([spec] if spec is not None else [])
    runner = AgentOrchestrator(
        store,
        catalog,
        _configs(tmp_path),
        provider_factory=lambda _: provider or FakeProvider([]),
        **kwargs,
    )
    return runner, store


def _new_run(store: AgentStore) -> tuple[str, str]:
    thread = store.create_thread()
    store.add_message(thread.id, "user", "go")
    run = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=60.0
    )
    return run.id, thread.id


async def _wait_status(store: AgentStore, run_id: str, wanted: set[RunStatus]) -> RunStatus:
    for _ in range(400):
        run = store.get_run(run_id)
        assert run is not None
        if run.status in wanted:
            return run.status
        await asyncio.sleep(0.01)
    raise AssertionError("run status timeout")


def _cancel_after(runner: AgentOrchestrator, falses: int) -> None:
    """Report cancellation only from the Nth checkpoint onwards."""
    calls = {"n": 0}

    def check(run_id: str) -> bool:
        calls["n"] += 1
        return calls["n"] > falses

    runner._check_cancelled = check  # type: ignore[method-assign]


@pytest.mark.asyncio
async def test_forgetting_an_unknown_task_leaves_the_registry_alone(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path)
    kept = asyncio.create_task(asyncio.sleep(0))
    stranger = asyncio.create_task(asyncio.sleep(0))
    runner._tasks["kept"] = kept

    runner._forget_task(stranger)
    assert "kept" in runner._tasks

    runner._forget_task(kept)
    assert runner._tasks == {}
    await asyncio.gather(kept, stranger)


@pytest.mark.asyncio
async def test_cancel_without_a_live_task_still_records_the_request(tmp_path: Path) -> None:
    runner, store = _runner(tmp_path)
    run_id, _ = _new_run(store)

    dumped = await runner.cancel(run_id)

    assert dumped["cancel_requested"] is True


@pytest.mark.asyncio
async def test_decide_refuses_missing_and_terminal_runs(tmp_path: Path) -> None:
    runner, store = _runner(tmp_path)
    with pytest.raises(ValueError, match="terminal or missing"):
        await runner.decide("missing", "c1", "sha", approved=True)

    run_id, _ = _new_run(store)
    store.transition(run_id, RunStatus.FAILED, error="x")
    with pytest.raises(ValueError, match="terminal or missing"):
        await runner.decide(run_id, "c1", "sha", approved=True)


@pytest.mark.asyncio
async def test_decide_requires_the_redacted_decision_to_stay_an_object(
    tmp_path: Path,
) -> None:
    class ListStore(AgentStore):
        def decide_tool_call(
            self, run_id: str, tool_call_id: str, args_sha256: str, *, approved: bool
        ) -> Any:
            return ["not", "an", "object"]

    store = ListStore(tmp_path / "agent.db")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([]),
        _configs(tmp_path),
        provider_factory=lambda _: FakeProvider([]),
    )
    run_id, _ = _new_run(store)

    with pytest.raises(TypeError, match="must be an object"):
        await runner.decide(run_id, "c1", "sha", approved=True)


@pytest.mark.asyncio
async def test_finishers_are_quiet_for_missing_or_terminal_runs(tmp_path: Path) -> None:
    runner, store = _runner(tmp_path)
    await runner._finish_failure("missing", "boom", event="run.failed")
    await runner._finish_cancel("missing")

    run_id, _ = _new_run(store)
    store.transition(run_id, RunStatus.STREAMING)
    store.transition(run_id, RunStatus.COMPLETED)
    await runner._finish_failure(run_id, "boom", event="run.failed")
    await runner._finish_cancel(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.COMPLETED


@pytest.mark.asyncio
async def test_the_loop_returns_quietly_when_the_run_vanished(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path)
    await runner._run_loop("missing")


@pytest.mark.asyncio
async def test_the_loop_raises_for_a_thread_the_store_lost(tmp_path: Path) -> None:
    class ForgetfulStore(AgentStore):
        lose_threads = False

        def get_thread(self, thread_id: str) -> Any:
            if self.lose_threads:
                return None
            return super().get_thread(thread_id)

    store = ForgetfulStore(tmp_path / "agent.db")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([]),
        _configs(tmp_path),
        provider_factory=lambda _: FakeProvider([]),
    )
    run_id, _ = _new_run(store)
    store.lose_threads = True

    with pytest.raises(KeyError):
        await runner._run_loop(run_id)


def test_provider_tools_skips_specs_without_handler_or_schema(tmp_path: Path) -> None:
    complete = _spec(lambda: {"ok": True})
    no_schema = CommandSpec(
        "test.noschema",
        "test_noschema",
        frozenset({CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=lambda: {"ok": True},
        input_schema=None,
    )
    store = AgentStore(tmp_path / "agent.db")
    runner = AgentOrchestrator(
        store,
        CommandCatalog([complete, no_schema]),
        _configs(tmp_path),
        provider_factory=lambda _: FakeProvider([]),
    )

    offered = [tool["function"]["name"] for tool in runner._provider_tools()]

    assert offered == ["test.tool"]


# ---------------------------------------------------------------------------
# cancel checkpoints inside the loop


@pytest.mark.asyncio
async def test_a_pre_cancelled_run_never_reaches_the_provider(tmp_path: Path) -> None:
    provider = FakeProvider([[ProviderEvent("completed")]])
    runner, store = _runner(tmp_path, provider)
    run_id, _ = _new_run(store)
    store.request_cancel(run_id)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED
    assert provider.round == 0, "the provider must not be streamed for a dead run"


@pytest.mark.asyncio
async def test_cancel_between_the_two_preflight_checks_still_stops_the_run(
    tmp_path: Path,
) -> None:
    provider = FakeProvider([[ProviderEvent("completed")]])
    runner, store = _runner(tmp_path, provider)
    run_id, _ = _new_run(store)
    _cancel_after(runner, falses=1)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED
    assert provider.round == 0


@pytest.mark.asyncio
async def test_cancel_discovered_mid_stream_flushes_and_reports_the_round(
    tmp_path: Path,
) -> None:
    provider = FakeProvider(
        [[ProviderEvent("text_delta", text="partial"), ProviderEvent("completed")]]
    )
    runner, store = _runner(tmp_path, provider)
    run_id, _ = _new_run(store)
    _cancel_after(runner, falses=2)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED
    types = [event.type for event in store.list_events(run_id)]
    assert "llm.completed" in types, "the round must be closed out even on cancel"


@pytest.mark.asyncio
async def test_cancel_after_the_stream_refuses_to_start_the_tool(tmp_path: Path) -> None:
    executed: list[str] = []

    def tool() -> JsonObject:
        executed.append("ran")
        return {"ok": True}

    provider = FakeProvider(
        [
            [
                ProviderEvent("text_delta", text="x"),
                ProviderEvent("completed", tool_calls=(ProviderToolCall("c1", "test.tool", {}),)),
            ]
        ]
    )
    runner, store = _runner(tmp_path, provider, spec=_spec(tool))
    run_id, _ = _new_run(store)
    # 1: round preflight, 2: pre-stream, 3+4: one per stream event, 5: before the call.
    _cancel_after(runner, falses=4)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED
    assert executed == []


# ---------------------------------------------------------------------------
# stream event shapes


@pytest.mark.asyncio
async def test_reasoning_deltas_flush_at_the_threshold(tmp_path: Path) -> None:
    reasoning = "r" * 100
    provider = FakeProvider(
        [[ProviderEvent("reasoning_delta", text=reasoning), ProviderEvent("completed")]]
    )
    runner, store = _runner(tmp_path, provider)
    run_id, _ = _new_run(store)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.COMPLETED
    deltas = [
        event.data["delta"]
        for event in store.list_events(run_id)
        if event.type == "reasoning.delta"
    ]
    assert deltas == [reasoning]


@pytest.mark.asyncio
async def test_a_usage_event_without_tokens_is_ignored(tmp_path: Path) -> None:
    provider = FakeProvider(
        [[ProviderEvent("usage", output_tokens=None), ProviderEvent("completed")]]
    )
    runner, store = _runner(tmp_path, provider)
    run_id, _ = _new_run(store)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.COMPLETED
    assert not any(event.type == "llm.progress" for event in store.list_events(run_id))


# ---------------------------------------------------------------------------
# approvals that never arrive, cannot be consumed, or are overtaken by cancel


@pytest.mark.asyncio
async def test_an_approval_nobody_answers_times_out_and_fails_the_run(
    tmp_path: Path,
) -> None:
    """An unanswered approval is an absent reviewer, not a server defect.

    This used to travel the defect path: the run's error read
    "RuntimeError: tool approval timed out (incident ...)" -- an exception
    class and a minted incident id for a human who was away -- and the
    tool_calls row stayed 'proposed' forever, so the audit trail showed a call
    still waiting for a decision on a run that had already failed.
    """
    provider = FakeProvider(
        [[ProviderEvent("completed", tool_calls=(ProviderToolCall("c1", "test.tool", {}),))]]
    )
    runner, store = _runner(
        tmp_path,
        provider,
        spec=_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE),
        approval_timeout=1.0,
    )
    thread = store.create_thread()
    store.add_message(thread.id, "user", "go")
    run = await runner.start_run(thread.id)

    assert await _wait_status(store, run["id"], {RunStatus.FAILED}) is RunStatus.FAILED
    stored = store.get_run(run["id"])
    assert stored is not None and stored.error == "tool approval timed out"

    call = store.get_tool_call(run["id"], "c1")
    assert call["status"] == "failed"
    assert call["result"] is not None
    assert call["result"]["error"]["code"] == "approval_timeout"

    events = {event.type: event.data for event in store.list_events(run["id"])}
    assert events["tool.completed"]["error"] == "approval_timeout"
    assert events["run.failed"]["error"] == "tool approval timed out"


@pytest.mark.asyncio
async def test_an_approval_that_cannot_be_consumed_fails_closed(tmp_path: Path) -> None:
    class UnconsumableStore(AgentStore):
        def consume_approval(self, run_id: str, tool_call_id: str, args_sha256: str) -> bool:
            return False

    store = UnconsumableStore(tmp_path / "agent.db")
    provider = FakeProvider(
        [[ProviderEvent("completed", tool_calls=(ProviderToolCall("c1", "test.tool", {}),))]]
    )
    executed: list[str] = []

    def tool() -> JsonObject:
        executed.append("ran")
        return {"ok": True}

    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(tool, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
    )
    thread = store.create_thread()
    store.add_message(thread.id, "user", "go")
    run = await runner.start_run(thread.id)
    assert (
        await _wait_status(store, run["id"], {RunStatus.AWAITING_APPROVAL})
        is RunStatus.AWAITING_APPROVAL
    )
    event = next(item for item in store.list_events(run["id"]) if item.type == "approval.required")
    await runner.decide(run["id"], "c1", str(event.data["args_sha256"]), approved=True)

    assert await _wait_status(store, run["id"], {RunStatus.FAILED}) is RunStatus.FAILED
    stored = store.get_run(run["id"])
    assert stored is not None and "approval could not be consumed" in str(stored.error)
    assert executed == []


@pytest.mark.asyncio
async def test_a_store_level_cancel_interrupts_the_approval_wait(tmp_path: Path) -> None:
    """runner.cancel() kills the task; a bare store flag must also be honoured."""
    provider = FakeProvider(
        [[ProviderEvent("completed", tool_calls=(ProviderToolCall("c1", "test.tool", {}),))]]
    )
    runner, store = _runner(
        tmp_path, provider, spec=_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)
    )
    thread = store.create_thread()
    store.add_message(thread.id, "user", "go")
    run = await runner.start_run(thread.id)
    assert (
        await _wait_status(store, run["id"], {RunStatus.AWAITING_APPROVAL})
        is RunStatus.AWAITING_APPROVAL
    )

    store.request_cancel(run["id"])

    assert await _wait_status(store, run["id"], {RunStatus.CANCELLED}) is RunStatus.CANCELLED


# ---------------------------------------------------------------------------
# tool execution edges


@pytest.mark.asyncio
async def test_a_cancelled_run_cannot_enter_a_tool_call(tmp_path: Path) -> None:
    runner, store = _runner(tmp_path, spec=_spec(lambda: {"ok": True}))
    run_id, _ = _new_run(store)
    store.request_cancel(run_id)

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_a_tool_outside_the_agent_transport_is_refused(tmp_path: Path) -> None:
    mcp_only = CommandSpec(
        "test.tool",
        "test_tool",
        frozenset({CommandTransport.MCP}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=lambda: {"ok": True},
        input_schema={"type": "object", "properties": {}},
    )
    runner, store = _runner(tmp_path, spec=mcp_only)
    run_id, _ = _new_run(store)

    with pytest.raises(PermissionError, match="unavailable to Agent"):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_a_slow_tool_emits_progress_heartbeats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def slow_tool() -> JsonObject:
        real_time.sleep(0.2)
        return {"ok": True, "data": {}}

    runner, store = _runner(tmp_path, spec=_spec(slow_tool))
    run_id, _ = _new_run(store)
    store.transition(run_id, RunStatus.STREAMING)

    clock = {"now": 1000.0}

    def racing_monotonic() -> float:
        clock["now"] += 1.0
        return clock["now"]

    monkeypatch.setattr(orchestrator_module, "time", SimpleNamespace(monotonic=racing_monotonic))

    result = await runner._handle_tool_call(run_id, "c1", "test.tool", {})

    assert result["ok"] is True
    progress = [event.data for event in store.list_events(run_id) if event.type == "tool.progress"]
    assert progress, "a tool past the heartbeat interval must be visible as running"
    assert progress[0]["tool_call_id"] == "c1"
    assert progress[0]["name"] == "test.tool"


def test_arguments_that_exhaust_the_encoder_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The depth walk runs first; if it ever misses, the encoder crash is caught.

    How deep the real encoder can go before RecursionError depends on the
    platform's C stack, so the encoder itself is faked to give up.
    """
    monkeypatch.setattr(orchestrator_module, "_arguments_too_deep", lambda value: False)

    def exhausted(*args: Any, **kwargs: Any) -> str:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(orchestrator_module, "json", SimpleNamespace(dumps=exhausted))
    runner, _ = _runner(tmp_path)

    refusal = runner._arguments_too_large({"k": "leaf"})

    assert refusal is not None
    assert refusal["error"]["code"] == "arguments_too_large"
    assert "nested too deeply" in refusal["error"]["message"]
