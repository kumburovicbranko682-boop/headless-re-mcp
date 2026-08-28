"""Unit-level coverage for the orchestrator's helpers and refusal paths.

These exercise the pieces the end-to-end run tests reach only incidentally: the
token estimators, the argument-depth guard, and the early exits that keep a
missing run, a vanished thread, a tool that Agent may not call, or an approval
that never comes from turning into a server-level defect.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.agent.autonomy import AutonomyPolicy
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
    ResourcePolicy,
    ToolEffect,
)

JsonObject = dict[str, Any]


class FakeProvider:
    """Yields a single completed event so a run loop terminates at once."""

    def __init__(self, calls: list[tuple[ProviderToolCall, ...]]) -> None:
        self.calls = calls

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
        yield ProviderEvent("completed", tool_calls=())

    async def list_models(self) -> list[str]:
        return ["fake"]


def _configs(tmp_path: Path) -> ProviderConfigStore:
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(
        ProviderProfile("default", "https://example.invalid", "fake", api_key="never-exposed")
    )
    return configs


def _runner(
    tmp_path: Path,
    catalog: CommandCatalog,
    store: AgentStore,
    *,
    autonomy: AutonomyPolicy | None = None,
    approval_timeout: float = 300.0,
) -> AgentOrchestrator:
    return AgentOrchestrator(
        store,
        catalog,
        _configs(tmp_path),
        provider_factory=lambda _profile: FakeProvider([]),
        autonomy=autonomy,
        approval_timeout=approval_timeout,
    )


def _mutate_spec() -> CommandSpec:
    return CommandSpec(
        "test.mutate",
        "test_mutate",
        frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({ToolEffect.STATE_CHANGE}),
        handler=lambda: {"ok": True},
        input_schema={"type": "object", "properties": {}},
        resource_policy=ResourcePolicy(),
    )


async def _wait_status(store: AgentStore, run_id: str, wanted: set[RunStatus]) -> RunStatus:
    for _ in range(300):
        run = store.get_run(run_id)
        assert run is not None
        if run.status in wanted:
            return run.status
        await asyncio.sleep(0.01)
    raise AssertionError("run status timeout")


def test_estimate_output_tokens_matches_the_latin_cjk_heuristic() -> None:
    assert estimate_output_tokens("") == 0
    # Four Latin characters count as roughly one token.
    assert estimate_output_tokens("abcd") == 1
    # Non-Latin characters count one each.
    assert estimate_output_tokens("你好") == 2
    # Mixed: one CJK plus four Latin -> 1 + 1.
    assert estimate_output_tokens("你aaaa") == 2


def test_llm_output_meter_ignores_empty_text_and_zero_provider_tokens(tmp_path: Path) -> None:
    class _Recorder:
        def __init__(self) -> None:
            self.events: list[tuple[str, JsonObject]] = []

        def append_event(self, run_id: str, kind: str, data: JsonObject) -> None:
            del run_id
            self.events.append((kind, data))

    recorder = _Recorder()
    meter = _LlmOutputMeter(cast(AgentStore, recorder), "run")

    meter.add("")  # empty text is a no-op, so nothing is flushed
    assert recorder.events == []

    meter.add("你")  # a non-Latin char takes the ``other`` branch and flushes
    assert meter.other == 1
    assert recorder.events and recorder.events[-1][0] == "llm.progress"

    before = len(recorder.events)
    meter.set_provider_tokens(0)  # a non-positive provider count is ignored
    assert len(recorder.events) == before

    meter.set_provider_tokens(80)
    assert meter.tokens == 80


def test_system_prompt_does_not_duplicate_rules_already_in_the_persona() -> None:
    persona = f"be terse\n{_DESKTOP_RULE}\n{_STEALTH_RULE}"
    prompt = thread_system_prompt("sess", persona)
    assert prompt.count(_DESKTOP_RULE) == 1
    assert prompt.count(_STEALTH_RULE) == 1
    assert "session_id=sess" in prompt


def test_arguments_too_deep_walks_both_lists_and_dicts() -> None:
    assert _arguments_too_deep({"a": [1, {"b": 2}, 3]}) is False
    nested: Any = "leaf"
    for _ in range(300):
        nested = [nested]
    assert _arguments_too_deep(nested, limit=250) is True


def test_provider_tools_skips_specs_without_a_bound_handler_or_schema(tmp_path: Path) -> None:
    bound = CommandSpec(
        "t.bound",
        "m",
        frozenset({CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=lambda: {"ok": True},
        input_schema={"type": "object", "properties": {}},
    )
    no_schema = CommandSpec(
        "t.noschema",
        "m",
        frozenset({CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=lambda: {"ok": True},
        input_schema=None,
    )
    no_handler = CommandSpec(
        "t.nohandler",
        "m",
        frozenset({CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=None,
        input_schema={"type": "object"},
    )
    store = AgentStore(tmp_path / "tools.db")
    runner = _runner(tmp_path, CommandCatalog([bound, no_schema, no_handler]), store)

    names = {tool["function"]["name"] for tool in runner._provider_tools()}
    assert names == {"t.bound"}


@pytest.mark.asyncio
async def test_decide_refuses_a_missing_run(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "decide.db")
    runner = _runner(tmp_path, CommandCatalog([_mutate_spec()]), store)
    with pytest.raises(ValueError, match="terminal or missing"):
        await runner.decide("no-such-run", "call", "sha", approved=True)


@pytest.mark.asyncio
async def test_cancel_marks_a_run_that_has_no_live_task(tmp_path: Path) -> None:
    """A run created but never started has no task; cancel still records intent."""
    store = AgentStore(tmp_path / "cancel.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="m", deadline_seconds=10.0
    )
    runner = _runner(tmp_path, CommandCatalog([_mutate_spec()]), store)

    result = await runner.cancel(run.id)

    assert result["id"] == run.id
    refreshed = store.get_run(run.id)
    assert refreshed is not None and refreshed.cancel_requested is True


@pytest.mark.asyncio
async def test_finish_helpers_are_silent_on_a_missing_run(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "finish.db")
    runner = _runner(tmp_path, CommandCatalog([_mutate_spec()]), store)
    # Neither should raise or write anything for a run that is not there.
    await runner._finish_failure("gone", "boom", event="run.failed")
    await runner._finish_cancel("gone")


@pytest.mark.asyncio
async def test_run_loop_returns_quietly_when_the_run_is_gone(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "loop.db")
    runner = _runner(tmp_path, CommandCatalog([_mutate_spec()]), store)
    await runner._run_loop("gone")  # get_run is None -> return


@pytest.mark.asyncio
async def test_run_loop_raises_when_the_thread_has_vanished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "loop-thread.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="m", deadline_seconds=10.0
    )
    runner = _runner(tmp_path, CommandCatalog([_mutate_spec()]), store)
    monkeypatch.setattr(store, "get_thread", lambda _tid: None)

    with pytest.raises(KeyError):
        await runner._run_loop(run.id)


@pytest.mark.asyncio
async def test_handle_tool_call_stops_at_once_when_cancel_is_requested(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "handle-cancel.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="m", deadline_seconds=10.0
    )
    store.request_cancel(run.id)
    runner = _runner(tmp_path, CommandCatalog([_mutate_spec()]), store)

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run.id, "call", "test.mutate", {})


@pytest.mark.asyncio
async def test_handle_tool_call_refuses_a_tool_not_exposed_to_agent(tmp_path: Path) -> None:
    mcp_only = CommandSpec(
        "mcp.only",
        "m",
        frozenset({CommandTransport.MCP}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=lambda: {"ok": True},
        input_schema={"type": "object"},
    )
    store = AgentStore(tmp_path / "handle-perm.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="m", deadline_seconds=10.0
    )
    runner = _runner(tmp_path, CommandCatalog([mcp_only]), store)

    with pytest.raises(PermissionError, match="unavailable to Agent"):
        await runner._handle_tool_call(run.id, "call", "mcp.only", {})


@pytest.mark.asyncio
async def test_tool_approval_times_out_when_no_one_answers(tmp_path: Path) -> None:
    """An unanswered approval must fail the call rather than wait forever."""
    store = AgentStore(tmp_path / "approval-timeout.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="m", deadline_seconds=10.0
    )
    store.transition(run.id, RunStatus.STREAMING)
    runner = _runner(
        tmp_path,
        CommandCatalog([_mutate_spec()]),
        store,
        approval_timeout=1.0,
    )

    with pytest.raises(RuntimeError, match="approval timed out"):
        await runner._handle_tool_call(run.id, "call", "test.mutate", {})


@pytest.mark.asyncio
async def test_approval_that_cannot_be_consumed_is_a_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A yes that the store cannot atomically consume must not run the tool.

    The consume step is the guard against a stale approval being spent twice; if
    it fails, the only safe answer is to refuse, not to proceed on the strength
    of the approval flag alone.
    """
    store = AgentStore(tmp_path / "approval-consume.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model="m", deadline_seconds=10.0
    )
    store.transition(run.id, RunStatus.STREAMING)
    runner = _runner(tmp_path, CommandCatalog([_mutate_spec()]), store)

    task = asyncio.create_task(runner._handle_tool_call(run.id, "call", "test.mutate", {}))
    await _wait_status(store, run.id, {RunStatus.AWAITING_APPROVAL})
    required = next(
        event for event in store.list_events(run.id) if event.type == "approval.required"
    )
    sha = str(required.data["args_sha256"])
    monkeypatch.setattr(store, "consume_approval", lambda *_a, **_k: False)

    await runner.decide(run.id, "call", sha, approved=True)

    with pytest.raises(PermissionError, match="could not be consumed"):
        await task


class _LongReasoningProvider:
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
        # One reasoning delta past the 64-char flush threshold forces a mid-stream
        # reasoning flush rather than only the terminal one.
        yield ProviderEvent("reasoning_delta", text="r" * 80)
        yield ProviderEvent("reasoning_delta", text="tail")
        yield ProviderEvent("text_delta", text="answer")
        yield ProviderEvent("completed", tool_calls=())

    async def list_models(self) -> list[str]:
        return ["fake"]


@pytest.mark.asyncio
async def test_reasoning_deltas_flush_mid_stream_past_the_threshold(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "reason-flush.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "think hard")
    spec = CommandSpec(
        "test.tool",
        "test_tool",
        frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=lambda: {"ok": True},
        input_schema={"type": "object", "properties": {}},
    )
    runner = AgentOrchestrator(
        store,
        CommandCatalog([spec]),
        _configs(tmp_path),
        provider_factory=lambda _profile: _LongReasoningProvider(),
    )

    run = await runner.start_run(thread.id)
    assert (
        await _wait_status(store, run["id"], {RunStatus.COMPLETED, RunStatus.FAILED})
        is RunStatus.COMPLETED
    )
    reasoning = [
        event for event in store.list_events(run["id"]) if event.type == "reasoning.delta"
    ]
    assert "".join(str(event.data.get("delta") or "") for event in reasoning) == "r" * 80 + "tail"
    # The long first delta must have produced at least two flush rows.
    assert len(reasoning) >= 2
