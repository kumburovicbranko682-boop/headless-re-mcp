"""Edge-path coverage for agent/orchestrator.py.

Targets the guard arms the happy-path orchestrator tests never reach: prompt
deduplication, meter guards, cancel checks at every stage of the run loop,
approval-wait outcomes, and the bounded tool invocation seams.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_agent_orchestrator import FakeProvider, _configs, _single_spec, _wait_status

from headless_re_mcp.agent import orchestrator as orch
from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.orchestrator import (
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


def _harness(
    tmp_path: Path,
    *,
    catalog: CommandCatalog | None = None,
    provider: Any = None,
    **kwargs: Any,
) -> tuple[AgentStore, AgentOrchestrator, str]:
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "work")
    chosen = provider or FakeProvider([])
    runner = AgentOrchestrator(
        store,
        catalog or CommandCatalog([_single_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _: chosen,
        **kwargs,
    )
    run = store.create_run(
        thread.id, provider_profile="default", model="fake", deadline_seconds=60.0
    )
    # The tool-call paths assume the loop already moved the run to STREAMING.
    store.transition(run.id, RunStatus.STREAMING)
    return store, runner, run.id


# --- module-level helpers ---


def test_system_prompt_does_not_duplicate_rules_the_persona_carries() -> None:
    persona = f"custom persona\n{orch._DESKTOP_RULE}\n{orch._STEALTH_RULE}"
    body = thread_system_prompt(None, persona)
    assert body.count(orch._DESKTOP_RULE) == 1
    assert body.count(orch._STEALTH_RULE) == 1
    assert body.startswith("custom persona")


def test_estimate_output_tokens_matches_the_console_heuristic() -> None:
    assert estimate_output_tokens("") == 0
    assert estimate_output_tokens("abcd") == 1
    assert estimate_output_tokens("\u4e2d\u6587") == 2
    assert estimate_output_tokens("ab\u4e2d") == 2


def test_arguments_too_deep_walks_lists_as_well_as_objects() -> None:
    assert _arguments_too_deep([[["leaf"]]], limit=10) is False
    nested: Any = "leaf"
    for _ in range(12):
        nested = [nested]
    assert _arguments_too_deep(nested, limit=10) is True


def test_meter_ignores_empty_text_and_non_positive_provider_counts(
    tmp_path: Path,
) -> None:
    store, _, run_id = _harness(tmp_path)
    meter = _LlmOutputMeter(store, run_id)
    meter.add("")
    assert meter.tokens == 0
    meter.set_provider_tokens(0)
    assert meter.tokens == 0
    meter.add("\u4e2d")
    assert meter.other == 1
    assert meter.tokens == 1


# --- tool catalog projection ---


def test_provider_tools_skip_specs_without_handler_or_schema(tmp_path: Path) -> None:
    def read() -> JsonObject:
        return {"ok": True}

    agent = frozenset({CommandTransport.AGENT})
    read_only = frozenset({ToolEffect.READ_ONLY})
    usable = CommandSpec(
        "test.usable", "m1", agent, read_only, handler=read,
        input_schema={"type": "object"},
    )
    no_handler = CommandSpec(
        "test.nohandler", "m2", agent, read_only, input_schema={"type": "object"}
    )
    no_schema = CommandSpec("test.noschema", "m3", agent, read_only, handler=read)
    _, runner, _ = _harness(
        tmp_path, catalog=CommandCatalog([usable, no_handler, no_schema])
    )

    names = [tool["function"]["name"] for tool in runner._provider_tools()]

    assert names == ["test.usable"]


# --- task bookkeeping and decide guard ---


@pytest.mark.asyncio
async def test_forget_task_ignores_a_task_it_never_registered(tmp_path: Path) -> None:
    _, runner, _ = _harness(tmp_path)

    async def _noop() -> None:
        return None

    keeper = asyncio.create_task(_noop())
    stranger = asyncio.create_task(_noop())
    await asyncio.gather(keeper, stranger)
    runner._tasks = {"keep": keeper, "gone": stranger}

    runner._forget_task(stranger)
    assert runner._tasks == {"keep": keeper}

    runner._forget_task(stranger)
    assert runner._tasks == {"keep": keeper}


@pytest.mark.asyncio
async def test_decide_refuses_a_redaction_that_is_not_an_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, runner, run_id = _harness(tmp_path)
    proposed = store.propose_tool_call(run_id, "c1", "test.tool", {"a": 1}, ["read_only"])
    monkeypatch.setattr(orch, "redact", lambda value: ["not", "an", "object"])

    with pytest.raises(TypeError, match="redacted decision"):
        await runner.decide(run_id, "c1", str(proposed["args_sha256"]), approved=True)


# --- finish helpers and run-loop guards ---


@pytest.mark.asyncio
async def test_finish_helpers_ignore_a_missing_run(tmp_path: Path) -> None:
    _, runner, _ = _harness(tmp_path)
    await runner._finish_failure("missing", "err", event="run.failed")
    await runner._finish_cancel("missing")


@pytest.mark.asyncio
async def test_run_loop_returns_when_the_run_is_missing(tmp_path: Path) -> None:
    _, runner, _ = _harness(tmp_path)
    await runner._run_loop("missing")


@pytest.mark.asyncio
async def test_run_loop_raises_when_the_thread_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, runner, run_id = _harness(tmp_path)
    # delete_thread cascades to the run, so simulate a row that vanished
    # between the run lookup and the thread lookup.
    monkeypatch.setattr(store, "get_thread", lambda thread_id: None)

    with pytest.raises(KeyError):
        await runner._run_loop(run_id)


@pytest.mark.asyncio
async def test_run_loop_cancels_at_the_start_of_a_round(tmp_path: Path) -> None:
    store, runner, run_id = _harness(tmp_path)
    store.request_cancel(run_id)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_run_loop_cancels_between_the_round_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, runner, run_id = _harness(tmp_path)
    answers = iter([False, True])
    monkeypatch.setattr(runner, "_check_cancelled", lambda _rid: next(answers, True))

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_run_loop_cancels_in_the_middle_of_the_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider([(ProviderToolCall("c1", "test.tool", {}),)])
    store, runner, run_id = _harness(tmp_path, provider=provider)
    answers = iter([False, False, True])
    monkeypatch.setattr(runner, "_check_cancelled", lambda _rid: next(answers, True))

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED
    events = store.list_events(run_id)
    assert any(event.type == "llm.completed" for event in events)


@pytest.mark.asyncio
async def test_run_loop_cancels_before_executing_a_tool_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider([(ProviderToolCall("c1", "test.tool", {}),)])
    store, runner, run_id = _harness(tmp_path, provider=provider)
    # 393 round start, 408 pre-stream, 420 x2 stream events, then True at 488.
    answers = iter([False, False, False, False, True])
    monkeypatch.setattr(runner, "_check_cancelled", lambda _rid: next(answers, True))

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED
    assert not any(
        event.type == "tool.started" for event in store.list_events(run_id)
    )


@pytest.mark.asyncio
async def test_run_loop_cancels_after_a_tool_result_is_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider([(ProviderToolCall("c1", "test.tool", {}),)])
    store, runner, run_id = _harness(tmp_path, provider=provider)

    async def fake_handle(
        rid: str, call_id: str, name: str, arguments: JsonObject
    ) -> JsonObject:
        store.request_cancel(rid)
        return {"ok": True}

    monkeypatch.setattr(runner, "_handle_tool_call", fake_handle)

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.CANCELLED
    run_record = store.get_run(run_id)
    assert run_record is not None
    tool_messages = [
        message
        for message in store.list_messages(run_record.thread_id)
        if message.role == "tool"
    ]
    assert len(tool_messages) == 1


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
        yield ProviderEvent("reasoning_delta", text="r" * 100)
        # An event no branch claims must fall through without effect.
        yield ProviderEvent("usage", output_tokens=None)
        yield ProviderEvent("text_delta", text="answer")
        yield ProviderEvent("completed", tool_calls=())

    async def list_models(self) -> list[str]:
        return ["fake"]


@pytest.mark.asyncio
async def test_long_reasoning_is_flushed_at_the_threshold(tmp_path: Path) -> None:
    store, runner, run_id = _harness(tmp_path, provider=_LongReasoningProvider())

    await runner._run_loop(run_id)

    run = store.get_run(run_id)
    assert run is not None and run.status is RunStatus.COMPLETED
    reasoning = [
        event for event in store.list_events(run_id) if event.type == "reasoning.delta"
    ]
    assert "".join(str(event.data.get("delta") or "") for event in reasoning) == "r" * 100


# --- argument bounding ---


def test_arguments_too_large_wraps_an_encoder_recursion_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, runner, _ = _harness(tmp_path)

    def _explode(*args: Any, **kwargs: Any) -> str:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(orch, "json", SimpleNamespace(dumps=_explode))

    refusal = runner._arguments_too_large({"a": 1})

    assert refusal is not None
    assert refusal["error"]["code"] == "arguments_too_large"
    assert "nested too deeply" in refusal["error"]["message"]


# --- bounded tool invocation seams ---


@pytest.mark.asyncio
async def test_a_slow_tool_reports_live_progress(tmp_path: Path) -> None:
    def slow() -> JsonObject:
        time.sleep(2.3)
        return {"ok": True}

    store, runner, run_id = _harness(
        tmp_path, catalog=CommandCatalog([_single_spec(slow)])
    )

    result = await runner._invoke_tool_bounded(run_id, "test.tool", {}, 10.0, call_id="c1")

    assert result == {"ok": True}
    progress = [
        event for event in store.list_events(run_id) if event.type == "tool.progress"
    ]
    assert progress, "a tool past two seconds must say it is still running"
    assert progress[0].data["name"] == "test.tool"
    assert float(progress[0].data["elapsed_s"]) >= 2.0


@pytest.mark.asyncio
async def test_a_cancel_observed_after_the_tool_finishes_still_cancels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finished = threading.Event()

    def instant() -> JsonObject:
        finished.set()
        return {"ok": True}

    _, runner, run_id = _harness(
        tmp_path, catalog=CommandCatalog([_single_spec(instant)])
    )
    monkeypatch.setattr(runner, "_check_cancelled", lambda _rid: finished.is_set())

    with pytest.raises(asyncio.CancelledError):
        await runner._invoke_tool_bounded(run_id, "test.tool", {}, 5.0)


# --- _handle_tool_call guard arms ---


@pytest.mark.asyncio
async def test_handle_tool_call_raises_when_already_cancelled(tmp_path: Path) -> None:
    store, runner, run_id = _harness(tmp_path)
    store.request_cancel(run_id)

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_handle_tool_call_refuses_a_tool_outside_the_agent_surface(
    tmp_path: Path,
) -> None:
    hidden = CommandSpec(
        "test.hidden",
        "m_hidden",
        frozenset({CommandTransport.MCP}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=lambda: {"ok": True},
        input_schema={"type": "object"},
    )
    _, runner, run_id = _harness(tmp_path, catalog=CommandCatalog([hidden]))

    with pytest.raises(PermissionError, match="unavailable to Agent"):
        await runner._handle_tool_call(run_id, "c1", "test.hidden", {})


@pytest.mark.asyncio
async def test_the_approval_wait_stops_when_the_run_is_cancelled(
    tmp_path: Path,
) -> None:
    store, runner, run_id = _harness(
        tmp_path,
        catalog=CommandCatalog(
            [_single_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]
        ),
    )
    task = asyncio.create_task(runner._handle_tool_call(run_id, "c1", "test.tool", {}))
    await _wait_status(store, run_id, {RunStatus.AWAITING_APPROVAL})
    store.request_cancel(run_id)

    with pytest.raises(asyncio.CancelledError):
        await task


async def _proposed_sha(store: AgentStore, run_id: str, call_id: str) -> str:
    for _ in range(300):
        try:
            return str(store.get_tool_call(run_id, call_id)["args_sha256"])
        except KeyError:
            await asyncio.sleep(0.01)
    raise AssertionError("tool call was never proposed")


def _cancel_after_approval(
    store: AgentStore, run_id: str, call_id: str, *, checks: int
) -> Any:
    """A cancel checker that turns true N checks after the approval lands."""
    seen: list[int] = []

    def checker(_rid: str) -> bool:
        try:
            current = store.get_tool_call(run_id, call_id)
        except KeyError:
            return False
        if current["approved"] is not True:
            return False
        seen.append(1)
        return len(seen) >= checks

    return checker


@pytest.mark.asyncio
async def test_a_cancel_between_approval_and_consumption_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, runner, run_id = _harness(
        tmp_path,
        catalog=CommandCatalog(
            [_single_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]
        ),
    )
    monkeypatch.setattr(
        runner, "_check_cancelled", _cancel_after_approval(store, run_id, "c1", checks=2)
    )
    task = asyncio.create_task(runner._handle_tool_call(run_id, "c1", "test.tool", {}))
    sha = await _proposed_sha(store, run_id, "c1")
    store.decide_tool_call(run_id, "c1", sha, approved=True)

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_an_approval_that_cannot_be_consumed_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, runner, run_id = _harness(
        tmp_path,
        catalog=CommandCatalog(
            [_single_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]
        ),
    )
    monkeypatch.setattr(store, "consume_approval", lambda rid, cid, sha: False)
    task = asyncio.create_task(runner._handle_tool_call(run_id, "c1", "test.tool", {}))
    sha = await _proposed_sha(store, run_id, "c1")
    store.decide_tool_call(run_id, "c1", sha, approved=True)

    with pytest.raises(PermissionError, match="could not be consumed"):
        await task


@pytest.mark.asyncio
async def test_an_unanswered_approval_times_out(tmp_path: Path) -> None:
    store, runner, run_id = _harness(
        tmp_path,
        catalog=CommandCatalog(
            [_single_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]
        ),
        approval_timeout=1.0,
    )
    task = asyncio.create_task(runner._handle_tool_call(run_id, "c1", "test.tool", {}))
    await _wait_status(store, run_id, {RunStatus.AWAITING_APPROVAL})

    with pytest.raises(RuntimeError, match="approval timed out"):
        await task


@pytest.mark.asyncio
async def test_a_cancel_right_after_consumption_stops_the_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, runner, run_id = _harness(
        tmp_path,
        catalog=CommandCatalog(
            [_single_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]
        ),
    )
    monkeypatch.setattr(
        runner, "_check_cancelled", _cancel_after_approval(store, run_id, "c1", checks=3)
    )
    task = asyncio.create_task(runner._handle_tool_call(run_id, "c1", "test.tool", {}))
    sha = await _proposed_sha(store, run_id, "c1")
    store.decide_tool_call(run_id, "c1", sha, approved=True)

    with pytest.raises(asyncio.CancelledError):
        await task
    assert not any(
        event.type == "tool.started" for event in store.list_events(run_id)
    )


@pytest.mark.asyncio
async def test_a_cancel_right_after_the_tool_ran_discards_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finished = threading.Event()

    def instant() -> JsonObject:
        finished.set()
        return {"ok": True}

    store, runner, run_id = _harness(
        tmp_path, catalog=CommandCatalog([_single_spec(instant)])
    )
    seen: list[int] = []

    def checker(_rid: str) -> bool:
        if not finished.is_set():
            return False
        seen.append(1)
        return len(seen) >= 2

    monkeypatch.setattr(runner, "_check_cancelled", checker)

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})
    completed = [
        event for event in store.list_events(run_id) if event.type == "tool.completed"
    ]
    assert completed == []
