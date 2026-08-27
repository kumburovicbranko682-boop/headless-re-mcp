"""Guard, helper, and cancellation branches of the Agent orchestrator.

The main loop -- read-only auto-run, approvals, rounds, tool timeouts, delta
coalescing, compaction -- is pinned in ``test_agent_orchestrator.py``. This
file covers the corners around it: the small pure helpers, the "the row is
gone / terminal" guards on every store-touching entry point, the permission
and encoding refusals a hostile model reaches, and the cancellation checkpoints
scattered through a run so a cancel is honoured wherever it lands. Each is a
place an unattended run could otherwise crash the server, run a refused tool,
or ignore a cancel and keep spending budget.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent import orchestrator as orch_module
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.orchestrator import (
    AgentOrchestrator,
    _arguments_too_deep,
    _LlmOutputMeter,
    estimate_output_tokens,
    thread_system_prompt,
)
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ResourcePolicy,
    ToolEffect,
)

JsonObject = dict[str, Any]


# ==========================================================================
# pure helpers
# ==========================================================================


def test_system_prompt_does_not_double_up_rules_a_persona_already_states() -> None:
    """A persona that already carries both rules must not get them appended twice."""
    both = f"custom preamble\n{orch_module._DESKTOP_RULE}\n{orch_module._STEALTH_RULE}"
    built = thread_system_prompt(None, both)
    assert built.count(orch_module._DESKTOP_RULE) == 1
    assert built.count(orch_module._STEALTH_RULE) == 1


def test_estimate_output_tokens_weights_latin_against_cjk() -> None:
    """Empty text is zero; Latin is quartered; wide characters count one each."""
    assert estimate_output_tokens("") == 0
    assert estimate_output_tokens("abcd") == 1
    assert estimate_output_tokens("中文字") == 3


def test_arguments_too_deep_walks_lists_as_well_as_dicts() -> None:
    """Nesting through lists counts toward the depth bound, not only dicts."""
    shallow: Any = [[["leaf"]]]
    assert _arguments_too_deep(shallow, limit=10) is False
    deep: Any = "leaf"
    for _ in range(12):
        deep = [deep]
    assert _arguments_too_deep(deep, limit=10) is True


def test_output_meter_counts_wide_characters_and_ignores_a_zero_provider_count(
    tmp_path: Path,
) -> None:
    """The meter estimates from text but defers to a positive provider count only.

    A wide (CJK) delta counts as a whole token, so the local estimate is
    non-zero; a provider usage report of zero is not an update and is ignored,
    leaving the estimate in place rather than blanking the meter.
    """
    store = orch_module.AgentStore(tmp_path / "meter.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=60
    )
    meter = _LlmOutputMeter(store, run.id)
    meter.add("")  # empty text is a no-op, not a flush
    assert meter.tokens == 0
    meter.add("héllo")  # non-ASCII forces the else branch and a first-token flush
    assert meter.tokens >= 1
    before = meter.tokens
    meter.set_provider_tokens(0)  # non-positive: ignored
    assert meter.tokens == before


# ==========================================================================
# fixtures / providers
# ==========================================================================


def _configs(tmp_path: Path) -> ProviderConfigStore:
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(ProviderProfile("default", "https://example.invalid", "fake", api_key="k"))
    return configs


def _spec(
    handler: Any,
    *,
    name: str = "test.tool",
    effect: ToolEffect = ToolEffect.READ_ONLY,
    transports: frozenset[CommandTransport] | None = None,
) -> CommandSpec:
    return CommandSpec(
        name,
        "test_tool",
        transports or frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({effect}),
        handler=handler,
        input_schema={"type": "object", "properties": {}},
        resource_policy=ResourcePolicy(max_result_bytes=262_144),
    )


class _Provider:
    """Yields a scripted list of events for round 0, then a bare completion."""

    def __init__(self, events: list[ProviderEvent]) -> None:
        self._events_list = events
        self.round = 0

    def stream_chat(self, **_: Any) -> AsyncIterator[ProviderEvent]:
        return self._emit()

    async def _emit(self) -> AsyncIterator[ProviderEvent]:
        if self.round == 0:
            for event in self._events_list:
                yield event
        else:
            yield ProviderEvent("completed", tool_calls=())
        self.round += 1

    async def list_models(self) -> list[str]:
        return ["fake"]


def _runner(
    tmp_path: Path, provider: Any, **kwargs: Any
) -> tuple[AgentOrchestrator, Any, Any]:
    store = orch_module.AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(lambda: {"ok": True})]),
        _configs(tmp_path),
        provider_factory=lambda _profile: provider,
        **kwargs,
    )
    return runner, store, thread


def _script_cancel(runner: AgentOrchestrator, *, true_on: int) -> dict[str, int]:
    counter = {"n": 0}

    def fake(run_id: str) -> bool:
        counter["n"] += 1
        return counter["n"] == true_on

    runner._check_cancelled = fake  # type: ignore[method-assign]
    return counter


def _new_run(store: Any, thread: Any) -> str:
    run = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=60
    )
    return run.id


# ==========================================================================
# task bookkeeping / cancel / decide guards
# ==========================================================================


@pytest.mark.asyncio
async def test_forget_task_tolerates_a_task_it_never_tracked(tmp_path: Path) -> None:
    """The done-callback fires for tasks the map may no longer hold."""
    import asyncio

    runner, _store, _thread = _runner(tmp_path, _Provider([]))
    tracked = asyncio.create_task(asyncio.sleep(0))
    runner._tasks["other"] = tracked
    stray = asyncio.create_task(asyncio.sleep(0))

    runner._forget_task(stray)  # no match: iterate, then fall off the end

    assert runner._tasks == {"other": tracked}
    await tracked
    await stray


@pytest.mark.asyncio
async def test_cancel_of_a_run_with_no_live_task_just_flags_the_store(
    tmp_path: Path,
) -> None:
    """A run whose task already finished is cancelled by the store flag alone."""
    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)

    result = await runner.cancel(run_id)  # never started, so no task to cancel

    assert result["cancel_requested"] is True


@pytest.mark.asyncio
async def test_decide_refuses_a_terminal_or_missing_run(tmp_path: Path) -> None:
    runner, store, thread = _runner(tmp_path, _Provider([]))
    with pytest.raises(ValueError, match="terminal or missing"):
        await runner.decide("no-such-run", "c1", "sha", approved=True)

    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.CANCELLED, error="cancelled")
    with pytest.raises(ValueError, match="terminal or missing"):
        await runner.decide(run_id, "c1", "sha", approved=True)


@pytest.mark.asyncio
async def test_decide_refuses_a_redaction_that_is_not_an_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The decision handed back is promised to be an object; a list is refused."""
    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)

    monkeypatch.setattr(store, "decide_tool_call", lambda *a, **k: {"decided": True})
    monkeypatch.setattr(store, "append_event", lambda *a, **k: None)
    monkeypatch.setattr(orch_module, "redact", lambda value: ["not", "an", "object"])

    with pytest.raises(TypeError, match="must be an object"):
        await runner.decide(run_id, "c1", "sha", approved=True)


# ==========================================================================
# _finish_* / _run_loop entry guards
# ==========================================================================


@pytest.mark.asyncio
async def test_finish_failure_and_cancel_are_noops_on_a_terminal_run(
    tmp_path: Path,
) -> None:
    """Neither finisher may re-stamp a run that already reached a terminal state."""
    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)
    store.transition(run_id, RunStatus.COMPLETED)

    await runner._finish_failure(run_id, "late error", event="run.failed")
    await runner._finish_cancel(run_id)

    assert store.get_run(run_id).status is RunStatus.COMPLETED
    assert not any(
        event.type in {"run.failed", "run.cancelled"}
        for event in store.list_events(run_id)
    )


@pytest.mark.asyncio
async def test_run_loop_returns_quietly_for_a_missing_run(tmp_path: Path) -> None:
    runner, _store, _thread = _runner(tmp_path, _Provider([]))
    await runner._run_loop("no-such-run")  # must not raise


@pytest.mark.asyncio
async def test_run_loop_raises_when_the_thread_vanished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run whose thread was deleted underneath it is a hard, named error."""
    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)
    monkeypatch.setattr(store, "get_thread", lambda _tid: None)
    with pytest.raises(KeyError):
        await runner._run_loop(run_id)


# ==========================================================================
# _provider_tools visibility
# ==========================================================================


def test_provider_tools_skips_unimplemented_and_hidden_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spec with no handler/schema, and one the profile hides, are both omitted.

    An AGENT-transport entry that was declared but never wired (no handler or no
    input schema) cannot be offered to the model, and a profile that hides a
    tool must keep it out too; the offered set is only what a run could actually
    call.
    """
    import headless_re_mcp.core.workspace as workspace

    store = orch_module.AgentStore(tmp_path / "agent.db")
    store.create_thread()
    unimplemented = CommandSpec(
        "noimpl.tool",
        "noimpl",
        frozenset({CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
    )
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(lambda: {"ok": True}), unimplemented]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
    )
    monkeypatch.setattr(workspace, "is_tool_visible", lambda name, profile: False)
    assert runner._provider_tools() == []


# ==========================================================================
# argument-size refusals
# ==========================================================================


def test_arguments_too_large_treats_an_unencodable_payload_as_oversized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the encoder itself gives up, the answer is the same as too many bytes.

    A payload shallow enough to pass the depth check can still exhaust the JSON
    encoder; that RecursionError is mapped to the same arguments_too_large
    refusal so the model is told to send a reference rather than inline data.
    """
    runner, _store, _thread = _runner(tmp_path, _Provider([]))

    def blow_up(*_a: Any, **_k: Any) -> str:
        raise RecursionError("encoder gave up")

    monkeypatch.setattr(orch_module.json, "dumps", blow_up)
    refusal = runner._arguments_too_large({"session_id": "abc"})
    assert refusal is not None
    assert refusal["error"]["code"] == "arguments_too_large"


# ==========================================================================
# _handle_tool_call permission / approval branches
# ==========================================================================


@pytest.mark.asyncio
async def test_handle_tool_call_refuses_a_tool_not_exposed_to_the_agent(
    tmp_path: Path,
) -> None:
    """A catalog entry without the AGENT transport must not be callable by a run."""
    store = orch_module.AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    mcp_only = _spec(
        lambda: {"ok": True}, name="mcp.only", transports=frozenset({CommandTransport.MCP})
    )
    runner = AgentOrchestrator(
        store,
        CommandCatalog([mcp_only]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
    )
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)

    with pytest.raises(PermissionError, match="unavailable to Agent"):
        await runner._handle_tool_call(run_id, "c1", "mcp.only", {})


@pytest.mark.asyncio
async def test_handle_tool_call_bails_immediately_when_already_cancelled(
    tmp_path: Path,
) -> None:
    import asyncio

    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)
    _script_cancel(runner, true_on=1)

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_handle_tool_call_honours_a_cancel_during_the_approval_wait(
    tmp_path: Path,
) -> None:
    """A cancel that arrives while a write waits for approval stops the wait."""
    import asyncio

    store = orch_module.AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
    )
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)
    _script_cancel(runner, true_on=2)  # pass the top check, trip the first wait check

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})
    assert store.get_run(run_id).status is RunStatus.AWAITING_APPROVAL


@pytest.mark.asyncio
async def test_handle_tool_call_times_out_an_approval_that_never_comes(
    tmp_path: Path,
) -> None:
    """An unattended write with no grant and no human is failed, not left hanging."""
    store = orch_module.AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
        approval_timeout=1.0,
    )
    # The floor is 1.0s; drop it below that after construction to keep the test fast.
    runner.approval_timeout = 0.05
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)

    with pytest.raises(RuntimeError, match="approval timed out"):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_handle_tool_call_raises_cancel_when_the_tool_cancels_the_run(
    tmp_path: Path,
) -> None:
    """A tool that flips cancel mid-flight is honoured the moment it returns."""
    import asyncio

    store = orch_module.AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    run_holder: dict[str, str] = {}

    def cancelling_tool() -> JsonObject:
        store.request_cancel(run_holder["id"])
        return {"ok": True}

    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(cancelling_tool)]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
    )
    run_id = _new_run(store, thread)
    run_holder["id"] = run_id
    store.transition(run_id, RunStatus.STREAMING)

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_an_approval_that_cannot_be_consumed_fails_the_run(tmp_path: Path) -> None:
    """A single-use approval that will not consume is a hard stop, not a retry.

    The approval token is bound to the argument hash and consumed once. If that
    consume fails -- a tampered hash, a double-spend -- the run must fail rather
    than execute a write on an approval it could not actually claim.
    """
    store = orch_module.AgentStore(tmp_path / "consume.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "do the write")
    provider = _Provider([ProviderEvent("completed", tool_calls=(
        ProviderToolCall("w1", "test.tool", {}),
    ))])
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _p: provider,
    )

    run = await runner.start_run(thread.id)
    for _ in range(300):
        current = store.get_run(run["id"])
        assert current is not None
        if current.status is RunStatus.AWAITING_APPROVAL:
            break
        import asyncio

        await asyncio.sleep(0.01)

    # Break the consume so the granted approval cannot be claimed.
    def refuse_consume(*_a: Any, **_k: Any) -> bool:
        return False

    original = store.consume_approval
    store.consume_approval = refuse_consume  # type: ignore[method-assign]
    try:
        event = next(
            item for item in store.list_events(run["id"]) if item.type == "approval.required"
        )
        await runner.decide(run["id"], "w1", str(event.data["args_sha256"]), approved=True)
        import asyncio

        for _ in range(300):
            current = store.get_run(run["id"])
            assert current is not None
            if current.status is RunStatus.FAILED:
                break
            await asyncio.sleep(0.01)
    finally:
        store.consume_approval = original  # type: ignore[method-assign]

    failed = store.get_run(run["id"])
    assert failed is not None and failed.status is RunStatus.FAILED


# ==========================================================================
# _run_loop cancellation checkpoints
# ==========================================================================


@pytest.mark.asyncio
async def test_run_loop_cancel_before_the_first_round(tmp_path: Path) -> None:
    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)
    _script_cancel(runner, true_on=1)

    await runner._run_loop(run_id)

    assert store.get_run(run_id).status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_run_loop_cancel_between_the_two_pre_stream_checks(tmp_path: Path) -> None:
    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)
    _script_cancel(runner, true_on=2)

    await runner._run_loop(run_id)

    assert store.get_run(run_id).status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_run_loop_cancel_mid_stream_flushes_and_stops(tmp_path: Path) -> None:
    """A cancel during streaming flushes what arrived, then ends the run."""
    provider = _Provider(
        [ProviderEvent("text_delta", text="partial"), ProviderEvent("completed", tool_calls=())]
    )
    runner, store, thread = _runner(tmp_path, provider)
    run_id = _new_run(store, thread)
    _script_cancel(runner, true_on=3)  # first in-stream event check

    await runner._run_loop(run_id)

    assert store.get_run(run_id).status is RunStatus.CANCELLED
    assert any(event.type == "llm.completed" for event in store.list_events(run_id))


@pytest.mark.asyncio
async def test_handle_tool_call_honours_a_cancel_right_after_the_tool_returns(
    tmp_path: Path,
) -> None:
    """A cancel landing between the tool finishing and its result being kept.

    The invocation is stubbed to return cleanly so the counter lands the cancel
    on the post-invoke check, proving a cancel there stops the run rather than
    storing the result and continuing.
    """
    import asyncio

    runner, store, thread = _runner(tmp_path, _Provider([]))
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)

    async def clean_invoke(*_a: Any, **_k: Any) -> JsonObject:
        return {"ok": True}

    runner._invoke_tool_bounded = clean_invoke  # type: ignore[method-assign]
    _script_cancel(runner, true_on=3)  # 1: top, 2: pre-exec, 3: post-invoke

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_handle_tool_call_honours_a_cancel_just_after_approval_is_granted(
    tmp_path: Path,
) -> None:
    """A cancel between an approval landing and the run acting on it is honoured."""
    import asyncio

    store = orch_module.AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
    )
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)
    store.get_tool_call = lambda *_a, **_k: {"approved": True}  # type: ignore[method-assign]
    _script_cancel(runner, true_on=3)  # 1: top, 2: first wait, 3: post-approval

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_handle_tool_call_honours_a_cancel_after_consuming_the_approval(
    tmp_path: Path,
) -> None:
    """The last cancel gate, between consuming an approval and executing, holds."""
    import asyncio

    store = orch_module.AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(lambda: {"ok": True}, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
    )
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)
    store.get_tool_call = lambda *_a, **_k: {"approved": True}  # type: ignore[method-assign]
    store.consume_approval = lambda *_a, **_k: True  # type: ignore[method-assign]
    # 1: top, 2: first wait, 3: post-approval, 4: after the approval block
    _script_cancel(runner, true_on=4)

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run_id, "c1", "test.tool", {})


@pytest.mark.asyncio
async def test_run_loop_cancel_after_a_tool_call_completes(tmp_path: Path) -> None:
    """A cancel that lands once a tool result is stored ends the run there.

    _handle_tool_call is stubbed so the scripted counter measures only the run
    loop's own checks, landing the cancel on the post-tool gate.
    """
    provider = _Provider(
        [
            ProviderEvent("text_delta", text="ok"),
            ProviderEvent(
                "completed", tool_calls=(ProviderToolCall("c1", "test.tool", {}),)
            ),
        ]
    )
    runner, store, thread = _runner(tmp_path, provider)
    run_id = _new_run(store, thread)

    async def stub_handle(*_a: Any, **_k: Any) -> JsonObject:
        return {"ok": True}

    runner._handle_tool_call = stub_handle  # type: ignore[method-assign]
    # 1: pre-round, 2: pre-stream, 3-4: two events, 5: pre-dispatch, 6: post-tool
    _script_cancel(runner, true_on=6)

    await runner._run_loop(run_id)

    assert store.get_run(run_id).status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_run_loop_cancel_before_dispatching_a_tool_call(tmp_path: Path) -> None:
    """A cancel after the stream but before the first tool call is honoured."""
    provider = _Provider(
        [
            ProviderEvent("text_delta", text="ok"),
            ProviderEvent(
                "completed", tool_calls=(ProviderToolCall("c1", "test.tool", {}),)
            ),
        ]
    )
    runner, store, thread = _runner(tmp_path, provider)
    run_id = _new_run(store, thread)
    # 1: pre-round, 2: pre-stream, 3-4: two stream events, 5: the tool-call loop check
    _script_cancel(runner, true_on=5)

    await runner._run_loop(run_id)

    assert store.get_run(run_id).status is RunStatus.CANCELLED


# ==========================================================================
# stream-event fallthroughs
# ==========================================================================


@pytest.mark.asyncio
async def test_run_loop_flushes_a_long_reasoning_burst_mid_stream(tmp_path: Path) -> None:
    """A reasoning delta over the flush window is written out during the stream."""
    provider = _Provider(
        [
            ProviderEvent("reasoning_delta", text="r" * 200),
            ProviderEvent("completed", tool_calls=()),
        ]
    )
    runner, store, thread = _runner(tmp_path, provider)
    run_id = _new_run(store, thread)

    await runner._run_loop(run_id)

    assert store.get_run(run_id).status is RunStatus.COMPLETED
    reasoning = [e for e in store.list_events(run_id) if e.type == "reasoning.delta"]
    assert "".join(str(e.data.get("delta") or "") for e in reasoning) == "r" * 200


@pytest.mark.asyncio
async def test_run_loop_ignores_a_usage_event_without_a_token_count(
    tmp_path: Path,
) -> None:
    """A usage event carrying no tokens matches no branch and is simply skipped."""
    provider = _Provider(
        [
            ProviderEvent("usage", output_tokens=None),
            ProviderEvent("completed", tool_calls=()),
        ]
    )
    runner, store, thread = _runner(tmp_path, provider)
    run_id = _new_run(store, thread)

    await runner._run_loop(run_id)

    assert store.get_run(run_id).status is RunStatus.COMPLETED


# ==========================================================================
# _invoke_tool_bounded progress
# ==========================================================================


@pytest.mark.asyncio
async def test_invoke_tool_bounded_emits_progress_for_a_slow_tool(tmp_path: Path) -> None:
    """A tool that runs past the 2s mark emits a tool.progress heartbeat.

    Long analyses (IDA, unpacking) can run minutes; without a heartbeat the
    console shows a frozen run. The event is what the tok/s-less progress meter
    and the operator read to know the backend is still working.
    """
    import time

    def slow_tool() -> JsonObject:
        time.sleep(2.2)
        return {"ok": True}

    store = orch_module.AgentStore(tmp_path / "progress.db")
    thread = store.create_thread()
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec(slow_tool)]),
        _configs(tmp_path),
        provider_factory=lambda _p: _Provider([]),
    )
    run_id = _new_run(store, thread)
    store.transition(run_id, RunStatus.STREAMING)

    value = await runner._invoke_tool_bounded(
        run_id, "test.tool", {}, timeout=10.0, call_id="c1"
    )

    assert value == {"ok": True}
    assert any(event.type == "tool.progress" for event in store.list_events(run_id))
