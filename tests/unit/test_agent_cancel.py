from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.autonomy import AutonomyPolicy
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.orchestrator import AgentOrchestrator
from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.agent.scheduler import MissionScheduler
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


class _CancelOnEventStore(AgentStore):
    """Requests cancellation the instant a chosen run event is recorded.

    This models a user who cancels at an exact point in the tool lifecycle --
    as the call is proposed, as the approval prompt appears, or as the result
    lands -- without any real timing. It lets a direct orchestrator call land
    the cancel in the narrow window each re-check guards, deterministically.
    """

    def __init__(self, path: Path, *, cancel_on: str) -> None:
        super().__init__(path)
        self._cancel_on = cancel_on

    def append_event(self, run_id: str, event_type: str, data: JsonObject) -> Any:
        event = super().append_event(run_id, event_type, data)
        if event_type == self._cancel_on:
            super().request_cancel(run_id)
        return event


async def _wait_status(store: AgentStore, run_id: str, wanted: set[RunStatus]) -> RunStatus:
    for _ in range(400):
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


def _spec(name: str, handler: Any, *, effect: ToolEffect = ToolEffect.READ_ONLY) -> CommandSpec:
    return CommandSpec(
        name,
        name.replace(".", "_"),
        frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
        frozenset({effect}),
        handler=handler,
        input_schema={"type": "object", "properties": {}},
        resource_policy=ResourcePolicy(timeout_seconds=60.0),
    )


@pytest.mark.asyncio
async def test_cancel_stops_a_hanging_tool_and_blocks_further_handlers(tmp_path: Path) -> None:
    """A cancel must finish the run task, not leave the next write queued."""
    entered = threading.Event()
    release = threading.Event()
    invoked: list[str] = []

    def hang() -> JsonObject:
        invoked.append("hang")
        entered.set()
        release.wait(30)
        return {"ok": True}

    def write() -> JsonObject:
        invoked.append("write")
        return {"ok": True, "data": {"changed": True}}

    store = AgentStore(tmp_path / "cancel.db")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "do work")
    provider = FakeProvider(
        [
            (
                ProviderToolCall("hang-1", "test.hang", {}),
                ProviderToolCall("write-1", "test.write", {}),
            ),
            (),
        ]
    )
    runner = AgentOrchestrator(
        store,
        CommandCatalog(
            [
                _spec("test.hang", hang),
                _spec("test.write", write, effect=ToolEffect.STATE_CHANGE),
            ]
        ),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy(auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE})),
        tool_timeout=30.0,
    )
    run = await runner.start_run(thread.id)
    async with runner._lock:
        task = runner._tasks[run["id"]]
    try:
        for _ in range(500):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert entered.is_set(), "the hanging tool never started"

        dumped = await runner.cancel(run["id"])
        assert dumped["cancel_requested"] is True

        with suppress(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
        assert task.done()
        assert task.cancelled()

        final = store.get_run(run["id"])
        assert final is not None
        assert final.status is RunStatus.CANCELLED
        assert final.cancel_requested is True
        assert any(event.type == "run.cancelled" for event in store.list_events(run["id"]))
        assert invoked == ["hang"]
    finally:
        release.set()


@pytest.mark.asyncio
async def test_an_auto_approved_read_only_tool_still_aborts_on_a_cancel(tmp_path: Path) -> None:
    """A read-only tool auto-approves, so it skips the approval wait entirely.

    The re-check right before execution is the only thing that stops it once a
    cancel has landed; without it a cancelled run would still run one more tool.
    """
    store = _CancelOnEventStore(tmp_path / "auto.db", cancel_on="tool.proposed")
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=60)
    store.transition(run.id, RunStatus.STREAMING)

    invoked: list[str] = []

    def readonly() -> JsonObject:
        invoked.append("ran")
        return {"ok": True}

    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec("test.read", readonly)]),
        _configs(tmp_path),
        provider_factory=lambda _: FakeProvider([]),
        autonomy=AutonomyPolicy(),
    )

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run.id, "c1", "test.read", {})

    assert invoked == []


@pytest.mark.asyncio
async def test_a_cancel_while_awaiting_approval_aborts_before_the_tool_runs(tmp_path: Path) -> None:
    """A write waits for a human; a cancel arriving at the prompt must break the
    wait and abort, not sit until the approval timeout or run the tool."""
    store = _CancelOnEventStore(tmp_path / "await.db", cancel_on="approval.required")
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=60)
    store.transition(run.id, RunStatus.STREAMING)

    invoked: list[str] = []

    def writer() -> JsonObject:
        invoked.append("ran")
        return {"ok": True}

    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec("test.write", writer, effect=ToolEffect.STATE_CHANGE)]),
        _configs(tmp_path),
        provider_factory=lambda _: FakeProvider([]),
        autonomy=AutonomyPolicy(),
    )

    with pytest.raises(asyncio.CancelledError):
        await runner._handle_tool_call(run.id, "w1", "test.write", {})

    assert invoked == []


@pytest.mark.asyncio
async def test_a_cancel_landing_as_a_tool_finishes_ends_the_run_before_the_next_round(
    tmp_path: Path,
) -> None:
    """The run loop re-checks cancellation after each tool result is recorded.

    The tool itself completed before the cancel arrived, so every check inside
    _handle_tool_call has already passed; only the loop's own re-check stands
    between a cancelled run and another provider round. The tool.completed
    event is the last write of a successful call, so cancelling on it lands in
    exactly that window.
    """
    store = _CancelOnEventStore(tmp_path / "afterresult.db", cancel_on="tool.completed")
    thread = store.create_thread()
    store.add_message(thread.id, "user", "do one read")
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=60)

    invoked: list[str] = []

    def readonly() -> JsonObject:
        invoked.append("ran")
        return {"ok": True}

    provider = FakeProvider([(ProviderToolCall("r1", "test.read", {}),), ()])
    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec("test.read", readonly)]),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy(),
    )

    await runner._run_loop(run.id)

    assert invoked == ["ran"], "the tool that finished before the cancel keeps its result"
    assert provider.round == 1, "a cancelled run must not start another provider round"
    final = store.get_run(run.id)
    assert final is not None
    assert final.status is RunStatus.CANCELLED
    assert any(event.type == "run.cancelled" for event in store.list_events(run.id))


@pytest.mark.asyncio
async def test_a_result_finishing_alongside_a_cancel_is_discarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancel that lands while the worker computes its value must win.

    The bounded invoker polls for cancellation while the tool runs, but a value
    can be produced in the same beat the cancel is written. Its final check
    catches exactly that: the finished value is dropped and the call aborts
    instead of handing a result to a run the user already stopped.

    Running the worker inline on the event loop makes the beat exact: the
    cancel write and the work finishing happen atomically between two polls,
    with no worker-thread timing involved.
    """
    store = AgentStore(tmp_path / "landed.db")
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=60)
    store.transition(run.id, RunStatus.STREAMING)

    invoked: list[str] = []

    def cancel_then_finish() -> JsonObject:
        invoked.append("ran")
        store.request_cancel(run.id)
        return {"ok": True, "data": {"note": "finished after the user cancelled"}}

    runner = AgentOrchestrator(
        store,
        CommandCatalog([_spec("test.selfcancel", cancel_then_finish)]),
        _configs(tmp_path),
        provider_factory=lambda _: FakeProvider([]),
        autonomy=AutonomyPolicy(),
    )

    async def _inline_run_sync(func: Any, *args: Any, **kwargs: Any) -> Any:
        del kwargs  # abandon_on_cancel and limiter only matter for real threads
        return func(*args)

    monkeypatch.setattr("anyio.to_thread.run_sync", _inline_run_sync)

    with pytest.raises(asyncio.CancelledError):
        await runner._invoke_tool_bounded(run.id, "test.selfcancel", {}, 5.0)

    assert invoked == ["ran"], "the worker really produced a value before the abort"


@pytest.mark.asyncio
async def test_cancel_mission_stops_inflight_run_and_is_not_reclaimed(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    invoked: list[str] = []

    def hang() -> JsonObject:
        invoked.append("hang")
        entered.set()
        release.wait(30)
        return {"ok": True}

    def write() -> JsonObject:
        invoked.append("write")
        return {"ok": True}

    store = AgentStore(tmp_path / "mission-cancel.db")
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "abandon the dump")
    store.claim_next_mission()
    provider = FakeProvider(
        [
            (
                ProviderToolCall("hang-1", "test.hang", {}),
                ProviderToolCall("write-1", "test.write", {}),
            ),
        ]
    )
    runner = AgentOrchestrator(
        store,
        CommandCatalog(
            [
                _spec("test.hang", hang),
                _spec("test.write", write, effect=ToolEffect.STATE_CHANGE),
            ]
        ),
        _configs(tmp_path),
        provider_factory=lambda _: provider,
        autonomy=AutonomyPolicy(auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE})),
        tool_timeout=30.0,
    )
    run = await runner.start_run(thread.id)
    store.note_mission_run(mission.id, run["id"])
    try:
        for _ in range(500):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert entered.is_set()

        cancelled = store.cancel_mission(mission.id)
        assert cancelled.status is MissionStatus.CANCELLED
        live = store.get_run(run["id"])
        assert live is not None
        assert live.cancel_requested is True
        assert await _wait_status(store, run["id"], {RunStatus.CANCELLED}) is RunStatus.CANCELLED
        assert invoked == ["hang"]
        assert store.claim_next_mission() is None
    finally:
        release.set()


def test_cancel_mission_marks_active_runs_and_claim_skips_them(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "store-cancel.db")
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "stop this")
    claimed = store.claim_next_mission()
    assert claimed is not None and claimed.id == mission.id
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=60)
    store.note_mission_run(mission.id, run.id)
    store.transition(run.id, RunStatus.STREAMING)

    cancelled = store.cancel_mission(mission.id)
    assert cancelled.status is MissionStatus.CANCELLED
    refreshed = store.get_run(run.id)
    assert refreshed is not None
    assert refreshed.cancel_requested is True
    assert store.claim_next_mission() is None

    other = store.create_mission(thread.id, "still queued")
    nxt = store.claim_next_mission()
    assert nxt is not None and nxt.id == other.id


def test_consume_approval_refuses_a_cancelled_run(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "approval-cancel.db")
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=60)
    store.transition(run.id, RunStatus.STREAMING)
    proposed = store.propose_tool_call(run.id, "w1", "test.write", {}, ["state_change"])
    store.decide_tool_call(run.id, "w1", str(proposed["args_sha256"]), approved=True)
    store.request_cancel(run.id)
    assert store.consume_approval(run.id, "w1", str(proposed["args_sha256"])) is False


@pytest.mark.asyncio
async def test_scheduler_timeout_cancels_the_bound_orchestrator_run(tmp_path: Path) -> None:
    """A wait timeout must stop the run, not only flip the row."""
    store = AgentStore(tmp_path / "timeout-cancel.db")
    cancelled: list[str] = []

    class BoundRunner:
        async def start_run(self, thread_id: str, **kwargs: Any) -> JsonObject:
            del kwargs
            run = store.create_run(
                thread_id,
                provider_profile="default",
                model=None,
                deadline_seconds=60,
            )
            store.transition(run.id, RunStatus.STREAMING)
            return run.dump()

        async def cancel(self, run_id: str) -> JsonObject:
            cancelled.append(run_id)
            store.request_cancel(run_id)
            current = store.get_run(run_id)
            if current is not None and current.status not in {
                RunStatus.COMPLETED,
                RunStatus.REJECTED,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
                RunStatus.INTERRUPTED,
            }:
                store.transition(run_id, RunStatus.CANCELLED, error="cancelled")
                store.append_event(run_id, "run.cancelled", {"status": RunStatus.CANCELLED.value})
            finished = store.get_run(run_id)
            assert finished is not None
            return finished.dump()

    runner = BoundRunner()
    scheduler = MissionScheduler(store, runner.start_run, interval_s=0.01)
    scheduler.run_wait_timeout_s = 0.2
    scheduler.run_poll_interval_s = 0.01
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "never finishes", max_runs=3)

    await asyncio.wait_for(scheduler.tick(), timeout=10)

    assert cancelled, "timeout must call cancel on the bound runner"
    final = store.get_mission(mission.id)
    assert final is not None
    assert final.status is MissionStatus.FAILED
    stranded = store.get_run(cancelled[0])
    assert stranded is not None
    assert stranded.status is RunStatus.CANCELLED
    assert stranded.cancel_requested is True
