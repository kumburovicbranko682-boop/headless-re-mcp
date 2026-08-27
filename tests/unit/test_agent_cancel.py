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


def test_cancel_mission_leaves_a_sibling_missions_run_running(tmp_path: Path) -> None:
    """Cancelling one mission must not stop another that shares the thread.

    The API lets a new objective reuse an existing analysis thread (so the
    session and conversation persist), so two missions can live on one thread.
    Runs carry a thread id but no mission id, and cancel_mission used to flag
    every non-terminal run on the thread -- which cancelled the sibling's
    in-flight run the moment either objective was cancelled. Only the
    cancelled mission's own last run may be stopped.
    """
    store = AgentStore(tmp_path / "sibling-cancel.db")
    thread = store.create_thread()
    keep = store.create_mission(thread.id, "keep working")
    drop = store.create_mission(thread.id, "cancel me")

    # Each mission has a run of its own in flight on the shared thread.
    run_keep = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=60
    )
    store.note_mission_run(keep.id, run_keep.id)
    store.transition(run_keep.id, RunStatus.STREAMING)
    run_drop = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=60
    )
    store.note_mission_run(drop.id, run_drop.id)
    store.transition(run_drop.id, RunStatus.STREAMING)

    store.cancel_mission(drop.id)

    dropped_run = store.get_run(run_drop.id)
    kept_run = store.get_run(run_keep.id)
    assert dropped_run is not None and dropped_run.cancel_requested is True
    assert kept_run is not None and kept_run.cancel_requested is False
    assert store.get_mission(drop.id).status is MissionStatus.CANCELLED
    assert store.get_mission(keep.id).status is not MissionStatus.CANCELLED


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
