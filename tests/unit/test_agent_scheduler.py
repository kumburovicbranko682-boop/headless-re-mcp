from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.models import (
    MISSION_COMPLETE_MARKER,
    MissionStatus,
    RunStatus,
)
from headless_re_mcp.agent.scheduler import MissionScheduler
from headless_re_mcp.agent.store import AgentStore

JsonObject = dict[str, Any]


class FakeRunner:
    """Stands in for the orchestrator: records runs and ends them on command."""

    def __init__(self, store: AgentStore, replies: list[str]) -> None:
        self.store = store
        self.replies = list(replies)
        self.started: list[str] = []
        self.profiles: list[str | None] = []

    async def start_run(self, thread_id: str, *, profile_id: str | None = None, model: str | None = None) -> JsonObject:
        run = self.store.create_run(thread_id, provider_profile=profile_id or "default", model=model, deadline_seconds=60)
        self.started.append(run.id)
        self.profiles.append(profile_id)
        reply = self.replies.pop(0) if self.replies else "still working"
        outcome = RunStatus.FAILED if reply == "__fail__" else RunStatus.COMPLETED
        if outcome is RunStatus.COMPLETED:
            self.store.add_message(thread_id, "assistant", reply, run_id=run.id)
        self.store.transition(run.id, RunStatus.STREAMING)
        self.store.transition(run.id, outcome, error=None if outcome is RunStatus.COMPLETED else "provider down")
        return run.dump()


def _scheduler(tmp_path: Path, replies: list[str]) -> tuple[MissionScheduler, AgentStore, FakeRunner]:
    store = AgentStore(tmp_path / "agent.db")
    runner = FakeRunner(store, replies)
    return MissionScheduler(store, runner.start_run, interval_s=0.01), store, runner


@pytest.mark.asyncio
async def test_a_pending_mission_starts_without_anyone_pressing_start(tmp_path: Path) -> None:
    """The gap that made unattended operation impossible: nobody to POST a run."""
    scheduler, store, runner = _scheduler(tmp_path, [f"{MISSION_COMPLETE_MARKER} done"])
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "map the licence check")

    assert await scheduler.tick() is True

    assert runner.started, "the scheduler must have started a run on its own"
    assert store.get_mission(mission.id).status is MissionStatus.COMPLETED


@pytest.mark.asyncio
async def test_one_objective_is_carried_across_several_bounded_runs(tmp_path: Path) -> None:
    """A run is capped at minutes; the mission is what outlives it."""
    scheduler, store, runner = _scheduler(
        tmp_path,
        ["progress one", "progress two", f"{MISSION_COMPLETE_MARKER} found it"],
    )
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "recover the serial", max_runs=5)

    for _ in range(3):
        assert await scheduler.tick() is True

    assert len(runner.started) == 3
    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.COMPLETED
    assert final.runs_used == 3


@pytest.mark.asyncio
async def test_a_mission_that_never_finishes_stops_at_its_budget(tmp_path: Path) -> None:
    """Without a budget an unmet objective would burn provider quota forever."""
    scheduler, store, runner = _scheduler(tmp_path, ["nope"] * 10)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "prove something impossible", max_runs=2)

    for _ in range(5):
        await scheduler.tick()

    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.EXHAUSTED
    assert final.runs_used == 2
    assert len(runner.started) == 2
    assert "within 2 runs" in str(final.error)


@pytest.mark.asyncio
async def test_a_failed_run_stops_the_mission_rather_than_burning_the_budget(tmp_path: Path) -> None:
    scheduler, store, runner = _scheduler(tmp_path, ["__fail__"])
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "do the thing", max_runs=5)

    await scheduler.tick()

    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.FAILED
    assert "failed" in str(final.error)
    assert len(runner.started) == 1


@pytest.mark.asyncio
async def test_a_restart_resumes_the_mission_instead_of_losing_it(tmp_path: Path) -> None:
    """The objective survives what killed its run.

    interrupt_incomplete_runs marks the in-flight run INTERRUPTED, which is
    correct, but the mission has to go back to the queue or the work is simply
    gone and no one is there to notice.
    """
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "long analysis")
    claimed = store.claim_next_mission()
    assert claimed is not None and claimed.id == mission.id
    assert store.get_mission(mission.id).status is MissionStatus.RUNNING

    # Restart: a fresh store over the same database, as the service does.
    reopened = AgentStore(tmp_path / "agent.db")

    resumed = reopened.get_mission(mission.id)
    assert resumed.status is MissionStatus.PENDING
    assert reopened.claim_next_mission().id == mission.id


@pytest.mark.asyncio
async def test_a_cancelled_mission_is_not_restarted_by_the_scheduler(tmp_path: Path) -> None:
    scheduler, store, runner = _scheduler(tmp_path, ["still going"])
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "abandon me")
    store.cancel_mission(mission.id)

    assert await scheduler.tick() is False
    assert runner.started == []
    assert store.get_mission(mission.id).status is MissionStatus.CANCELLED


def test_claiming_is_atomic_so_two_schedulers_cannot_share_a_mission(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    store.create_mission(thread.id, "only once")

    first = store.claim_next_mission()
    second = store.claim_next_mission()

    assert first is not None
    assert second is None, "a claimed mission must not be handed out twice"


def test_missions_are_claimed_oldest_first(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    first = store.create_mission(thread.id, "first")
    second = store.create_mission(thread.id, "second")

    assert store.claim_next_mission().id == first.id
    assert store.claim_next_mission().id == second.id


def test_an_empty_objective_is_rejected(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    with pytest.raises(ValueError, match="must not be empty"):
        store.create_mission(thread.id, "   ")


@pytest.mark.asyncio
async def test_the_background_loop_drains_the_queue_without_being_asked(tmp_path: Path) -> None:
    scheduler, store, runner = _scheduler(
        tmp_path, [f"{MISSION_COMPLETE_MARKER} a", f"{MISSION_COMPLETE_MARKER} b"]
    )
    thread = store.create_thread()
    one = store.create_mission(thread.id, "first objective")
    two = store.create_mission(thread.id, "second objective")

    scheduler.start()
    try:
        for _ in range(200):
            statuses = {store.get_mission(one.id).status, store.get_mission(two.id).status}
            if statuses == {MissionStatus.COMPLETED}:
                break
            await asyncio.sleep(0.02)
    finally:
        await scheduler.stop()

    assert store.get_mission(one.id).status is MissionStatus.COMPLETED
    assert store.get_mission(two.id).status is MissionStatus.COMPLETED
    assert scheduler.running is False


@pytest.mark.asyncio
async def test_the_loop_survives_a_scheduler_error(tmp_path: Path) -> None:
    """A scheduler that dies is the one failure nobody is there to notice."""
    store = AgentStore(tmp_path / "agent.db")
    calls: list[int] = []

    async def exploding_start(thread_id: str, **kwargs: Any) -> JsonObject:
        calls.append(1)
        raise RuntimeError("provider exploded")

    scheduler = MissionScheduler(store, exploding_start, interval_s=0.01)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "will explode")

    scheduler.start()
    try:
        for _ in range(200):
            if store.get_mission(mission.id).status is MissionStatus.FAILED:
                break
            await asyncio.sleep(0.02)
    finally:
        await scheduler.stop()

    assert calls, "the scheduler should have attempted the run"
    assert store.get_mission(mission.id).status is MissionStatus.FAILED
    assert "provider exploded" in str(store.get_mission(mission.id).error)