"""Lifecycle and mid-advance branches of the mission scheduler.

The happy path -- claim, run, budget, isolation, watchdog, run-wait timeout --
is pinned in ``test_agent_scheduler.py``. This file covers the corners that
happen when the surrounding world moves underneath a mission: start/stop called
out of order, a mission cancelled at each point during a single advance, the
inflight-cancel fallbacks, and the two "the row is gone" guards. Each is a spot
where an unattended scheduler could otherwise start a run on a cancelled
mission, park on a task it cannot stop, or crash the loop nobody is watching.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent import scheduler as scheduler_module
from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.scheduler import MissionScheduler
from headless_re_mcp.agent.store import AgentStore

JsonObject = dict[str, Any]


async def _dummy_start(thread_id: str, **kwargs: Any) -> JsonObject:
    raise AssertionError("start_run must not be called in this test")


class _Runner:
    """Creates and completes a run, like the orchestrator's fast path."""

    def __init__(self, store: AgentStore) -> None:
        self.store = store
        self.started: list[str] = []

    async def start_run(
        self, thread_id: str, *, profile_id: str | None = None, model: str | None = None
    ) -> JsonObject:
        run = self.store.create_run(
            thread_id, provider_profile=profile_id or "default", model=model, deadline_seconds=60
        )
        self.started.append(run.id)
        self.store.add_message(thread_id, "assistant", "done", run_id=run.id)
        self.store.transition(run.id, RunStatus.STREAMING)
        self.store.transition(run.id, RunStatus.COMPLETED)
        return run.dump()


def _claimed(store: AgentStore, *, max_runs: int = 3) -> Any:
    thread = store.create_thread()
    store.create_mission(thread.id, "objective", max_runs=max_runs)
    mission = store.claim_next_mission()
    assert mission is not None
    return mission


# --------------------------------------------------------------------------
# start / stop lifecycle
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_is_idempotent_while_a_task_is_running(tmp_path: Path) -> None:
    """A second start must not spawn a rival loop over the same store."""
    store = AgentStore(tmp_path / "agent.db")
    scheduler = MissionScheduler(store, _dummy_start, interval_s=0.01)
    scheduler.start()
    first = scheduler._task
    scheduler.start()
    assert scheduler._task is first
    await scheduler.stop()


@pytest.mark.asyncio
async def test_stop_before_start_is_a_noop(tmp_path: Path) -> None:
    """Shutting down a scheduler that never started must not raise."""
    store = AgentStore(tmp_path / "agent.db")
    scheduler = MissionScheduler(store, _dummy_start)
    await scheduler.stop()
    assert scheduler.running is False


@pytest.mark.asyncio
async def test_stop_cancels_a_loop_that_will_not_exit_in_time(tmp_path: Path) -> None:
    """If the loop ignores the stop event, stop() escalates to cancellation."""
    store = AgentStore(tmp_path / "agent.db")
    scheduler = MissionScheduler(store, _dummy_start)
    scheduler._stop = asyncio.Event()
    stubborn = asyncio.create_task(asyncio.sleep(10))
    scheduler._task = stubborn

    await scheduler.stop(timeout=0.01)

    with pytest.raises(asyncio.CancelledError):
        await stubborn
    assert stubborn.cancelled()


@pytest.mark.asyncio
async def test_the_loop_keeps_running_when_claiming_itself_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A store error in claim happens outside tick's own guard, so _loop catches it.

    tick() only wraps the per-mission advance; the claim that precedes it can
    still throw (a locked database, a torn row). If that escaped _loop, the
    scheduler task would die and no mission would ever run again while the
    process stayed up.
    """
    store = AgentStore(tmp_path / "agent.db")
    recorded: list[str] = []
    monkeypatch.setattr(
        scheduler_module,
        "record_exception",
        lambda exc, context="": recorded.append(context) or {"incident_id": "x", "message": "m"},
    )

    def boom() -> Any:
        raise RuntimeError("claim failed")

    monkeypatch.setattr(store, "claim_next_mission", boom)
    scheduler = MissionScheduler(store, _dummy_start, interval_s=0.01)
    scheduler.start()
    try:
        for _ in range(200):
            if recorded:
                break
            await asyncio.sleep(0.01)
        running = scheduler.running
    finally:
        await scheduler.stop()

    assert recorded, "the claim failure must have been recorded"
    assert running, "the loop must survive a claim that raised"


# --------------------------------------------------------------------------
# _bound_cancel / _stop_inflight_run
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bound_cancel_prefers_the_explicit_canceller(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")

    async def canceller(run_id: str) -> JsonObject:
        return {}

    scheduler = MissionScheduler(store, _dummy_start, cancel_run=canceller)
    assert scheduler._bound_cancel() is canceller


@pytest.mark.asyncio
async def test_bound_cancel_discovers_cancel_on_the_run_starter(tmp_path: Path) -> None:
    """When start_run is a bound method, its object's cancel is used automatically.

    Wiring start_run to the orchestrator is enough; the scheduler finds
    ``orchestrator.cancel`` through ``start_run.__self__`` so a timeout can stop
    the tracked asyncio task without the web layer passing a second callback.
    """
    store = AgentStore(tmp_path / "agent.db")

    class Orchestrator:
        async def start_run(self, thread_id: str, **kwargs: Any) -> JsonObject:
            return {"id": "r"}

        async def cancel(self, run_id: str) -> JsonObject:
            return {}

    orch = Orchestrator()
    scheduler = MissionScheduler(store, orch.start_run)
    bound = scheduler._bound_cancel()
    # Bound methods are fresh objects per access, so compare by function+owner.
    assert bound is not None
    assert bound.__func__ is Orchestrator.cancel  # type: ignore[attr-defined]
    assert bound.__self__ is orch  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_stop_inflight_uses_a_canceller_that_succeeds(tmp_path: Path) -> None:
    """The ordinary case: a canceller that stops the run returns without fallback."""
    store = AgentStore(tmp_path / "agent.db")
    called: list[str] = []

    async def canceller(run_id: str) -> JsonObject:
        called.append(run_id)
        return {}

    scheduler = MissionScheduler(store, _dummy_start, cancel_run=canceller)
    await scheduler._stop_inflight_run("run-1")
    assert called == ["run-1"]


@pytest.mark.asyncio
async def test_stop_inflight_swallows_a_cancel_that_no_longer_applies(
    tmp_path: Path,
) -> None:
    """A run that finished between the flip and the cancel is not an error."""
    store = AgentStore(tmp_path / "agent.db")

    async def canceller(run_id: str) -> JsonObject:
        raise KeyError(run_id)

    scheduler = MissionScheduler(store, _dummy_start, cancel_run=canceller)
    await scheduler._stop_inflight_run("gone")  # must not raise


@pytest.mark.asyncio
async def test_stop_inflight_falls_back_to_the_store_flag_for_a_missing_run(
    tmp_path: Path,
) -> None:
    """Without a canceller, the store flag is used, and an unknown run is tolerated."""
    store = AgentStore(tmp_path / "agent.db")
    scheduler = MissionScheduler(store, _dummy_start)
    await scheduler._stop_inflight_run("no-such-run")  # KeyError swallowed


# --------------------------------------------------------------------------
# _advance early exits
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_advance_does_nothing_for_an_already_cancelled_mission(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)
    mission = _claimed(store)
    store.cancel_mission(mission.id)

    await scheduler._advance(mission)

    assert runner.started == []
    assert store.get_mission(mission.id).status is MissionStatus.CANCELLED


@pytest.mark.asyncio
async def test_advance_exhausts_a_mission_with_no_budget_left(tmp_path: Path) -> None:
    """A claimed mission whose runs are already spent is filed EXHAUSTED, not run."""
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)
    mission = _claimed(store, max_runs=2)
    spent = replace(mission, runs_used=mission.max_runs)

    await scheduler._advance(spent)

    assert runner.started == []
    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.EXHAUSTED
    assert "within 2 runs" in str(final.error)


def _script_cancel(
    monkeypatch: pytest.MonkeyPatch, *, true_on: int
) -> dict[str, int]:
    """Make _mission_cancelled answer True on exactly its ``true_on``-th call."""
    counter = {"n": 0}

    def fake(self: MissionScheduler, mission_id: str) -> bool:
        counter["n"] += 1
        return counter["n"] == true_on

    monkeypatch.setattr(MissionScheduler, "_mission_cancelled", fake)
    return counter


@pytest.mark.asyncio
async def test_advance_bails_when_cancelled_just_before_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancellation checked after the budget gate but before the VM rollback."""
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)

    class Iso:
        def __init__(self) -> None:
            self.calls = 0

        def rotate(self, *, reason: str) -> JsonObject:
            self.calls += 1
            return {"ok": True, "performed": True}

    iso = Iso()
    scheduler.isolation = iso
    mission = _claimed(store)
    _script_cancel(monkeypatch, true_on=2)

    await scheduler._advance(mission)

    assert iso.calls == 0, "must return before running the rollback command"
    assert runner.started == []


@pytest.mark.asyncio
async def test_advance_bails_when_cancelled_during_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancel that lands while the rollback ran stops before the first run."""
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)

    class Iso:
        def __init__(self) -> None:
            self.calls = 0

        def rotate(self, *, reason: str) -> JsonObject:
            self.calls += 1
            return {"ok": True, "performed": True}

    iso = Iso()
    scheduler.isolation = iso
    mission = _claimed(store)
    _script_cancel(monkeypatch, true_on=3)

    await scheduler._advance(mission)

    assert iso.calls == 1, "the rollback ran"
    assert runner.started == [], "but no run started after the cancel"


@pytest.mark.asyncio
async def test_advance_bails_when_cancelled_before_the_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)
    mission = _claimed(store)
    _script_cancel(monkeypatch, true_on=2)

    await scheduler._advance(mission)

    assert runner.started == []


@pytest.mark.asyncio
async def test_advance_bails_when_cancelled_before_starting_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)
    mission = _claimed(store)
    _script_cancel(monkeypatch, true_on=3)

    await scheduler._advance(mission)

    assert runner.started == [], "the prompt was queued but no run was started"


@pytest.mark.asyncio
async def test_advance_stops_the_run_when_cancelled_right_after_it_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancel between start and the wait must stop the run it just launched."""
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)
    mission = _claimed(store)
    _script_cancel(monkeypatch, true_on=4)

    await scheduler._advance(mission)

    assert len(runner.started) == 1, "the run had started before the cancel landed"
    # The mission status is left as the store had it; the run was asked to stop.
    assert store.get_mission(mission.id).status is not MissionStatus.COMPLETED


@pytest.mark.asyncio
async def test_advance_bails_after_the_run_when_the_mission_was_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run can finish just as the mission is cancelled; the result is dropped."""
    store = AgentStore(tmp_path / "agent.db")
    runner = _Runner(store)
    scheduler = MissionScheduler(store, runner.start_run)
    mission = _claimed(store)
    _script_cancel(monkeypatch, true_on=5)

    await scheduler._advance(mission)

    assert len(runner.started) == 1
    assert store.get_mission(mission.id).status is not MissionStatus.COMPLETED


# --------------------------------------------------------------------------
# _await_run / _run_spent_its_budget "the row is gone" guards
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_await_run_treats_a_vanished_run_as_interrupted(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    scheduler = MissionScheduler(store, _dummy_start)
    assert await scheduler._await_run("no-such-run", "mid") is RunStatus.INTERRUPTED


@pytest.mark.asyncio
async def test_await_run_stops_a_cancel_requested_run_then_times_it_out(
    tmp_path: Path,
) -> None:
    """A run flagged for cancel that never turns terminal is stopped once, then bounded.

    The first loop sees ``cancel_requested`` and stops the inflight run; from
    then on it is already stopped, so the deadline path must not stop it a
    second time before declaring it interrupted.
    """
    store = AgentStore(tmp_path / "cancel.db")
    thread = store.create_thread()
    run = store.create_run(
        thread.id, provider_profile="default", model=None, deadline_seconds=60
    )
    store.transition(run.id, RunStatus.STREAMING)
    store.request_cancel(run.id)

    scheduler = MissionScheduler(store, _dummy_start)
    scheduler.run_wait_timeout_s = 0.05
    scheduler.run_poll_interval_s = 0.01

    status = await asyncio.wait_for(scheduler._await_run(run.id, "mid"), timeout=5)

    assert status is RunStatus.INTERRUPTED
    stranded = store.get_run(run.id)
    assert stranded is not None and stranded.status is RunStatus.INTERRUPTED
    assert "scheduler wait timed out" in str(stranded.error)


@pytest.mark.asyncio
async def test_await_run_returns_the_terminal_status_stopping_produced(
    tmp_path: Path,
) -> None:
    """When the deadline's stop turns the run terminal, that status is returned.

    A run past its wait deadline is stopped; if that stop is what finally moves
    it into a terminal state, the scheduler reports that real status rather than
    forcing a synthetic INTERRUPTED transition on top of it.
    """
    store = AgentStore(tmp_path / "terminal.db")
    mission = _claimed(store)  # a real, non-cancelled mission id
    thread_id = mission.thread_id
    run = store.create_run(
        thread_id, provider_profile="default", model=None, deadline_seconds=60
    )
    store.transition(run.id, RunStatus.STREAMING)

    async def canceller(run_id: str) -> JsonObject:
        store.transition(run_id, RunStatus.CANCELLED, error="stopped by scheduler")
        return {}

    scheduler = MissionScheduler(store, _dummy_start, cancel_run=canceller)
    scheduler.run_wait_timeout_s = 0.02
    scheduler.run_poll_interval_s = 0.01

    status = await asyncio.wait_for(scheduler._await_run(run.id, mission.id), timeout=5)

    assert status is RunStatus.CANCELLED
    assert store.get_run(run.id).status is RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_failure_reason_survives_a_run_lookup_that_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading the detail must not become a second failure on top of the first."""
    store = AgentStore(tmp_path / "agent.db")
    scheduler = MissionScheduler(store, _dummy_start)

    def boom(run_id: str) -> Any:
        raise RuntimeError("db unavailable")

    monkeypatch.setattr(store, "get_run", boom)
    reason = scheduler._failure_reason("run-9", RunStatus.FAILED)
    assert reason == "run run-9 ended as failed"


@pytest.mark.asyncio
async def test_run_spent_its_budget_is_false_for_a_missing_run(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    scheduler = MissionScheduler(store, _dummy_start)
    assert scheduler._run_spent_its_budget("no-such-run") is False
