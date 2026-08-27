"""Lifecycle and cancellation-race guard coverage for MissionScheduler.

``test_agent_scheduler.py`` covers the happy paths and the main failure
policies. This file pins the defensive edges: start/stop lifecycle, the
loop-level catch that keeps an unattended scheduler alive, the several
cancellation re-checks inside ``_advance``, ``_stop_inflight_run`` error
swallowing, and the ``_await_run`` run-missing / cancel / already-stopped
timeout arcs.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent import scheduler as scheduler_module
from headless_re_mcp.agent.models import MissionStatus, RunStatus
from headless_re_mcp.agent.scheduler import MissionScheduler
from headless_re_mcp.agent.store import AgentStore

JsonObject = dict[str, Any]


async def _noop_start(thread_id: str, **kwargs: Any) -> JsonObject:
    return {"id": "unused"}


def _mission(store: AgentStore, mission_id: str) -> Any:
    found = store.get_mission(mission_id)
    assert found is not None
    return found


def _run(store: AgentStore, run_id: str) -> Any:
    found = store.get_run(run_id)
    assert found is not None
    return found


def _cancel_on_nth_call(n: int) -> Any:
    """Class-level replacement for ``_mission_cancelled`` firing on call n."""
    state = {"i": 0}

    def fake(self: MissionScheduler, mission_id: str) -> bool:
        state["i"] += 1
        return state["i"] == n

    fake.state = state  # type: ignore[attr-defined]
    return fake


@pytest.mark.asyncio
async def test_start_is_idempotent_and_stop_before_start_is_safe(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "life.db")
    sched = MissionScheduler(store, _noop_start, interval_s=0.01)

    await sched.stop()  # _stop is None and task is None

    sched.start()
    first = sched._task
    sched.start()  # already running -> early return, same task
    assert sched._task is first
    await sched.stop()
    assert sched.running is False


@pytest.mark.asyncio
async def test_stop_cancels_a_task_that_ignores_the_stop_event(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "cancel.db")
    sched = MissionScheduler(store, _noop_start)

    async def _forever() -> None:
        # Must not swallow the cancellation: wait_for only reports a timeout
        # when the inner task actually surfaces CancelledError.
        await asyncio.sleep(3600)

    sched._stop = asyncio.Event()
    sched._task = asyncio.create_task(_forever())
    task = sched._task
    await asyncio.sleep(0)

    await sched.stop(timeout=0.05)

    assert sched._task is None
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled() or task.done()


@pytest.mark.asyncio
async def test_loop_records_and_survives_a_tick_that_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "loop.db")
    sched = MissionScheduler(store, _noop_start, interval_s=0.01)
    sched._stop = asyncio.Event()

    calls: list[int] = []

    def boom_claim() -> None:
        calls.append(1)
        assert sched._stop is not None
        sched._stop.set()
        raise RuntimeError("claim blew up")

    recorded: list[str | None] = []

    def fake_record(exc: BaseException, *, context: str | None = None) -> JsonObject:
        recorded.append(context)
        return {"message": "x", "incident_id": "i"}

    monkeypatch.setattr(store, "claim_next_mission", boom_claim)
    monkeypatch.setattr(scheduler_module, "record_exception", fake_record)

    await sched._loop()

    assert calls == [1]
    assert "mission-scheduler" in recorded


def test_bound_cancel_prefers_the_explicit_callback(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "bound.db")

    async def my_cancel(run_id: str) -> JsonObject:
        return {"cancelled": run_id}

    sched = MissionScheduler(store, _noop_start, cancel_run=my_cancel)
    assert sched._bound_cancel() is my_cancel


def test_bound_cancel_discovers_cancel_on_the_run_starter_owner(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "owner.db")

    class Orchestrator:
        async def start_run(self, thread_id: str, **kwargs: Any) -> JsonObject:
            return {"id": "r"}

        async def cancel(self, run_id: str) -> JsonObject:
            return {"cancelled": run_id}

    orch = Orchestrator()
    sched = MissionScheduler(store, orch.start_run)
    bound = sched._bound_cancel()
    assert bound is not None
    assert bound == orch.cancel


@pytest.mark.asyncio
async def test_stop_inflight_run_uses_the_bound_cancel_when_it_succeeds(
    tmp_path: Path,
) -> None:
    store = AgentStore(tmp_path / "ok-cancel.db")
    called: list[str] = []

    async def ok_cancel(run_id: str) -> JsonObject:
        called.append(run_id)
        return {}

    sched = MissionScheduler(store, _noop_start, cancel_run=ok_cancel)
    await sched._stop_inflight_run("run-ok")
    assert called == ["run-ok"]


@pytest.mark.asyncio
async def test_stop_inflight_run_swallows_cancel_lookup_errors(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "swallow.db")

    async def cancel_boom(run_id: str) -> JsonObject:
        raise KeyError(run_id)

    sched = MissionScheduler(store, _noop_start, cancel_run=cancel_boom)
    await sched._stop_inflight_run("run-x")  # returns quietly


@pytest.mark.asyncio
async def test_stop_inflight_run_falls_back_and_swallows_store_keyerror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "fallback.db")
    sched = MissionScheduler(store, _noop_start)

    def req_boom(run_id: str) -> None:
        raise KeyError(run_id)

    monkeypatch.setattr(store, "request_cancel", req_boom)
    await sched._stop_inflight_run("missing-run")  # returns quietly


@pytest.mark.asyncio
async def test_advance_returns_when_mission_is_already_cancelled(tmp_path: Path) -> None:
    started: list[str] = []

    async def record_start(thread_id: str, **kwargs: Any) -> JsonObject:
        started.append(thread_id)
        return {"id": "r"}

    store = AgentStore(tmp_path / "adv-cancel.db")
    sched = MissionScheduler(store, record_start, interval_s=0.01)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "abandon")
    claimed = store.claim_next_mission()
    assert claimed is not None
    store.cancel_mission(mission.id)

    await sched._advance(claimed)

    assert started == []
    assert _mission(store, mission.id).status is MissionStatus.CANCELLED


@pytest.mark.asyncio
async def test_advance_exhausts_a_mission_claimed_without_budget(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "adv-budget.db")
    sched = MissionScheduler(store, _noop_start, interval_s=0.01)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "spent", max_runs=2)
    claimed = store.claim_next_mission()
    assert claimed is not None
    spent = dataclasses.replace(claimed, runs_used=claimed.max_runs)

    await sched._advance(spent)

    final = _mission(store, mission.id)
    assert final.status is MissionStatus.EXHAUSTED
    assert "within 2 runs" in str(final.error)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("nth", "isolation"),
    [
        (2, True),  # cancelled inside the isolation block, before rotate
        (3, True),  # cancelled right after rotate
        (2, False),  # cancelled after the isolation block
        (3, False),  # cancelled after the continuation message is added
    ],
)
async def test_advance_bails_out_on_a_late_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    nth: int,
    isolation: bool,
) -> None:
    started: list[str] = []

    async def record_start(thread_id: str, **kwargs: Any) -> JsonObject:
        started.append(thread_id)
        return {"id": "r"}

    store = AgentStore(tmp_path / f"late-{nth}-{isolation}.db")
    sched = MissionScheduler(store, record_start, interval_s=0.01)
    if isolation:

        class Rotates:
            def rotate(self, *, reason: str) -> JsonObject:
                return {"ok": True, "performed": True}

        sched.isolation = Rotates()
    thread = store.create_thread()
    store.create_mission(thread.id, "cancel mid-flight", max_runs=3)
    claimed = store.claim_next_mission()
    assert claimed is not None

    fake = _cancel_on_nth_call(nth)
    monkeypatch.setattr(MissionScheduler, "_mission_cancelled", fake)

    await sched._advance(claimed)

    assert started == [], "a cancelled mission must not start a run"
    assert fake.state["i"] == nth


@pytest.mark.asyncio
async def test_advance_stops_inflight_run_when_cancelled_after_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "after-start.db")
    cancelled: list[str] = []

    async def start_and_track(thread_id: str, **kwargs: Any) -> JsonObject:
        run = store.create_run(thread_id, provider_profile="p", model=None, deadline_seconds=60)
        store.transition(run.id, RunStatus.STREAMING)
        return run.dump()

    sched = MissionScheduler(store, start_and_track, interval_s=0.01)

    def track_cancel(run_id: str) -> None:
        cancelled.append(run_id)

    monkeypatch.setattr(store, "request_cancel", track_cancel)
    thread = store.create_thread()
    store.create_mission(thread.id, "cancel after start", max_runs=3)
    claimed = store.claim_next_mission()
    assert claimed is not None

    monkeypatch.setattr(MissionScheduler, "_mission_cancelled", _cancel_on_nth_call(4))

    await sched._advance(claimed)

    assert len(cancelled) == 1, "the in-flight run must be stopped, not left streaming"


@pytest.mark.asyncio
async def test_advance_returns_when_cancelled_after_run_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "after-run.db")

    async def start_and_complete(thread_id: str, **kwargs: Any) -> JsonObject:
        run = store.create_run(thread_id, provider_profile="p", model=None, deadline_seconds=60)
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.COMPLETED)
        return run.dump()

    sched = MissionScheduler(store, start_and_complete, interval_s=0.01)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "cancel after run", max_runs=3)
    claimed = store.claim_next_mission()
    assert claimed is not None

    monkeypatch.setattr(MissionScheduler, "_mission_cancelled", _cancel_on_nth_call(5))

    await sched._advance(claimed)

    # Cancelled at the last re-check, so the completed run is not scored.
    assert _mission(store, mission.id).status is MissionStatus.RUNNING


@pytest.mark.asyncio
async def test_failure_reason_survives_a_run_lookup_that_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentStore(tmp_path / "reason.db")
    sched = MissionScheduler(store, _noop_start)

    def get_boom(run_id: str) -> None:
        raise RuntimeError("db exploded")

    monkeypatch.setattr(store, "get_run", get_boom)

    reason = sched._failure_reason("run-9", RunStatus.FAILED)
    assert reason == "run run-9 ended as failed"


@pytest.mark.asyncio
async def test_await_run_reports_interrupted_when_the_run_vanishes(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "vanish.db")
    sched = MissionScheduler(store, _noop_start)

    status = await sched._await_run("no-such-run", "no-such-mission")
    assert status is RunStatus.INTERRUPTED


@pytest.mark.asyncio
async def test_await_run_stops_a_cancel_requested_run_then_times_out(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "cancel-wait.db")
    sched = MissionScheduler(store, _noop_start)
    sched.run_wait_timeout_s = 0.05
    sched.run_poll_interval_s = 0.01
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    store.transition(run.id, RunStatus.STREAMING)
    store.request_cancel(run.id)

    status = await sched._await_run(run.id, "mission-x")

    assert status is RunStatus.INTERRUPTED
    stranded = store.get_run(run.id)
    assert stranded is not None and stranded.status is RunStatus.INTERRUPTED
    assert "scheduler wait timed out" in str(stranded.error)


@pytest.mark.asyncio
async def test_await_run_returns_terminal_status_reached_at_the_timeout(
    tmp_path: Path,
) -> None:
    store = AgentStore(tmp_path / "timeout-terminal.db")

    async def cancel_and_finish(run_id: str) -> JsonObject:
        store.transition(run_id, RunStatus.CANCELLED)
        return {}

    sched = MissionScheduler(store, _noop_start, cancel_run=cancel_and_finish)
    sched.run_wait_timeout_s = 0.05
    sched.run_poll_interval_s = 0.01
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "still pending")
    run = store.create_run(thread.id, provider_profile="p", model=None, deadline_seconds=60)
    store.transition(run.id, RunStatus.STREAMING)

    status = await sched._await_run(run.id, mission.id)

    assert status is RunStatus.CANCELLED
    assert _run(store, run.id).status is RunStatus.CANCELLED


def test_run_spent_its_budget_is_false_for_a_missing_run(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "spent.db")
    sched = MissionScheduler(store, _noop_start)
    assert sched._run_spent_its_budget("no-such-run") is False
