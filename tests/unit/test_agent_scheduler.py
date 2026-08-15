from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.models import (
    MISSION_COMPLETE_MARKER,
    RUN_DEADLINE_EXCEEDED,
    RUN_ROUNDS_EXHAUSTED,
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

    recover_after_restart marks the in-flight run INTERRUPTED, which is correct,
    but the mission has to go back to the queue or the work is simply gone and
    no one is there to notice.
    """
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "long analysis")
    claimed = store.claim_next_mission()
    assert claimed is not None and claimed.id == mission.id
    assert store.get_mission(mission.id).status is MissionStatus.RUNNING

    # Restart: a fresh store over the same database, as the service does, and
    # then the explicit hand-over the service performs on startup.
    reopened = AgentStore(tmp_path / "agent.db")
    reopened.recover_after_restart()

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

@pytest.mark.asyncio
async def test_isolation_runs_once_per_mission_and_blocks_a_dirty_machine(tmp_path: Path) -> None:
    """The sample boundary is the mission, not the run.

    Runs within one mission share a target, so rolling the machine back between
    them would destroy the state the next run needs. A failed rotation stops the
    mission outright, because continuing would analyse a new sample on a machine
    the previous one touched.
    """
    calls: list[str] = []

    class Isolation:
        def __init__(self, ok: bool) -> None:
            self.ok = ok

        def rotate(self, *, reason: str) -> dict[str, Any]:
            calls.append(reason)
            return {"ok": self.ok, "performed": True, "detail": None if self.ok else "snapshot missing"}

    scheduler, store, runner = _scheduler(tmp_path, ["keep going", f"{MISSION_COMPLETE_MARKER} ok"])
    scheduler.isolation = Isolation(ok=True)
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "two runs", max_runs=4)

    await scheduler.tick()
    await scheduler.tick()

    assert store.get_mission(mission.id).status is MissionStatus.COMPLETED
    assert len(runner.started) == 2
    assert calls == [f"mission:{mission.id}"], "rotation belongs between samples, not between runs"

    blocked_scheduler, blocked_store, blocked_runner = _scheduler(tmp_path / "second", ["never"])
    blocked_scheduler.isolation = Isolation(ok=False)
    blocked_thread = blocked_store.create_thread()
    blocked = blocked_store.create_mission(blocked_thread.id, "dirty machine")

    await blocked_scheduler.tick()

    assert blocked_runner.started == [], "no run may start on a machine that was not rotated"
    final = blocked_store.get_mission(blocked.id)
    assert final.status is MissionStatus.FAILED
    assert "isolation step failed" in str(final.error)


@pytest.mark.asyncio
async def test_the_loop_survives_an_incident_log_that_cannot_be_written(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The recorder this loop leans on used to raise on a full volume.

    Every tick is wrapped so one bad mission cannot stop the scheduler, but the
    wrapper reports the failure through record_exception, and that call opened
    the incident log. With no space left it raised from inside the except block,
    left _loop, and ended the task permanently -- no missions ever again, while
    the web server in the same process kept answering 200.
    """
    import headless_re_mcp.error_boundary as boundary

    def full_disk(*args: object, **kwargs: object) -> Path:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(boundary, "_LOG_PATH", None)
    monkeypatch.setattr(boundary, "attach_rotating_handler", full_disk)

    attempts: list[str] = []
    store = AgentStore(tmp_path / "agent.db")

    async def start_but_explode(thread_id: str, **kwargs: Any) -> JsonObject:
        attempts.append(thread_id)
        raise RuntimeError("provider exploded")

    scheduler = MissionScheduler(store, start_but_explode, interval_s=0.01)
    for _ in range(3):
        store.create_mission(store.create_thread().id, "objective")

    scheduler.start()
    try:
        for _ in range(200):
            if len(attempts) >= 3:
                break
            await asyncio.sleep(0.01)
    finally:
        running = scheduler.running
        await scheduler.stop()

    assert len(attempts) >= 3, "the loop stopped at the first failure it could not log"
    assert running, "the scheduler task must still be alive"


@pytest.mark.asyncio
async def test_a_failed_mission_carries_the_reason_the_run_recorded(tmp_path: Path) -> None:
    """The mission is what an operator reads, so the cause has to reach it.

    Runs record something specific and incident-linked. Measured against a
    provider answering badly in three different ways -- invalid tool arguments,
    a tool name that does not exist, a message over the size cap -- the mission
    said "run <id> ended as failed" for all three, so three unrelated causes
    were indistinguishable at the only level anyone looks at.
    """
    scheduler, store, _ = _scheduler(tmp_path, ["nothing useful"])
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=600)
    store.transition(run.id, RunStatus.STREAMING)
    store.transition(
        run.id,
        RunStatus.FAILED,
        error="ValueError: provider emitted invalid tool arguments at index 0 (incident abc)",
    )

    reason = scheduler._failure_reason(run.id, RunStatus.FAILED)

    assert "invalid tool arguments" in reason, reason
    assert "incident abc" in reason, "the incident id has to survive too"
    assert run.id in reason, "and the run is still named, for anyone digging further"


@pytest.mark.asyncio
async def test_a_failure_with_nothing_recorded_still_names_the_run(tmp_path: Path) -> None:
    """No detail is not a reason to lose the run id as well."""
    scheduler, store, _ = _scheduler(tmp_path, ["nothing useful"])
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=600)
    store.transition(run.id, RunStatus.STREAMING)
    store.transition(run.id, RunStatus.FAILED)

    reason = scheduler._failure_reason(run.id, RunStatus.FAILED)

    assert reason == f"run {run.id} ended as failed"


@pytest.mark.asyncio
async def test_a_reason_that_cannot_be_read_does_not_replace_the_failure(
    tmp_path: Path,
) -> None:
    """Looking up the detail must not become a second failure on top of the first."""
    scheduler, _store, _ = _scheduler(tmp_path, ["nothing useful"])

    reason = scheduler._failure_reason("no-such-run", RunStatus.FAILED)

    assert reason == "run no-such-run ended as failed"


@pytest.mark.asyncio
async def test_a_queue_running_without_isolation_says_so_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """rotate() separates "rotated" from "nothing to rotate with" on purpose.

    The scheduler dropped that, so a queue taking one sample after another ran
    each on whatever the last one left behind with nothing saying so. The
    debugger executes the sample, which is what makes it matter. Said once,
    because it describes the deployment rather than any one mission.
    """
    from headless_re_mcp.agent import scheduler as scheduler_module

    alerts: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        scheduler_module,
        "record_alert",
        lambda kind, **kwargs: alerts.append((kind, kwargs)),
    )

    class NotConfigured:
        def rotate(self, *, reason: str) -> dict[str, Any]:
            return {"ok": True, "performed": False, "reason": "no isolation command configured"}

    scheduler, store, _ = _scheduler(
        tmp_path,
        [f"{MISSION_COMPLETE_MARKER} a", f"{MISSION_COMPLETE_MARKER} b"],
    )
    scheduler.isolation = NotConfigured()
    for _ in range(2):
        store.create_mission(store.create_thread().id, "sample")

    await scheduler.tick()
    await scheduler.tick()

    kinds = [kind for kind, _ in alerts]
    assert kinds == ["samples_not_isolated"], f"once, not per mission: {kinds}"
    assert "left behind" in str(alerts[0][1]["fields"]["consequence"])


@pytest.mark.asyncio
async def test_a_rotation_that_happened_is_not_reported_as_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The notice has to mean something, so a real rotation stays quiet."""
    from headless_re_mcp.agent import scheduler as scheduler_module

    alerts: list[str] = []
    monkeypatch.setattr(
        scheduler_module, "record_alert", lambda kind, **kwargs: alerts.append(kind)
    )

    class Rotates:
        def rotate(self, *, reason: str) -> dict[str, Any]:
            return {"ok": True, "performed": True, "elapsed_s": 1.0}

    scheduler, store, _ = _scheduler(tmp_path, [f"{MISSION_COMPLETE_MARKER} done"])
    scheduler.isolation = Rotates()
    store.create_mission(store.create_thread().id, "sample")

    await scheduler.tick()

    assert alerts == []


@pytest.mark.asyncio
async def test_the_isolation_step_does_not_freeze_the_event_loop(tmp_path: Path) -> None:
    """The rotation runs an operator command whose timeout defaults to 600s.

    A VM rollback is why that default is ten minutes. Called inline it stops the
    loop the web server shares for the whole rollback: no HTTP, no /healthz, no
    SSE, no other mission. A supervisor polling the health check reads that as a
    dead process and restarts it in the middle of the rollback.
    """
    import time as _time

    class SlowIsolation:
        def __init__(self) -> None:
            self.calls = 0

        def rotate(self, *, reason: str) -> dict[str, Any]:
            self.calls += 1
            _time.sleep(0.5)
            return {"ok": True, "performed": True, "reason": reason}

    scheduler, store, runner = _scheduler(tmp_path, [f"{MISSION_COMPLETE_MARKER} done"])
    isolation = SlowIsolation()
    scheduler.isolation = isolation
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "rotate before the first run")

    async def probe() -> float:
        started = _time.perf_counter()
        await asyncio.sleep(0.02)
        return _time.perf_counter() - started

    task = asyncio.create_task(probe())
    await asyncio.sleep(0)
    await scheduler.tick()
    delay = await task

    assert isolation.calls == 1, "the rotation must still happen"
    assert store.get_mission(mission.id).status is MissionStatus.COMPLETED
    assert delay < 0.4, f"the loop was blocked for {delay:.2f}s during the rotation"


@pytest.mark.asyncio
async def test_the_watchdog_is_swept_from_the_scheduler_loop(tmp_path: Path) -> None:
    """One periodic tick, not two: a single place that can fall behind."""
    sweeps: list[int] = []

    class FakeWatchdog:
        def sweep(self) -> dict[str, Any]:
            sweeps.append(1)
            return {"checked": 0}

    scheduler, store, _ = _scheduler(tmp_path, [])
    scheduler.watchdog = FakeWatchdog()
    scheduler.watchdog_interval_s = 0.0

    await scheduler._maybe_sweep()
    assert sweeps == [], "an interval of zero disables the sweep"

    # Comfortably longer than a thread-pool dispatch, so this measures the
    # cadence rather than how long it took to hand the sweep to a worker.
    scheduler.watchdog_interval_s = 30.0
    await scheduler._maybe_sweep()
    assert len(sweeps) == 1

    await scheduler._maybe_sweep()
    assert len(sweeps) == 1, "the sweep must respect its own slower cadence"


@pytest.mark.asyncio
async def test_a_watchdog_that_raises_does_not_stop_the_scheduler(tmp_path: Path) -> None:
    class Exploding:
        def sweep(self) -> dict[str, Any]:
            raise RuntimeError("watchdog blew up")

    scheduler, store, runner = _scheduler(tmp_path, [f"{MISSION_COMPLETE_MARKER} fine"])
    scheduler.watchdog = Exploding()
    scheduler.watchdog_interval_s = 0.01
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "still works")

    await scheduler._maybe_sweep()
    assert await scheduler.tick() is True
    assert store.get_mission(mission.id).status is MissionStatus.COMPLETED


@pytest.mark.asyncio
async def test_a_slow_watchdog_sweep_does_not_freeze_the_event_loop(tmp_path: Path) -> None:
    """The sweep is synchronous and can reconnect a backend, which takes seconds.

    It shares an event loop with the web server, so running it inline stopped
    HTTP, SSE and every other mission for its whole duration. Measured before
    the fix: a 20ms await took 1000ms behind a one-second sweep.
    """
    import time as _time

    class SlowWatchdog:
        def __init__(self) -> None:
            self.sweeps = 0

        def sweep(self) -> dict[str, Any]:
            self.sweeps += 1
            _time.sleep(0.5)
            return {"checked": 1}

    scheduler, store, _ = _scheduler(tmp_path, [])
    watchdog = SlowWatchdog()
    scheduler.watchdog = watchdog
    scheduler.watchdog_interval_s = 0.01

    async def probe() -> float:
        started = _time.perf_counter()
        await asyncio.sleep(0.02)
        return _time.perf_counter() - started

    task = asyncio.create_task(probe())
    await asyncio.sleep(0)
    await scheduler._maybe_sweep()
    delay = await task

    assert watchdog.sweeps == 1, "the sweep must still run"
    assert delay < 0.4, f"the loop was blocked for {delay:.2f}s during the sweep"


@pytest.mark.asyncio
async def test_a_run_that_never_finishes_does_not_park_the_scheduler(
    tmp_path: Path,
) -> None:
    """A run stuck off the terminal states must not starve every other mission.

    The orchestrator bounds its own runs, so this only happens when that failed
    -- a task that died without recording a status. An unbounded wait here left
    the scheduler parked on it forever while the process stayed up and /readyz
    kept answering 200, which is the failure nobody is watching for.
    """
    store = AgentStore(tmp_path / "stuck.db")
    started: list[str] = []

    async def start_but_never_finish(thread_id: str, **kwargs: Any) -> JsonObject:
        run = store.create_run(thread_id, provider_profile="default", model=None, deadline_seconds=60)
        store.transition(run.id, RunStatus.STREAMING)
        started.append(run.id)
        return run.dump()

    scheduler = MissionScheduler(store, start_but_never_finish, interval_s=0.01)
    scheduler.run_wait_timeout_s = 0.2
    scheduler.run_poll_interval_s = 0.01
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "never finishes", max_runs=3)

    await asyncio.wait_for(scheduler.tick(), timeout=10)

    assert len(started) == 1
    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.FAILED
    assert "interrupted" in str(final.error)
    stranded = store.get_run(started[0])
    assert stranded is not None and stranded.status is RunStatus.INTERRUPTED, (
        f"scheduler moved on but left the run {stranded.status.value if stranded else 'missing'}"
    )
    assert "scheduler wait timed out" in str(stranded.error)
    assert any(
        event.type == "run.failed" and event.data.get("status") == "interrupted"
        for event in store.list_events(stranded.id)
    ), "the run-level timeout must be visible to event consumers"
    # And the queue keeps moving: a second mission is still reachable.
    other = store.create_mission(thread.id, "next one")
    assert store.claim_next_mission().id == other.id

@pytest.mark.asyncio
async def test_a_mission_still_completes_on_a_thread_past_the_message_cap(
    tmp_path: Path,
) -> None:
    """The failure an unattended deployment hits after a few days of uptime.

    The completion check reads the thread back to find the marker its own run
    just wrote. While the history window returned the oldest messages, that
    read came back empty on any thread past the cap, so a met objective was
    retried until the budget ran out and then filed as EXHAUSTED -- with the
    error text claiming it was "not met within N runs".
    """
    scheduler, store, runner = _scheduler(tmp_path, [f"{MISSION_COMPLETE_MARKER} found it"])
    thread = store.create_thread()
    for index in range(700):
        store.add_message(thread.id, "user", f"earlier turn {index}")
    mission = store.create_mission(thread.id, "one more objective", max_runs=3)

    assert await scheduler.tick() is True

    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.COMPLETED, (
        f"objective was met but the mission ended {final.status.value}: {final.error}"
    )
    assert len(runner.started) == 1, "it must not have retried a completed objective"

@pytest.mark.asyncio
async def test_an_exhausted_mission_says_whether_the_model_claimed_completion(
    tmp_path: Path,
) -> None:
    """Two different failures were being filed under the same sentence.

    Completion is recognised only when the marker opens the final reply. A model
    that did the work but wrote the marker further into its reply is therefore
    indistinguishable, in the mission record, from one that never finished --
    after paying for every run in the budget. Whoever reads that record later
    has to fix a prompt in one case and an objective in the other.
    """
    marker_buried = f"I checked everything. {MISSION_COMPLETE_MARKER}"
    scheduler, store, _ = _scheduler(tmp_path, [marker_buried, marker_buried])
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "find the check", max_runs=2)

    await scheduler.tick()
    await scheduler.tick()

    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.EXHAUSTED
    assert MISSION_COMPLETE_MARKER in str(final.error)
    assert "does not begin with it" in str(final.error)


@pytest.mark.asyncio
async def test_a_mission_that_really_ran_out_says_only_that(tmp_path: Path) -> None:
    """The extra sentence must not appear when it would be wrong."""
    scheduler, store, _ = _scheduler(tmp_path, ["still working", "still working"])
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "unfinished", max_runs=2)

    await scheduler.tick()
    await scheduler.tick()

    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.EXHAUSTED
    assert str(final.error) == "objective not met within 2 runs"

@pytest.mark.asyncio
async def test_a_failing_provider_does_not_take_the_whole_queue_with_it(
    tmp_path: Path,
) -> None:
    """One outage must not spend every queued mission on itself.

    A failed run ends its mission, which is the intended policy. What was not
    intended is the speed: the loop treated a failure as progress and came
    straight back, so every queued mission met the same broken provider within
    milliseconds. A six-second blip turned a fifty-mission queue into fifty
    permanent failures in 1.7 seconds, at an hour when nobody requeues anything.
    """
    store = AgentStore(tmp_path / "outage.db")
    store.recover_after_restart()
    thread = store.create_thread()
    for index in range(20):
        store.create_mission(thread.id, f"objective {index}", max_runs=3)

    async def provider_is_down(thread_id: str, **kwargs: Any) -> JsonObject:
        run = store.create_run(
            thread_id, provider_profile="p", model=None, deadline_seconds=60
        )
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.FAILED, error="provider unreachable")
        return run.dump()

    scheduler = MissionScheduler(store, provider_is_down, interval_s=0.2)
    scheduler.start()
    await asyncio.sleep(0.7)
    await scheduler.stop()

    missions = store.list_missions(limit=100)
    failed = [m for m in missions if m.status is MissionStatus.FAILED]
    pending = [m for m in missions if m.status is MissionStatus.PENDING]

    assert failed, "the outage is real, so something must have failed"
    assert len(failed) <= 6, (
        f"the outage consumed {len(failed)} of 20 missions; the loop is not waiting"
    )
    assert len(pending) >= 14, "the rest of the queue must survive to be retried later"


@pytest.mark.asyncio
async def test_a_tick_that_failed_reports_that_it_should_not_be_repeated(
    tmp_path: Path,
) -> None:
    """The loop reads tick()'s answer to decide whether to wait."""
    scheduler, store, _ = _scheduler(tmp_path, ["__fail__"])
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "will fail")

    assert await scheduler.tick() is False
    assert store.get_mission(mission.id).status is MissionStatus.FAILED

@pytest.mark.asyncio
async def test_a_run_that_uses_up_its_tool_rounds_continues_the_mission(
    tmp_path: Path,
) -> None:
    """Spending a run's budget is how a bounded run ends, not how a mission dies.

    A mission exists to carry one objective across several bounded runs. Running
    out of tool rounds is exactly what the end of a bounded run looks like when
    there is more to do -- and it was being treated as a failure, so an
    objective big enough to need a second run died on the first with the rest of
    its budget unspent. That is precisely the objective this mechanism is for.
    """
    store = AgentStore(tmp_path / "rounds.db")
    store.recover_after_restart()
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "a big objective", max_runs=4)

    async def run_out_of_rounds(thread_id: str, **kwargs: Any) -> JsonObject:
        run = store.create_run(
            thread_id, provider_profile="p", model=None, deadline_seconds=60
        )
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.FAILED, error=f"RuntimeError: {RUN_ROUNDS_EXHAUSTED}")
        return run.dump()

    scheduler = MissionScheduler(store, run_out_of_rounds, interval_s=0.01)

    assert await scheduler.tick() is True
    assert store.get_mission(mission.id).status is MissionStatus.PENDING, (
        "the mission must go back to the queue for its next run"
    )

    for _ in range(6):
        if store.get_mission(mission.id).status is not MissionStatus.PENDING:
            break
        await scheduler.tick()

    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.EXHAUSTED, "the run budget must still bind"
    assert final.runs_used == 4, f"it should have spent all four runs, used {final.runs_used}"


@pytest.mark.asyncio
async def test_a_run_that_actually_broke_still_ends_the_mission(tmp_path: Path) -> None:
    """Only the rounds ending is forgiven; a broken provider is still fatal."""
    store = AgentStore(tmp_path / "broke.db")
    store.recover_after_restart()
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "will break", max_runs=4)

    async def broken(thread_id: str, **kwargs: Any) -> JsonObject:
        run = store.create_run(
            thread_id, provider_profile="p", model=None, deadline_seconds=60
        )
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.FAILED, error="ConnectionError: provider unreachable")
        return run.dump()

    scheduler = MissionScheduler(store, broken, interval_s=0.01)
    await scheduler.tick()

    assert store.get_mission(mission.id).status is MissionStatus.FAILED

@pytest.mark.asyncio
async def test_a_run_that_hit_its_deadline_also_continues_the_mission(
    tmp_path: Path,
) -> None:
    """The deadline is the bound a real analysis meets first.

    Same shape as the tool-round bound and more likely to fire: ten minutes is
    not long for a debugger session, and a mission budgeted for eight runs was
    dying on the first timeout with seven unspent.
    """
    store = AgentStore(tmp_path / "deadline.db")
    store.recover_after_restart()
    thread = store.create_thread()
    mission = store.create_mission(thread.id, "a long analysis", max_runs=3)

    async def times_out(thread_id: str, **kwargs: Any) -> JsonObject:
        run = store.create_run(
            thread_id, provider_profile="p", model=None, deadline_seconds=60
        )
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.FAILED, error=RUN_DEADLINE_EXCEEDED)
        return run.dump()

    scheduler = MissionScheduler(store, times_out, interval_s=0.01)

    await scheduler.tick()
    assert store.get_mission(mission.id).status is MissionStatus.PENDING

    for _ in range(6):
        if store.get_mission(mission.id).status is not MissionStatus.PENDING:
            break
        await scheduler.tick()

    final = store.get_mission(mission.id)
    assert final.status is MissionStatus.EXHAUSTED
    assert final.runs_used == 3
    assert "own bound" in str(final.error), "the record should say which bound ended it"
    assert RUN_DEADLINE_EXCEEDED in str(final.error)
