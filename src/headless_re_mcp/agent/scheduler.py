"""Drive missions to completion without anyone pressing start.

A run is bounded on purpose: a few minutes and a dozen tool rounds. An analysis
is not. Nothing in the service closed that gap, so unattended operation failed
at the first hurdle -- a run only ever began because a human POSTed for it, and
when it hit its deadline the objective simply stopped.

The scheduler is the missing piece. It claims pending missions, feeds them runs
one at a time, and decides after each run whether the objective is met, out of
budget, or should continue. Restart safety comes from the store: an interrupted
mission returns to PENDING, so the work resumes rather than being lost.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from headless_re_mcp.agent.models import (
    MISSION_COMPLETE_MARKER,
    TERMINAL_RUN_STATUSES,
    AgentMission,
    MissionStatus,
    RunStatus,
)
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.error_boundary import record_exception

JsonObject = dict[str, Any]
RunStarter = Callable[..., Awaitable[JsonObject]]

_CONTINUATION_CONTRACT = (
    "You are working a long-running objective across several bounded runs.\n"
    "Objective: {objective}\n"
    "Run {attempt} of at most {budget}.\n"
    "Make concrete progress with the tools available. When, and only when, the "
    f"objective is fully met, begin your final reply with {MISSION_COMPLETE_MARKER}. "
    "Otherwise end with the single next step, and a later run will continue from here."
)


@dataclass(slots=True)
class MissionScheduler:
    """Claim missions and keep giving them runs until they finish.

    Deliberately serial per tick: a run holds a debugger session, and starting
    several at once would have them contend for the same target long before the
    LLM budget became the limit.
    """

    store: AgentStore
    start_run: RunStarter
    interval_s: float = 2.0
    # Swept from this loop rather than a thread of its own: it is already the
    # process's periodic tick, and one place that can fall behind is easier to
    # reason about than two.
    watchdog: Any | None = None
    watchdog_interval_s: float = 30.0
    # Run between missions rather than between runs: the runs of one mission
    # share a target, and rolling the machine back underneath them would destroy
    # the very state the next run needs.
    isolation: Any | None = None
    _task: asyncio.Task[None] | None = field(default=None, init=False)
    _stop: asyncio.Event | None = field(default=None, init=False)
    _last_sweep: float = field(default=0.0, init=False)

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="mission-scheduler")

    async def stop(self, *, timeout: float = 5.0) -> None:
        if self._stop is not None:
            self._stop.set()
        task = self._task
        self._task = None
        if task is None:
            return
        try:
            await asyncio.wait_for(task, timeout=timeout)
        except (TimeoutError, asyncio.CancelledError):
            task.cancel()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def _loop(self) -> None:
        stop = self._stop
        assert stop is not None
        while not stop.is_set():
            self._maybe_sweep()
            # A scheduler that can raise stops scheduling, which is the one
            # failure an unattended deployment cannot notice on its own.
            try:
                progressed = await self.tick()
            except BaseException as exc:  # noqa: BLE001 - recorded, never fatal
                record_exception(exc, context="mission-scheduler")
                progressed = False
            if progressed:
                continue
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval_s)
            except TimeoutError:
                continue

    def _maybe_sweep(self) -> None:
        """Run the watchdog on its own slower cadence, if one is attached."""
        if self.watchdog is None or self.watchdog_interval_s <= 0:
            return
        now = time.monotonic()
        if now - self._last_sweep < self.watchdog_interval_s:
            return
        self._last_sweep = now
        # sweep() is documented never to raise, but the loop must survive it
        # even if that ever stops being true.
        try:
            self.watchdog.sweep()
        except BaseException as exc:  # noqa: BLE001 - recorded, never fatal
            record_exception(exc, context="watchdog-sweep")

    async def tick(self) -> bool:
        """Advance one mission by at most one run. True if anything happened."""
        mission = self.store.claim_next_mission()
        if mission is None:
            return False
        try:
            await self._advance(mission)
        except BaseException as exc:  # noqa: BLE001 - one mission cannot kill the loop
            incident = record_exception(exc, context=f"mission:{mission.id}")
            self.store.set_mission_status(
                mission.id,
                MissionStatus.FAILED,
                error=f"{type(exc).__name__}: {incident['message']} (incident {incident['incident_id']})",
            )
        return True

    async def _advance(self, mission: AgentMission) -> None:
        if mission.budget_left <= 0:
            self.store.set_mission_status(
                mission.id,
                MissionStatus.EXHAUSTED,
                error=f"objective not met within {mission.max_runs} runs",
            )
            return

        if mission.runs_used == 0 and self.isolation is not None:
            # Only before the first run of a mission: that is the sample
            # boundary. A failure here is fatal to the mission by design, since
            # continuing would analyse a new sample on a dirty machine.
            outcome = self.isolation.rotate(reason=f"mission:{mission.id}")
            if not outcome.get("ok", True):
                self.store.set_mission_status(
                    mission.id,
                    MissionStatus.FAILED,
                    error=f"isolation step failed: {outcome.get('detail')}",
                )
                return

        attempt = mission.runs_used + 1
        self.store.add_message(
            mission.thread_id,
            "user",
            _CONTINUATION_CONTRACT.format(
                objective=mission.objective,
                attempt=attempt,
                budget=mission.max_runs,
            ),
        )
        started = await self.start_run(
            mission.thread_id,
            profile_id=mission.provider_profile,
            model=mission.model,
        )
        run_id = str(started["id"])
        self.store.note_mission_run(mission.id, run_id)
        status = await self._await_run(run_id)

        if self.store.get_mission(mission.id) is None:
            return
        current = self.store.get_mission(mission.id)
        if current is not None and current.status is MissionStatus.CANCELLED:
            return

        if status is RunStatus.COMPLETED:
            if self._objective_met(mission.thread_id, run_id):
                self.store.set_mission_status(mission.id, MissionStatus.COMPLETED)
                return
            if attempt >= mission.max_runs:
                self.store.set_mission_status(
                    mission.id,
                    MissionStatus.EXHAUSTED,
                    error=f"objective not met within {mission.max_runs} runs",
                )
                return
            # More work to do and budget to do it with: back to the queue so the
            # next tick picks it up, rather than looping here and holding the
            # scheduler on one mission.
            self.store.set_mission_status(mission.id, MissionStatus.PENDING)
            return

        # A run that was rejected, cancelled or failed stops the mission: retrying
        # a refused write or a broken provider would just burn the budget.
        self.store.set_mission_status(
            mission.id,
            MissionStatus.FAILED,
            error=f"run {run_id} ended as {status.value}",
        )

    async def _await_run(self, run_id: str) -> RunStatus:
        while True:
            run = self.store.get_run(run_id)
            if run is None:
                return RunStatus.INTERRUPTED
            if run.status in TERMINAL_RUN_STATUSES:
                return run.status
            await asyncio.sleep(0.05)

    def _objective_met(self, thread_id: str, run_id: str) -> bool:
        """Look for the completion marker in what this run actually said."""
        for message in reversed(self.store.list_messages(thread_id)):
            if message.run_id != run_id or message.role != "assistant":
                continue
            return message.content.lstrip().startswith(MISSION_COMPLETE_MARKER)
        return False