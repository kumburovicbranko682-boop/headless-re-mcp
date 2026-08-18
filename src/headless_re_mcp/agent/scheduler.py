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
from typing import Any, cast

from headless_re_mcp.agent.models import (
    MISSION_COMPLETE_MARKER,
    RUN_BUDGET_ENDINGS,
    TERMINAL_RUN_STATUSES,
    AgentMission,
    MissionStatus,
    RunStatus,
)
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.error_boundary import record_exception
from headless_re_mcp.telemetry import record_alert

JsonObject = dict[str, Any]
RunStarter = Callable[..., Awaitable[JsonObject]]
RunCanceller = Callable[[str], Awaitable[JsonObject]]

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
    # Backstop for a run that never records a terminal status. Comfortably above
    # the orchestrator's own 3600s ceiling so it only fires when that failed.
    run_wait_timeout_s: float = 3900.0
    run_poll_interval_s: float = 0.05
    # Optional: when start_run is orchestrator.start_run, cancel() is also
    # discovered on that same object so a timeout can stop the asyncio task
    # without the web layer having to wire a second callback.
    cancel_run: RunCanceller | None = None
    _warned_unrotated: bool = field(default=False, init=False)
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
            await self._maybe_sweep()
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

    def _due_watchdog(self) -> Any | None:
        """The watchdog if its cadence has come round, else None."""
        if self.watchdog is None or self.watchdog_interval_s <= 0:
            return None
        now = time.monotonic()
        if now - self._last_sweep < self.watchdog_interval_s:
            return None
        self._last_sweep = now
        return self.watchdog

    async def _maybe_sweep(self) -> None:
        """Run the watchdog on its own slower cadence, off the event loop.

        The sweep is synchronous and can reconnect a backend, which XdbgClient
        allows thirty seconds for. Calling it inline froze the loop this shares
        with the web server for that whole time: no HTTP, no SSE, no other
        mission. Measured at one second of sleep, a 20ms await took 1000ms.
        """
        watchdog = self._due_watchdog()
        if watchdog is None:
            return
        # sweep() is documented never to raise, but the loop must survive it
        # even if that ever stops being true.
        try:
            await asyncio.to_thread(watchdog.sweep)
        except BaseException as exc:  # noqa: BLE001 - recorded, never fatal
            record_exception(exc, context="watchdog-sweep")

    async def tick(self) -> bool:
        """Advance one mission by at most one run.

        Returns whether the loop should come straight back instead of waiting
        out its interval. A mission that failed answers no. The usual reason a
        run fails is the provider, and every queued mission is about to meet
        that same provider: coming straight back walks the whole queue into the
        outage as fast as the loop can spin. Measured without this, a six-second
        blip turned fifty queued missions into fifty permanent failures in 1.7
        seconds -- at an hour when nobody is going to requeue them.

        Waiting does not make a failure retryable, which is a separate decision.
        It stops one outage from spending the entire queue on itself.
        """
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
            return False
        current = self.store.get_mission(mission.id)
        return current is None or current.status is not MissionStatus.FAILED

    def _mission_cancelled(self, mission_id: str) -> bool:
        current = self.store.get_mission(mission_id)
        return current is None or current.status is MissionStatus.CANCELLED

    def _bound_cancel(self) -> RunCanceller | None:
        if self.cancel_run is not None:
            return self.cancel_run
        owner = getattr(self.start_run, "__self__", None)
        candidate = getattr(owner, "cancel", None)
        if callable(candidate):
            return cast(RunCanceller, candidate)
        return None

    async def _stop_inflight_run(self, run_id: str) -> None:
        """Stop the current run, not just this wait.

        A status flip leaves the orchestrator task and its tool thread running.
        Prefer the orchestrator's cancel so the tracked asyncio.Task is
        cancelled; fall back to the store flag the run loop already watches.
        """
        cancel = self._bound_cancel()
        if cancel is not None:
            try:
                await cancel(run_id)
                return
            except (KeyError, ValueError):
                return
        try:
            self.store.request_cancel(run_id)
        except KeyError:
            return

    async def _advance(self, mission: AgentMission) -> None:
        if self._mission_cancelled(mission.id):
            return
        if mission.budget_left <= 0:
            self.store.set_mission_status(
                mission.id,
                MissionStatus.EXHAUSTED,
                error=f"objective not met within {mission.max_runs} runs",
            )
            return

        if mission.runs_used == 0 and self.isolation is not None:
            if self._mission_cancelled(mission.id):
                return
            # Only before the first run of a mission: that is the sample
            # boundary. A failure here is fatal to the mission by design, since
            # continuing would analyse a new sample on a dirty machine.
            #
            # Off the loop for the same reason the watchdog sweep is: this runs
            # the operator's command, and its timeout defaults to ten minutes
            # because a VM rollback takes that long. Inline, the loop the web
            # server shares stops for the whole rollback, and a supervisor
            # polling the health check restarts the process in the middle of it.
            outcome = await asyncio.to_thread(
                self.isolation.rotate, reason=f"mission:{mission.id}"
            )
            if self._mission_cancelled(mission.id):
                return
            if not outcome.get("ok", False):
                self.store.set_mission_status(
                    mission.id,
                    MissionStatus.FAILED,
                    error=f"isolation step failed: {outcome.get('detail')}",
                )
                return
            self._note_if_nothing_was_rotated(outcome)

        if self._mission_cancelled(mission.id):
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
        if self._mission_cancelled(mission.id):
            return
        started = await self.start_run(
            mission.thread_id,
            profile_id=mission.provider_profile,
            model=mission.model,
        )
        run_id = str(started["id"])
        self.store.note_mission_run(mission.id, run_id)
        if self._mission_cancelled(mission.id):
            await self._stop_inflight_run(run_id)
            return
        status = await self._await_run(run_id, mission.id)

        if self._mission_cancelled(mission.id):
            return

        # A run that spent its tool rounds or its deadline has used a bound, not
        # broken. Treating that as a failure contradicted the whole point of a
        # mission: an objective large enough to need several runs died on the
        # first one, with the rest of its budget unspent, filed as failed. That
        # is the objective this mechanism exists for.
        if status is RunStatus.COMPLETED or self._run_spent_its_budget(run_id):
            if self._objective_met(mission.thread_id, run_id):
                self.store.set_mission_status(mission.id, MissionStatus.COMPLETED)
                return
            if attempt >= mission.max_runs:
                self.store.set_mission_status(
                    mission.id,
                    MissionStatus.EXHAUSTED,
                    error=self._exhausted_reason(mission, run_id),
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
            error=self._failure_reason(run_id, status),
        )

    def _failure_reason(self, run_id: str, status: RunStatus) -> str:
        """Why the run ended, not just that it did.

        The run records something specific and incident-linked -- invalid tool
        arguments at a given index, a tool name that does not exist, a message
        over the size cap -- and this used to replace all of it with "run <id>
        ended as failed". The mission is what an operator reads, and three
        unrelated causes arrived there looking identical.
        """
        detail = ""
        try:
            run = self.store.get_run(run_id)
        except Exception:  # noqa: BLE001 - a failure here must not hide the failure
            run = None
        if run is not None:
            detail = str(getattr(run, "error", "") or "").strip()
        if not detail:
            return f"run {run_id} ended as {status.value}"
        return f"run {run_id} ended as {status.value}: {detail}"

    def _note_if_nothing_was_rotated(self, outcome: JsonObject) -> None:
        """Say once that samples are following each other on the same machine.

        rotate() distinguishes "rotated" from "nothing configured to rotate with"
        precisely so the difference can be seen, and this dropped it: a queue
        that takes one sample after another was running each on whatever the
        last one left behind, and nothing at the mission level said so. The
        debugger executes the sample, which is what makes that matter.

        Once per process, because the answer is a property of the deployment's
        configuration rather than of any one mission.
        """
        if outcome.get("performed", True) or self._warned_unrotated:
            return
        self._warned_unrotated = True
        record_alert(
            "samples_not_isolated",
            fields={
                "detail": str(outcome.get("reason") or "no isolation step ran"),
                "consequence": "each sample runs on what the previous one left behind",
            },
        )

    async def _await_run(self, run_id: str, mission_id: str) -> RunStatus:
        """Wait for a run to reach a terminal state, but not forever.

        The orchestrator bounds its own runs, so in the normal case this always
        returns. It is the abnormal case this guards: a run whose task died
        without recording a status stays non-terminal for good, and an unbounded
        wait here would park the scheduler on it. Every other mission then
        starves while the process stays up and /readyz keeps answering 200 --
        the exact failure an unattended deployment cannot see.
        """
        deadline = time.monotonic() + self.run_wait_timeout_s
        stopped = False
        while True:
            run = self.store.get_run(run_id)
            if run is None:
                return RunStatus.INTERRUPTED
            if run.status in TERMINAL_RUN_STATUSES:
                return run.status
            if not stopped and (run.cancel_requested or self._mission_cancelled(mission_id)):
                await self._stop_inflight_run(run_id)
                stopped = True
                continue
            if time.monotonic() >= deadline:
                record_alert(
                    "run_wait_timeout",
                    fields={
                        "run_id": run_id,
                        "status": run.status.value,
                        "waited_s": round(self.run_wait_timeout_s, 1),
                    },
                )
                if not stopped:
                    await self._stop_inflight_run(run_id)
                current = self.store.get_run(run_id)
                if current is not None and current.status in TERMINAL_RUN_STATUSES:
                    return current.status
                error = (
                    f"scheduler wait timed out after {self.run_wait_timeout_s:g}s"
                )
                # The bound has to end the run, not merely this wait. Leaving
                # it streaming strands an active row forever and gives run
                # event consumers no terminal explanation.
                self.store.transition(run_id, RunStatus.INTERRUPTED, error=error)
                self.store.append_event(
                    run_id,
                    "run.failed",
                    {"status": RunStatus.INTERRUPTED.value, "error": error},
                )
                return RunStatus.INTERRUPTED
            await asyncio.sleep(self.run_poll_interval_s)

    def _run_spent_its_budget(self, run_id: str) -> bool:
        """Did this run end by spending a bound rather than by breaking?

        Both bounds -- the tool rounds and the run deadline -- are the shape of
        a bounded run that still has work left. The deadline is the one a real
        analysis meets first.
        """
        run = self.store.get_run(run_id)
        if run is None:
            return False
        error = run.error or ""
        return any(ending in error for ending in RUN_BUDGET_ENDINGS)

    def _exhausted_reason(self, mission: AgentMission, run_id: str) -> str:
        """Say which kind of exhaustion this was.

        Completion is recognised only when the marker opens the final reply,
        which is what the contract asks for and what keeps a model musing about
        finishing from ending the mission. The cost of that strictness lands
        here: a model that did the work but wrote the marker further into its
        reply looks exactly like a model that never finished, and the mission is
        filed as "objective not met" after paying for every run in its budget.
        Those two need different responses from whoever reads this later, so
        they get different text.
        """
        base = f"objective not met within {mission.max_runs} runs"
        final = self._final_reply(mission.thread_id, run_id)
        if final is not None and MISSION_COMPLETE_MARKER in final:
            return (
                f"{base}; the final reply contains {MISSION_COMPLETE_MARKER} but does "
                "not begin with it, so completion was not recognised"
            )
        run = self.store.get_run(run_id)
        error = (run.error or "") if run is not None else ""
        for ending in RUN_BUDGET_ENDINGS:
            if ending in error:
                # A run that hit its own bound says the objective is too large
                # for the shape of the runs, not that it cannot be done.
                return f"{base}; the last run ended on its own bound ({ending})"
        return base

    def _final_reply(self, thread_id: str, run_id: str) -> str | None:
        for message in reversed(self.store.list_messages(thread_id)):
            if message.run_id != run_id or message.role != "assistant":
                continue
            return message.content
        return None

    def _objective_met(self, thread_id: str, run_id: str) -> bool:
        """Look for the completion marker in what this run actually said."""
        final = self._final_reply(thread_id, run_id)
        return final is not None and final.lstrip().startswith(MISSION_COMPLETE_MARKER)
