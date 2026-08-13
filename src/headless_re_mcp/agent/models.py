"""Persistent Agent domain records and legal run transitions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class RunStatus(StrEnum):
    QUEUED = "queued"
    STREAMING = "streaming"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING_TOOL = "executing_tool"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


TERMINAL_RUN_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.REJECTED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
        RunStatus.INTERRUPTED,
    }
)

RUN_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.QUEUED: frozenset({RunStatus.STREAMING, RunStatus.CANCELLED, RunStatus.FAILED, RunStatus.INTERRUPTED}),
    RunStatus.STREAMING: frozenset({RunStatus.AWAITING_APPROVAL, RunStatus.EXECUTING_TOOL, RunStatus.COMPLETED, RunStatus.CANCELLED, RunStatus.FAILED, RunStatus.INTERRUPTED}),
    RunStatus.AWAITING_APPROVAL: frozenset({RunStatus.EXECUTING_TOOL, RunStatus.STREAMING, RunStatus.REJECTED, RunStatus.CANCELLED, RunStatus.FAILED, RunStatus.INTERRUPTED}),
    RunStatus.EXECUTING_TOOL: frozenset({RunStatus.STREAMING, RunStatus.AWAITING_APPROVAL, RunStatus.COMPLETED, RunStatus.CANCELLED, RunStatus.FAILED, RunStatus.INTERRUPTED}),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.REJECTED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
    RunStatus.INTERRUPTED: frozenset(),
}


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class MissionStatus(StrEnum):
    """A mission outlives the bounded runs that carry it out.

    One run is capped at a few minutes and a dozen tool rounds, which is far
    less than an analysis takes. A mission is the durable objective that the
    scheduler keeps feeding runs to until it is met, gives up, or runs out of
    budget.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXHAUSTED = "exhausted"


TERMINAL_MISSION_STATUSES = frozenset(
    {
        MissionStatus.COMPLETED,
        MissionStatus.FAILED,
        MissionStatus.CANCELLED,
        MissionStatus.EXHAUSTED,
    }
)

# The marker a run's final message uses to declare the objective met. Chosen to
# be unmistakable in free text, since the alternative -- inferring completion
# from the absence of tool calls -- ends a mission the first time the model
# pauses to think.
MISSION_COMPLETE_MARKER = "MISSION_COMPLETE"

# A run that uses up its tool rounds has spent its budget, not broken. Shared so
# the scheduler can tell that ending apart from a genuine failure: a mission is
# meant to be carried across several bounded runs, and this is what the end of a
# bounded run looks like when there is more to do.
RUN_ROUNDS_EXHAUSTED = "maximum tool rounds exceeded"


@dataclass(frozen=True, slots=True)
class AgentThread:
    id: str
    title: str
    session_id: str | None
    created_at: str
    updated_at: str

    def dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AgentMessage:
    id: str
    thread_id: str
    role: str
    content: str
    run_id: str | None
    tool_call_id: str | None
    created_at: str

    def dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AgentRun:
    id: str
    thread_id: str
    status: RunStatus
    provider_profile: str
    model: str | None
    cancel_requested: bool
    error: str | None
    created_at: str
    updated_at: str
    deadline_at: str | None

    def dump(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value


@dataclass(frozen=True, slots=True)
class AgentMission:
    id: str
    thread_id: str
    objective: str
    status: MissionStatus
    provider_profile: str | None
    model: str | None
    max_runs: int
    runs_used: int
    last_run_id: str | None
    error: str | None
    created_at: str
    updated_at: str

    def dump(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value

    @property
    def budget_left(self) -> int:
        return max(0, self.max_runs - self.runs_used)


@dataclass(frozen=True, slots=True)
class RunEvent:
    run_id: str
    seq: int
    type: str
    data: dict[str, Any]
    created_at: str

    def dump(self) -> dict[str, Any]:
        return asdict(self)
