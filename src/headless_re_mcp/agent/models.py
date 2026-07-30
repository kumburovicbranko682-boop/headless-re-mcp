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
class RunEvent:
    run_id: str
    seq: int
    type: str
    data: dict[str, Any]
    created_at: str

    def dump(self) -> dict[str, Any]:
        return asdict(self)
