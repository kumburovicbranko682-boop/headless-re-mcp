from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from headless_re_mcp.workflows.engine import WorkflowState
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState

JsonObject = dict[str, Any]


class WorkflowRunStatus(StrEnum):
    IDLE = "idle"
    ACTIVE = "active"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class WorkflowFailure:
    code: str
    message: str
    details: JsonObject
    retryable: bool = False

    def to_dict(self) -> JsonObject:
        return {
            "code": self.code,
            "message": self.message,
            "details": dict(self.details),
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True)
class WorkflowRuntime:
    id: str
    created_at: datetime
    updated_at: datetime
    status: WorkflowRunStatus
    operation_count: int
    state: WorkflowState
    failure: WorkflowFailure | None = None

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("workflow id must not be blank")
        if self.operation_count < 0:
            raise ValueError("workflow operation count must be non-negative")
        if self.status == WorkflowRunStatus.FAILED and self.failure is None:
            raise ValueError("failed workflow requires a structured failure")
        if self.status != WorkflowRunStatus.FAILED and self.failure is not None:
            raise ValueError("only a failed workflow may contain a failure")

    def to_dict(self) -> JsonObject:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "status": self.status.value,
            "operation_count": self.operation_count,
            "failure": self.failure.to_dict() if self.failure is not None else None,
            "state": _workflow_state_json(self.state),
        }


def create_workflow_runtime(*, cursor: int = 0) -> WorkflowRuntime:
    now = datetime.now(UTC)
    return WorkflowRuntime(
        id=uuid4().hex,
        created_at=now,
        updated_at=now,
        status=WorkflowRunStatus.IDLE,
        operation_count=0,
        state=WorkflowState(lifecycle=ModuleLifecycleState(cursor=cursor)),
    )


def advance_workflow_runtime(
    runtime: WorkflowRuntime,
    state: WorkflowState,
    *,
    status: WorkflowRunStatus | None = None,
    operations: int = 1,
) -> WorkflowRuntime:
    if runtime.status == WorkflowRunStatus.FAILED:
        raise ValueError("failed workflow state cannot advance")
    if operations < 0:
        raise ValueError("workflow operation increment must be non-negative")
    return replace(
        runtime,
        updated_at=datetime.now(UTC),
        status=status or runtime.status,
        operation_count=runtime.operation_count + operations,
        state=state,
        failure=None,
    )


def fail_workflow_runtime(
    runtime: WorkflowRuntime,
    *,
    code: str,
    message: str,
    details: JsonObject | None = None,
    retryable: bool = False,
    state: WorkflowState | None = None,
    operations: int = 1,
) -> WorkflowRuntime:
    if operations <= 0:
        raise ValueError("workflow failure operation increment must be positive")
    return replace(
        runtime,
        updated_at=datetime.now(UTC),
        status=WorkflowRunStatus.FAILED,
        operation_count=runtime.operation_count + operations,
        state=state or runtime.state,
        failure=WorkflowFailure(
            code=code,
            message=message,
            details=dict(details or {}),
            retryable=retryable,
        ),
    )


def _workflow_state_json(state: WorkflowState) -> JsonObject:
    lifecycle = state.lifecycle
    navigation = state.navigation
    return {
        "cursor": lifecycle.cursor,
        "generation": lifecycle.generation,
        "stream_reliable": lifecycle.stream_reliable,
        "modules": [
            {
                "key": module.key,
                "selector": module.selector.model_dump(mode="json", exclude_none=True),
                "preferred_base": module.preferred_base,
                "image_size": module.image_size,
                "runtime": module.runtime.to_dict(),
                "sha256": module.sha256,
                "status": module.status.value,
                "revision": module.revision,
            }
            for module in lifecycle.modules
        ],
        "breakpoints": {
            "intents": [
                {
                    "id": intent.id,
                    "module_key": intent.module_key,
                    "rva": intent.rva,
                    "enabled": intent.enabled,
                    "one_shot": intent.one_shot,
                }
                for intent in state.breakpoints.intents
            ],
            "bindings": [
                {
                    "intent_id": binding.intent_id,
                    "address": binding.address,
                    "module_revision": binding.module_revision,
                }
                for binding in state.breakpoints.bindings
            ],
        },
        "navigation": (
            None
            if navigation is None
            else {
                "pattern": {
                    "kind": navigation.pattern.kind,
                    "fields": dict(navigation.pattern.fields),
                },
                "cursor": navigation.cursor,
                "event_budget": navigation.event_budget,
                "observed_events": navigation.observed_events,
                "status": navigation.status.value,
                "matched_event": (
                    navigation.matched_event.to_dict()
                    if navigation.matched_event is not None
                    else None
                ),
                "terminal_event": (
                    navigation.terminal_event.to_dict()
                    if navigation.terminal_event is not None
                    else None
                ),
            }
        ),
    }