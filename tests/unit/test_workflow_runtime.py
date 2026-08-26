"""The workflow runtime ledger must keep status and failure in lockstep.

service.py advances this ledger on every debugger operation and the console
renders its to_dict(); a FAILED entry without a structured failure (or a live
entry still carrying one) would tell the operator a story the state machine
never produced. The invariants live in __post_init__ and the two transition
functions -- none of which had a direct test.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows.breakpoints import BreakpointIntent
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    acknowledge_workflow_breakpoint_operation,
    put_workflow_breakpoint_intent,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.runtime import (
    WorkflowFailure,
    WorkflowRunStatus,
    WorkflowRuntime,
    advance_workflow_runtime,
    create_workflow_runtime,
    fail_workflow_runtime,
)


def _bound_state() -> WorkflowState:
    lifecycle = track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        RebasedModuleMapping(
            identity=ModuleIdentity(
                name="payload.dll",
                path=r"C:\sample\fixtures\payload.dll",
                sha256="c" * 64,
                architecture=Architecture.X64,
            ),
            preferred_base=0x180000000,
            image_size=0x5000,
            runtime=RuntimeModule(
                base=0x7FF800000000,
                size=0x5000,
                name="payload.dll",
                path=r"C:\sample\fixtures\payload.dll",
            ),
            match_basis="name",
        ),
    )
    planned = put_workflow_breakpoint_intent(
        WorkflowState(lifecycle=lifecycle),
        BreakpointIntent(id="oep", module_key="payload", rva=0x1234),
    )
    return acknowledge_workflow_breakpoint_operation(
        planned.state, planned.breakpoint_reconciliation.operations[0]
    )


def test_a_fresh_runtime_is_idle_with_a_unique_id() -> None:
    first, second = create_workflow_runtime(), create_workflow_runtime()
    assert first.status is WorkflowRunStatus.IDLE
    assert first.operation_count == 0
    assert first.failure is None
    assert first.id != second.id


def test_status_and_failure_move_together() -> None:
    now = datetime.now(UTC)
    failure = WorkflowFailure(code="x", message="boom", details={})
    common = {"created_at": now, "updated_at": now, "operation_count": 0,
              "state": WorkflowState()}

    with pytest.raises(ValueError, match="structured failure"):
        WorkflowRuntime(id="a", status=WorkflowRunStatus.FAILED, failure=None, **common)
    with pytest.raises(ValueError, match="only a failed workflow"):
        WorkflowRuntime(id="a", status=WorkflowRunStatus.ACTIVE, failure=failure, **common)
    with pytest.raises(ValueError, match="blank"):
        WorkflowRuntime(id="  ", status=WorkflowRunStatus.IDLE, failure=None, **common)
    with pytest.raises(ValueError, match="non-negative"):
        WorkflowRuntime(
            id="a", status=WorkflowRunStatus.IDLE, failure=None,
            created_at=now, updated_at=now, operation_count=-1, state=WorkflowState(),
        )


def test_advance_counts_operations_and_refuses_a_failed_runtime() -> None:
    runtime = create_workflow_runtime()
    active = advance_workflow_runtime(
        runtime, _bound_state(), status=WorkflowRunStatus.ACTIVE, operations=2
    )
    assert active.status is WorkflowRunStatus.ACTIVE
    assert active.operation_count == 2
    assert active.updated_at >= runtime.updated_at

    with pytest.raises(ValueError, match="non-negative"):
        advance_workflow_runtime(active, active.state, operations=-1)

    failed = fail_workflow_runtime(active, code="port_error", message="boom")
    with pytest.raises(ValueError, match="cannot advance"):
        advance_workflow_runtime(failed, failed.state)


def test_advance_cannot_smuggle_a_transition_into_failed() -> None:
    """Only fail_workflow_runtime may fail: advance clears the failure slot,
    so asking it for FAILED violates the lockstep invariant and must raise."""
    runtime = create_workflow_runtime()
    with pytest.raises(ValueError, match="structured failure"):
        advance_workflow_runtime(runtime, runtime.state, status=WorkflowRunStatus.FAILED)


def test_fail_records_the_failure_and_requires_progress() -> None:
    runtime = advance_workflow_runtime(
        create_workflow_runtime(), _bound_state(), status=WorkflowRunStatus.ACTIVE
    )
    failed = fail_workflow_runtime(
        runtime,
        code="port_error",
        message="debugger refused",
        details={"op": "set"},
        retryable=True,
    )
    assert failed.status is WorkflowRunStatus.FAILED
    assert failed.operation_count == runtime.operation_count + 1
    assert failed.state is runtime.state  # no state given: the last good one stays
    assert failed.failure is not None
    assert failed.failure.to_dict() == {
        "code": "port_error",
        "message": "debugger refused",
        "details": {"op": "set"},
        "retryable": True,
    }
    # A failure claiming zero progress would hide the operation that failed.
    with pytest.raises(ValueError, match="positive"):
        fail_workflow_runtime(runtime, code="x", message="m", operations=0)


def test_to_dict_serializes_the_ledger_the_console_renders() -> None:
    runtime = advance_workflow_runtime(
        create_workflow_runtime(), _bound_state(), status=WorkflowRunStatus.ACTIVE
    )
    payload = runtime.to_dict()

    assert payload["status"] == "active"
    assert payload["failure"] is None
    assert payload["operation_count"] == 1
    # ISO timestamps, not datetime objects: this dict goes straight to JSON.
    datetime.fromisoformat(payload["created_at"])
    datetime.fromisoformat(payload["updated_at"])

    state = payload["state"]
    assert [module["key"] for module in state["modules"]] == ["payload"]
    assert state["modules"][0]["selector"] == {"name": "payload.dll"}
    assert state["breakpoints"]["intents"][0]["id"] == "oep"
    assert state["breakpoints"]["bindings"][0]["address"] == 0x7FF800000000 + 0x1234
    assert state["navigation"] is None

    failed = fail_workflow_runtime(runtime, code="x", message="m")
    assert failed.to_dict()["failure"] == failed.failure.to_dict()  # type: ignore[union-attr]
