from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic
from typing import Protocol

from headless_re_mcp.core.addressing import RebasedModuleMapping
from headless_re_mcp.core.models import ModuleSelector
from headless_re_mcp.workflows.breakpoints import BreakpointOperation
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    WorkflowTransition,
    acknowledge_workflow_breakpoint_operation,
    apply_workflow_module_refresh,
)
from headless_re_mcp.workflows.navigation import NavigationEffect


class WorkflowExecutionPort(Protocol):
    def resume(self, *, timeout: float) -> None: ...

    def ensure_paused(self, *, timeout: float) -> None: ...

    def apply_breakpoint(
        self,
        operation: BreakpointOperation,
        *,
        timeout: float,
    ) -> None: ...

    def refresh_modules(
        self,
        selectors: Mapping[str, ModuleSelector],
        *,
        timeout: float,
    ) -> dict[str, RebasedModuleMapping | None]: ...


@dataclass(frozen=True, slots=True)
class WorkflowExecution:
    state: WorkflowState
    effect_count: int
    breakpoint_operation_count: int
    refreshed_module_keys: frozenset[str]

    @property
    def operation_count(self) -> int:
        return self.effect_count + self.breakpoint_operation_count


class WorkflowExecutionError(RuntimeError):
    def __init__(
        self,
        cause: BaseException,
        execution: WorkflowExecution,
    ) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.execution = execution


def execute_workflow_transition(
    transition: WorkflowTransition,
    port: WorkflowExecutionPort,
    *,
    timeout: float,
) -> WorkflowExecution:
    if timeout <= 0:
        raise ValueError("workflow execution timeout must be positive")
    deadline = monotonic() + timeout
    state = transition.state
    effect_count = 0
    breakpoint_count = 0
    refreshed_keys = frozenset[str]()

    try:
        for effect in transition.navigation_effects:
            if effect == NavigationEffect.ENSURE_PAUSED:
                port.ensure_paused(timeout=_remaining(deadline))
                effect_count += 1

        state, applied = _reconcile(
            state,
            transition.breakpoint_reconciliation.operations,
            port,
            deadline=deadline,
            effect_count=effect_count,
            breakpoint_count=breakpoint_count,
            refreshed_keys=refreshed_keys,
        )
        breakpoint_count += applied

        requested_refresh = transition.refresh_module_keys
        if requested_refresh:
            selectors = {
                key: module.selector
                for key in sorted(requested_refresh)
                if (module := state.lifecycle.get(key)) is not None
            }
            if selectors.keys() != requested_refresh:
                raise ValueError("workflow refresh references an untracked module")
            port.ensure_paused(timeout=_remaining(deadline))
            effect_count += 1
            resolutions = port.refresh_modules(
                selectors,
                timeout=_remaining(deadline),
            )
            refreshed = apply_workflow_module_refresh(state, resolutions)
            state = refreshed.state
            # Only now is the refresh a fact: the port returned bases and the
            # state reflects them. Recording it at the requested set earlier
            # made a failure inside ensure_paused/refresh_modules report modules
            # as refreshed that never were -- the one place this executor's
            # "report exactly how far it got" contract read untrue.
            refreshed_keys = requested_refresh
            state, applied = _reconcile(
                state,
                refreshed.breakpoint_reconciliation.operations,
                port,
                deadline=deadline,
                effect_count=effect_count,
                breakpoint_count=breakpoint_count,
                refreshed_keys=refreshed_keys,
            )
            breakpoint_count += applied

        for effect in transition.navigation_effects:
            if effect == NavigationEffect.RESUME:
                port.resume(timeout=_remaining(deadline))
                effect_count += 1
    except WorkflowExecutionError:
        raise
    except BaseException as exc:
        execution = WorkflowExecution(
            state=state,
            effect_count=effect_count,
            breakpoint_operation_count=breakpoint_count,
            refreshed_module_keys=refreshed_keys,
        )
        raise WorkflowExecutionError(exc, execution) from exc

    return WorkflowExecution(
        state=state,
        effect_count=effect_count,
        breakpoint_operation_count=breakpoint_count,
        refreshed_module_keys=refreshed_keys,
    )


def _reconcile(
    state: WorkflowState,
    operations: tuple[BreakpointOperation, ...],
    port: WorkflowExecutionPort,
    *,
    deadline: float,
    effect_count: int,
    breakpoint_count: int,
    refreshed_keys: frozenset[str],
) -> tuple[WorkflowState, int]:
    applied = 0
    for operation in operations:
        try:
            port.apply_breakpoint(operation, timeout=_remaining(deadline))
            state = acknowledge_workflow_breakpoint_operation(state, operation)
        except BaseException as exc:
            execution = WorkflowExecution(
                state=state,
                effect_count=effect_count,
                breakpoint_operation_count=breakpoint_count + applied,
                refreshed_module_keys=refreshed_keys,
            )
            raise WorkflowExecutionError(exc, execution) from exc
        applied += 1
    return state, applied


def _remaining(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("workflow execution timed out")
    return remaining