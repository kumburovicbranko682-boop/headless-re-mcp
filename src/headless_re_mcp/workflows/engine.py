from __future__ import annotations

from dataclasses import dataclass, field, replace

from headless_re_mcp.core.addressing import RebasedModuleMapping
from headless_re_mcp.core.events import DebugEventBatch
from headless_re_mcp.core.models import ModuleSelector
from headless_re_mcp.workflows.breakpoints import (
    BreakpointIntent,
    BreakpointOperation,
    BreakpointReconciliation,
    BreakpointState,
    acknowledge_breakpoint_operation,
    consume_breakpoint_hit,
    disable_breakpoint_intent,
    plan_breakpoint_reconciliation,
    put_breakpoint_intent,
    remove_breakpoint_intent,
)
from headless_re_mcp.workflows.lifecycle import (
    ModuleLifecycleState,
    consume_module_events,
    refresh_modules,
    track_module,
    untrack_module,
)
from headless_re_mcp.workflows.models import WorkflowInvariantError
from headless_re_mcp.workflows.navigation import (
    EventPattern,
    NavigationEffect,
    NavigationState,
    NavigationStatus,
    cancel_navigation,
    consume_navigation_events,
    start_navigation,
    timeout_navigation,
)


@dataclass(frozen=True, slots=True)
class WorkflowState:
    lifecycle: ModuleLifecycleState = field(default_factory=ModuleLifecycleState)
    breakpoints: BreakpointState = field(default_factory=BreakpointState)
    navigation: NavigationState | None = None

    def __post_init__(self) -> None:
        if (
            self.navigation is not None
            and self.navigation.status == NavigationStatus.WAITING
            and self.navigation.cursor != self.lifecycle.cursor
        ):
            raise WorkflowInvariantError(
                "active navigation and module lifecycle cursors must match"
            )


@dataclass(frozen=True, slots=True)
class WorkflowTransition:
    state: WorkflowState
    navigation_effects: tuple[NavigationEffect, ...]
    invalidated_module_keys: frozenset[str]
    unloaded_module_bases: frozenset[int]
    refresh_module_keys: frozenset[str]
    breakpoint_hit_ids: tuple[str, ...]
    breakpoint_reconciliation: BreakpointReconciliation


def put_workflow_breakpoint_intent(
    state: WorkflowState,
    intent: BreakpointIntent,
) -> WorkflowTransition:
    breakpoints = put_breakpoint_intent(state.breakpoints, intent)
    next_state = replace(state, breakpoints=breakpoints)
    return _transition(next_state)


def disable_workflow_breakpoint_intent(
    state: WorkflowState,
    intent_id: str,
) -> WorkflowTransition:
    breakpoints = disable_breakpoint_intent(state.breakpoints, intent_id)
    return _transition(replace(state, breakpoints=breakpoints))


def remove_workflow_breakpoint_intent(
    state: WorkflowState,
    intent_id: str,
) -> WorkflowTransition:
    breakpoints = remove_breakpoint_intent(state.breakpoints, intent_id)
    return _transition(replace(state, breakpoints=breakpoints))


def track_workflow_module(
    state: WorkflowState,
    key: str,
    selector: ModuleSelector,
    mapping: RebasedModuleMapping,
) -> WorkflowTransition:
    lifecycle = track_module(state.lifecycle, key, selector, mapping)
    return _transition(replace(state, lifecycle=lifecycle))


def untrack_workflow_module(
    state: WorkflowState,
    key: str,
) -> WorkflowTransition:
    lifecycle = untrack_module(state.lifecycle, key)
    return _transition(replace(state, lifecycle=lifecycle))


def request_workflow_module_refresh(
    state: WorkflowState,
    keys: frozenset[str] | None = None,
) -> WorkflowTransition:
    selected = (
        frozenset(module.key for module in state.lifecycle.modules)
        if keys is None
        else keys
    )
    known = frozenset(module.key for module in state.lifecycle.modules)
    unknown = selected - known
    if unknown:
        rendered = ", ".join(sorted(unknown))
        raise WorkflowInvariantError(f"cannot refresh untracked modules: {rendered}")
    return _transition(state, refresh_module_keys=selected)


def cancel_workflow_navigation(state: WorkflowState) -> WorkflowTransition:
    navigation = state.navigation
    if navigation is None:
        return _transition(state)
    cancelled = cancel_navigation(navigation)
    return _transition(
        replace(state, navigation=cancelled.state),
        navigation_effects=cancelled.effects,
    )


def timeout_workflow_navigation(state: WorkflowState) -> WorkflowTransition:
    navigation = state.navigation
    if navigation is None:
        return _transition(state)
    timed_out = timeout_navigation(navigation)
    return _transition(
        replace(state, navigation=timed_out.state),
        navigation_effects=timed_out.effects,
    )


def prepare_workflow_reset(state: WorkflowState) -> WorkflowTransition:
    breakpoints = state.breakpoints
    for intent in breakpoints.intents:
        if intent.enabled:
            breakpoints = disable_breakpoint_intent(breakpoints, intent.id)
    navigation = state.navigation
    effects: tuple[NavigationEffect, ...] = ()
    if navigation is not None:
        cancelled = cancel_navigation(navigation)
        navigation = cancelled.state
        effects = cancelled.effects
    return _transition(
        replace(state, breakpoints=breakpoints, navigation=navigation),
        navigation_effects=effects,
    )


def start_workflow_navigation(
    state: WorkflowState,
    pattern: EventPattern,
    *,
    event_budget: int = 1024,
) -> WorkflowTransition:
    if (
        state.navigation is not None
        and state.navigation.status == NavigationStatus.WAITING
    ):
        raise WorkflowInvariantError("a navigation workflow is already active")
    started = start_navigation(
        pattern,
        cursor=state.lifecycle.cursor,
        event_budget=event_budget,
    )
    next_state = replace(state, navigation=started.state)
    return _transition(next_state, navigation_effects=started.effects)


def consume_workflow_events(
    state: WorkflowState,
    batch: DebugEventBatch,
) -> WorkflowTransition:
    lifecycle = consume_module_events(state.lifecycle, batch)

    breakpoints = state.breakpoints
    hit_ids: list[str] = []
    for event in batch.events:
        hit = consume_breakpoint_hit(breakpoints, event)
        breakpoints = hit.state
        hit_ids.extend(hit.hit_intent_ids)

    navigation = state.navigation
    navigation_effects: tuple[NavigationEffect, ...] = ()
    if navigation is not None and navigation.status == NavigationStatus.WAITING:
        navigated = consume_navigation_events(navigation, batch)
        navigation = navigated.state
        navigation_effects = navigated.effects

    next_state = WorkflowState(
        lifecycle=lifecycle.state,
        breakpoints=breakpoints,
        navigation=navigation,
    )
    return _transition(
        next_state,
        navigation_effects=navigation_effects,
        invalidated_module_keys=lifecycle.invalidated_keys,
        unloaded_module_bases=lifecycle.unloaded_bases,
        refresh_module_keys=lifecycle.refresh_required,
        breakpoint_hit_ids=tuple(hit_ids),
    )


def apply_workflow_module_refresh(
    state: WorkflowState,
    resolutions: dict[str, RebasedModuleMapping | None],
) -> WorkflowTransition:
    lifecycle = refresh_modules(state.lifecycle, resolutions)
    return _transition(replace(state, lifecycle=lifecycle))


def acknowledge_workflow_breakpoint_operation(
    state: WorkflowState,
    operation: BreakpointOperation,
) -> WorkflowState:
    breakpoints = acknowledge_breakpoint_operation(
        state.breakpoints,
        state.lifecycle,
        operation,
    )
    return replace(state, breakpoints=breakpoints)


def _transition(
    state: WorkflowState,
    *,
    navigation_effects: tuple[NavigationEffect, ...] = (),
    invalidated_module_keys: frozenset[str] = frozenset(),
    unloaded_module_bases: frozenset[int] = frozenset(),
    refresh_module_keys: frozenset[str] | None = None,
    breakpoint_hit_ids: tuple[str, ...] = (),
) -> WorkflowTransition:
    refresh = (
        state.lifecycle.refresh_required
        if refresh_module_keys is None
        else refresh_module_keys
    )
    return WorkflowTransition(
        state=state,
        navigation_effects=navigation_effects,
        invalidated_module_keys=invalidated_module_keys,
        unloaded_module_bases=unloaded_module_bases,
        refresh_module_keys=refresh,
        breakpoint_hit_ids=breakpoint_hit_ids,
        breakpoint_reconciliation=plan_breakpoint_reconciliation(
            state.breakpoints,
            state.lifecycle,
        ),
    )