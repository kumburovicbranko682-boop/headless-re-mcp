from __future__ import annotations

import pytest

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows.breakpoints import (
    BreakpointIntent,
    BreakpointOperationKind,
)
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    acknowledge_workflow_breakpoint_operation,
    apply_workflow_module_refresh,
    cancel_workflow_navigation,
    consume_workflow_events,
    disable_workflow_breakpoint_intent,
    prepare_workflow_reset,
    put_workflow_breakpoint_intent,
    remove_workflow_breakpoint_intent,
    request_workflow_module_refresh,
    start_workflow_navigation,
    timeout_workflow_navigation,
    track_workflow_module,
    untrack_workflow_module,
)
from headless_re_mcp.workflows.lifecycle import (
    ModuleLifecycleState,
    track_module,
)
from headless_re_mcp.workflows.models import WorkflowInvariantError
from headless_re_mcp.workflows.navigation import (
    EventPattern,
    NavigationEffect,
    NavigationStatus,
)


def _mapping(base: int) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name="payload.dll",
            path=r"C:\sample\fixtures\payload.dll",
            sha256="c" * 64,
            architecture=Architecture.X64,
        ),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=RuntimeModule(
            base=base,
            size=0x5000,
            name="payload.dll",
            path=r"C:\sample\fixtures\payload.dll",
        ),
        match_basis="name",
    )


def _state(base: int = 0x7FF800000000) -> WorkflowState:
    lifecycle = track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping(base),
    )
    return WorkflowState(lifecycle=lifecycle)


def _event(
    sequence: int,
    kind: str,
    data: dict[str, object] | None = None,
) -> DebugEvent:
    return DebugEvent(
        sequence=sequence,
        timestamp_unix_ms=1_700_000_000_000 + sequence,
        source="x64dbg.plugin_callback",
        kind=kind,
        data=data or {},
    )


def _batch(
    cursor: int,
    *events: DebugEvent,
    dropped: int = 0,
) -> DebugEventBatch:
    next_cursor = events[-1].sequence if events else cursor + dropped
    return DebugEventBatch(
        events=events,
        cursor=cursor,
        next_cursor=next_cursor,
        oldest_sequence=(1 if next_cursor else 0),
        latest_sequence=next_cursor,
        dropped=dropped,
        dropped_total=dropped,
        has_more=False,
        capacity=1024,
    )


def _with_bound_breakpoint(
    state: WorkflowState,
    *,
    one_shot: bool = False,
) -> tuple[WorkflowState, int]:
    planned = put_workflow_breakpoint_intent(
        state,
        BreakpointIntent(
            id="oep",
            module_key="payload",
            rva=0x1234,
            one_shot=one_shot,
        ),
    )
    operation = planned.breakpoint_reconciliation.operations[0]
    applied = acknowledge_workflow_breakpoint_operation(planned.state, operation)
    return applied, operation.address


def test_one_event_batch_drives_navigation_lifecycle_and_breakpoints() -> None:
    state, address = _with_bound_breakpoint(_state(), one_shot=True)
    started = start_workflow_navigation(
        state,
        EventPattern.create("breakpoint.hit", {"address": address}),
    )
    assert started.navigation_effects == (NavigationEffect.RESUME,)

    transition = consume_workflow_events(
        started.state,
        _batch(
            0,
            _event(1, "debug.resumed"),
            _event(2, "breakpoint.hit", {"address": address, "type": 0}),
        ),
    )

    assert transition.state.lifecycle.cursor == 2
    assert transition.state.navigation is not None
    assert transition.state.navigation.status == NavigationStatus.MATCHED
    assert transition.breakpoint_hit_ids == ("oep",)
    assert transition.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)
    assert [
        operation.kind for operation in transition.breakpoint_reconciliation.operations
    ] == [BreakpointOperationKind.REMOVE]


def test_event_loss_invalidates_modules_navigation_and_bound_breakpoints() -> None:
    state, _ = _with_bound_breakpoint(_state())
    state = start_workflow_navigation(
        state,
        EventPattern.create("breakpoint.hit"),
    ).state

    transition = consume_workflow_events(state, _batch(0, dropped=4))

    assert transition.invalidated_module_keys == {"payload"}
    assert transition.refresh_module_keys == {"payload"}
    assert transition.state.navigation is not None
    assert transition.state.navigation.status == NavigationStatus.EVENT_LOSS
    assert transition.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)
    assert transition.breakpoint_reconciliation.deferred_intent_ids == {"oep"}
    assert [
        operation.kind for operation in transition.breakpoint_reconciliation.operations
    ] == [BreakpointOperationKind.REMOVE]


def test_unload_then_refresh_rebinds_breakpoint_at_new_base() -> None:
    state, old_address = _with_bound_breakpoint(_state())

    unloaded = consume_workflow_events(
        state,
        _batch(
            0,
            _event(1, "module.unloaded", {"base": 0x7FF800000000}),
        ),
    )
    assert unloaded.unloaded_module_bases == {0x7FF800000000}
    removal = unloaded.breakpoint_reconciliation.operations[0]
    assert removal.kind == BreakpointOperationKind.REMOVE
    state = acknowledge_workflow_breakpoint_operation(unloaded.state, removal)

    refreshed = apply_workflow_module_refresh(
        state,
        {"payload": _mapping(0x7FF900000000)},
    )
    addition = refreshed.breakpoint_reconciliation.operations[0]
    assert addition.kind == BreakpointOperationKind.SET
    assert addition.address == 0x7FF900001234
    assert addition.address != old_address


def test_engine_refuses_two_simultaneous_navigations() -> None:
    started = start_workflow_navigation(
        _state(),
        EventPattern.create("debug.paused"),
    ).state

    with pytest.raises(WorkflowInvariantError, match="already active"):
        start_workflow_navigation(
            started,
            EventPattern.create("breakpoint.hit"),
        )


def test_active_navigation_must_share_lifecycle_cursor() -> None:
    navigation = start_workflow_navigation(
        _state(),
        EventPattern.create("debug.paused"),
    ).state.navigation
    assert navigation is not None

    with pytest.raises(WorkflowInvariantError, match="cursors must match"):
        WorkflowState(
            lifecycle=ModuleLifecycleState(cursor=9),
            navigation=navigation,
        )


def test_cancel_navigation_without_an_active_one_is_a_no_op() -> None:
    transition = cancel_workflow_navigation(_state())
    assert transition.state.navigation is None
    assert transition.navigation_effects == ()


def test_cancel_navigation_stops_an_active_navigation() -> None:
    started = start_workflow_navigation(_state(), EventPattern.create("debug.paused"))
    cancelled = cancel_workflow_navigation(started.state)
    assert cancelled.state.navigation is not None
    assert cancelled.state.navigation.status == NavigationStatus.CANCELLED
    assert cancelled.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)


def test_timeout_navigation_without_an_active_one_is_a_no_op() -> None:
    transition = timeout_workflow_navigation(_state())
    assert transition.state.navigation is None
    assert transition.navigation_effects == ()


def test_timeout_navigation_ends_an_active_navigation() -> None:
    started = start_workflow_navigation(_state(), EventPattern.create("debug.paused"))
    timed_out = timeout_workflow_navigation(started.state)
    assert timed_out.state.navigation is not None
    assert timed_out.state.navigation.status == NavigationStatus.TIMED_OUT
    assert timed_out.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)


def test_track_workflow_module_binds_a_module_into_an_empty_state() -> None:
    transition = track_workflow_module(
        WorkflowState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping(0x7FF800000000),
    )
    module = transition.state.lifecycle.get("payload")
    assert module is not None
    assert module.runtime.base == 0x7FF800000000


def test_untrack_workflow_module_drops_the_binding() -> None:
    state = _state()
    assert state.lifecycle.get("payload") is not None

    transition = untrack_workflow_module(state, "payload")

    assert transition.state.lifecycle.get("payload") is None
    assert transition.state.lifecycle.modules == ()


def test_remove_workflow_breakpoint_intent_deletes_an_unbound_intent() -> None:
    state = put_workflow_breakpoint_intent(
        _state(),
        BreakpointIntent(id="scratch", module_key="payload", rva=0x40),
    ).state
    assert state.breakpoints.intent("scratch") is not None

    transition = remove_workflow_breakpoint_intent(state, "scratch")

    assert transition.state.breakpoints.intent("scratch") is None


def test_request_module_refresh_defaults_to_every_tracked_module() -> None:
    transition = request_workflow_module_refresh(_state())
    # keys=None selects every tracked module and surfaces it as the refresh set
    # without mutating the lifecycle.
    assert transition.refresh_module_keys == {"payload"}
    assert transition.state.lifecycle.get("payload") is not None


def test_request_module_refresh_rejects_untracked_keys() -> None:
    with pytest.raises(WorkflowInvariantError, match="cannot refresh untracked modules: ghost"):
        request_workflow_module_refresh(_state(), frozenset({"ghost"}))


def test_reset_disables_enabled_intents_and_skips_already_disabled_ones() -> None:
    state, _ = _with_bound_breakpoint(_state())
    # A second intent, then disabled, so reset's loop meets both an enabled
    # intent (oep) and an already-disabled one (second, the skip branch).
    state = put_workflow_breakpoint_intent(
        state,
        BreakpointIntent(id="second", module_key="payload", rva=0x2000),
    ).state
    state = disable_workflow_breakpoint_intent(state, "second").state
    assert {intent.id: intent.enabled for intent in state.breakpoints.intents} == {
        "oep": True,
        "second": False,
    }

    reset = prepare_workflow_reset(state)

    assert all(not intent.enabled for intent in reset.state.breakpoints.intents)
    # oep still holds its binding, so disabling it queues that binding's removal.
    assert [
        operation.kind for operation in reset.breakpoint_reconciliation.operations
    ] == [BreakpointOperationKind.REMOVE]


def test_reset_also_cancels_an_active_navigation() -> None:
    state, _ = _with_bound_breakpoint(_state())
    started = start_workflow_navigation(state, EventPattern.create("debug.paused"))

    reset = prepare_workflow_reset(started.state)

    assert reset.state.navigation is not None
    assert reset.state.navigation.status == NavigationStatus.CANCELLED
    assert reset.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)
    assert all(not intent.enabled for intent in reset.state.breakpoints.intents)