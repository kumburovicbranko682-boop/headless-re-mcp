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
    BreakpointState,
    acknowledge_breakpoint_operation,
    consume_breakpoint_hit,
    plan_breakpoint_reconciliation,
    put_breakpoint_intent,
)
from headless_re_mcp.workflows.lifecycle import (
    ModuleLifecycleState,
    consume_module_events,
    refresh_modules,
    track_module,
)
from headless_re_mcp.workflows.models import WorkflowInvariantError


def _mapping(base: int) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name="payload.dll",
            path=r"E:\fixtures\payload.dll",
            sha256="b" * 64,
            architecture=Architecture.X64,
        ),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=RuntimeModule(
            base=base,
            size=0x5000,
            name="payload.dll",
            path=r"E:\fixtures\payload.dll",
        ),
        match_basis="name",
    )


def _lifecycle(base: int = 0x7FF800000000) -> ModuleLifecycleState:
    return track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping(base),
    )


def _state(*intents: BreakpointIntent) -> BreakpointState:
    state = BreakpointState()
    for intent in intents:
        state = put_breakpoint_intent(state, intent)
    return state


def _unload_batch(base: int) -> DebugEventBatch:
    event = DebugEvent(
        sequence=1,
        timestamp_unix_ms=1_700_000_000_001,
        source="x64dbg.plugin_callback",
        kind="module.unloaded",
        data={"base": base},
    )
    return DebugEventBatch(
        events=(event,),
        cursor=0,
        next_cursor=1,
        oldest_sequence=1,
        latest_sequence=1,
        dropped=0,
        dropped_total=0,
        has_more=False,
        capacity=1024,
    )


def _hit(address: int) -> DebugEvent:
    return DebugEvent(
        sequence=7,
        timestamp_unix_ms=1_700_000_000_007,
        source="x64dbg.plugin_callback",
        kind="breakpoint.hit",
        data={"address": address, "type": 0},
    )


def test_reconciliation_sets_rva_based_breakpoint() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x1234))

    plan = plan_breakpoint_reconciliation(state, lifecycle)

    assert plan.deferred_intent_ids == frozenset()
    assert len(plan.operations) == 1
    operation = plan.operations[0]
    assert operation.kind == BreakpointOperationKind.SET
    assert operation.address == 0x7FF800001234

    applied = acknowledge_breakpoint_operation(state, lifecycle, operation)
    assert applied.binding("oep") is not None
    assert plan_breakpoint_reconciliation(applied, lifecycle).operations == ()


def test_module_unload_removes_binding_and_defers_intent() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x1234))
    initial = plan_breakpoint_reconciliation(state, lifecycle).operations[0]
    state = acknowledge_breakpoint_operation(state, lifecycle, initial)
    unloaded = consume_module_events(
        lifecycle,
        _unload_batch(0x7FF800000000),
    ).state

    plan = plan_breakpoint_reconciliation(state, unloaded)

    assert plan.deferred_intent_ids == {"oep"}
    assert [(operation.kind, operation.address) for operation in plan.operations] == [
        (BreakpointOperationKind.REMOVE, 0x7FF800001234)
    ]
    state = acknowledge_breakpoint_operation(state, unloaded, plan.operations[0])
    assert state.binding("oep") is None


def test_reloaded_module_rebinds_same_intent_at_new_runtime_base() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x1234))
    initial = plan_breakpoint_reconciliation(state, lifecycle).operations[0]
    state = acknowledge_breakpoint_operation(state, lifecycle, initial)

    refreshed = refresh_modules(lifecycle, {"payload": _mapping(0x7FF900000000)})
    plan = plan_breakpoint_reconciliation(state, refreshed)

    assert [operation.kind for operation in plan.operations] == [
        BreakpointOperationKind.REMOVE,
        BreakpointOperationKind.SET,
    ]
    assert [operation.address for operation in plan.operations] == [
        0x7FF800001234,
        0x7FF900001234,
    ]

    with pytest.raises(WorkflowInvariantError, match="remove the previous"):
        acknowledge_breakpoint_operation(state, refreshed, plan.operations[1])

    for operation in plan.operations:
        state = acknowledge_breakpoint_operation(state, refreshed, operation)
    binding = state.binding("oep")
    module = refreshed.get("payload")
    assert binding is not None
    assert module is not None
    assert binding.address == 0x7FF900001234
    assert binding.module_revision == module.revision


def test_stale_set_acknowledgement_is_rejected_after_module_refresh() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x40))
    stale_operation = plan_breakpoint_reconciliation(state, lifecycle).operations[0]
    refreshed = refresh_modules(lifecycle, {"payload": _mapping(0x7FF900000000)})

    with pytest.raises(WorkflowInvariantError, match="stale breakpoint set"):
        acknowledge_breakpoint_operation(state, refreshed, stale_operation)


def test_stale_removal_cannot_delete_newer_binding_at_same_address() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x40))
    initial = plan_breakpoint_reconciliation(state, lifecycle).operations[0]
    state = acknowledge_breakpoint_operation(state, lifecycle, initial)

    refreshed = refresh_modules(lifecycle, {"payload": _mapping(0x7FF800000000)})
    replacement = plan_breakpoint_reconciliation(state, refreshed).operations
    stale_removal, new_set = replacement
    state = acknowledge_breakpoint_operation(state, refreshed, stale_removal)
    state = acknowledge_breakpoint_operation(state, refreshed, new_set)

    with pytest.raises(WorkflowInvariantError, match="stale breakpoint removal"):
        acknowledge_breakpoint_operation(state, refreshed, stale_removal)


def test_one_shot_hit_disables_intent_then_plans_removal() -> None:
    lifecycle = _lifecycle()
    state = _state(
        BreakpointIntent(
            id="unpack-ready",
            module_key="payload",
            rva=0x250,
            one_shot=True,
        )
    )
    operation = plan_breakpoint_reconciliation(state, lifecycle).operations[0]
    state = acknowledge_breakpoint_operation(state, lifecycle, operation)

    transition = consume_breakpoint_hit(state, _hit(operation.address))

    assert transition.hit_intent_ids == ("unpack-ready",)
    intent = transition.state.intent("unpack-ready")
    assert intent is not None and intent.enabled is False
    removal = plan_breakpoint_reconciliation(transition.state, lifecycle)
    assert [operation.kind for operation in removal.operations] == [
        BreakpointOperationKind.REMOVE
    ]


def test_breakpoint_rva_must_fit_tracked_image() -> None:
    state = _state(
        BreakpointIntent(id="outside", module_key="payload", rva=0x5000)
    )

    with pytest.raises(WorkflowInvariantError, match="outside module"):
        plan_breakpoint_reconciliation(state, _lifecycle())


def test_two_intents_cannot_claim_same_physical_address() -> None:
    state = _state(
        BreakpointIntent(id="first", module_key="payload", rva=0x100),
        BreakpointIntent(id="second", module_key="payload", rva=0x100),
    )

    with pytest.raises(WorkflowInvariantError, match="resolve to"):
        plan_breakpoint_reconciliation(state, _lifecycle())