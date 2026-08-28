"""Module untrack/refresh transitions on the workflow engine.

The engine's navigation, event-loss and rebind paths are exercised elsewhere;
these pin the two module-tracking edges that were not: dropping a tracked module
(``untrack_workflow_module``) and the fail-closed guard that refuses to refresh
a module the engine does not track. The refuse path matters because a refresh
names modules the caller expects to exist -- silently skipping an unknown key
would let a stale breakpoint plan look reconciled against a module that was
never there.
"""

from __future__ import annotations

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
    prepare_workflow_reset,
    put_workflow_breakpoint_intent,
    request_workflow_module_refresh,
    track_workflow_module,
    untrack_workflow_module,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.models import WorkflowInvariantError


def _mapping(name: str, base: int) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name=name,
            path=rf"C:\sample\fixtures\{name}",
            sha256="d" * 64,
            architecture=Architecture.X64,
        ),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=RuntimeModule(
            base=base,
            size=0x5000,
            name=name,
            path=rf"C:\sample\fixtures\{name}",
        ),
        match_basis="name",
    )


def _state_with(*keys: str) -> WorkflowState:
    lifecycle = ModuleLifecycleState()
    for index, key in enumerate(keys):
        lifecycle = track_module(
            lifecycle,
            key,
            ModuleSelector(name=f"{key}.dll"),
            _mapping(f"{key}.dll", 0x7FF800000000 + index * 0x10000),
        )
    return WorkflowState(lifecycle=lifecycle)


def test_untrack_drops_the_named_module_and_keeps_the_rest() -> None:
    state = _state_with("payload", "helper")
    assert state.lifecycle.get("payload") is not None

    transition = untrack_workflow_module(state, "payload")

    assert transition.state.lifecycle.get("payload") is None
    assert transition.state.lifecycle.get("helper") is not None
    assert {module.key for module in transition.state.lifecycle.modules} == {"helper"}


def test_refresh_all_tracked_modules_selects_every_key() -> None:
    state = _state_with("payload", "helper")
    transition = request_workflow_module_refresh(state)
    assert transition.refresh_module_keys == frozenset({"payload", "helper"})


def test_refresh_an_explicit_tracked_subset_selects_only_it() -> None:
    state = _state_with("payload", "helper")
    transition = request_workflow_module_refresh(state, frozenset({"helper"}))
    assert transition.refresh_module_keys == frozenset({"helper"})


def test_refresh_refuses_untracked_modules_by_name() -> None:
    state = _state_with("payload")
    with pytest.raises(
        WorkflowInvariantError, match="cannot refresh untracked modules: ghost, phantom"
    ):
        request_workflow_module_refresh(state, frozenset({"ghost", "phantom", "payload"}))


def test_refresh_on_an_empty_lifecycle_selects_nothing() -> None:
    transition = request_workflow_module_refresh(WorkflowState())
    assert transition.refresh_module_keys == frozenset()


def test_track_then_untrack_round_trips_to_an_empty_lifecycle() -> None:
    state = WorkflowState()
    tracked = track_workflow_module(
        state,
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping("payload.dll", 0x7FF800000000),
    )
    assert tracked.state.lifecycle.get("payload") is not None
    untracked = untrack_workflow_module(tracked.state, "payload")
    assert untracked.state.lifecycle.modules == ()


def test_reset_disables_enabled_intents_and_leaves_disabled_ones_alone() -> None:
    # A mix of enabled and already-disabled intents makes the reset loop take
    # both arms: it must disable the enabled one and skip the disabled one
    # rather than churn it.
    state = _state_with("payload")
    state = put_workflow_breakpoint_intent(
        state, BreakpointIntent(id="a", module_key="payload", rva=0x100, enabled=True)
    ).state
    state = put_workflow_breakpoint_intent(
        state, BreakpointIntent(id="b", module_key="payload", rva=0x200, enabled=False)
    ).state

    reset = prepare_workflow_reset(state)

    intents = {intent.id: intent for intent in reset.state.breakpoints.intents}
    assert intents["a"].enabled is False
    assert intents["b"].enabled is False
