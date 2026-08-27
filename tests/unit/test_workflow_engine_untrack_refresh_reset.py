"""Untrack, refresh-guard, and reset paths of the workflow engine.

These are the state-machine edges the happy-path engine suite skips: dropping a
tracked module, refusing a refresh that names a module the engine never tracked
(refreshing an unknown key would silently rebind nothing and hide a caller bug),
and resetting a workflow whose breakpoint intents are already disabled (the reset
must leave those alone rather than redundantly disabling them).
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
    disable_workflow_breakpoint_intent,
    prepare_workflow_reset,
    put_workflow_breakpoint_intent,
    request_workflow_module_refresh,
    untrack_workflow_module,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.models import WorkflowInvariantError


def _mapping(base: int = 0x7FF800000000) -> RebasedModuleMapping:
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


def _state() -> WorkflowState:
    lifecycle = track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping(),
    )
    return WorkflowState(lifecycle=lifecycle)


def test_untracking_a_module_drops_it_from_the_lifecycle() -> None:
    state = _state()
    assert [module.key for module in state.lifecycle.modules] == ["payload"]

    transition = untrack_workflow_module(state, "payload")

    assert [module.key for module in transition.state.lifecycle.modules] == []


def test_refreshing_an_untracked_module_is_refused() -> None:
    state = _state()

    with pytest.raises(WorkflowInvariantError, match="untracked"):
        request_workflow_module_refresh(state, frozenset({"ghost"}))


def test_reset_leaves_an_already_disabled_intent_untouched() -> None:
    # Put an intent, then disable it, so prepare_workflow_reset iterates an
    # intent whose enabled flag is already False and takes the skip path rather
    # than issuing a second, pointless disable.
    planned = put_workflow_breakpoint_intent(
        _state(),
        BreakpointIntent(id="oep", module_key="payload", rva=0x1234),
    )
    disabled = disable_workflow_breakpoint_intent(planned.state, "oep")
    intents = {intent.id: intent for intent in disabled.state.breakpoints.intents}
    assert intents["oep"].enabled is False

    transition = prepare_workflow_reset(disabled.state)

    after = {intent.id: intent for intent in transition.state.breakpoints.intents}
    assert after["oep"].enabled is False
    assert transition.navigation_effects == ()
