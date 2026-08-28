"""Two engine guards the batch- and executor-driven suites never reach directly.

test_workflow_engine drives whole event batches, and test_workflow_executor
refreshes an untracked module by *bypassing* the engine -- it builds the
transition with replace() and hands it straight to the executor -- so the
engine's own checks stay dark:

- request_workflow_module_refresh must refuse an explicit key that names no
  tracked module, rather than silently returning a refresh for a subset (or
  for a module the port cannot resolve).
- prepare_workflow_reset must step over an intent that is already disabled while
  it disables the rest, so a reset over a mixed set is idempotent on the ones
  already off.

Both are pure state transitions, pinned here without a debugger.
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


def test_refreshing_an_explicit_untracked_key_is_refused() -> None:
    """A stale key must fail closed by name, not refresh a silent subset."""
    with pytest.raises(
        WorkflowInvariantError,
        match="cannot refresh untracked modules: ghost",
    ):
        request_workflow_module_refresh(_state(), keys=frozenset({"ghost"}))


def test_refresh_reports_every_unknown_key_it_was_handed() -> None:
    """The message names all offenders (sorted), not just the first."""
    with pytest.raises(WorkflowInvariantError) as excinfo:
        request_workflow_module_refresh(_state(), keys=frozenset({"payload", "alpha", "omega"}))
    assert "alpha, omega" in str(excinfo.value)
    assert "payload" not in str(excinfo.value)


def test_reset_disables_live_intents_and_steps_over_already_disabled_ones() -> None:
    state = put_workflow_breakpoint_intent(
        _state(), BreakpointIntent(id="a", module_key="payload", rva=0x10)
    ).state
    state = put_workflow_breakpoint_intent(
        state, BreakpointIntent(id="b", module_key="payload", rva=0x20)
    ).state
    # "a" is already off before the reset runs, so the reset's loop takes the
    # skip arm for it and the disable arm for the still-live "b".
    state = disable_workflow_breakpoint_intent(state, "a").state

    reset = prepare_workflow_reset(state)

    enabled_by_id = {intent.id: intent.enabled for intent in reset.state.breakpoints.intents}
    assert enabled_by_id == {"a": False, "b": False}
