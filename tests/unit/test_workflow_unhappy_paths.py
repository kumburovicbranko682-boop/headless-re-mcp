"""Cancel, timeout and reset are the workflow paths a stuck target exercises.

The happy path (start -> events -> match) is well tested; the transitions the
service reaches for when the target never produces the awaited event were not:
timeout_workflow_navigation had no test at all, cancel was tested only for the
no-navigation no-op, and prepare_workflow_reset -- the between-samples cleanup
that must disarm every breakpoint and stop watching -- had none. Each must
request ENSURE_PAUSED exactly once and be idempotent, so a retried cancel does
not send the debugger a second pause for a navigation already settled.
"""

from __future__ import annotations

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows.breakpoints import (
    BreakpointIntent,
    BreakpointOperationKind,
)
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    acknowledge_workflow_breakpoint_operation,
    cancel_workflow_navigation,
    prepare_workflow_reset,
    put_workflow_breakpoint_intent,
    start_workflow_navigation,
    timeout_workflow_navigation,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.navigation import (
    EventPattern,
    NavigationEffect,
    NavigationStatus,
)


def _tracked_state() -> WorkflowState:
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
    return WorkflowState(lifecycle=lifecycle)


def _waiting_state() -> WorkflowState:
    started = start_workflow_navigation(
        _tracked_state(), EventPattern.create("breakpoint.hit", {"address": 1})
    )
    return started.state


def test_cancel_stops_a_waiting_navigation_and_asks_for_a_pause() -> None:
    transition = cancel_workflow_navigation(_waiting_state())
    navigation = transition.state.navigation
    assert navigation is not None
    assert navigation.status is NavigationStatus.CANCELLED
    assert transition.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)


def test_timeout_marks_the_navigation_timed_out_and_asks_for_a_pause() -> None:
    transition = timeout_workflow_navigation(_waiting_state())
    navigation = transition.state.navigation
    assert navigation is not None
    assert navigation.status is NavigationStatus.TIMED_OUT
    assert transition.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)


def test_cancel_and_timeout_are_idempotent_on_a_settled_navigation() -> None:
    """A second cancel/timeout must not emit another pause command."""
    cancelled = cancel_workflow_navigation(_waiting_state()).state
    for again in (cancel_workflow_navigation, timeout_workflow_navigation):
        repeated = again(cancelled)
        navigation = repeated.state.navigation
        assert navigation is not None
        assert navigation.status is NavigationStatus.CANCELLED  # unchanged
        assert repeated.navigation_effects == ()

    # And on a state with no navigation at all, timeout is a plain no-op too.
    untouched = timeout_workflow_navigation(_tracked_state())
    assert untouched.state.navigation is None
    assert untouched.navigation_effects == ()


def test_reset_disarms_every_breakpoint_and_cancels_the_navigation() -> None:
    """The between-samples reset must leave nothing armed and nothing watched."""
    planned = put_workflow_breakpoint_intent(
        _waiting_state(), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    bound = acknowledge_workflow_breakpoint_operation(
        planned.state, planned.breakpoint_reconciliation.operations[0]
    )

    reset = prepare_workflow_reset(bound)

    navigation = reset.state.navigation
    assert navigation is not None
    assert navigation.status is NavigationStatus.CANCELLED
    assert reset.navigation_effects == (NavigationEffect.ENSURE_PAUSED,)
    # The intent is disabled, so reconciliation now plans the physical removal.
    assert all(not intent.enabled for intent in reset.state.breakpoints.intents)
    assert [op.kind for op in reset.breakpoint_reconciliation.operations] == [
        BreakpointOperationKind.REMOVE
    ]
    assert reset.breakpoint_reconciliation.operations[0].address == 0x7FF800000000 + 0x1234


def test_reset_of_an_idle_state_plans_no_work() -> None:
    reset = prepare_workflow_reset(_tracked_state())
    assert reset.navigation_effects == ()
    assert reset.breakpoint_reconciliation.operations == ()
