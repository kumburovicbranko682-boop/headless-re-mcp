"""Two engine guards the executor-level tests step around.

``request_workflow_module_refresh`` refuses keys for modules it is not tracking,
and ``prepare_workflow_reset`` disarms only the breakpoint intents that are still
enabled. The executor suite reaches both functions but never through these
branches: it either passes no keys (all tracked) or forces an unknown key with a
post-hoc ``replace(...)`` that bypasses the raise, and it only resets states whose
intents are all enabled. That left the untracked-key refusal (a WorkflowInvariant)
and the already-disabled skip untested -- a silently mis-sized refusal or a
double-disable would not have been caught. These pin the pure-logic decisions.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.core.models import ModuleSelector
from headless_re_mcp.workflows.breakpoints import BreakpointIntent, BreakpointState
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    prepare_workflow_reset,
    request_workflow_module_refresh,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.models import WorkflowInvariantError
from tests.unit.test_workflow_engine import _mapping


def _tracked() -> WorkflowState:
    lifecycle = track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping(0x7FF800000000),
    )
    return WorkflowState(lifecycle=lifecycle)


def test_refresh_refuses_untracked_keys_and_names_them_sorted() -> None:
    state = _tracked()
    with pytest.raises(
        WorkflowInvariantError,
        match="cannot refresh untracked modules: ghost, phantom",
    ):
        request_workflow_module_refresh(state, frozenset({"phantom", "ghost"}))


def test_refresh_of_a_tracked_key_is_accepted() -> None:
    # Control: a key the lifecycle knows passes and is carried on the transition.
    transition = request_workflow_module_refresh(_tracked(), frozenset({"payload"}))
    assert transition.refresh_module_keys == {"payload"}


def test_refresh_with_no_keys_selects_every_tracked_module() -> None:
    transition = request_workflow_module_refresh(_tracked())
    assert transition.refresh_module_keys == {"payload"}


def test_reset_disarms_enabled_intents_and_leaves_disabled_ones_untouched() -> None:
    # One enabled and one already-disabled intent: reset must flip only the first
    # and iterate past the second (the branch the executor tests never take).
    breakpoints = BreakpointState(
        intents=(
            BreakpointIntent(id="live", module_key="payload", rva=0x10, enabled=True),
            BreakpointIntent(id="off", module_key="payload", rva=0x20, enabled=False),
        )
    )
    state = WorkflowState(lifecycle=_tracked().lifecycle, breakpoints=breakpoints)

    reset = prepare_workflow_reset(state)

    resulting = {intent.id: intent.enabled for intent in reset.state.breakpoints.intents}
    assert resulting == {"live": False, "off": False}
