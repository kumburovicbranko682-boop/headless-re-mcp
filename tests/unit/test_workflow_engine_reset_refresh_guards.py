"""Cover two engine guards not exercised elsewhere.

- ``request_workflow_module_refresh`` must refuse keys that name modules the
  lifecycle is not tracking, rather than silently issuing a refresh for them.
- ``prepare_workflow_reset`` disables every enabled breakpoint intent and must
  leave already-disabled intents untouched (the skip branch in its loop).
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


def _state_with_payload() -> WorkflowState:
    lifecycle = track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping(0x7FF800000000),
    )
    return WorkflowState(lifecycle=lifecycle)


def test_refresh_refuses_untracked_module_keys() -> None:
    state = _state_with_payload()
    with pytest.raises(
        WorkflowInvariantError,
        match="cannot refresh untracked modules: ghost, phantom",
    ):
        request_workflow_module_refresh(state, frozenset({"ghost", "phantom"}))


def test_refresh_of_tracked_key_is_accepted() -> None:
    state = _state_with_payload()
    transition = request_workflow_module_refresh(state, frozenset({"payload"}))
    assert transition.refresh_module_keys == {"payload"}


def test_refresh_with_no_keys_selects_all_tracked() -> None:
    state = _state_with_payload()
    transition = request_workflow_module_refresh(state)
    assert transition.refresh_module_keys == {"payload"}


def test_reset_disables_enabled_intents_and_skips_disabled_ones() -> None:
    breakpoints = BreakpointState(
        intents=(
            BreakpointIntent(id="enabled", module_key="payload", rva=0x10, enabled=True),
            BreakpointIntent(id="already-off", module_key="payload", rva=0x20, enabled=False),
        )
    )
    state = WorkflowState(lifecycle=_state_with_payload().lifecycle, breakpoints=breakpoints)

    transition = prepare_workflow_reset(state)

    resulting = {intent.id: intent.enabled for intent in transition.state.breakpoints.intents}
    assert resulting == {"enabled": False, "already-off": False}
