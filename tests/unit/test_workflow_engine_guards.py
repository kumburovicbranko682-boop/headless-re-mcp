"""Pin the engine arms the workflow suites leave unexercised.

``untrack_workflow_module`` had no test at all, the unknown-key refusal in
``request_workflow_module_refresh`` was unpinned, and ``prepare_workflow_reset``
was only ever driven with enabled intents, so the skip arm for an
already-disabled intent was never taken. Also pins the executor's deadline
enforcement through the public entry point: a port that outlives the budget
must surface a structured ``WorkflowExecutionError`` wrapping ``TimeoutError``
with the partial execution accounted for, not hang or return success.
"""

from __future__ import annotations

import time
from collections.abc import Mapping

import pytest

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows.breakpoints import BreakpointIntent, BreakpointOperation
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    disable_workflow_breakpoint_intent,
    prepare_workflow_reset,
    put_workflow_breakpoint_intent,
    request_workflow_module_refresh,
    track_workflow_module,
    untrack_workflow_module,
)
from headless_re_mcp.workflows.executor import (
    WorkflowExecutionError,
    execute_workflow_transition,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.models import WorkflowInvariantError

_BASE = 0x7FF800000000


def _mapping(base: int = _BASE) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name="payload.dll",
            path=r"C:\sample\payload.dll",
            sha256="c" * 64,
            architecture=Architecture.X64,
        ),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=RuntimeModule(
            base=base, size=0x5000, name="payload.dll", path=r"C:\sample\payload.dll"
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


def test_untracking_a_workflow_module_removes_exactly_that_binding() -> None:
    state = track_workflow_module(
        _state(),
        "helper",
        ModuleSelector(name="helper.dll"),
        _mapping(0x71000000),
    ).state

    transition = untrack_workflow_module(state, "helper")

    assert transition.state.lifecycle.get("helper") is None
    assert transition.state.lifecycle.get("payload") is not None
    with pytest.raises(WorkflowInvariantError, match="module is not tracked"):
        untrack_workflow_module(transition.state, "helper")


def test_refresh_request_refuses_an_untracked_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="cannot refresh untracked modules: ghost"):
        request_workflow_module_refresh(_state(), frozenset({"ghost"}))


def test_reset_leaves_an_already_disabled_intent_alone() -> None:
    armed = put_workflow_breakpoint_intent(
        _state(),
        BreakpointIntent(id="oep", module_key="payload", rva=0x1234),
    ).state
    disabled = disable_workflow_breakpoint_intent(armed, "oep").state

    transition = prepare_workflow_reset(disabled)

    intent = next(intent for intent in transition.state.breakpoints.intents if intent.id == "oep")
    assert intent.enabled is False


class _GlacialPort:
    """Honors the protocol but takes longer than the whole budget per call."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.resumed = 0

    def resume(self, *, timeout: float) -> None:
        self.resumed += 1

    def ensure_paused(self, *, timeout: float) -> None:
        time.sleep(self.delay)

    def apply_breakpoint(self, operation: BreakpointOperation, *, timeout: float) -> None:
        raise AssertionError("no breakpoint work in this plan")

    def refresh_modules(
        self, selectors: Mapping[str, ModuleSelector], *, timeout: float
    ) -> dict[str, RebasedModuleMapping | None]:
        raise AssertionError("no refresh work in this plan")


def test_a_port_that_outlives_the_deadline_surfaces_a_structured_timeout() -> None:
    # A refresh plan calls ensure_paused first and refresh_modules second;
    # when ensure_paused eats the whole budget, the next deadline check must
    # refuse with TimeoutError rather than call into the port with a negative
    # timeout or hang.
    transition = request_workflow_module_refresh(_state())
    port = _GlacialPort(delay=0.05)

    with pytest.raises(WorkflowExecutionError) as excinfo:
        execute_workflow_transition(transition, port, timeout=0.01)

    assert isinstance(excinfo.value.cause, TimeoutError)
    # The pause landed before the deadline tripped, and nothing resumed.
    assert excinfo.value.execution.effect_count == 1
    assert port.resumed == 0
