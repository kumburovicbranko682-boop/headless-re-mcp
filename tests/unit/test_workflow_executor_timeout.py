"""The shared deadline that shrinks across every port call in a transition.

test_workflow_executor pins the happy paths and a mid-sequence *failure*, all
with a generous timeout, so the one arm that never runs is the deadline itself
expiring between steps: _remaining returning zero-or-less must raise, and the
executor must surface that as a WorkflowExecutionError whose partial execution
reports how far it got -- nothing, when the clock is already spent before the
first port call. A fake monotonic clock makes that deterministic; without it a
timed-out transition could look like a plain failure or, worse, report progress
the debugger never made.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows import executor as executor_module
from headless_re_mcp.workflows.breakpoints import BreakpointIntent, BreakpointOperation
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    put_workflow_breakpoint_intent,
)
from headless_re_mcp.workflows.executor import (
    WorkflowExecutionError,
    _remaining,
    execute_workflow_transition,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.navigation import NavigationEffect


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


class _NeverCalledPort:
    """Every method fails the test: an expired deadline must reach none of them."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def resume(self, *, timeout: float) -> None:
        self.calls.append("resume")

    def ensure_paused(self, *, timeout: float) -> None:
        self.calls.append("ensure_paused")

    def apply_breakpoint(self, operation: BreakpointOperation, *, timeout: float) -> None:
        self.calls.append("apply_breakpoint")

    def refresh_modules(self, selectors: object, *, timeout: float) -> dict[str, object]:
        self.calls.append("refresh_modules")
        return {}


class _Clock:
    """monotonic() stand-in: the first read seeds the deadline, the rest are spent.

    execute_workflow_transition reads the clock once to set ``deadline`` and then
    again inside _remaining before the first port call; returning a time far past
    the deadline on that second read forces the timeout on the very first step.
    """

    def __init__(self) -> None:
        self.reads = 0

    def __call__(self) -> float:
        self.reads += 1
        return 0.0 if self.reads == 1 else 1_000.0


def test_remaining_returns_the_time_left_before_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "monotonic", lambda: 100.0)
    assert _remaining(105.0) == pytest.approx(5.0)


def test_remaining_treats_a_deadline_reached_exactly_now_as_expired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero left is out of time, not a last free call: the guard is ``<= 0``."""
    monkeypatch.setattr(executor_module, "monotonic", lambda: 100.0)
    with pytest.raises(TimeoutError, match="workflow execution timed out"):
        _remaining(100.0)


def test_an_expired_deadline_before_the_first_step_reports_no_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "monotonic", _Clock())
    planned = put_workflow_breakpoint_intent(
        _state(), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    transition = replace(planned, navigation_effects=(NavigationEffect.ENSURE_PAUSED,))

    port = _NeverCalledPort()
    with pytest.raises(WorkflowExecutionError) as excinfo:
        execute_workflow_transition(transition, port, timeout=5.0)

    error = excinfo.value
    assert isinstance(error.cause, TimeoutError)
    assert str(error.cause) == "workflow execution timed out"
    partial = error.execution
    assert partial.effect_count == 0
    assert partial.breakpoint_operation_count == 0
    assert partial.operation_count == 0
    assert partial.refreshed_module_keys == frozenset()
    # The deadline was spent before the argument to the first port call was even
    # evaluated, so the debugger was never touched.
    assert port.calls == []
