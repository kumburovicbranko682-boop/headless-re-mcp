"""The workflow executor is the piece that touches the real debugger port.

Engine, navigation, lifecycle and breakpoints are all pure and well tested;
executor.py is where their planned transitions become ordered port calls
(pause -> apply breakpoints -> refresh -> reconcile again -> resume), where a
shared deadline shrinks across calls, and where a mid-sequence failure must
report exactly how far it got so the service can reconcile. None of that was
tested. A fake port that records every call pins the contract.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows.breakpoints import (
    BreakpointIntent,
    BreakpointOperation,
    BreakpointOperationKind,
    plan_breakpoint_reconciliation,
)
from headless_re_mcp.workflows.engine import (
    WorkflowState,
    put_workflow_breakpoint_intent,
    request_workflow_module_refresh,
)
from headless_re_mcp.workflows.executor import (
    WorkflowExecutionError,
    execute_workflow_transition,
)
from headless_re_mcp.workflows.lifecycle import ModuleLifecycleState, track_module
from headless_re_mcp.workflows.navigation import NavigationEffect


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


@dataclass
class _RecordingPort:
    """Records every call in order; individual steps can be told to fail."""

    refresh_result: dict[str, RebasedModuleMapping | None] | None = None
    fail_on_apply: int | None = None
    fail_on_refresh: bool = False

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.timeouts: list[float] = []
        self._applies = 0

    def resume(self, *, timeout: float) -> None:
        self.calls.append(("resume", None))
        self.timeouts.append(timeout)

    def ensure_paused(self, *, timeout: float) -> None:
        self.calls.append(("ensure_paused", None))
        self.timeouts.append(timeout)

    def apply_breakpoint(self, operation: BreakpointOperation, *, timeout: float) -> None:
        self._applies += 1
        if self.fail_on_apply is not None and self._applies >= self.fail_on_apply:
            raise RuntimeError("debugger refused the breakpoint")
        self.calls.append(("apply_breakpoint", operation))
        self.timeouts.append(timeout)

    def refresh_modules(
        self,
        selectors: dict[str, ModuleSelector],
        *,
        timeout: float,
    ) -> dict[str, RebasedModuleMapping | None]:
        self.calls.append(("refresh_modules", dict(selectors)))
        self.timeouts.append(timeout)
        if self.fail_on_refresh:
            raise RuntimeError("debugger dropped during module refresh")
        assert self.refresh_result is not None, "test forgot to stub the refresh"
        return self.refresh_result


def test_a_nonpositive_timeout_is_refused_before_any_port_call() -> None:
    port = _RecordingPort()
    transition = put_workflow_breakpoint_intent(
        _state(), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    for bad in (0.0, -1.0):
        with pytest.raises(ValueError, match="timeout must be positive"):
            execute_workflow_transition(transition, port, timeout=bad)
    assert port.calls == []


def test_planned_breakpoints_are_applied_and_acknowledged() -> None:
    """A SET plan reaches the port once and the returned state has no residue."""
    port = _RecordingPort()
    transition = put_workflow_breakpoint_intent(
        _state(), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    assert len(transition.breakpoint_reconciliation.operations) == 1

    execution = execute_workflow_transition(transition, port, timeout=5.0)

    assert [name for name, _ in port.calls] == ["apply_breakpoint"]
    assert execution.breakpoint_operation_count == 1
    assert execution.effect_count == 0
    assert execution.operation_count == 1
    # The acknowledgement landed: planning again on the result finds nothing.
    residue = plan_breakpoint_reconciliation(
        execution.state.breakpoints, execution.state.lifecycle
    )
    assert residue.operations == ()


def test_effects_run_in_pause_first_resume_last_order() -> None:
    """RESUME before the breakpoints are set would let the target run past them."""
    port = _RecordingPort()
    planned = put_workflow_breakpoint_intent(
        _state(), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    transition = replace(
        planned,
        navigation_effects=(NavigationEffect.ENSURE_PAUSED, NavigationEffect.RESUME),
    )

    execution = execute_workflow_transition(transition, port, timeout=5.0)

    assert [name for name, _ in port.calls] == [
        "ensure_paused",
        "apply_breakpoint",
        "resume",
    ]
    assert execution.effect_count == 2
    assert all(0 < t <= 5.0 for t in port.timeouts)


def test_a_mid_sequence_failure_reports_exactly_how_far_it_got() -> None:
    """The service reconciles from the partial execution, so counts must be true."""
    state = _state()
    first = put_workflow_breakpoint_intent(
        state, BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    both = put_workflow_breakpoint_intent(
        first.state, BreakpointIntent(id="iat", module_key="payload", rva=0x2000)
    )
    assert len(both.breakpoint_reconciliation.operations) == 2

    port = _RecordingPort(fail_on_apply=2)
    with pytest.raises(WorkflowExecutionError) as excinfo:
        execute_workflow_transition(both, port, timeout=5.0)

    error = excinfo.value
    assert isinstance(error.cause, RuntimeError)
    partial = error.execution
    assert partial.breakpoint_operation_count == 1
    # The first operation was acknowledged into the carried state, the second
    # was not, so replanning from the partial state finds exactly one SET left.
    residue = plan_breakpoint_reconciliation(partial.state.breakpoints, partial.state.lifecycle)
    assert [op.kind for op in residue.operations] == [BreakpointOperationKind.SET]


def test_a_module_refresh_rebinds_breakpoints_at_the_new_base() -> None:
    """The refresh path pauses, asks the port for new bases, then reconciles."""
    old_base, new_base = 0x7FF800000000, 0x7FF900000000
    planned = put_workflow_breakpoint_intent(
        _state(old_base), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    bound_port = _RecordingPort()
    bound = execute_workflow_transition(planned, bound_port, timeout=5.0)

    refresh = request_workflow_module_refresh(bound.state)
    port = _RecordingPort(refresh_result={"payload": _mapping(new_base)})
    execution = execute_workflow_transition(refresh, port, timeout=5.0)

    names = [name for name, _ in port.calls]
    assert names[:2] == ["ensure_paused", "refresh_modules"]
    assert names.count("apply_breakpoint") == 2  # remove old binding, set new
    applied = [op for name, op in port.calls if name == "apply_breakpoint"]
    kinds = {op.kind: op.address for op in applied if isinstance(op, BreakpointOperation)}
    assert kinds[BreakpointOperationKind.REMOVE] == old_base + 0x1234
    assert kinds[BreakpointOperationKind.SET] == new_base + 0x1234
    assert execution.refreshed_module_keys == frozenset({"payload"})
    residue = plan_breakpoint_reconciliation(
        execution.state.breakpoints, execution.state.lifecycle
    )
    assert residue.operations == ()


def test_a_failed_refresh_does_not_claim_the_modules_were_refreshed() -> None:
    """A refresh that never completed must not report its modules as refreshed.

    The executor's contract is to report exactly how far it got so the service
    can reconcile. ``refreshed_module_keys`` used to be set to the requested set
    before the port was touched, so a debugger that dropped inside
    ``ensure_paused``/``refresh_modules`` produced a partial execution claiming
    the modules were refreshed when the state never changed. The keys are a fact
    only once the port has returned new bases and the state reflects them.
    """
    old_base = 0x7FF800000000
    planned = put_workflow_breakpoint_intent(
        _state(old_base), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    bound = execute_workflow_transition(planned, _RecordingPort(), timeout=5.0)
    refresh = request_workflow_module_refresh(bound.state)

    port = _RecordingPort(fail_on_refresh=True)
    with pytest.raises(WorkflowExecutionError) as excinfo:
        execute_workflow_transition(refresh, port, timeout=5.0)

    error = excinfo.value
    assert isinstance(error.cause, RuntimeError)
    # The refresh was reached but raised, so it is not a fact.
    assert [name for name, _ in port.calls] == ["ensure_paused", "refresh_modules"]
    assert error.execution.refreshed_module_keys == frozenset()
    # The state is untouched: the old binding is still bound at the old base.
    residue = plan_breakpoint_reconciliation(
        error.execution.state.breakpoints, error.execution.state.lifecycle
    )
    assert residue.operations == ()


def test_a_refresh_of_an_untracked_module_fails_closed() -> None:
    """A stale key must stop the run, not silently refresh a subset."""
    planned = put_workflow_breakpoint_intent(
        _state(), BreakpointIntent(id="oep", module_key="payload", rva=0x1234)
    )
    executed = execute_workflow_transition(planned, _RecordingPort(), timeout=5.0)
    transition = replace(
        request_workflow_module_refresh(executed.state),
        refresh_module_keys=frozenset({"payload", "ghost"}),
    )

    port = _RecordingPort()
    with pytest.raises(WorkflowExecutionError) as excinfo:
        execute_workflow_transition(transition, port, timeout=5.0)

    assert isinstance(excinfo.value.cause, ValueError)
    assert "untracked module" in str(excinfo.value.cause)
    assert all(name != "refresh_modules" for name, _ in port.calls)
