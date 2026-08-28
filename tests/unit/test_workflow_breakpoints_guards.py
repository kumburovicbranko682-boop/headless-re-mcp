"""Guard-path coverage for workflow breakpoint intents, bindings, and hits.

Complements ``test_workflow_breakpoints.py`` (happy-path reconciliation) with
the fail-closed edges: dataclass invariants, undefined-intent operations,
stale/conflicting acknowledgements, and non-hit / malformed hit events.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.events import DebugEvent
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows.breakpoints import (
    BreakpointBinding,
    BreakpointIntent,
    BreakpointOperation,
    BreakpointOperationKind,
    BreakpointState,
    acknowledge_breakpoint_operation,
    consume_breakpoint_hit,
    disable_breakpoint_intent,
    plan_breakpoint_reconciliation,
    put_breakpoint_intent,
    remove_breakpoint_intent,
)
from headless_re_mcp.workflows.lifecycle import (
    ModuleLifecycleState,
    track_module,
)
from headless_re_mcp.workflows.models import WorkflowInvariantError

_BASE = 0x7FF800000000


def _mapping(base: int = _BASE) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name="payload.dll",
            path=r"C:\sample\fixtures\payload.dll",
            sha256="b" * 64,
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


def _lifecycle() -> ModuleLifecycleState:
    return track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="payload.dll"),
        _mapping(),
    )


def _state(*intents: BreakpointIntent) -> BreakpointState:
    state = BreakpointState()
    for intent in intents:
        state = put_breakpoint_intent(state, intent)
    return state


def _event(kind: str, data: dict[str, object]) -> DebugEvent:
    return DebugEvent(
        sequence=9,
        timestamp_unix_ms=1_700_000_000_009,
        source="x64dbg.plugin_callback",
        kind=kind,
        data=data,
    )


def test_intent_rejects_blank_id() -> None:
    with pytest.raises(WorkflowInvariantError, match="intent id"):
        BreakpointIntent(id="   ", module_key="payload", rva=0)


def test_intent_rejects_blank_module_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="module key"):
        BreakpointIntent(id="oep", module_key="   ", rva=0)


def test_intent_rejects_negative_rva() -> None:
    with pytest.raises(WorkflowInvariantError, match="non-negative"):
        BreakpointIntent(id="oep", module_key="payload", rva=-1)


@pytest.mark.parametrize("intent_id", [5, None, ["oep"]])
def test_intent_rejects_a_non_string_id(intent_id: object) -> None:
    """workflow.breakpoint.put binds id straight from model output.

    A non-string hit id.strip() with an AttributeError that the service filed
    as a logged internal_error incident, while the blank-id invariant right
    next to it already read as invalid_request.
    """
    with pytest.raises(WorkflowInvariantError, match="id must be a string"):
        BreakpointIntent(id=cast(Any, intent_id), module_key="payload", rva=0)


@pytest.mark.parametrize("module_key", [5, None, ["payload"]])
def test_intent_rejects_a_non_string_module_key(module_key: object) -> None:
    with pytest.raises(WorkflowInvariantError, match="key must be a string"):
        BreakpointIntent(id="oep", module_key=cast(Any, module_key), rva=0)


@pytest.mark.parametrize("rva", ["10", 1.5, None, True])
def test_intent_rejects_a_non_integer_rva(rva: object) -> None:
    """The type is the invariant, not just the sign.

    A str/None rva crashed the ``< 0`` compare with a TypeError filed as
    internal_error, a float slipped through as a fractional RVA, and rva=True
    was silently accepted as a breakpoint at RVA 1.
    """
    with pytest.raises(WorkflowInvariantError, match="RVA must be an integer"):
        BreakpointIntent(id="oep", module_key="payload", rva=cast(Any, rva))


def test_binding_rejects_blank_intent_id() -> None:
    with pytest.raises(WorkflowInvariantError, match="binding intent id"):
        BreakpointBinding(intent_id="   ", address=0x1000, module_revision=0)


def test_binding_rejects_non_positive_address() -> None:
    with pytest.raises(WorkflowInvariantError, match="address must be positive"):
        BreakpointBinding(intent_id="oep", address=0, module_revision=0)


def test_binding_rejects_negative_module_revision() -> None:
    with pytest.raises(WorkflowInvariantError, match="revision must be non-negative"):
        BreakpointBinding(intent_id="oep", address=0x1000, module_revision=-1)


def test_state_rejects_duplicate_intent_ids() -> None:
    intent = BreakpointIntent(id="oep", module_key="payload", rva=0x40)
    with pytest.raises(WorkflowInvariantError, match="intent ids must be unique"):
        BreakpointState(intents=(intent, intent))


def test_state_rejects_duplicate_bindings_per_intent() -> None:
    intent = BreakpointIntent(id="oep", module_key="payload", rva=0x40)
    first = BreakpointBinding(intent_id="oep", address=0x1000, module_revision=0)
    second = BreakpointBinding(intent_id="oep", address=0x2000, module_revision=1)
    with pytest.raises(WorkflowInvariantError, match="unique per intent"):
        BreakpointState(intents=(intent,), bindings=(first, second))


def test_state_rejects_binding_without_intent() -> None:
    orphan = BreakpointBinding(intent_id="ghost", address=0x1000, module_revision=0)
    with pytest.raises(WorkflowInvariantError, match="reference defined intents"):
        BreakpointState(bindings=(orphan,))


def test_state_rejects_duplicate_binding_addresses() -> None:
    first = BreakpointIntent(id="first", module_key="payload", rva=0x40)
    second = BreakpointIntent(id="second", module_key="payload", rva=0x80)
    bindings = (
        BreakpointBinding(intent_id="first", address=0x1000, module_revision=0),
        BreakpointBinding(intent_id="second", address=0x1000, module_revision=0),
    )
    with pytest.raises(WorkflowInvariantError, match="addresses must be unique"):
        BreakpointState(intents=(first, second), bindings=bindings)


def test_disable_unknown_intent_raises() -> None:
    with pytest.raises(WorkflowInvariantError, match="not defined"):
        disable_breakpoint_intent(BreakpointState(), "ghost")


def test_remove_unknown_intent_raises() -> None:
    with pytest.raises(WorkflowInvariantError, match="not defined"):
        remove_breakpoint_intent(BreakpointState(), "ghost")


def test_remove_intent_with_live_binding_raises() -> None:
    intent = BreakpointIntent(id="oep", module_key="payload", rva=0x40)
    binding = BreakpointBinding(intent_id="oep", address=0x1000, module_revision=0)
    state = BreakpointState(intents=(intent,), bindings=(binding,))
    with pytest.raises(WorkflowInvariantError, match="remove the breakpoint binding"):
        remove_breakpoint_intent(state, "oep")


def test_remove_unbound_intent_succeeds() -> None:
    state = _state(
        BreakpointIntent(id="keep", module_key="payload", rva=0x40),
        BreakpointIntent(id="drop", module_key="payload", rva=0x80),
    )
    trimmed = remove_breakpoint_intent(state, "drop")
    assert trimmed.intent("drop") is None
    assert trimmed.intent("keep") is not None


def test_acknowledge_remove_for_missing_binding_is_noop() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x40))
    operation = BreakpointOperation(
        kind=BreakpointOperationKind.REMOVE,
        intent_id="oep",
        address=_BASE + 0x40,
        module_revision=0,
    )
    assert acknowledge_breakpoint_operation(state, lifecycle, operation) is state


def test_acknowledge_set_for_unknown_intent_is_stale() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x40))
    operation = BreakpointOperation(
        kind=BreakpointOperationKind.SET,
        intent_id="ghost",
        address=_BASE + 0x40,
        module_revision=0,
    )
    with pytest.raises(WorkflowInvariantError, match="stale breakpoint set"):
        acknowledge_breakpoint_operation(state, lifecycle, operation)


def test_acknowledge_set_for_untracked_module_is_stale() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="untracked", rva=0x40))
    operation = BreakpointOperation(
        kind=BreakpointOperationKind.SET,
        intent_id="oep",
        address=0x1000,
        module_revision=0,
    )
    with pytest.raises(WorkflowInvariantError, match="stale breakpoint set"):
        acknowledge_breakpoint_operation(state, lifecycle, operation)


def test_acknowledge_set_rejects_address_already_bound() -> None:
    lifecycle = _lifecycle()
    module = lifecycle.get("payload")
    assert module is not None
    address = module.runtime.base + 0x40
    occupant = BreakpointBinding(
        intent_id="occupant",
        address=address,
        module_revision=module.revision,
    )
    state = BreakpointState(
        intents=(
            BreakpointIntent(id="newcomer", module_key="payload", rva=0x40),
            BreakpointIntent(id="occupant", module_key="payload", rva=0x80),
        ),
        bindings=(occupant,),
    )
    operation = BreakpointOperation(
        kind=BreakpointOperationKind.SET,
        intent_id="newcomer",
        address=address,
        module_revision=module.revision,
    )
    with pytest.raises(WorkflowInvariantError, match="already bound"):
        acknowledge_breakpoint_operation(state, lifecycle, operation)


def test_consume_non_hit_event_is_passthrough() -> None:
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x40))
    transition = consume_breakpoint_hit(state, _event("debug.paused", {}))
    assert transition.state is state
    assert transition.hit_intent_ids == ()


@pytest.mark.parametrize("address", ["0x1000", None, 0, -1, True])
def test_consume_hit_rejects_invalid_address(address: object) -> None:
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x40))
    event = _event("breakpoint.hit", {"address": address})
    with pytest.raises(WorkflowInvariantError, match="valid address"):
        consume_breakpoint_hit(state, event)


def test_consume_hit_leaves_persistent_intent_enabled() -> None:
    lifecycle = _lifecycle()
    state = _state(BreakpointIntent(id="oep", module_key="payload", rva=0x40))
    operation = plan_breakpoint_reconciliation(state, lifecycle).operations[0]
    state = acknowledge_breakpoint_operation(state, lifecycle, operation)

    transition = consume_breakpoint_hit(
        state, _event("breakpoint.hit", {"address": operation.address})
    )

    assert transition.hit_intent_ids == ("oep",)
    intent = transition.state.intent("oep")
    assert intent is not None and intent.enabled is True
    assert transition.state.binding("oep") is not None
