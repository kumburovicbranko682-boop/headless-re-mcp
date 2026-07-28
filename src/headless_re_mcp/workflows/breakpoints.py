from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum

from headless_re_mcp.core.events import DebugEvent
from headless_re_mcp.workflows.lifecycle import (
    ModuleBindingStatus,
    ModuleLifecycleState,
    TrackedModule,
)
from headless_re_mcp.workflows.models import WorkflowInvariantError


class BreakpointOperationKind(StrEnum):
    REMOVE = "remove"
    SET = "set"


@dataclass(frozen=True, slots=True)
class BreakpointIntent:
    id: str
    module_key: str
    rva: int
    enabled: bool = True
    one_shot: bool = False

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise WorkflowInvariantError("breakpoint intent id must not be blank")
        if not self.module_key.strip():
            raise WorkflowInvariantError("breakpoint module key must not be blank")
        if self.rva < 0:
            raise WorkflowInvariantError("breakpoint RVA must be non-negative")


@dataclass(frozen=True, slots=True)
class BreakpointBinding:
    intent_id: str
    address: int
    module_revision: int

    def __post_init__(self) -> None:
        if not self.intent_id.strip():
            raise WorkflowInvariantError("breakpoint binding intent id must not be blank")
        if self.address <= 0:
            raise WorkflowInvariantError("breakpoint binding address must be positive")
        if self.module_revision < 0:
            raise WorkflowInvariantError(
                "breakpoint binding module revision must be non-negative"
            )


@dataclass(frozen=True, slots=True)
class BreakpointState:
    intents: tuple[BreakpointIntent, ...] = ()
    bindings: tuple[BreakpointBinding, ...] = ()

    def __post_init__(self) -> None:
        intent_ids = tuple(intent.id for intent in self.intents)
        binding_ids = tuple(binding.intent_id for binding in self.bindings)
        binding_addresses = tuple(binding.address for binding in self.bindings)
        if len(intent_ids) != len(set(intent_ids)):
            raise WorkflowInvariantError("breakpoint intent ids must be unique")
        if len(binding_ids) != len(set(binding_ids)):
            raise WorkflowInvariantError("breakpoint bindings must be unique per intent")
        if not set(binding_ids) <= set(intent_ids):
            raise WorkflowInvariantError(
                "breakpoint bindings must reference defined intents"
            )
        if len(binding_addresses) != len(set(binding_addresses)):
            raise WorkflowInvariantError("breakpoint binding addresses must be unique")

    def intent(self, intent_id: str) -> BreakpointIntent | None:
        return next(
            (intent for intent in self.intents if intent.id == intent_id),
            None,
        )

    def binding(self, intent_id: str) -> BreakpointBinding | None:
        return next(
            (binding for binding in self.bindings if binding.intent_id == intent_id),
            None,
        )


@dataclass(frozen=True, slots=True)
class BreakpointOperation:
    kind: BreakpointOperationKind
    intent_id: str
    address: int
    module_revision: int


@dataclass(frozen=True, slots=True)
class BreakpointReconciliation:
    operations: tuple[BreakpointOperation, ...]
    deferred_intent_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class BreakpointHitTransition:
    state: BreakpointState
    hit_intent_ids: tuple[str, ...]


def put_breakpoint_intent(
    state: BreakpointState,
    intent: BreakpointIntent,
) -> BreakpointState:
    intents = {current.id: current for current in state.intents}
    intents[intent.id] = intent
    return replace(state, intents=_ordered_intents(intents.values()))


def disable_breakpoint_intent(
    state: BreakpointState,
    intent_id: str,
) -> BreakpointState:
    intent = state.intent(intent_id)
    if intent is None:
        raise WorkflowInvariantError(f"breakpoint intent is not defined: {intent_id}")
    return put_breakpoint_intent(state, replace(intent, enabled=False))


def remove_breakpoint_intent(
    state: BreakpointState,
    intent_id: str,
) -> BreakpointState:
    intent = state.intent(intent_id)
    if intent is None:
        raise WorkflowInvariantError(f"breakpoint intent is not defined: {intent_id}")
    if state.binding(intent_id) is not None:
        raise WorkflowInvariantError(
            "remove the breakpoint binding before deleting its intent"
        )
    return replace(
        state,
        intents=_ordered_intents(
            current for current in state.intents if current.id != intent_id
        ),
    )


def plan_breakpoint_reconciliation(
    state: BreakpointState,
    lifecycle: ModuleLifecycleState,
) -> BreakpointReconciliation:
    desired: dict[str, BreakpointBinding] = {}
    deferred: set[str] = set()
    addresses: dict[int, str] = {}

    for intent in state.intents:
        if not intent.enabled:
            continue
        module = lifecycle.get(intent.module_key)
        if module is None or module.status != ModuleBindingStatus.VALID:
            deferred.add(intent.id)
            continue
        address = _resolve_intent(intent, module)
        conflict = addresses.get(address)
        if conflict is not None:
            raise WorkflowInvariantError(
                f"breakpoint intents {conflict} and {intent.id} resolve to 0x{address:X}"
            )
        addresses[address] = intent.id
        desired[intent.id] = BreakpointBinding(
            intent_id=intent.id,
            address=address,
            module_revision=module.revision,
        )

    existing = {binding.intent_id: binding for binding in state.bindings}
    removals: list[BreakpointOperation] = []
    additions: list[BreakpointOperation] = []

    for intent_id, binding in existing.items():
        target = desired.get(intent_id)
        if target != binding:
            removals.append(_operation(BreakpointOperationKind.REMOVE, binding))

    for intent_id, binding in desired.items():
        if existing.get(intent_id) != binding:
            additions.append(_operation(BreakpointOperationKind.SET, binding))

    return BreakpointReconciliation(
        operations=tuple(
            sorted(removals, key=_operation_sort_key)
            + sorted(additions, key=_operation_sort_key)
        ),
        deferred_intent_ids=frozenset(deferred),
    )


def acknowledge_breakpoint_operation(
    state: BreakpointState,
    lifecycle: ModuleLifecycleState,
    operation: BreakpointOperation,
) -> BreakpointState:
    bindings = {binding.intent_id: binding for binding in state.bindings}

    if operation.kind == BreakpointOperationKind.REMOVE:
        current = bindings.get(operation.intent_id)
        if current is None:
            return state
        if (
            current.address != operation.address
            or current.module_revision != operation.module_revision
        ):
            raise WorkflowInvariantError(
                "cannot acknowledge a stale breakpoint removal operation"
            )
        del bindings[operation.intent_id]
        return replace(state, bindings=_ordered_bindings(bindings.values()))

    expected = _expected_binding(state, lifecycle, operation.intent_id)
    submitted = BreakpointBinding(
        intent_id=operation.intent_id,
        address=operation.address,
        module_revision=operation.module_revision,
    )
    if expected != submitted:
        raise WorkflowInvariantError("cannot acknowledge a stale breakpoint set operation")
    current = bindings.get(operation.intent_id)
    if current is not None and current != submitted:
        raise WorkflowInvariantError(
            "remove the previous breakpoint binding before acknowledging its replacement"
        )
    conflicting = next(
        (
            binding
            for binding in bindings.values()
            if binding.intent_id != submitted.intent_id
            and binding.address == submitted.address
        ),
        None,
    )
    if conflicting is not None:
        raise WorkflowInvariantError(
            f"breakpoint address 0x{submitted.address:X} is already bound"
        )
    bindings[submitted.intent_id] = submitted
    return replace(state, bindings=_ordered_bindings(bindings.values()))


def consume_breakpoint_hit(
    state: BreakpointState,
    event: DebugEvent,
) -> BreakpointHitTransition:
    if event.kind != "breakpoint.hit":
        return BreakpointHitTransition(state=state, hit_intent_ids=())
    address = event.data.get("address")
    if type(address) is not int or address <= 0:
        raise WorkflowInvariantError(
            "breakpoint.hit event does not contain a valid address"
        )

    hit_ids = tuple(
        sorted(
            binding.intent_id
            for binding in state.bindings
            if binding.address == address
        )
    )
    next_state = state
    for intent_id in hit_ids:
        intent = next_state.intent(intent_id)
        if intent is not None and intent.one_shot and intent.enabled:
            next_state = disable_breakpoint_intent(next_state, intent_id)
    return BreakpointHitTransition(state=next_state, hit_intent_ids=hit_ids)


def _expected_binding(
    state: BreakpointState,
    lifecycle: ModuleLifecycleState,
    intent_id: str,
) -> BreakpointBinding | None:
    intent = state.intent(intent_id)
    if intent is None or not intent.enabled:
        return None
    module = lifecycle.get(intent.module_key)
    if module is None or module.status != ModuleBindingStatus.VALID:
        return None
    return BreakpointBinding(
        intent_id=intent.id,
        address=_resolve_intent(intent, module),
        module_revision=module.revision,
    )


def _resolve_intent(intent: BreakpointIntent, module: TrackedModule) -> int:
    if intent.rva >= module.image_size:
        raise WorkflowInvariantError(
            f"breakpoint {intent.id} RVA 0x{intent.rva:X} is outside module {module.key}"
        )
    return module.runtime.base + intent.rva


def _operation(
    kind: BreakpointOperationKind,
    binding: BreakpointBinding,
) -> BreakpointOperation:
    return BreakpointOperation(
        kind=kind,
        intent_id=binding.intent_id,
        address=binding.address,
        module_revision=binding.module_revision,
    )


def _operation_sort_key(operation: BreakpointOperation) -> tuple[int, str]:
    return operation.address, operation.intent_id


def _ordered_intents(
    intents: Iterable[BreakpointIntent],
) -> tuple[BreakpointIntent, ...]:
    return tuple(sorted(intents, key=lambda intent: intent.id))


def _ordered_bindings(
    bindings: Iterable[BreakpointBinding],
) -> tuple[BreakpointBinding, ...]:
    return tuple(sorted(bindings, key=lambda binding: binding.intent_id))