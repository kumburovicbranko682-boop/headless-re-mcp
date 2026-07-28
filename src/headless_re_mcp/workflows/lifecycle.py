from __future__ import annotations

import ntpath
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from headless_re_mcp.core.addressing import RebasedModuleMapping, RuntimeModule
from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.core.models import ModuleSelector
from headless_re_mcp.workflows.models import WorkflowInvariantError


class ModuleBindingStatus(StrEnum):
    VALID = "valid"
    STALE = "stale"
    UNLOADED = "unloaded"


@dataclass(frozen=True, slots=True)
class TrackedModule:
    key: str
    selector: ModuleSelector
    preferred_base: int
    image_size: int
    runtime: RuntimeModule
    sha256: str
    status: ModuleBindingStatus
    revision: int

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise WorkflowInvariantError("tracked module key must not be blank")
        if self.preferred_base <= 0:
            raise WorkflowInvariantError("preferred module base must be positive")
        if self.image_size <= 0:
            raise WorkflowInvariantError("tracked module size must be positive")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in self.sha256
        ):
            raise WorkflowInvariantError(
                "tracked module SHA-256 must contain 64 hexadecimal characters"
            )
        if self.revision < 0:
            raise WorkflowInvariantError("tracked module revision must be non-negative")


@dataclass(frozen=True, slots=True)
class ModuleLifecycleState:
    modules: tuple[TrackedModule, ...] = ()
    cursor: int = 0
    generation: int = 0
    stream_reliable: bool = True

    def __post_init__(self) -> None:
        if self.cursor < 0:
            raise WorkflowInvariantError("module lifecycle cursor must be non-negative")
        if self.generation < 0:
            raise WorkflowInvariantError("module lifecycle generation must be non-negative")
        keys = tuple(module.key for module in self.modules)
        if len(keys) != len(set(keys)):
            raise WorkflowInvariantError("tracked module keys must be unique")

    def get(self, key: str) -> TrackedModule | None:
        return next((module for module in self.modules if module.key == key), None)

    @property
    def refresh_required(self) -> frozenset[str]:
        return frozenset(
            module.key
            for module in self.modules
            if module.status == ModuleBindingStatus.STALE
        )


@dataclass(frozen=True, slots=True)
class ModuleLifecycleTransition:
    state: ModuleLifecycleState
    invalidated_keys: frozenset[str] = frozenset()
    unloaded_bases: frozenset[int] = frozenset()
    refresh_required: frozenset[str] = frozenset()


def track_module(
    state: ModuleLifecycleState,
    key: str,
    selector: ModuleSelector,
    mapping: RebasedModuleMapping,
) -> ModuleLifecycleState:
    normalized_key = key.strip()
    if not normalized_key:
        raise WorkflowInvariantError("tracked module key must not be blank")
    generation = state.generation + 1
    tracked = _tracked_from_mapping(
        normalized_key,
        selector,
        mapping,
        revision=generation,
    )
    modules = {
        module.key: module
        for module in state.modules
        if module.key != normalized_key
    }
    modules[normalized_key] = tracked
    return replace(
        state,
        modules=_ordered_modules(modules.values()),
        generation=generation,
        stream_reliable=state.stream_reliable and not any(
            module.status == ModuleBindingStatus.STALE
            for module in modules.values()
        ),
    )


def untrack_module(
    state: ModuleLifecycleState,
    key: str,
) -> ModuleLifecycleState:
    normalized_key = key.strip()
    if not normalized_key:
        raise WorkflowInvariantError("tracked module key must not be blank")
    if state.get(normalized_key) is None:
        raise WorkflowInvariantError(f"module is not tracked: {normalized_key}")
    modules = tuple(
        module for module in state.modules if module.key != normalized_key
    )
    return replace(
        state,
        modules=modules,
        generation=state.generation + 1,
        stream_reliable=state.stream_reliable and not any(
            module.status == ModuleBindingStatus.STALE for module in modules
        ),
    )


def refresh_modules(
    state: ModuleLifecycleState,
    resolutions: Mapping[str, RebasedModuleMapping | None],
) -> ModuleLifecycleState:
    known_keys = {module.key for module in state.modules}
    unknown_keys = set(resolutions) - known_keys
    if unknown_keys:
        rendered = ", ".join(sorted(unknown_keys))
        raise WorkflowInvariantError(f"cannot refresh untracked modules: {rendered}")

    required = state.refresh_required
    missing = required - resolutions.keys()
    if missing:
        rendered = ", ".join(sorted(missing))
        raise WorkflowInvariantError(f"module refresh is incomplete: {rendered}")

    if not resolutions and not required and state.stream_reliable:
        return state

    generation = state.generation + 1
    refreshed: list[TrackedModule] = []
    for module in state.modules:
        if module.key not in resolutions:
            refreshed.append(module)
            continue
        mapping = resolutions[module.key]
        if mapping is None:
            refreshed.append(
                replace(
                    module,
                    status=ModuleBindingStatus.UNLOADED,
                    revision=generation,
                )
            )
            continue
        refreshed.append(
            _tracked_from_mapping(
                module.key,
                module.selector,
                mapping,
                revision=generation,
            )
        )

    has_stale = any(
        module.status == ModuleBindingStatus.STALE for module in refreshed
    )
    return replace(
        state,
        modules=_ordered_modules(refreshed),
        generation=generation,
        stream_reliable=not has_stale,
    )


def consume_module_events(
    state: ModuleLifecycleState,
    batch: DebugEventBatch,
) -> ModuleLifecycleTransition:
    if batch.cursor != state.cursor:
        raise WorkflowInvariantError(
            f"event batch cursor {batch.cursor} does not match workflow cursor {state.cursor}"
        )

    modules = {module.key: module for module in state.modules}
    invalidated: set[str] = set()
    unloaded_bases: set[int] = set()
    generation = state.generation
    stream_reliable = state.stream_reliable

    if batch.dropped:
        generation += 1
        stream_reliable = False
        for key, module in tuple(modules.items()):
            if module.status != ModuleBindingStatus.STALE:
                modules[key] = replace(
                    module,
                    status=ModuleBindingStatus.STALE,
                    revision=generation,
                )
                invalidated.add(key)

    for event in batch.events:
        changed, event_invalidated, event_unloaded = _consume_event(
            modules,
            event,
            generation=generation + 1,
        )
        if changed:
            generation += 1
        invalidated.update(event_invalidated)
        unloaded_bases.update(event_unloaded)

    next_state = ModuleLifecycleState(
        modules=_ordered_modules(modules.values()),
        cursor=batch.next_cursor,
        generation=generation,
        stream_reliable=stream_reliable,
    )
    return ModuleLifecycleTransition(
        state=next_state,
        invalidated_keys=frozenset(invalidated),
        unloaded_bases=frozenset(unloaded_bases),
        refresh_required=next_state.refresh_required,
    )


def _consume_event(
    modules: dict[str, TrackedModule],
    event: DebugEvent,
    *,
    generation: int,
) -> tuple[bool, set[str], set[int]]:
    invalidated: set[str] = set()
    unloaded_bases: set[int] = set()

    if event.kind == "module.loaded":
        for key, module in tuple(modules.items()):
            if (
                _loaded_event_might_match(module, event)
                and module.status != ModuleBindingStatus.STALE
            ):
                modules[key] = replace(
                    module,
                    status=ModuleBindingStatus.STALE,
                    revision=generation,
                )
                invalidated.add(key)
        return bool(invalidated), invalidated, unloaded_bases

    if event.kind == "module.unloaded":
        base = _event_integer(event, "base")
        unloaded_bases.add(base)
        for key, module in tuple(modules.items()):
            if (
                module.runtime.base == base
                and module.status != ModuleBindingStatus.UNLOADED
            ):
                modules[key] = replace(
                    module,
                    status=ModuleBindingStatus.UNLOADED,
                    revision=generation,
                )
                invalidated.add(key)
        return bool(invalidated), invalidated, unloaded_bases

    if event.kind in {"debug.init", "process.created"}:
        for key, module in tuple(modules.items()):
            if module.status != ModuleBindingStatus.STALE:
                modules[key] = replace(
                    module,
                    status=ModuleBindingStatus.STALE,
                    revision=generation,
                )
                invalidated.add(key)
        return bool(invalidated), invalidated, unloaded_bases

    if event.kind in {"debug.stopped", "process.exited"}:
        for key, module in tuple(modules.items()):
            unloaded_bases.add(module.runtime.base)
            if module.status != ModuleBindingStatus.UNLOADED:
                modules[key] = replace(
                    module,
                    status=ModuleBindingStatus.UNLOADED,
                    revision=generation,
                )
                invalidated.add(key)
        return bool(invalidated), invalidated, unloaded_bases

    return False, invalidated, unloaded_bases


def _loaded_event_might_match(module: TrackedModule, event: DebugEvent) -> bool:
    base = event.data.get("base")
    if module.selector.base is not None:
        return base == module.selector.base

    raw_name = event.data.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        return base == module.runtime.base
    loaded_name = raw_name.casefold()
    truncated = event.data.get("name_truncated") is True

    if module.selector.name is not None:
        expected_name = module.selector.name.casefold()
    elif module.selector.path is not None:
        expected_name = ntpath.basename(module.selector.path).casefold()
    else:
        expected_name = module.runtime.name.casefold()
    return (
        expected_name.startswith(loaded_name)
        if truncated
        else loaded_name == expected_name
    )


def _event_integer(event: DebugEvent, key: str) -> int:
    value = event.data.get(key)
    if type(value) is not int or value < 0:
        raise WorkflowInvariantError(
            f"event {event.kind} does not contain a valid {key}"
        )
    return value


def _tracked_from_mapping(
    key: str,
    selector: ModuleSelector,
    mapping: RebasedModuleMapping,
    *,
    revision: int,
) -> TrackedModule:
    return TrackedModule(
        key=key,
        selector=selector,
        preferred_base=mapping.preferred_base,
        image_size=mapping.image_size,
        runtime=mapping.runtime,
        sha256=mapping.identity.sha256,
        status=ModuleBindingStatus.VALID,
        revision=revision,
    )


def _ordered_modules(
    modules: Iterable[TrackedModule],
) -> tuple[TrackedModule, ...]:
    return tuple(sorted(modules, key=lambda module: module.key))