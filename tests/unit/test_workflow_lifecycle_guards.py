"""Pin the invariant guards and skip arms of the module lifecycle machine.

``test_workflow_lifecycle.py`` drives the happy transitions. This module pins
the fail-closed edges around them: the constructor invariants that refuse a
corrupt tracked-module or lifecycle state outright, the blank/unknown-key
guards on track/untrack/refresh, the no-op refresh short-circuit, and the
idempotence skip arms in event consumption (a module already STALE or
UNLOADED must not be re-invalidated when the same class of event repeats).
Also pins the loaded-event matcher's selector fallbacks and the strict
integer check on unload bases, both of which decide whether a hostile or
malformed debugger event can silently detach a binding.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.core.addressing import (
    ModuleIdentity,
    RebasedModuleMapping,
    RuntimeModule,
)
from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.core.models import Architecture, ModuleSelector
from headless_re_mcp.workflows.lifecycle import (
    ModuleBindingStatus,
    ModuleLifecycleState,
    TrackedModule,
    consume_module_events,
    refresh_modules,
    track_module,
    untrack_module,
)
from headless_re_mcp.workflows.models import WorkflowInvariantError

_BASE = 0x7FF800000000


def _mapping(base: int = _BASE, *, name: str = "payload.dll") -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name=name,
            path=rf"C:\sample\{name}",
            sha256="a" * 64,
            architecture=Architecture.X64,
        ),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=RuntimeModule(base=base, size=0x5000, name=name, path=rf"C:\sample\{name}"),
        match_basis="name",
    )


def _event(sequence: int, kind: str, data: dict[str, object] | None = None) -> DebugEvent:
    return DebugEvent(
        sequence=sequence,
        timestamp_unix_ms=1_700_000_000_000 + sequence,
        source="x64dbg.plugin_callback",
        kind=kind,
        data=data or {},
    )


def _batch(cursor: int, *events: DebugEvent, dropped: int = 0) -> DebugEventBatch:
    latest = events[-1].sequence if events else cursor + dropped
    return DebugEventBatch(
        events=events,
        cursor=cursor,
        next_cursor=latest,
        oldest_sequence=(cursor + dropped + 1 if latest else 0),
        latest_sequence=latest,
        dropped=dropped,
        dropped_total=dropped,
        has_more=False,
        capacity=1024,
    )


def _tracked(key: str = "payload", selector: ModuleSelector | None = None) -> TrackedModule:
    return TrackedModule(
        key=key,
        selector=selector or ModuleSelector(name="payload.dll"),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=RuntimeModule(
            base=_BASE, size=0x5000, name="payload.dll", path=r"C:\sample\payload.dll"
        ),
        sha256="a" * 64,
        status=ModuleBindingStatus.VALID,
        revision=1,
    )


def _state(*, selector: ModuleSelector | None = None) -> ModuleLifecycleState:
    return track_module(
        ModuleLifecycleState(),
        "payload",
        selector or ModuleSelector(name="payload.dll"),
        _mapping(),
    )


@pytest.mark.parametrize(
    ("overrides", "complaint"),
    [
        ({"key": "   "}, "key must not be blank"),
        ({"preferred_base": 0}, "preferred module base must be positive"),
        ({"image_size": 0}, "module size must be positive"),
        ({"sha256": "a" * 63}, "64 hexadecimal"),
        ({"sha256": "z" * 64}, "64 hexadecimal"),
        ({"revision": -1}, "revision must be non-negative"),
    ],
)
def test_a_corrupt_tracked_module_is_refused_at_construction(
    overrides: dict[str, Any], complaint: str
) -> None:
    fields: dict[str, Any] = {
        "key": "payload",
        "selector": ModuleSelector(name="payload.dll"),
        "preferred_base": 0x180000000,
        "image_size": 0x5000,
        "runtime": RuntimeModule(
            base=_BASE, size=0x5000, name="payload.dll", path=r"C:\sample\payload.dll"
        ),
        "sha256": "a" * 64,
        "status": ModuleBindingStatus.VALID,
        "revision": 1,
    }
    fields.update(overrides)
    with pytest.raises(WorkflowInvariantError, match=complaint):
        TrackedModule(**fields)


def test_a_corrupt_lifecycle_state_is_refused_at_construction() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        ModuleLifecycleState(cursor=-1)
    with pytest.raises(WorkflowInvariantError, match="generation must be non-negative"):
        ModuleLifecycleState(generation=-1)
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=(_tracked(), _tracked()))


def test_track_and_untrack_refuse_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(ModuleLifecycleState(), "  ", ModuleSelector(name="x.dll"), _mapping())
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(_state(), "  ")


def test_untrack_refuses_an_unknown_key_and_removes_a_known_one() -> None:
    state = _state()
    with pytest.raises(WorkflowInvariantError, match="module is not tracked: ghost"):
        untrack_module(state, "ghost")

    after = untrack_module(state, "payload")
    assert after.get("payload") is None
    assert after.modules == ()
    assert after.generation == state.generation + 1
    assert after.stream_reliable is True


def test_refresh_refuses_keys_that_are_not_tracked() -> None:
    with pytest.raises(WorkflowInvariantError, match="cannot refresh untracked modules: ghost"):
        refresh_modules(_state(), {"ghost": _mapping()})


def test_refresh_with_nothing_to_do_returns_the_same_state() -> None:
    state = _state()
    assert refresh_modules(state, {}) is state


def test_refresh_leaves_modules_outside_the_resolution_untouched() -> None:
    state = track_module(
        _state(),
        "helper",
        ModuleSelector(name="helper.dll"),
        _mapping(0x71000000, name="helper.dll"),
    )
    before = state.get("helper")
    assert before is not None

    refreshed = refresh_modules(state, {"payload": _mapping(0x7FF900000000)})

    # The unresolved module rides along unchanged: same revision, same status.
    assert refreshed.get("helper") == before
    payload = refreshed.get("payload")
    assert payload is not None
    assert payload.runtime.base == 0x7FF900000000


def test_a_second_event_loss_does_not_reinvalidate_stale_modules() -> None:
    stale = consume_module_events(_state(), _batch(0, dropped=2)).state
    assert stale.refresh_required == {"payload"}

    again = consume_module_events(stale, _batch(stale.cursor, dropped=2))

    assert again.invalidated_keys == frozenset()
    assert again.state.stream_reliable is False


def test_an_unload_for_an_unknown_base_detaches_nothing() -> None:
    transition = consume_module_events(
        _state(),
        _batch(0, _event(1, "module.unloaded", {"base": 0x123456})),
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {0x123456}
    module = transition.state.get("payload")
    assert module is not None and module.status == ModuleBindingStatus.VALID


def test_process_creation_does_not_reinvalidate_an_already_stale_module() -> None:
    stale = consume_module_events(_state(), _batch(0, dropped=1)).state

    transition = consume_module_events(
        stale,
        _batch(stale.cursor, _event(stale.cursor + 1, "process.created", {"process_id": 7})),
    )

    assert transition.invalidated_keys == frozenset()


def test_process_exit_does_not_reinvalidate_an_already_unloaded_module() -> None:
    unloaded = consume_module_events(
        _state(),
        _batch(0, _event(1, "module.unloaded", {"base": _BASE})),
    ).state

    transition = consume_module_events(
        unloaded,
        _batch(unloaded.cursor, _event(unloaded.cursor + 1, "process.exited", {"exit_code": 0})),
    )

    # The base is still reported as gone, but the binding is not re-touched.
    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {_BASE}


@pytest.mark.parametrize(
    ("event_base", "expected_invalidated"),
    [(0x71000000, {"payload"}), (0x999, frozenset())],
)
def test_a_base_selector_matches_loaded_events_by_base_alone(
    event_base: int, expected_invalidated: frozenset[str]
) -> None:
    state = track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000),
    )

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": event_base, "name": "whatever.dll"})),
    )

    assert transition.invalidated_keys == frozenset(expected_invalidated)


@pytest.mark.parametrize(
    ("event_base", "expected_invalidated"),
    [(_BASE, {"payload"}), (0x999, frozenset())],
)
def test_a_nameless_loaded_event_falls_back_to_the_runtime_base(
    event_base: int, expected_invalidated: frozenset[str]
) -> None:
    transition = consume_module_events(
        _state(),
        _batch(0, _event(1, "module.loaded", {"base": event_base})),
    )

    assert transition.invalidated_keys == frozenset(expected_invalidated)


def test_a_path_selector_matches_loaded_events_by_basename() -> None:
    state = track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(path=r"C:\sample\payload.dll"),
        _mapping(),
    )

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x7FF900000000, "name": "PAYLOAD.DLL"})),
    )

    assert transition.invalidated_keys == {"payload"}


def test_an_empty_selector_falls_back_to_the_runtime_name() -> None:
    # A validated ModuleSelector always carries at least one field, so the
    # runtime-name fallback is a defensive arm. Pin it anyway: if a selector
    # ever arrives empty (deserialized state, future constructor), matching
    # must degrade to the runtime module name, not crash or match nothing.
    empty_selector = ModuleSelector.model_construct(base=None, path=None, name=None)
    state = track_module(ModuleLifecycleState(), "payload", empty_selector, _mapping())

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x7FF900000000, "name": "payload.dll"})),
    )

    assert transition.invalidated_keys == {"payload"}


@pytest.mark.parametrize("base", [None, -1, True, "4096"])
def test_an_unload_event_without_a_valid_base_is_refused(base: object) -> None:
    data: dict[str, object] = {} if base is None else {"base": base}
    with pytest.raises(WorkflowInvariantError, match="does not contain a valid base"):
        consume_module_events(_state(), _batch(0, _event(1, "module.unloaded", data)))
