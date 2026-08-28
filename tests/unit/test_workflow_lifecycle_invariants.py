"""Invariant and edge-branch coverage for module lifecycle tracking.

The main lifecycle suite drives the happy transitions. These pin the guards that
keep a malformed tracked module, a duplicate key, an untracked refresh, or a
malformed debug event from silently corrupting the binding table, plus the
event-matching branches (base/path selectors, a nameless load) and the
skip-when-already-in-target-state loop arms.
"""

from __future__ import annotations

from pathlib import Path

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


def _mapping(
    base: int,
    *,
    name: str = "event_fixture.dll",
    path: str = r"C:\sample\fixtures\event_fixture.dll",
    preferred_base: int = 0x180000000,
    image_size: int = 0x5000,
) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name=name,
            path=str(Path(path)),
            sha256="a" * 64,
            architecture=Architecture.X64,
        ),
        preferred_base=preferred_base,
        image_size=image_size,
        runtime=RuntimeModule(base=base, size=image_size, name=name, path=path),
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


def _tracked_state(base: int = 0x7FF800000000) -> ModuleLifecycleState:
    return track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="event_fixture.dll"),
        _mapping(base),
    )


_RUNTIME = RuntimeModule(base=0x1000, size=0x1000, name="x.dll", path=r"C:\x.dll")


def _tracked(**overrides: object) -> TrackedModule:
    fields: dict[str, object] = {
        "key": "k",
        "selector": ModuleSelector(name="x.dll"),
        "preferred_base": 0x1000,
        "image_size": 0x1000,
        "runtime": _RUNTIME,
        "sha256": "a" * 64,
        "status": ModuleBindingStatus.VALID,
        "revision": 0,
    }
    fields.update(overrides)
    return TrackedModule(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"key": "   "}, "key must not be blank"),
        ({"preferred_base": 0}, "preferred module base must be positive"),
        ({"image_size": 0}, "tracked module size must be positive"),
        ({"sha256": "z" * 64}, "64 hexadecimal characters"),
        ({"sha256": "abc"}, "64 hexadecimal characters"),
        ({"revision": -1}, "revision must be non-negative"),
    ],
)
def test_tracked_module_rejects_malformed_fields(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(WorkflowInvariantError, match=message):
        _tracked(**overrides)


def test_lifecycle_state_rejects_negative_counters_and_duplicate_keys() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        ModuleLifecycleState(cursor=-1)
    with pytest.raises(WorkflowInvariantError, match="generation must be non-negative"):
        ModuleLifecycleState(generation=-1)
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=(_tracked(key="dup"), _tracked(key="dup")))


def test_track_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(
            ModuleLifecycleState(),
            "   ",
            ModuleSelector(name="event_fixture.dll"),
            _mapping(0x7FF800000000),
        )


def test_untrack_module_removes_a_binding_and_guards_its_inputs() -> None:
    state = _tracked_state()
    dropped = untrack_module(state, "payload")
    assert dropped.get("payload") is None
    assert dropped.generation == state.generation + 1

    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(state, "  ")
    with pytest.raises(WorkflowInvariantError, match="is not tracked"):
        untrack_module(state, "absent")


def test_refresh_rejects_resolutions_for_untracked_modules() -> None:
    with pytest.raises(WorkflowInvariantError, match="cannot refresh untracked modules"):
        refresh_modules(_tracked_state(), {"stranger": _mapping(0x7FF900000000)})


def test_refresh_is_a_noop_when_nothing_is_stale() -> None:
    state = _tracked_state()
    # No resolutions, nothing stale, stream reliable -> the same object comes back.
    assert refresh_modules(state, {}) is state


def test_refresh_leaves_modules_absent_from_the_resolution_map_untouched() -> None:
    state = track_module(
        _tracked_state(),
        "helper",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )
    before = state.get("helper")
    refreshed = refresh_modules(state, {"payload": _mapping(0x7FF900000000)})
    # "helper" was not in the map, so it is carried over unchanged.
    assert refreshed.get("helper") == before
    payload = refreshed.get("payload")
    assert payload is not None and payload.runtime.base == 0x7FF900000000


def test_loaded_event_matches_a_base_selector() -> None:
    state = track_module(
        ModuleLifecycleState(),
        "hlp",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )
    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x71000000, "size": 0x1000})),
    )
    assert transition.invalidated_keys == {"hlp"}


def test_loaded_event_without_a_name_falls_back_to_the_runtime_base() -> None:
    state = _tracked_state(base=0x7FF800000000)
    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x7FF800000000, "size": 0x5000})),
    )
    assert transition.invalidated_keys == {"payload"}


def test_loaded_event_matches_a_path_selector_by_basename() -> None:
    state = track_module(
        ModuleLifecycleState(),
        "bypath",
        ModuleSelector(path=r"C:\sample\fixtures\event_fixture.dll"),
        _mapping(0x7FF800000000),
    )
    transition = consume_module_events(
        state,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x999, "size": 0x5000, "name": "event_fixture.dll"},
            ),
        ),
    )
    assert transition.invalidated_keys == {"bypath"}


def test_unload_event_without_a_base_is_rejected() -> None:
    with pytest.raises(WorkflowInvariantError, match="valid base"):
        consume_module_events(_tracked_state(), _batch(0, _event(1, "module.unloaded", {})))


def test_a_second_drop_skips_a_module_that_is_already_stale() -> None:
    first = consume_module_events(_tracked_state(), _batch(0, dropped=2)).state
    assert first.get("payload").status == ModuleBindingStatus.STALE  # type: ignore[union-attr]
    second = consume_module_events(first, _batch(first.cursor, dropped=2))
    # The module was already stale, so this drop invalidates nothing new.
    assert second.invalidated_keys == frozenset()
    assert second.state.get("payload").status == ModuleBindingStatus.STALE  # type: ignore[union-attr]


def test_unload_with_an_unmatched_base_touches_no_binding() -> None:
    transition = consume_module_events(
        _tracked_state(),
        _batch(0, _event(1, "module.unloaded", {"base": 0xDEAD0000})),
    )
    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {0xDEAD0000}
    assert transition.state.get("payload").status == ModuleBindingStatus.VALID  # type: ignore[union-attr]


def test_repeated_process_created_skips_an_already_stale_module() -> None:
    transition = consume_module_events(
        _tracked_state(),
        _batch(0, _event(1, "process.created", {}), _event(2, "process.created", {})),
    )
    assert transition.state.get("payload").status == ModuleBindingStatus.STALE  # type: ignore[union-attr]


def test_an_unrecognized_event_kind_changes_nothing() -> None:
    state = _tracked_state()
    transition = consume_module_events(
        state,
        _batch(0, _event(1, "thread.created", {"thread_id": 3})),
    )
    assert transition.invalidated_keys == frozenset()
    assert transition.state.get("payload") == state.get("payload")


def test_repeated_process_exit_skips_an_already_unloaded_module() -> None:
    transition = consume_module_events(
        _tracked_state(),
        _batch(0, _event(1, "process.exited", {}), _event(2, "process.exited", {})),
    )
    module = transition.state.get("payload")
    assert module is not None and module.status == ModuleBindingStatus.UNLOADED
    assert transition.unloaded_bases == {0x7FF800000000}
