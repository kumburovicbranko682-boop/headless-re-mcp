"""Branch coverage for the module lifecycle state machine.

``test_workflow_lifecycle.py`` pins the happy paths (unload, reload-needs-refresh,
truncated-name match, event loss, process create/exit). This file fills the
guard and edge branches those leave untouched: the two dataclass
``__post_init__`` invariant sets, ``untrack_module`` (which the sibling file does
not even import), ``refresh_modules`` early-return / unknown-key / partial-keep
arcs, the base- and path-selector matching rules and the no-name fallback in
``_loaded_event_might_match``, the "already in the target status, skip" arms of
every event handler, and the malformed-event integer guard.

All matching behaviour is exercised through ``consume_module_events`` rather than
the private helper, so these stay behavioural rather than white-box.
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


def _runtime(
    base: int,
    *,
    name: str = "event_fixture.dll",
    path: str = r"C:\sample\fixtures\event_fixture.dll",
    size: int = 0x5000,
) -> RuntimeModule:
    return RuntimeModule(base=base, size=size, name=name, path=path)


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
        runtime=_runtime(base, name=name, path=path, size=image_size),
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


def _valid_tracked(**overrides: object) -> TrackedModule:
    fields: dict[str, object] = {
        "key": "payload",
        "selector": ModuleSelector(name="event_fixture.dll"),
        "preferred_base": 0x180000000,
        "image_size": 0x5000,
        "runtime": _runtime(0x7FF800000000),
        "sha256": "a" * 64,
        "status": ModuleBindingStatus.VALID,
        "revision": 1,
    }
    fields.update(overrides)
    return TrackedModule(**fields)  # type: ignore[arg-type]


def _tracked_state(base: int = 0x7FF800000000) -> ModuleLifecycleState:
    return track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="event_fixture.dll"),
        _mapping(base),
    )


def _module(state: ModuleLifecycleState, key: str) -> TrackedModule:
    module = state.get(key)
    assert module is not None
    return module


# --- TrackedModule invariants -------------------------------------------------


def test_tracked_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        _valid_tracked(key="   ")


def test_tracked_module_rejects_a_non_positive_preferred_base() -> None:
    with pytest.raises(WorkflowInvariantError, match="preferred module base must be positive"):
        _valid_tracked(preferred_base=0)


def test_tracked_module_rejects_a_non_positive_image_size() -> None:
    with pytest.raises(WorkflowInvariantError, match="size must be positive"):
        _valid_tracked(image_size=0)


def test_tracked_module_rejects_a_malformed_sha256() -> None:
    with pytest.raises(WorkflowInvariantError, match="64 hexadecimal"):
        _valid_tracked(sha256="z" * 64)
    with pytest.raises(WorkflowInvariantError, match="64 hexadecimal"):
        _valid_tracked(sha256="ab")


def test_tracked_module_rejects_a_negative_revision() -> None:
    with pytest.raises(WorkflowInvariantError, match="revision must be non-negative"):
        _valid_tracked(revision=-1)


# --- ModuleLifecycleState invariants -----------------------------------------


def test_state_rejects_a_negative_cursor() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        ModuleLifecycleState(cursor=-1)


def test_state_rejects_a_negative_generation() -> None:
    with pytest.raises(WorkflowInvariantError, match="generation must be non-negative"):
        ModuleLifecycleState(generation=-1)


def test_state_rejects_duplicate_module_keys() -> None:
    duplicate = _valid_tracked()
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=(duplicate, _valid_tracked(runtime=_runtime(0x72000000))))


# --- track / untrack guards ---------------------------------------------------


def test_track_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(
            ModuleLifecycleState(),
            "  ",
            ModuleSelector(name="event_fixture.dll"),
            _mapping(0x7FF800000000),
        )


def test_untrack_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(_tracked_state(), "   ")


def test_untrack_module_rejects_an_unknown_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="module is not tracked: ghost"):
        untrack_module(_tracked_state(), "ghost")


def test_untrack_module_removes_the_binding_and_bumps_generation() -> None:
    state = _tracked_state()
    after = untrack_module(state, "payload")
    assert after.get("payload") is None
    assert after.modules == ()
    assert after.generation == state.generation + 1


# --- refresh_modules arcs -----------------------------------------------------


def test_refresh_with_nothing_to_do_returns_the_same_state() -> None:
    state = _tracked_state()
    # No resolutions, no stale modules, stream already reliable -> identity return.
    assert refresh_modules(state, {}) is state


def test_refresh_rejects_untracked_keys() -> None:
    with pytest.raises(WorkflowInvariantError, match="cannot refresh untracked modules: ghost"):
        refresh_modules(_tracked_state(), {"ghost": None})


def test_refresh_keeps_modules_absent_from_the_resolution_map() -> None:
    with_helper = track_module(
        _tracked_state(),
        "helper",
        ModuleSelector(name="helper.dll"),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )
    # A module.loaded that matches only payload (by name) makes it stale while
    # helper stays valid, so the refresh map covers payload alone.
    observed = consume_module_events(
        with_helper,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x7FF900000000, "size": 0x5000, "name": "event_fixture.dll"},
            ),
        ),
    ).state
    assert _module(observed, "payload").status == ModuleBindingStatus.STALE
    helper_before = observed.get("helper")

    refreshed = refresh_modules(observed, {"payload": _mapping(0x7FF900000000)})

    # payload was resolved; helper was untouched because it was not in the map.
    assert _module(refreshed, "payload").status == ModuleBindingStatus.VALID
    assert _module(refreshed, "payload").runtime.base == 0x7FF900000000
    assert refreshed.get("helper") == helper_before
    assert refreshed.stream_reliable is True


# --- _loaded_event_might_match selectors --------------------------------------


def test_base_selector_matches_a_reload_at_the_same_base() -> None:
    state = track_module(
        ModuleLifecycleState(),
        "by_base",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )
    hit = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x71000000, "name": "anything.dll"})),
    )
    assert hit.invalidated_keys == {"by_base"}

    miss = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x99990000, "name": "helper.dll"})),
    )
    assert miss.invalidated_keys == frozenset()


def test_load_event_without_a_name_falls_back_to_runtime_base() -> None:
    state = _tracked_state(0x7FF800000000)
    # No name in the event: a name-selected module can only be correlated by the
    # runtime base it currently sits at.
    hit = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x7FF800000000})),
    )
    assert hit.invalidated_keys == {"payload"}

    miss = consume_module_events(
        _tracked_state(0x7FF800000000),
        _batch(0, _event(1, "module.loaded", {"base": 0x12340000})),
    )
    assert miss.invalidated_keys == frozenset()


def test_path_selector_matches_on_the_basename() -> None:
    state = track_module(
        ModuleLifecycleState(),
        "by_path",
        ModuleSelector(path=r"C:\other\place\event_fixture.dll"),
        _mapping(0x7FF800000000),
    )
    hit = consume_module_events(
        state,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x7FF900000000, "name": "event_fixture.dll"},
            ),
        ),
    )
    assert hit.invalidated_keys == {"by_path"}


# --- "already in target status" skip branches ---------------------------------


def test_a_second_drop_leaves_already_stale_modules_untouched() -> None:
    first = consume_module_events(_tracked_state(), _batch(0, dropped=2))
    assert _module(first.state, "payload").status == ModuleBindingStatus.STALE

    second = consume_module_events(first.state, _batch(2, dropped=2))
    assert _module(second.state, "payload").status == ModuleBindingStatus.STALE
    # Nothing changed status on the second drop, so nothing is re-invalidated.
    assert second.invalidated_keys == frozenset()


def test_process_created_skips_a_module_that_is_already_stale() -> None:
    stale = consume_module_events(_tracked_state(), _batch(0, dropped=2)).state
    after = consume_module_events(stale, _batch(2, _event(3, "debug.init", {})))
    assert _module(after.state, "payload").status == ModuleBindingStatus.STALE
    assert after.invalidated_keys == frozenset()


def test_unload_for_an_unowned_base_changes_nothing_but_reports_it() -> None:
    after = consume_module_events(
        _tracked_state(),
        _batch(0, _event(1, "module.unloaded", {"base": 0xDEAD0000})),
    )
    assert _module(after.state, "payload").status == ModuleBindingStatus.VALID
    assert after.invalidated_keys == frozenset()
    assert after.unloaded_bases == {0xDEAD0000}


def test_process_exit_records_an_already_unloaded_base_without_reinvalidating() -> None:
    unloaded = consume_module_events(
        _tracked_state(),
        _batch(0, _event(1, "module.unloaded", {"base": 0x7FF800000000})),
    ).state
    assert _module(unloaded, "payload").status == ModuleBindingStatus.UNLOADED

    stopped = consume_module_events(unloaded, _batch(1, _event(2, "process.exited", {})))
    assert _module(stopped.state, "payload").status == ModuleBindingStatus.UNLOADED
    assert stopped.unloaded_bases == {0x7FF800000000}
    assert stopped.invalidated_keys == frozenset()


def test_an_unrelated_event_kind_is_a_no_op() -> None:
    state = _tracked_state()
    after = consume_module_events(state, _batch(0, _event(1, "thread.created", {"tid": 9})))
    # A kind no handler recognises must not touch any binding, only advance the cursor.
    assert after.state.get("payload") == state.get("payload")
    assert after.invalidated_keys == frozenset()
    assert after.unloaded_bases == frozenset()
    assert after.state.generation == state.generation
    assert after.state.cursor == 1


# --- malformed event guard ----------------------------------------------------


def test_unload_event_with_a_non_integer_base_is_rejected() -> None:
    with pytest.raises(WorkflowInvariantError, match="valid base"):
        consume_module_events(
            _tracked_state(),
            _batch(0, _event(1, "module.unloaded", {"base": "not-an-int"})),
        )
