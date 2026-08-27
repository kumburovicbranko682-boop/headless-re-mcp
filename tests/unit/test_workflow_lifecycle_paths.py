"""Invariant guards and residual branch arcs of the module lifecycle.

The happy paths live in test_workflow_lifecycle.py; this file covers the
dataclass invariants, untrack_module, the refresh edge cases, the loaded-event
matching fallbacks, and the loops that skip already-stale or already-unloaded
bindings.
"""

from __future__ import annotations

from pathlib import Path
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
    _loaded_event_might_match,
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
) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(
            name=name,
            path=str(Path(path)),
            sha256="a" * 64,
            architecture=Architecture.X64,
        ),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=RuntimeModule(base=base, size=0x5000, name=name, path=path),
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


def _tracked_kwargs(**overrides: Any) -> dict[str, Any]:
    mapping = _mapping(0x7FF800000000)
    kwargs: dict[str, Any] = {
        "key": "payload",
        "selector": ModuleSelector(name="event_fixture.dll"),
        "preferred_base": mapping.preferred_base,
        "image_size": mapping.image_size,
        "runtime": mapping.runtime,
        "sha256": "a" * 64,
        "status": ModuleBindingStatus.VALID,
        "revision": 1,
    }
    kwargs.update(overrides)
    return kwargs


def _tracked_state(
    key: str = "payload",
    base: int = 0x7FF800000000,
    selector: ModuleSelector | None = None,
    state: ModuleLifecycleState | None = None,
    name: str = "event_fixture.dll",
) -> ModuleLifecycleState:
    return track_module(
        state or ModuleLifecycleState(),
        key,
        selector or ModuleSelector(name=name),
        _mapping(base, name=name),
    )


# --------------------------------------------------- TrackedModule invariants


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"key": "   "}, "must not be blank"),
        ({"preferred_base": 0}, "base must be positive"),
        ({"image_size": 0}, "size must be positive"),
        ({"sha256": "abc"}, "64 hexadecimal"),
        ({"sha256": "z" * 64}, "64 hexadecimal"),
        ({"revision": -1}, "must be non-negative"),
    ],
)
def test_tracked_module_rejects_invalid_fields(
    overrides: dict[str, Any], match: str
) -> None:
    with pytest.raises(WorkflowInvariantError, match=match):
        TrackedModule(**_tracked_kwargs(**overrides))


# --------------------------------------------- ModuleLifecycleState invariants


def test_lifecycle_state_rejects_a_negative_cursor() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        ModuleLifecycleState(cursor=-1)


def test_lifecycle_state_rejects_a_negative_generation() -> None:
    with pytest.raises(WorkflowInvariantError, match="generation must be non-negative"):
        ModuleLifecycleState(generation=-1)


def test_lifecycle_state_rejects_duplicate_module_keys() -> None:
    module = TrackedModule(**_tracked_kwargs())
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=(module, module))


# ------------------------------------------------- track / untrack guards


def test_track_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="must not be blank"):
        _tracked_state(key="   ")


def test_untrack_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="must not be blank"):
        untrack_module(_tracked_state(), "   ")


def test_untrack_module_rejects_an_unknown_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="not tracked: ghost"):
        untrack_module(_tracked_state(), "ghost")


def test_untrack_module_removes_the_binding_and_bumps_the_generation() -> None:
    state = _tracked_state()

    untracked = untrack_module(state, "payload")

    assert untracked.get("payload") is None
    assert untracked.modules == ()
    assert untracked.generation == state.generation + 1
    assert untracked.stream_reliable is True


def test_untracking_the_only_stale_binding_keeps_the_stream_unreliable() -> None:
    """stream_reliable records a past loss, not just the current bindings."""
    stale = consume_module_events(_tracked_state(), _batch(0, dropped=2)).state

    untracked = untrack_module(stale, "payload")

    assert untracked.modules == ()
    assert untracked.stream_reliable is False


# -------------------------------------------------------- refresh_modules


def test_refresh_rejects_untracked_module_keys() -> None:
    with pytest.raises(WorkflowInvariantError, match="untracked modules: ghost"):
        refresh_modules(_tracked_state(), {"ghost": None})


def test_a_noop_refresh_of_a_reliable_state_returns_it_unchanged() -> None:
    state = _tracked_state()

    assert refresh_modules(state, {}) is state


def test_refresh_keeps_bindings_that_were_not_resolved() -> None:
    state = _tracked_state(
        key="helper",
        base=0x71000000,
        name="helper.dll",
        state=_tracked_state(),
    )

    refreshed = refresh_modules(state, {"payload": _mapping(0x7FF900000000)})

    payload = refreshed.get("payload")
    assert payload is not None and payload.runtime.base == 0x7FF900000000
    helper_before = state.get("helper")
    helper_after = refreshed.get("helper")
    assert helper_before is not None and helper_after == helper_before


# ------------------------------------- consume_module_events residual arcs


def test_a_second_event_loss_does_not_reinvalidate_stale_modules() -> None:
    stale = consume_module_events(_tracked_state(), _batch(0, dropped=4)).state

    transition = consume_module_events(stale, _batch(stale.cursor, dropped=2))

    assert transition.invalidated_keys == frozenset()
    assert transition.state.stream_reliable is False


def test_an_unload_of_an_unrelated_base_invalidates_nothing() -> None:
    transition = consume_module_events(
        _tracked_state(),
        _batch(0, _event(1, "module.unloaded", {"base": 0x123000})),
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {0x123000}


def test_a_new_process_does_not_reinvalidate_stale_modules() -> None:
    stale = consume_module_events(_tracked_state(), _batch(0, dropped=2)).state

    transition = consume_module_events(
        stale,
        _batch(stale.cursor, _event(stale.cursor + 1, "process.created", {"process_id": 7})),
    )

    assert transition.invalidated_keys == frozenset()


def test_a_stop_does_not_reinvalidate_unloaded_modules() -> None:
    unloaded = consume_module_events(
        _tracked_state(),
        _batch(0, _event(1, "module.unloaded", {"base": 0x7FF800000000})),
    ).state

    transition = consume_module_events(
        unloaded,
        _batch(unloaded.cursor, _event(unloaded.cursor + 1, "process.exited", {"exit_code": 0})),
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {0x7FF800000000}


def test_an_unload_event_without_a_valid_base_is_rejected() -> None:
    with pytest.raises(WorkflowInvariantError, match="valid base"):
        consume_module_events(
            _tracked_state(),
            _batch(0, _event(1, "module.unloaded", {"base": "0x1000"})),
        )


# ------------------------------------------------ _loaded_event_might_match


def test_a_base_selector_matches_a_load_at_exactly_that_base() -> None:
    state = _tracked_state(selector=ModuleSelector(base=0x7FF800000000))

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x7FF800000000})),
    )

    assert transition.invalidated_keys == {"payload"}


def test_a_nameless_load_event_matches_on_the_runtime_base() -> None:
    state = _tracked_state()

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x7FF800000000})),
    )

    assert transition.invalidated_keys == {"payload"}


def test_a_path_selector_matches_on_its_basename() -> None:
    state = _tracked_state(
        selector=ModuleSelector(path=r"C:\sample\fixtures\event_fixture.dll"),
    )

    transition = consume_module_events(
        state,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x7FF900000000, "name": "EVENT_FIXTURE.DLL"},
            ),
        ),
    )

    assert transition.invalidated_keys == {"payload"}


def test_an_empty_selector_falls_back_to_the_runtime_name() -> None:
    """Defensive fallback: the model validator forbids an all-None selector,
    so the branch is reached with a construct that bypasses validation."""
    selector = ModuleSelector.model_construct(
        base=None, path=None, name=None, sha256=None
    )
    module = TrackedModule(**_tracked_kwargs(selector=selector))

    matched = _loaded_event_might_match(
        module,
        _event(1, "module.loaded", {"base": 0x7FF900000000, "name": "event_fixture.dll"}),
    )

    assert matched is True
    assert module.runtime.name == "event_fixture.dll"
