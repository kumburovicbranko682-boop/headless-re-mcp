"""Invariant and matching-path coverage for the module lifecycle tracker.

``test_workflow_lifecycle.py`` covers the happy flows: unload/reload/refresh,
event loss, and cursor mismatch. This file covers what had no automated
verification: every dataclass invariant raise, the whole ``untrack_module``
function, the refresh guards (unknown keys, the reliable no-op, partial
refresh), the already-stale/already-unloaded skip branches of event
consumption, the selector-base / no-name / path-basename / runtime-name paths
of ``_loaded_event_might_match``, and the ``_event_integer`` type guard.
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
        runtime=RuntimeModule(
            base=base,
            size=image_size,
            name=name,
            path=path,
        ),
        match_basis="name",
    )


def _event(
    sequence: int,
    kind: str,
    data: dict[str, object] | None = None,
) -> DebugEvent:
    return DebugEvent(
        sequence=sequence,
        timestamp_unix_ms=1_700_000_000_000 + sequence,
        source="x64dbg.plugin_callback",
        kind=kind,
        data=data or {},
    )


def _batch(
    cursor: int,
    *events: DebugEvent,
    dropped: int = 0,
) -> DebugEventBatch:
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


def _tracked(
    key: str = "payload",
    selector: ModuleSelector | None = None,
    base: int = 0x7FF800000000,
    state: ModuleLifecycleState | None = None,
) -> ModuleLifecycleState:
    return track_module(
        state or ModuleLifecycleState(),
        key,
        selector or ModuleSelector(name="event_fixture.dll"),
        _mapping(base),
    )


def _valid_module(**overrides: object) -> TrackedModule:
    fields: dict[str, object] = {
        "key": "payload",
        "selector": ModuleSelector(name="event_fixture.dll"),
        "preferred_base": 0x180000000,
        "image_size": 0x5000,
        "runtime": RuntimeModule(
            base=0x7FF800000000,
            size=0x5000,
            name="event_fixture.dll",
            path=r"C:\sample\fixtures\event_fixture.dll",
        ),
        "sha256": "a" * 64,
        "status": ModuleBindingStatus.VALID,
        "revision": 1,
    }
    fields.update(overrides)
    return TrackedModule(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Dataclass invariants


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"key": "   "}, "key must not be blank"),
        ({"preferred_base": 0}, "base must be positive"),
        ({"image_size": 0}, "size must be positive"),
        ({"sha256": "abc"}, "64 hexadecimal characters"),
        ({"sha256": "z" * 64}, "64 hexadecimal characters"),
        ({"revision": -1}, "revision must be non-negative"),
    ],
)
def test_tracked_module_rejects_invalid_fields(
    overrides: dict[str, object], match: str
) -> None:
    with pytest.raises(WorkflowInvariantError, match=match):
        _valid_module(**overrides)


def test_lifecycle_state_rejects_negative_cursor_and_generation() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        ModuleLifecycleState(cursor=-1)
    with pytest.raises(WorkflowInvariantError, match="generation must be non-negative"):
        ModuleLifecycleState(generation=-1)


def test_lifecycle_state_rejects_duplicate_module_keys() -> None:
    module = _valid_module()
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=(module, module))


def test_track_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(
            ModuleLifecycleState(),
            "   ",
            ModuleSelector(name="event_fixture.dll"),
            _mapping(0x7FF800000000),
        )


# ---------------------------------------------------------------------------
# untrack_module


def test_untrack_module_removes_the_binding_and_bumps_the_generation() -> None:
    state = _tracked("helper", base=0x71000000, state=_tracked())

    remaining = untrack_module(state, "payload")

    assert remaining.get("payload") is None
    assert remaining.get("helper") is not None
    assert remaining.generation == state.generation + 1


def test_untrack_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(_tracked(), "   ")


def test_untrack_module_rejects_an_unknown_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="not tracked: ghost"):
        untrack_module(_tracked(), "ghost")


def test_untracking_the_stale_module_does_not_restore_stream_reliability() -> None:
    """Dropped events broke reliability; removing a binding cannot cure that."""
    stale = consume_module_events(_tracked(), _batch(0, dropped=3)).state
    assert stale.stream_reliable is False

    remaining = untrack_module(stale, "payload")

    assert remaining.modules == ()
    assert remaining.stream_reliable is False


# ---------------------------------------------------------------------------
# refresh_modules guards


def test_refresh_rejects_resolutions_for_untracked_modules() -> None:
    with pytest.raises(WorkflowInvariantError, match="untracked modules: ghost"):
        refresh_modules(_tracked(), {"ghost": _mapping(0x71000000)})


def test_refresh_with_nothing_to_do_returns_the_same_state() -> None:
    state = _tracked()
    assert refresh_modules(state, {}) is state


def test_partial_refresh_leaves_unlisted_modules_untouched() -> None:
    state = _tracked("helper", base=0x71000000, state=_tracked())
    before = state.get("helper")
    assert before is not None

    refreshed = refresh_modules(state, {"payload": _mapping(0x7FF900000000)})

    assert refreshed.get("helper") == before
    payload = refreshed.get("payload")
    assert payload is not None
    assert payload.runtime.base == 0x7FF900000000
    assert refreshed.generation == state.generation + 1


# ---------------------------------------------------------------------------
# Idempotent event consumption


def test_second_event_loss_does_not_reinvalidate_stale_modules() -> None:
    stale = consume_module_events(_tracked(), _batch(0, dropped=2)).state

    again = consume_module_events(stale, _batch(stale.cursor, dropped=2))

    assert again.invalidated_keys == frozenset()
    assert again.state.stream_reliable is False


def test_unload_event_for_an_already_unloaded_module_is_not_reinvalidated() -> None:
    base = 0x7FF800000000
    unloaded = consume_module_events(
        _tracked(), _batch(0, _event(1, "module.unloaded", {"base": base}))
    ).state

    again = consume_module_events(
        unloaded, _batch(1, _event(2, "module.unloaded", {"base": base}))
    )

    assert again.invalidated_keys == frozenset()
    assert again.unloaded_bases == {base}, "the base itself must still be reported"


def test_debug_init_does_not_reinvalidate_a_stale_module() -> None:
    stale = consume_module_events(_tracked(), _batch(0, dropped=1)).state

    again = consume_module_events(
        stale, _batch(stale.cursor, _event(stale.cursor + 1, "debug.init", {}))
    )

    assert again.invalidated_keys == frozenset()


def test_debug_stopped_still_reports_bases_of_already_unloaded_modules() -> None:
    base = 0x7FF800000000
    unloaded = consume_module_events(
        _tracked(), _batch(0, _event(1, "module.unloaded", {"base": base}))
    ).state

    stopped = consume_module_events(
        unloaded, _batch(1, _event(2, "debug.stopped", {}))
    )

    assert stopped.invalidated_keys == frozenset()
    assert stopped.unloaded_bases == {base}


# ---------------------------------------------------------------------------
# _loaded_event_might_match paths


def test_base_selector_matches_only_the_exact_base() -> None:
    base = 0x7FF800000000
    state = _tracked(selector=ModuleSelector(base=base))

    hit = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": base, "name": "other.dll"})),
    )
    assert hit.invalidated_keys == {"payload"}

    miss = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x71000000, "name": "x.dll"})),
    )
    assert miss.invalidated_keys == frozenset()


def test_nameless_load_event_falls_back_to_the_runtime_base() -> None:
    base = 0x7FF800000000
    state = _tracked()

    hit = consume_module_events(
        state, _batch(0, _event(1, "module.loaded", {"base": base}))
    )
    assert hit.invalidated_keys == {"payload"}

    miss = consume_module_events(
        state, _batch(0, _event(1, "module.loaded", {"base": 0x71000000, "name": "  "}))
    )
    assert miss.invalidated_keys == frozenset()


def test_path_selector_matches_on_the_path_basename() -> None:
    state = _tracked(
        selector=ModuleSelector(path=r"C:\sample\fixtures\Event_Fixture.DLL")
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
    assert hit.invalidated_keys == {"payload"}


def test_empty_selector_falls_back_to_the_runtime_module_name() -> None:
    # Pydantic validation requires base, path, or name, so an all-None selector
    # can only exist if a caller bypassed validation. The matcher still has a
    # defined answer for it (the runtime module name); pin that behavior.
    state = _tracked(selector=ModuleSelector.model_construct(base=None, path=None, name=None))

    hit = consume_module_events(
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
    assert hit.invalidated_keys == {"payload"}


def test_unknown_event_kinds_change_nothing() -> None:
    state = _tracked()

    transition = consume_module_events(
        state, _batch(0, _event(1, "breakpoint.hit", {"address": 0x401000}))
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == frozenset()
    assert transition.state.get("payload") == state.get("payload")


# ---------------------------------------------------------------------------
# _event_integer guard


@pytest.mark.parametrize("bad_base", ["0x70", True, -1, None])
def test_unload_event_without_a_valid_base_is_rejected(bad_base: object) -> None:
    with pytest.raises(WorkflowInvariantError, match="valid base"):
        consume_module_events(
            _tracked(),
            _batch(0, _event(1, "module.unloaded", {"base": bad_base})),
        )
