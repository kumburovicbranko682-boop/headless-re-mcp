"""Invariant guards and matcher edge cases of the module lifecycle machine.

The behavioural flows (unload/reload/refresh/drop) live in
test_workflow_lifecycle.py; this file drives the fail-closed constructor
checks, the untrack/refresh guard clauses, the already-stale/already-unloaded
skip arms, and every reachable branch of the loaded-event name matcher.
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

_BASE = 0x7FF800000000


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


def _tracked(**overrides: object) -> TrackedModule:
    fields: dict[str, object] = {
        "key": "payload",
        "selector": ModuleSelector(name="event_fixture.dll"),
        "preferred_base": 0x180000000,
        "image_size": 0x5000,
        "runtime": RuntimeModule(
            base=_BASE,
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


def _state(selector: ModuleSelector | None = None) -> ModuleLifecycleState:
    return track_module(
        ModuleLifecycleState(),
        "payload",
        selector or ModuleSelector(name="event_fixture.dll"),
        _mapping(_BASE),
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"key": "   "}, "key must not be blank"),
        ({"preferred_base": 0}, "base must be positive"),
        ({"image_size": 0}, "size must be positive"),
        ({"sha256": "abc"}, "64 hexadecimal"),
        ({"sha256": "z" * 64}, "64 hexadecimal"),
        ({"revision": -1}, "revision must be non-negative"),
    ],
)
def test_tracked_module_rejects_invalid_fields(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(WorkflowInvariantError, match=message):
        _tracked(**overrides)


def test_lifecycle_state_rejects_invalid_shape() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        ModuleLifecycleState(cursor=-1)
    with pytest.raises(WorkflowInvariantError, match="generation must be non-negative"):
        ModuleLifecycleState(generation=-1)
    duplicate = _tracked()
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=(duplicate, duplicate))


def test_track_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(
            ModuleLifecycleState(),
            "   ",
            ModuleSelector(name="event_fixture.dll"),
            _mapping(_BASE),
        )


def test_untrack_module_guards_and_removal() -> None:
    state = track_module(
        _state(),
        "helper",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )

    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(state, "  ")
    with pytest.raises(WorkflowInvariantError, match="not tracked: ghost"):
        untrack_module(state, "ghost")

    trimmed = untrack_module(state, "helper")
    assert trimmed.get("helper") is None
    assert trimmed.get("payload") is not None
    assert trimmed.generation == state.generation + 1
    assert trimmed.stream_reliable is True


def test_refresh_rejects_resolutions_for_untracked_modules() -> None:
    with pytest.raises(WorkflowInvariantError, match="untracked modules: ghost"):
        refresh_modules(_state(), {"ghost": _mapping(_BASE)})


def test_refresh_with_nothing_to_do_returns_the_same_state() -> None:
    state = _state()
    assert refresh_modules(state, {}) is state


def test_refresh_leaves_unmentioned_modules_untouched() -> None:
    state = track_module(
        _state(),
        "helper",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )
    before = state.get("helper")
    assert before is not None

    refreshed = refresh_modules(state, {"payload": _mapping(0x7FF900000000)})

    moved = refreshed.get("payload")
    assert moved is not None
    assert moved.runtime.base == 0x7FF900000000
    assert moved.revision == refreshed.generation
    untouched = refreshed.get("helper")
    assert untouched is not None
    assert untouched.revision == before.revision
    assert untouched.runtime.base == before.runtime.base


def test_a_second_drop_does_not_reinvalidate_stale_modules() -> None:
    stale = consume_module_events(_state(), _batch(0, dropped=2)).state
    assert stale.refresh_required == {"payload"}

    again = consume_module_events(stale, _batch(2, dropped=3))

    assert again.invalidated_keys == frozenset()
    assert again.state.stream_reliable is False
    assert again.refresh_required == {"payload"}


def test_an_unrelated_unload_reports_its_base_without_invalidating() -> None:
    state = _state()

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.unloaded", {"base": 0x12340000})),
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {0x12340000}
    assert transition.state.get("payload") == state.get("payload")


def test_debug_init_skips_modules_that_are_already_stale() -> None:
    stale = consume_module_events(_state(), _batch(0, dropped=2)).state

    transition = consume_module_events(
        stale,
        _batch(2, _event(3, "debug.init", {})),
    )

    assert transition.invalidated_keys == frozenset()
    module = transition.state.get("payload")
    assert module is not None
    assert module.status == ModuleBindingStatus.STALE


def test_process_exit_skips_modules_that_are_already_unloaded() -> None:
    unloaded = consume_module_events(
        _state(),
        _batch(0, _event(1, "module.unloaded", {"base": _BASE})),
    ).state

    transition = consume_module_events(
        unloaded,
        _batch(1, _event(2, "process.exited", {"exit_code": 0})),
    )

    assert transition.invalidated_keys == frozenset()
    # The base is still reported so callers can retire cached disassembly.
    assert transition.unloaded_bases == {_BASE}


def test_base_selector_matches_loaded_events_by_base_only() -> None:
    state = track_module(
        ModuleLifecycleState(),
        "pinned",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )

    unrelated = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x9000000, "name": "helper.dll"})),
    )
    assert unrelated.invalidated_keys == frozenset()

    matched = consume_module_events(
        unrelated.state,
        _batch(1, _event(2, "module.loaded", {"base": 0x71000000})),
    )
    assert matched.invalidated_keys == {"pinned"}
    assert matched.refresh_required == {"pinned"}


def test_nameless_loaded_event_falls_back_to_the_runtime_base() -> None:
    matched = consume_module_events(
        _state(),
        _batch(0, _event(1, "module.loaded", {"base": _BASE})),
    )
    assert matched.invalidated_keys == {"payload"}

    blank_name = consume_module_events(
        _state(),
        _batch(0, _event(1, "module.loaded", {"base": 0x9000000, "name": "   "})),
    )
    assert blank_name.invalidated_keys == frozenset()


def test_path_selector_matches_loaded_events_by_basename() -> None:
    state = _state(ModuleSelector(path=r"C:\sample\fixtures\event_fixture.dll"))

    matched = consume_module_events(
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
    assert matched.invalidated_keys == {"payload"}

    other = consume_module_events(
        matched.state,
        _batch(1, _event(2, "module.loaded", {"base": 0x9000000, "name": "other.dll"})),
    )
    assert other.invalidated_keys == frozenset()


def test_unrelated_event_kinds_advance_the_cursor_without_changes() -> None:
    state = _state()

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "thread.created", {"thread_id": 7})),
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == frozenset()
    assert transition.state.cursor == 1
    assert transition.state.generation == state.generation
    assert transition.state.get("payload") == state.get("payload")


@pytest.mark.parametrize("base", ["0x1000", -1, None, True, 2.0])
def test_unload_events_must_carry_a_genuine_integer_base(base: object) -> None:
    with pytest.raises(WorkflowInvariantError, match="valid base"):
        consume_module_events(
            _state(),
            _batch(0, _event(1, "module.unloaded", {"base": base})),
        )
