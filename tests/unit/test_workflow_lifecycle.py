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


def _tracked_state(base: int = 0x7FF800000000) -> ModuleLifecycleState:
    return track_module(
        ModuleLifecycleState(),
        "payload",
        ModuleSelector(name="event_fixture.dll"),
        _mapping(base),
    )


def test_module_unload_invalidates_exact_runtime_binding() -> None:
    state = _tracked_state()

    transition = consume_module_events(
        state,
        _batch(
            0,
            _event(1, "module.unloaded", {"base": 0x7FF800000000}),
        ),
    )

    module = transition.state.get("payload")
    assert module is not None
    assert module.status == ModuleBindingStatus.UNLOADED
    assert transition.invalidated_keys == {"payload"}
    assert transition.unloaded_bases == {0x7FF800000000}
    assert transition.state.cursor == 1


def test_module_reload_requires_refresh_before_new_base_is_trusted() -> None:
    unloaded = consume_module_events(
        _tracked_state(),
        _batch(
            0,
            _event(1, "module.unloaded", {"base": 0x7FF800000000}),
        ),
    ).state

    observed = consume_module_events(
        unloaded,
        _batch(
            1,
            _event(
                2,
                "module.loaded",
                {
                    "base": 0x7FF900000000,
                    "size": 0x5000,
                    "name": "event_fixture.dll",
                },
            ),
        ),
    )

    pending = observed.state.get("payload")
    assert pending is not None
    assert pending.status == ModuleBindingStatus.STALE
    assert observed.refresh_required == {"payload"}

    refreshed = refresh_modules(
        observed.state,
        {"payload": _mapping(0x7FF900000000)},
    )
    current = refreshed.get("payload")
    assert current is not None
    assert current.status == ModuleBindingStatus.VALID
    assert current.runtime.base == 0x7FF900000000
    assert refreshed.stream_reliable is True


def test_unrelated_module_load_does_not_invalidate_explicit_selector() -> None:
    state = _tracked_state()

    transition = consume_module_events(
        state,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x70000000, "size": 0x1000, "name": "other.dll"},
            ),
        ),
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.refresh_required == frozenset()
    assert transition.state.get("payload") == state.get("payload")


def test_truncated_matching_module_name_is_invalidated_conservatively() -> None:
    state = _tracked_state()

    transition = consume_module_events(
        state,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {
                    "base": 0x7FF900000000,
                    "size": 0x5000,
                    "name": "event_fix",
                    "name_truncated": True,
                },
            ),
        ),
    )

    assert transition.invalidated_keys == {"payload"}
    assert transition.refresh_required == {"payload"}


def test_base_selector_module_is_invalidated_only_when_a_load_reuses_its_base() -> None:
    state = track_module(
        ModuleLifecycleState(),
        "pinned",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )

    # A base-keyed selector ignores the reported name entirely: a load elsewhere
    # leaves the binding valid even though the name matches exactly.
    untouched = consume_module_events(
        state,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x72000000, "size": 0x1000, "name": "helper.dll"},
            ),
        ),
    )
    assert untouched.invalidated_keys == frozenset()

    # A load that reuses the pinned base invalidates it regardless of the name.
    reloaded = consume_module_events(
        state,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x71000000, "size": 0x1000, "name": "totally-different.dll"},
            ),
        ),
    )
    assert reloaded.invalidated_keys == {"pinned"}
    assert reloaded.refresh_required == {"pinned"}


def test_nameless_load_falls_back_to_matching_the_runtime_base() -> None:
    state = _tracked_state()

    # Without a name, a load can only be tied back through its runtime base;
    # a different base leaves the binding valid.
    mismatch = consume_module_events(
        state,
        _batch(0, _event(1, "module.loaded", {"base": 0x1230000, "size": 0x1000})),
    )
    assert mismatch.invalidated_keys == frozenset()

    # A nameless load at the tracked runtime base still invalidates it.
    match = consume_module_events(
        state,
        _batch(
            0,
            _event(1, "module.loaded", {"base": 0x7FF800000000, "size": 0x1000}),
        ),
    )
    assert match.invalidated_keys == {"payload"}
    assert match.refresh_required == {"payload"}


def test_path_selector_matches_the_loaded_basename() -> None:
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
                {"base": 0x7FF900000000, "size": 0x5000, "name": "event_fixture.dll"},
            ),
        ),
    )

    assert transition.invalidated_keys == {"bypath"}
    assert transition.refresh_required == {"bypath"}


def test_module_unloaded_without_a_valid_base_is_rejected() -> None:
    with pytest.raises(WorkflowInvariantError, match="valid base"):
        consume_module_events(
            _tracked_state(),
            _batch(0, _event(1, "module.unloaded", {"base": -1})),
        )


def test_event_loss_marks_every_tracked_module_stale() -> None:
    state = track_module(
        _tracked_state(),
        "helper",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )

    transition = consume_module_events(state, _batch(0, dropped=4))

    assert transition.state.stream_reliable is False
    assert transition.invalidated_keys == {"payload", "helper"}
    assert transition.refresh_required == {"payload", "helper"}
    assert {
        module.status for module in transition.state.modules
    } == {ModuleBindingStatus.STALE}


def test_refresh_must_cover_all_stale_modules() -> None:
    stale = consume_module_events(_tracked_state(), _batch(0, dropped=2)).state

    with pytest.raises(WorkflowInvariantError, match="refresh is incomplete"):
        refresh_modules(stale, {})

    refreshed = refresh_modules(stale, {"payload": None})
    module = refreshed.get("payload")
    assert module is not None
    assert module.status == ModuleBindingStatus.UNLOADED
    assert refreshed.stream_reliable is True


def test_new_process_invalidates_and_stop_unloads_all_bindings() -> None:
    state = _tracked_state()
    initialized = consume_module_events(
        state,
        _batch(0, _event(1, "process.created", {"process_id": 7})),
    ).state
    module = initialized.get("payload")
    assert module is not None and module.status == ModuleBindingStatus.STALE

    stopped = consume_module_events(
        initialized,
        _batch(1, _event(2, "process.exited", {"exit_code": 0})),
    )
    module = stopped.state.get("payload")
    assert module is not None and module.status == ModuleBindingStatus.UNLOADED
    assert stopped.unloaded_bases == {0x7FF800000000}


def test_lifecycle_rejects_batch_from_another_cursor() -> None:
    with pytest.raises(WorkflowInvariantError, match="workflow cursor"):
        consume_module_events(_tracked_state(), _batch(7))


def _tracked_module(**overrides: object) -> TrackedModule:
    fields: dict[str, object] = {
        "key": "m",
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


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"key": "   "}, "key must not be blank"),
        ({"preferred_base": 0}, "preferred module base must be positive"),
        ({"image_size": 0}, "size must be positive"),
        ({"sha256": "a" * 63}, "64 hexadecimal"),
        ({"sha256": "z" * 64}, "64 hexadecimal"),
        ({"revision": -1}, "revision must be non-negative"),
    ],
)
def test_tracked_module_rejects_malformed_fields(
    overrides: dict[str, object], match: str
) -> None:
    with pytest.raises(WorkflowInvariantError, match=match):
        _tracked_module(**overrides)


def test_tracked_module_accepts_uppercase_hex_digest() -> None:
    # The digest check is case-insensitive, so an upper-case SHA-256 is valid.
    module = _tracked_module(sha256="A" * 64)
    assert module.sha256 == "A" * 64


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"cursor": -1}, "cursor must be non-negative"),
        ({"generation": -1}, "generation must be non-negative"),
    ],
)
def test_lifecycle_state_rejects_negative_counters(
    overrides: dict[str, object], match: str
) -> None:
    with pytest.raises(WorkflowInvariantError, match=match):
        ModuleLifecycleState(**overrides)  # type: ignore[arg-type]


def test_lifecycle_state_rejects_duplicate_module_keys() -> None:
    duplicate = (_tracked_module(key="dup"), _tracked_module(key="dup"))
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=duplicate)


def test_track_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(
            ModuleLifecycleState(),
            "   ",
            ModuleSelector(name="event_fixture.dll"),
            _mapping(0x7FF800000000),
        )


def test_untrack_module_rejects_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(_tracked_state(), "   ")


def test_untrack_module_rejects_an_unknown_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="not tracked: ghost"):
        untrack_module(_tracked_state(), "ghost")


def test_untrack_module_removes_only_the_named_binding() -> None:
    state = track_module(
        _tracked_state(),
        "helper",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )

    reduced = untrack_module(state, "  payload  ")

    assert reduced.get("payload") is None
    assert reduced.get("helper") is not None
    # Dropping a binding is a state change, so the generation must advance.
    assert reduced.generation == state.generation + 1


def test_refresh_rejects_resolutions_for_untracked_modules() -> None:
    with pytest.raises(WorkflowInvariantError, match="cannot refresh untracked modules: ghost"):
        refresh_modules(_tracked_state(), {"ghost": _mapping(0x7FF900000000)})


def test_refresh_with_nothing_pending_returns_the_same_state() -> None:
    state = _tracked_state()
    # A reliable stream with no stale bindings and no resolutions is a no-op:
    # the identical object comes back rather than a needlessly bumped generation.
    assert refresh_modules(state, {}) is state


def test_unloaded_event_for_an_unrelated_base_reports_it_without_invalidating() -> None:
    state = _tracked_state()

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "module.unloaded", {"base": 0x1230000})),
    )

    # The freed base is always disclosed, but no tracked binding sits there, so
    # nothing is invalidated and the binding keeps its identity.
    assert transition.unloaded_bases == {0x1230000}
    assert transition.invalidated_keys == frozenset()
    assert transition.state.get("payload") == state.get("payload")


def test_repeated_invalidation_signals_are_idempotent() -> None:
    # First loss marks the binding stale; a second loss finds it already stale
    # and must not re-list it as freshly invalidated, though a drop still bumps
    # the generation because the stream is known to have gaps.
    stale = consume_module_events(_tracked_state(), _batch(0, dropped=1)).state
    assert stale.get("payload").status == ModuleBindingStatus.STALE  # type: ignore[union-attr]

    again = consume_module_events(stale, _batch(stale.cursor, dropped=1))
    assert again.invalidated_keys == frozenset()
    assert again.state.generation == stale.generation + 1

    # A process (re)start on an already-stale binding likewise re-lists nothing.
    reinit = consume_module_events(
        again.state,
        _batch(again.state.cursor, _event(40, "process.created", {"process_id": 3})),
    )
    assert reinit.invalidated_keys == frozenset()
    again = reinit

    # A process exit unloads the (already stale) binding; exiting a second time
    # finds it already unloaded and invalidates nothing further.
    exited = consume_module_events(
        again.state,
        _batch(again.state.cursor, _event(50, "process.exited", {"exit_code": 0})),
    )
    assert exited.state.get("payload").status == ModuleBindingStatus.UNLOADED  # type: ignore[union-attr]

    exited_again = consume_module_events(
        exited.state,
        _batch(exited.state.cursor, _event(51, "process.exited", {"exit_code": 0})),
    )
    assert exited_again.invalidated_keys == frozenset()
    assert exited_again.state.get("payload").status == ModuleBindingStatus.UNLOADED  # type: ignore[union-attr]


def test_unmodelled_event_kind_leaves_every_binding_untouched() -> None:
    state = _tracked_state()

    transition = consume_module_events(
        state,
        _batch(0, _event(1, "thread.created", {"thread_id": 9})),
    )

    # A kind the lifecycle does not model must not invalidate or unload anything;
    # only the cursor advances.
    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == frozenset()
    assert transition.state.get("payload") == state.get("payload")
    assert transition.state.generation == state.generation
    assert transition.state.cursor == 1


def test_refresh_leaves_unresolved_bindings_untouched() -> None:
    state = track_module(
        _tracked_state(),
        "helper",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )

    refreshed = refresh_modules(state, {"payload": _mapping(0x7FF900000000)})

    # payload was resolved to a new runtime base; helper was not named in the
    # resolutions and must survive verbatim, keeping its earlier revision.
    assert refreshed.get("payload").runtime.base == 0x7FF900000000  # type: ignore[union-attr]
    assert refreshed.get("helper") == state.get("helper")
    assert refreshed.generation == state.generation + 1
    assert refreshed.stream_reliable is True