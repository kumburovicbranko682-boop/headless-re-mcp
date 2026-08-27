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
    consume_module_events,
    refresh_modules,
    track_module,
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


def test_event_marked_stale_module_lowers_stream_reliable() -> None:
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
                    "name": "event_fixture.dll",
                },
            ),
        ),
    )

    module = transition.state.get("payload")
    assert module is not None
    assert module.status == ModuleBindingStatus.STALE
    # A STALE module means the recorded base is no longer trustworthy, so the
    # snapshot must not simultaneously claim stream_reliable -- that is exactly
    # how track_module/untrack_module/refresh_modules already report the flag.
    assert transition.state.stream_reliable is False

    # The same stale condition must not flip depending on which mutator ran last.
    after_track = track_module(
        transition.state,
        "helper",
        ModuleSelector(base=0x71000000),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )
    assert after_track.stream_reliable is False


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