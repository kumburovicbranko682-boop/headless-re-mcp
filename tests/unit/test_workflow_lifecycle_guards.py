"""Invariants and event-matching arms of the module lifecycle state machine.

The engine- and executor-level suites drive lifecycle transitions through whole
event batches, which leaves the dataclass invariants, the track/untrack/refresh
guards, and several event-matching branches of consume_module_events unrun. All
of it is pure state logic -- no debugger, no PE -- so this pins each arm directly:

- TrackedModule / ModuleLifecycleState reject blank keys, non-positive bases and
  sizes, malformed SHA-256, negative counters, and duplicate keys.
- track/untrack/refresh refuse blank or untracked keys and short-circuit an empty
  refresh instead of churning a new generation.
- consume_module_events invalidates on drops, module (un)loads, and process
  boundary events, and correctly *skips* modules that are already in the target
  state, ignores unmatched unload bases, and rejects an unload with no base.
- _loaded_event_might_match resolves the expected name from a base selector, a
  path selector, a name selector, and the runtime fallback.
"""

from __future__ import annotations

from dataclasses import replace

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

_SHA = "a" * 64


def _runtime(
    base: int = 0x7FF800000000,
    name: str = "payload.dll",
    path: str = r"C:\sample\payload.dll",
) -> RuntimeModule:
    return RuntimeModule(base=base, size=0x5000, name=name, path=path)


def _mapping(
    base: int = 0x7FF800000000,
    name: str = "payload.dll",
    path: str = r"C:\sample\payload.dll",
    sha: str = "c" * 64,
) -> RebasedModuleMapping:
    return RebasedModuleMapping(
        identity=ModuleIdentity(name=name, path=path, sha256=sha, architecture=Architecture.X64),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=_runtime(base, name, path),
        match_basis="name",
    )


def _module(
    key: str = "m",
    *,
    selector: ModuleSelector | None = None,
    status: ModuleBindingStatus = ModuleBindingStatus.VALID,
    base: int = 0x7FF800000000,
    revision: int = 1,
    name: str = "payload.dll",
    path: str = r"C:\sample\payload.dll",
) -> TrackedModule:
    return TrackedModule(
        key=key,
        selector=selector or ModuleSelector(name=name),
        preferred_base=0x180000000,
        image_size=0x5000,
        runtime=_runtime(base, name, path),
        sha256=_SHA,
        status=status,
        revision=revision,
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
    next_cursor = events[-1].sequence if events else cursor + dropped
    return DebugEventBatch(
        events=events,
        cursor=cursor,
        next_cursor=next_cursor,
        oldest_sequence=(1 if next_cursor else 0),
        latest_sequence=next_cursor,
        dropped=dropped,
        dropped_total=dropped,
        has_more=False,
        capacity=1024,
    )


# --------------------------------------------------------------------------- #
# TrackedModule and ModuleLifecycleState invariants                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("key", "   ", "key must not be blank"),
        ("preferred_base", 0, "preferred module base must be positive"),
        ("image_size", 0, "size must be positive"),
        ("sha256", "z" * 64, "SHA-256 must contain 64 hexadecimal"),
        ("sha256", "abc", "SHA-256 must contain 64 hexadecimal"),
        ("revision", -1, "revision must be non-negative"),
    ],
)
def test_tracked_module_rejects_bad_fields(field: str, value: object, message: str) -> None:
    with pytest.raises(WorkflowInvariantError, match=message):
        replace(_module(), **{field: value})


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"cursor": -1}, "cursor must be non-negative"),
        ({"generation": -1}, "generation must be non-negative"),
        ({"modules": (_module(key="dup"), _module(key="dup"))}, "keys must be unique"),
    ],
)
def test_lifecycle_state_rejects_bad_construction(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(WorkflowInvariantError, match=message):
        ModuleLifecycleState(**kwargs)


# --------------------------------------------------------------------------- #
# track / untrack guards                                                      #
# --------------------------------------------------------------------------- #
def test_track_module_refuses_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(ModuleLifecycleState(), "   ", ModuleSelector(name="a.dll"), _mapping())


def test_untrack_refuses_a_blank_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(ModuleLifecycleState(), "   ")


def test_untrack_refuses_an_unknown_key() -> None:
    state = track_module(ModuleLifecycleState(), "m", ModuleSelector(name="a.dll"), _mapping())
    with pytest.raises(WorkflowInvariantError, match="module is not tracked: ghost"):
        untrack_module(state, "ghost")


def test_untrack_drops_the_named_module() -> None:
    state = track_module(ModuleLifecycleState(), "m", ModuleSelector(name="a.dll"), _mapping())
    dropped = untrack_module(state, "m")
    assert dropped.get("m") is None
    assert dropped.generation == state.generation + 1


# --------------------------------------------------------------------------- #
# refresh_modules                                                             #
# --------------------------------------------------------------------------- #
def test_refresh_refuses_an_untracked_key() -> None:
    state = track_module(ModuleLifecycleState(), "m", ModuleSelector(name="a.dll"), _mapping())
    with pytest.raises(WorkflowInvariantError, match="cannot refresh untracked modules: ghost"):
        refresh_modules(state, {"ghost": None})


def test_refresh_with_nothing_to_do_returns_the_same_state() -> None:
    """An empty refresh of a clean, reliable stream must not churn a generation."""
    state = track_module(ModuleLifecycleState(), "m", ModuleSelector(name="a.dll"), _mapping())
    assert refresh_modules(state, {}) is state


def test_refresh_leaves_modules_outside_the_resolution_set_untouched() -> None:
    state = track_module(ModuleLifecycleState(), "m1", ModuleSelector(name="a.dll"), _mapping())
    state = track_module(state, "m2", ModuleSelector(name="b.dll"), _mapping(base=0x7FF900000000))
    before = state.get("m2")

    refreshed = refresh_modules(state, {"m1": _mapping(base=0x7FFA00000000)})

    assert refreshed.get("m2") == before  # carried over by the skip branch
    assert refreshed.get("m1") is not None
    assert refreshed.get("m1").runtime.base == 0x7FFA00000000


# --------------------------------------------------------------------------- #
# consume_module_events: drops, (un)loads, boundaries, and their skips        #
# --------------------------------------------------------------------------- #
def test_a_dropped_batch_staleness_skips_modules_already_stale() -> None:
    state = ModuleLifecycleState(
        modules=(
            _module(key="live"),
            _module(key="already", status=ModuleBindingStatus.STALE),
        ),
        stream_reliable=False,
    )
    result = consume_module_events(state, _batch(0, dropped=4))
    assert "live" in result.invalidated_keys
    assert "already" not in result.invalidated_keys
    assert result.state.get("already").status == ModuleBindingStatus.STALE
    assert result.state.stream_reliable is False


def test_an_unknown_event_kind_changes_nothing() -> None:
    state = ModuleLifecycleState(modules=(_module(),))
    result = consume_module_events(state, _batch(0, _event(1, "thread.created")))
    assert result.invalidated_keys == frozenset()
    assert result.unloaded_bases == frozenset()
    assert result.state.get("m").status == ModuleBindingStatus.VALID


def test_an_unload_of_an_unmatched_base_records_the_base_but_invalidates_nothing() -> None:
    state = ModuleLifecycleState(modules=(_module(base=0x1000),))
    result = consume_module_events(state, _batch(0, _event(1, "module.unloaded", {"base": 0x2000})))
    assert result.unloaded_bases == frozenset({0x2000})
    assert result.invalidated_keys == frozenset()
    assert result.state.get("m").status == ModuleBindingStatus.VALID


def test_an_unload_without_a_base_is_rejected() -> None:
    state = ModuleLifecycleState(modules=(_module(),))
    with pytest.raises(WorkflowInvariantError, match="does not contain a valid base"):
        consume_module_events(state, _batch(0, _event(1, "module.unloaded", {})))


def test_process_start_staleness_skips_modules_already_stale() -> None:
    state = ModuleLifecycleState(
        modules=(
            _module(key="live"),
            _module(key="already", status=ModuleBindingStatus.STALE),
        ),
        stream_reliable=False,
    )
    result = consume_module_events(state, _batch(0, _event(1, "debug.init")))
    assert result.invalidated_keys == frozenset({"live"})
    assert result.state.get("already").status == ModuleBindingStatus.STALE


def test_process_exit_marks_unloaded_and_skips_ones_already_unloaded() -> None:
    state = ModuleLifecycleState(
        modules=(
            _module(key="live", base=0x1000),
            _module(key="gone", base=0x2000, status=ModuleBindingStatus.UNLOADED),
        )
    )
    result = consume_module_events(state, _batch(0, _event(1, "process.exited")))
    assert result.unloaded_bases == frozenset({0x1000, 0x2000})
    assert "live" in result.invalidated_keys
    assert "gone" not in result.invalidated_keys
    assert result.state.get("gone").status == ModuleBindingStatus.UNLOADED


# --------------------------------------------------------------------------- #
# _loaded_event_might_match, through consume_module_events                     #
# --------------------------------------------------------------------------- #
def test_a_base_selector_matches_a_load_at_that_base() -> None:
    state = ModuleLifecycleState(
        modules=(_module(selector=ModuleSelector(base=0x1234), base=0x9999),)
    )
    matched = consume_module_events(state, _batch(0, _event(1, "module.loaded", {"base": 0x1234})))
    assert "m" in matched.invalidated_keys
    missed = consume_module_events(state, _batch(0, _event(1, "module.loaded", {"base": 0x5678})))
    assert missed.invalidated_keys == frozenset()


def test_a_load_with_no_name_falls_back_to_the_runtime_base() -> None:
    state = ModuleLifecycleState(modules=(_module(base=0xABC0),))
    result = consume_module_events(state, _batch(0, _event(1, "module.loaded", {"base": 0xABC0})))
    assert "m" in result.invalidated_keys


def test_a_name_selector_matches_a_load_of_that_name() -> None:
    state = ModuleLifecycleState(
        modules=(_module(selector=ModuleSelector(name="payload.dll"), base=0x9999),)
    )
    result = consume_module_events(
        state, _batch(0, _event(1, "module.loaded", {"base": 0x1, "name": "PAYLOAD.DLL"}))
    )
    assert "m" in result.invalidated_keys  # case-insensitive name match


def test_a_path_selector_matches_a_load_by_file_name() -> None:
    state = ModuleLifecycleState(
        modules=(_module(selector=ModuleSelector(path=r"C:\other\payload.dll")),)
    )
    result = consume_module_events(
        state, _batch(0, _event(1, "module.loaded", {"base": 0x1, "name": "payload.dll"}))
    )
    assert "m" in result.invalidated_keys


def test_a_selector_with_no_criteria_falls_back_to_the_runtime_name() -> None:
    empty_selector = ModuleSelector.model_construct(base=None, path=None, name=None)
    state = ModuleLifecycleState(modules=(_module(selector=empty_selector, name="payload.dll"),))
    result = consume_module_events(
        state, _batch(0, _event(1, "module.loaded", {"base": 0x1, "name": "payload.dll"}))
    )
    assert "m" in result.invalidated_keys
