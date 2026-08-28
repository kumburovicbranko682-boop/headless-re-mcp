"""Invariant guards and matching fallbacks of the module lifecycle tracker.

test_workflow_lifecycle.py drives the tracker through its intended flows --
unload, reload, event loss, refresh -- with well-formed inputs, so the
dataclass invariants never fire, the refresh fast path and partial refresh
are never taken, the already-stale/already-unloaded loop skips never branch,
and the loaded-event matcher is only ever asked about a name selector. This
file pins the rest: what a corrupt TrackedModule or state is refused for,
which refresh calls are no-ops versus errors, that repeated invalidation is
idempotent (no revision churn on a module that is already stale or unloaded),
and how a loaded event is matched when the selector is a base, a path, or
nothing at all -- including the nameless-event fallback to the runtime base.
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


def _tracked(selector: ModuleSelector, base: int = _BASE) -> ModuleLifecycleState:
    return track_module(ModuleLifecycleState(), "payload", selector, _mapping(base))


def _module(**overrides: object) -> TrackedModule:
    fields: dict[str, object] = {
        "key": "payload",
        "selector": ModuleSelector(name="event_fixture.dll"),
        "preferred_base": 0x180000000,
        "image_size": 0x5000,
        "runtime": RuntimeModule(
            base=_BASE, size=0x5000, name="event_fixture.dll", path=r"C:\x\event_fixture.dll"
        ),
        "sha256": "a" * 64,
        "status": ModuleBindingStatus.VALID,
        "revision": 1,
    }
    fields.update(overrides)
    return TrackedModule(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# dataclass invariants: a corrupt module or state is refused at construction  #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"key": "   "}, "key must not be blank"),
        ({"preferred_base": 0}, "base must be positive"),
        ({"image_size": 0}, "size must be positive"),
        ({"sha256": "abc"}, "64 hexadecimal characters"),
        ({"sha256": "z" * 64}, "64 hexadecimal characters"),
        ({"revision": -1}, "revision must be non-negative"),
    ],
)
def test_a_corrupt_tracked_module_is_refused(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(WorkflowInvariantError, match=message):
        _module(**overrides)


def test_a_negative_cursor_or_generation_is_refused() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        ModuleLifecycleState(cursor=-1)
    with pytest.raises(WorkflowInvariantError, match="generation must be non-negative"):
        ModuleLifecycleState(generation=-1)


def test_duplicate_tracked_keys_are_refused() -> None:
    with pytest.raises(WorkflowInvariantError, match="keys must be unique"):
        ModuleLifecycleState(modules=(_module(), _module()))


# --------------------------------------------------------------------------- #
# track / untrack key guards                                                  #
# --------------------------------------------------------------------------- #
def test_tracking_a_blank_key_is_refused() -> None:
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        track_module(ModuleLifecycleState(), "  ", ModuleSelector(name="x.dll"), _mapping(_BASE))


def test_untracking_a_blank_or_unknown_key_is_refused() -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))
    with pytest.raises(WorkflowInvariantError, match="key must not be blank"):
        untrack_module(state, "  ")
    with pytest.raises(WorkflowInvariantError, match="not tracked: ghost"):
        untrack_module(state, "ghost")


# --------------------------------------------------------------------------- #
# refresh: unknown keys, the no-op fast path, and a partial refresh           #
# --------------------------------------------------------------------------- #
def test_refreshing_an_untracked_module_is_refused() -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))
    with pytest.raises(WorkflowInvariantError, match="untracked modules: ghost"):
        refresh_modules(state, {"ghost": _mapping(_BASE)})


def test_an_empty_refresh_of_a_healthy_state_is_a_noop(  # the fast path
) -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))
    assert refresh_modules(state, {}) is state, "nothing to do must not bump the generation"


def test_a_partial_refresh_leaves_the_other_modules_untouched() -> None:
    """Voluntarily re-resolving one healthy module must not churn the rest."""
    state = track_module(
        _tracked(ModuleSelector(name="event_fixture.dll")),
        "helper",
        ModuleSelector(name="helper.dll"),
        _mapping(0x71000000, name="helper.dll", path=r"C:\sample\fixtures\helper.dll"),
    )
    before = state.get("helper")
    assert before is not None

    refreshed = refresh_modules(state, {"payload": _mapping(0x7FF900000000)})

    moved = refreshed.get("payload")
    assert moved is not None
    assert moved.runtime.base == 0x7FF900000000
    assert moved.status == ModuleBindingStatus.VALID
    assert refreshed.get("helper") == before, "an unrefreshed module keeps its revision"


# --------------------------------------------------------------------------- #
# repeated invalidation is idempotent: no revision churn on stale/unloaded    #
# --------------------------------------------------------------------------- #
def test_a_second_event_loss_does_not_reinvalidate_stale_modules() -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))
    stale = consume_module_events(state, _batch(0, dropped=2)).state
    revision = stale.modules[0].revision

    again = consume_module_events(stale, _batch(2, dropped=3))

    assert again.invalidated_keys == frozenset(), "already-stale modules are not re-marked"
    assert again.state.modules[0].revision == revision
    assert again.state.stream_reliable is False


def test_a_process_start_does_not_reinvalidate_stale_modules() -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))
    stale = consume_module_events(state, _batch(0, dropped=2)).state

    transition = consume_module_events(
        stale, _batch(2, _event(3, "process.created", {"process_id": 7}))
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.state.get("payload") == stale.get("payload")


def test_a_process_exit_does_not_reunload_unloaded_modules() -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))
    unloaded = consume_module_events(
        state, _batch(0, _event(1, "module.unloaded", {"base": _BASE}))
    ).state
    revision = unloaded.modules[0].revision

    transition = consume_module_events(
        unloaded, _batch(1, _event(2, "process.exited", {"exit_code": 0}))
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {_BASE}, "the base is still reported for cache eviction"
    assert transition.state.modules[0].revision == revision


def test_an_unload_at_an_unknown_base_touches_no_binding() -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))

    transition = consume_module_events(
        state, _batch(0, _event(1, "module.unloaded", {"base": 0x1000}))
    )

    assert transition.invalidated_keys == frozenset()
    assert transition.unloaded_bases == {0x1000}
    assert transition.state.get("payload") == state.get("payload")


def test_an_unload_event_without_a_valid_base_is_refused() -> None:
    state = _tracked(ModuleSelector(name="event_fixture.dll"))
    with pytest.raises(WorkflowInvariantError, match="valid base"):
        consume_module_events(
            state, _batch(0, _event(1, "module.unloaded", {"base": "not-an-int"}))
        )


# --------------------------------------------------------------------------- #
# loaded-event matching: base selector, path selector, and the fallbacks      #
# --------------------------------------------------------------------------- #
def _loaded(sequence: int, data: dict[str, object]) -> DebugEventBatch:
    return _batch(sequence - 1, _event(sequence, "module.loaded", data))


def test_a_base_selector_matches_only_its_exact_base() -> None:
    state = _tracked(ModuleSelector(base=_BASE))

    missed = consume_module_events(
        state, _loaded(1, {"base": 0x1234, "size": 0x1000, "name": "event_fixture.dll"})
    )
    assert missed.invalidated_keys == frozenset(), "a name match must not override the base"

    hit = consume_module_events(
        missed.state, _loaded(2, {"base": _BASE, "size": 0x5000, "name": "renamed.dll"})
    )
    assert hit.invalidated_keys == {"payload"}


def test_a_nameless_load_falls_back_to_the_runtime_base() -> None:
    """The plugin can report a load whose name did not survive the ring buffer."""
    state = _tracked(ModuleSelector(name="event_fixture.dll"))

    elsewhere = consume_module_events(state, _loaded(1, {"base": 0x1234, "size": 0x1000}))
    assert elsewhere.invalidated_keys == frozenset()

    at_our_base = consume_module_events(
        elsewhere.state, _loaded(2, {"base": _BASE, "size": 0x5000, "name": "   "})
    )
    assert at_our_base.invalidated_keys == {"payload"}


def test_a_path_selector_matches_on_its_file_name() -> None:
    state = _tracked(ModuleSelector(path=r"C:\sample\fixtures\Event_Fixture.DLL"))

    transition = consume_module_events(
        state, _loaded(1, {"base": 0x7FF900000000, "size": 0x5000, "name": "event_fixture.dll"})
    )

    assert transition.invalidated_keys == {"payload"}
    assert transition.refresh_required == {"payload"}


def test_an_empty_selector_falls_back_to_the_runtime_name() -> None:
    """Validation demands one selector field, so this arm defends against an
    in-process caller that skipped it; model_construct is that caller."""
    state = _tracked(ModuleSelector.model_construct(base=None, path=None, name=None))

    unrelated = consume_module_events(
        state, _loaded(1, {"base": 0x1234, "size": 0x1000, "name": "other.dll"})
    )
    assert unrelated.invalidated_keys == frozenset()

    matching = consume_module_events(
        unrelated.state,
        _loaded(2, {"base": 0x7FF900000000, "size": 0x5000, "name": "EVENT_FIXTURE.dll"}),
    )
    assert matching.invalidated_keys == {"payload"}, "the runtime name is the last resort"
