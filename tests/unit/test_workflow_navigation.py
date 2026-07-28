from __future__ import annotations

import pytest

from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.workflows.models import WorkflowInvariantError
from headless_re_mcp.workflows.navigation import (
    EventPattern,
    NavigationEffect,
    NavigationStatus,
    consume_navigation_events,
    start_navigation,
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
    next_cursor = events[-1].sequence if events else cursor + dropped
    latest = max(next_cursor, cursor)
    return DebugEventBatch(
        events=events,
        cursor=cursor,
        next_cursor=next_cursor,
        oldest_sequence=(1 if latest else 0),
        latest_sequence=latest,
        dropped=dropped,
        dropped_total=dropped,
        has_more=False,
        capacity=1024,
    )


def test_navigation_starts_with_declarative_resume_effect() -> None:
    transition = start_navigation(
        EventPattern.create("breakpoint.hit", {"address": 0x401000}),
        cursor=8,
        event_budget=16,
    )

    assert transition.effects == (NavigationEffect.RESUME,)
    assert transition.state.cursor == 8
    assert transition.state.status == NavigationStatus.WAITING


def test_navigation_matches_event_fields_and_requests_stable_pause() -> None:
    started = start_navigation(
        EventPattern.create("module.loaded", {"name": "payload.dll"})
    ).state

    transition = consume_navigation_events(
        started,
        _batch(
            0,
            _event(1, "debug.resumed"),
            _event(
                2,
                "module.loaded",
                {"base": 0x70000000, "size": 0x4000, "name": "payload.dll"},
            ),
        ),
    )

    assert transition.state.status == NavigationStatus.MATCHED
    assert transition.state.matched_event is not None
    assert transition.state.matched_event.sequence == 2
    assert transition.state.observed_events == 2
    assert transition.effects == (NavigationEffect.ENSURE_PAUSED,)


def test_navigation_ignores_same_kind_with_different_identity() -> None:
    started = start_navigation(
        EventPattern.create("module.loaded", {"name": "payload.dll"})
    ).state

    transition = consume_navigation_events(
        started,
        _batch(
            0,
            _event(
                1,
                "module.loaded",
                {"base": 0x70000000, "size": 0x1000, "name": "other.dll"},
            ),
        ),
    )

    assert transition.state.status == NavigationStatus.WAITING
    assert transition.state.cursor == 1
    assert transition.effects == ()


def test_navigation_resumes_after_non_matching_intermediate_pause() -> None:
    started = start_navigation(
        EventPattern.create("module.loaded", {"name": "payload.dll"})
    ).state

    transition = consume_navigation_events(
        started,
        _batch(
            0,
            _event(1, "debug.system_breakpoint"),
            _event(2, "debug.paused"),
        ),
    )

    assert transition.state.status == NavigationStatus.WAITING
    assert transition.state.cursor == 2
    assert transition.effects == (NavigationEffect.RESUME,)


def test_navigation_fails_closed_when_event_stream_reports_loss() -> None:
    started = start_navigation(EventPattern.create("breakpoint.hit")).state

    transition = consume_navigation_events(started, _batch(0, dropped=5))

    assert transition.state.status == NavigationStatus.EVENT_LOSS
    assert transition.state.matched_event is None
    assert transition.effects == (NavigationEffect.ENSURE_PAUSED,)


def test_navigation_reports_target_exit_before_match() -> None:
    started = start_navigation(EventPattern.create("breakpoint.hit")).state
    exited = _event(1, "process.exited", {"exit_code": 3})

    transition = consume_navigation_events(started, _batch(0, exited))

    assert transition.state.status == NavigationStatus.TARGET_STOPPED
    assert transition.state.terminal_event == exited
    assert transition.effects == ()


def test_navigation_can_explicitly_match_process_exit_without_pause() -> None:
    started = start_navigation(
        EventPattern.create("process.exited", {"exit_code": 0})
    ).state
    exited = _event(1, "process.exited", {"exit_code": 0})

    transition = consume_navigation_events(started, _batch(0, exited))

    assert transition.state.status == NavigationStatus.MATCHED
    assert transition.state.matched_event == exited
    assert transition.effects == ()


def test_navigation_budget_is_bounded_and_fails_closed() -> None:
    started = start_navigation(
        EventPattern.create("breakpoint.hit"),
        event_budget=2,
    ).state

    transition = consume_navigation_events(
        started,
        _batch(
            0,
            _event(1, "debug.resumed"),
            _event(2, "thread.created", {"thread_id": 9}),
            _event(3, "breakpoint.hit", {"address": 0x401000, "type": 0}),
        ),
    )

    assert transition.state.status == NavigationStatus.BUDGET_EXHAUSTED
    assert transition.state.observed_events == 2
    assert transition.state.matched_event is None
    assert transition.effects == (NavigationEffect.ENSURE_PAUSED,)


def test_event_pattern_uses_strict_scalar_types() -> None:
    pattern = EventPattern.create("exception", {"first_chance": True})
    wrong_type = _event(
        1,
        "exception",
        {"code": 1, "address": 0x401000, "first_chance": 1},
    )

    assert pattern.matches(wrong_type) is False


def test_navigation_rejects_wrong_cursor_and_terminal_reuse() -> None:
    started = start_navigation(EventPattern.create("debug.paused")).state
    with pytest.raises(WorkflowInvariantError, match="navigation cursor"):
        consume_navigation_events(started, _batch(3))

    matched = consume_navigation_events(
        started,
        _batch(0, _event(1, "debug.paused")),
    ).state
    with pytest.raises(WorkflowInvariantError, match="cannot consume"):
        consume_navigation_events(matched, _batch(1))