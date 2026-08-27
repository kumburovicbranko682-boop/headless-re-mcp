"""Invariant and lifecycle coverage for workflow event navigation.

These exercise the fail-closed edges of ``workflows/navigation``: the
``EventPattern`` and ``NavigationState`` construction invariants, the
cancel / timeout transitions (both the WAITING path and the no-op once a
terminal status is reached), and the post-loop budget-exhaustion branch when a
batch consumes exactly the remaining event budget without a match.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.workflows.models import WorkflowInvariantError
from headless_re_mcp.workflows.navigation import (
    EventPattern,
    NavigationEffect,
    NavigationState,
    NavigationStatus,
    cancel_navigation,
    consume_navigation_events,
    start_navigation,
    timeout_navigation,
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


_PATTERN = EventPattern.create("breakpoint.hit")


# --- EventPattern invariants ---------------------------------------------


def test_event_pattern_rejects_blank_kind() -> None:
    with pytest.raises(WorkflowInvariantError, match="event kind"):
        EventPattern(kind="   ")


def test_event_pattern_rejects_blank_field_key() -> None:
    with pytest.raises(WorkflowInvariantError, match="field must not be blank"):
        EventPattern(kind="breakpoint.hit", fields=(("  ", 1),))


def test_event_pattern_rejects_duplicate_field_keys() -> None:
    with pytest.raises(WorkflowInvariantError, match="fields must be unique"):
        EventPattern(kind="breakpoint.hit", fields=(("addr", 1), ("addr", 2)))


def test_event_pattern_rejects_non_scalar_value() -> None:
    bad_value: Any = 1.5
    with pytest.raises(WorkflowInvariantError, match="strings, integers, or booleans"):
        EventPattern(kind="breakpoint.hit", fields=(("addr", bad_value),))


# --- NavigationState invariants ------------------------------------------


def test_state_rejects_negative_cursor() -> None:
    with pytest.raises(WorkflowInvariantError, match="cursor must be non-negative"):
        NavigationState(pattern=_PATTERN, cursor=-1, event_budget=8)


def test_state_rejects_non_positive_budget() -> None:
    with pytest.raises(WorkflowInvariantError, match="budget must be positive"):
        NavigationState(pattern=_PATTERN, cursor=0, event_budget=0)


def test_state_rejects_observed_outside_budget() -> None:
    with pytest.raises(WorkflowInvariantError, match="outside its budget"):
        NavigationState(
            pattern=_PATTERN, cursor=0, event_budget=8, observed_events=9
        )


def test_state_matched_requires_matched_event() -> None:
    with pytest.raises(WorkflowInvariantError, match="requires a matched event"):
        NavigationState(
            pattern=_PATTERN,
            cursor=0,
            event_budget=8,
            status=NavigationStatus.MATCHED,
        )


def test_state_matched_event_only_when_matched() -> None:
    with pytest.raises(WorkflowInvariantError, match="only a matched navigation"):
        NavigationState(
            pattern=_PATTERN,
            cursor=0,
            event_budget=8,
            status=NavigationStatus.WAITING,
            matched_event=_event(1, "breakpoint.hit"),
        )


def test_state_target_stopped_requires_terminal_event() -> None:
    with pytest.raises(WorkflowInvariantError, match="requires a terminal event"):
        NavigationState(
            pattern=_PATTERN,
            cursor=0,
            event_budget=8,
            status=NavigationStatus.TARGET_STOPPED,
        )


def test_state_matched_terminal_must_equal_matched_event() -> None:
    with pytest.raises(WorkflowInvariantError, match="terminal event must be the matched"):
        NavigationState(
            pattern=_PATTERN,
            cursor=0,
            event_budget=8,
            status=NavigationStatus.MATCHED,
            matched_event=_event(1, "breakpoint.hit"),
            terminal_event=_event(2, "process.exited"),
        )


def test_state_terminal_event_only_when_matched_or_stopped() -> None:
    with pytest.raises(WorkflowInvariantError, match="only matched or stopped"):
        NavigationState(
            pattern=_PATTERN,
            cursor=0,
            event_budget=8,
            status=NavigationStatus.EVENT_LOSS,
            terminal_event=_event(1, "process.exited"),
        )


def test_state_exhausted_must_consume_full_budget() -> None:
    with pytest.raises(WorkflowInvariantError, match="complete event budget"):
        NavigationState(
            pattern=_PATTERN,
            cursor=0,
            event_budget=8,
            observed_events=3,
            status=NavigationStatus.BUDGET_EXHAUSTED,
        )


# --- cancel_navigation / timeout_navigation ------------------------------


def test_cancel_waiting_requests_stable_pause() -> None:
    waiting = start_navigation(_PATTERN).state
    transition = cancel_navigation(waiting)
    assert transition.state.status == NavigationStatus.CANCELLED
    assert transition.effects == (NavigationEffect.ENSURE_PAUSED,)


def test_cancel_is_noop_once_terminal() -> None:
    stopped = NavigationState(
        pattern=_PATTERN,
        cursor=1,
        event_budget=8,
        observed_events=1,
        status=NavigationStatus.TARGET_STOPPED,
        terminal_event=_event(1, "process.exited"),
    )
    transition = cancel_navigation(stopped)
    assert transition.state is stopped
    assert transition.effects == ()


def test_timeout_waiting_requests_stable_pause() -> None:
    waiting = start_navigation(_PATTERN).state
    transition = timeout_navigation(waiting)
    assert transition.state.status == NavigationStatus.TIMED_OUT
    assert transition.effects == (NavigationEffect.ENSURE_PAUSED,)


def test_timeout_is_noop_once_terminal() -> None:
    stopped = NavigationState(
        pattern=_PATTERN,
        cursor=1,
        event_budget=8,
        observed_events=1,
        status=NavigationStatus.TARGET_STOPPED,
        terminal_event=_event(1, "process.exited"),
    )
    transition = timeout_navigation(stopped)
    assert transition.state is stopped
    assert transition.effects == ()


# --- post-loop budget exhaustion -----------------------------------------


def test_budget_exhausts_when_batch_consumes_the_whole_budget() -> None:
    started = start_navigation(_PATTERN, event_budget=2).state
    transition = consume_navigation_events(
        started,
        _batch(
            0,
            _event(1, "debug.resumed"),
            _event(2, "thread.created", {"thread_id": 9}),
        ),
    )
    assert transition.state.status == NavigationStatus.BUDGET_EXHAUSTED
    assert transition.state.observed_events == 2
    assert transition.state.matched_event is None
    assert transition.effects == (NavigationEffect.ENSURE_PAUSED,)
