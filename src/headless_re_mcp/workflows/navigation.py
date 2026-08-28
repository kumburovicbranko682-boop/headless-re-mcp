from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.workflows.models import WorkflowInvariantError

EventScalar = str | int | bool

_CONTINUATION_PAUSE_EVENTS = frozenset(
    {
        "debug.paused",
        "debug.stepped",
        "debug.system_breakpoint",
    }
)


class NavigationStatus(StrEnum):
    WAITING = "waiting"
    MATCHED = "matched"
    TARGET_STOPPED = "target_stopped"
    EVENT_LOSS = "event_loss"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class NavigationEffect(StrEnum):
    RESUME = "resume"
    ENSURE_PAUSED = "ensure_paused"


@dataclass(frozen=True, slots=True)
class EventPattern:
    kind: str
    fields: tuple[tuple[str, EventScalar], ...] = ()

    def __post_init__(self) -> None:
        # kind and the field keys arrive straight from model output on the
        # agent transport (no pydantic coercion), and every caller maps
        # WorkflowInvariantError to invalid_request -- while the AttributeError
        # a non-string raised out of .strip() was filed as a logged
        # internal_error incident. Name the wrong type the way a blank kind is
        # already named.
        if not isinstance(self.kind, str):
            raise WorkflowInvariantError("navigation event kind must be a string")
        if not self.kind.strip():
            raise WorkflowInvariantError("navigation event kind must not be blank")
        keys = tuple(key for key, _ in self.fields)
        if any(not isinstance(key, str) for key in keys):
            raise WorkflowInvariantError("navigation event field keys must be strings")
        if any(not key.strip() for key in keys):
            raise WorkflowInvariantError("navigation event field must not be blank")
        if len(keys) != len(set(keys)):
            raise WorkflowInvariantError("navigation event fields must be unique")
        if any(
            not isinstance(value, (str, int, bool))
            for _, value in self.fields
        ):
            raise WorkflowInvariantError(
                "navigation event values must be strings, integers, or booleans"
            )

    @classmethod
    def create(
        cls,
        kind: str,
        fields: Mapping[str, EventScalar] | None = None,
    ) -> EventPattern:
        # A non-mapping fields (list, str, int) crashed (fields or {}).items()
        # with AttributeError, and non-string keys crashed sorted() with
        # TypeError when mixed with strings -- both before __post_init__ could
        # name the problem. Check the shape first so every wrong fields reads
        # as the same invalid_request a blank kind earns.
        if fields is not None and not isinstance(fields, Mapping):
            raise WorkflowInvariantError("navigation event fields must be a mapping")
        if fields and any(not isinstance(key, str) for key in fields):
            raise WorkflowInvariantError("navigation event field keys must be strings")
        return cls(
            kind=kind,
            fields=tuple(sorted((fields or {}).items())),
        )

    def matches(self, event: DebugEvent) -> bool:
        if event.kind != self.kind:
            return False
        return all(
            key in event.data
            and type(event.data[key]) is type(expected)
            and event.data[key] == expected
            for key, expected in self.fields
        )


@dataclass(frozen=True, slots=True)
class NavigationState:
    pattern: EventPattern
    cursor: int
    event_budget: int
    observed_events: int = 0
    status: NavigationStatus = NavigationStatus.WAITING
    matched_event: DebugEvent | None = None
    terminal_event: DebugEvent | None = None

    def __post_init__(self) -> None:
        if self.cursor < 0:
            raise WorkflowInvariantError("navigation cursor must be non-negative")
        if self.event_budget <= 0:
            raise WorkflowInvariantError("navigation event budget must be positive")
        if not 0 <= self.observed_events <= self.event_budget:
            raise WorkflowInvariantError(
                "navigation observed event count is outside its budget"
            )
        if self.status == NavigationStatus.MATCHED and self.matched_event is None:
            raise WorkflowInvariantError(
                "matched navigation state requires a matched event"
            )
        if self.status != NavigationStatus.MATCHED and self.matched_event is not None:
            raise WorkflowInvariantError(
                "only a matched navigation state may contain a matched event"
            )
        if (
            self.status == NavigationStatus.TARGET_STOPPED
            and self.terminal_event is None
        ):
            raise WorkflowInvariantError(
                "stopped navigation state requires a terminal event"
            )
        if self.status == NavigationStatus.MATCHED:
            if (
                self.terminal_event is not None
                and self.terminal_event != self.matched_event
            ):
                raise WorkflowInvariantError(
                    "matched navigation terminal event must be the matched event"
                )
        elif (
            self.status != NavigationStatus.TARGET_STOPPED
            and self.terminal_event is not None
        ):
            raise WorkflowInvariantError(
                "only matched or stopped navigation may contain a terminal event"
            )
        if (
            self.status == NavigationStatus.BUDGET_EXHAUSTED
            and self.observed_events != self.event_budget
        ):
            raise WorkflowInvariantError(
                "exhausted navigation must consume its complete event budget"
            )


@dataclass(frozen=True, slots=True)
class NavigationTransition:
    state: NavigationState
    effects: tuple[NavigationEffect, ...] = ()


def start_navigation(
    pattern: EventPattern,
    *,
    cursor: int = 0,
    event_budget: int = 1024,
) -> NavigationTransition:
    return NavigationTransition(
        state=NavigationState(
            pattern=pattern,
            cursor=cursor,
            event_budget=event_budget,
        ),
        effects=(NavigationEffect.RESUME,),
    )


def cancel_navigation(state: NavigationState) -> NavigationTransition:
    if state.status != NavigationStatus.WAITING:
        return NavigationTransition(state=state)
    return NavigationTransition(
        state=replace(state, status=NavigationStatus.CANCELLED),
        effects=(NavigationEffect.ENSURE_PAUSED,),
    )


def timeout_navigation(state: NavigationState) -> NavigationTransition:
    if state.status != NavigationStatus.WAITING:
        return NavigationTransition(state=state)
    return NavigationTransition(
        state=replace(state, status=NavigationStatus.TIMED_OUT),
        effects=(NavigationEffect.ENSURE_PAUSED,),
    )


def consume_navigation_events(
    state: NavigationState,
    batch: DebugEventBatch,
) -> NavigationTransition:
    if state.status != NavigationStatus.WAITING:
        raise WorkflowInvariantError(
            f"cannot consume events after navigation reached {state.status.value}"
        )
    if batch.cursor != state.cursor:
        raise WorkflowInvariantError(
            f"event batch cursor {batch.cursor} does not match navigation cursor {state.cursor}"
        )
    if batch.dropped:
        return NavigationTransition(
            state=replace(
                state,
                cursor=batch.next_cursor,
                status=NavigationStatus.EVENT_LOSS,
            ),
            effects=(NavigationEffect.ENSURE_PAUSED,),
        )

    observed = state.observed_events
    for event in batch.events:
        if observed == state.event_budget:
            return _budget_exhausted(state, batch.next_cursor, observed)
        observed += 1
        if state.pattern.matches(event):
            effects = (
                ()
                if event.kind in {"process.exited", "debug.stopped"}
                else (NavigationEffect.ENSURE_PAUSED,)
            )
            return NavigationTransition(
                state=replace(
                    state,
                    cursor=batch.next_cursor,
                    observed_events=observed,
                    status=NavigationStatus.MATCHED,
                    matched_event=event,
                    terminal_event=(
                        event
                        if event.kind in {"process.exited", "debug.stopped"}
                        else None
                    ),
                ),
                effects=effects,
            )
        if event.kind in {"process.exited", "debug.stopped"}:
            return NavigationTransition(
                state=replace(
                    state,
                    cursor=batch.next_cursor,
                    observed_events=observed,
                    status=NavigationStatus.TARGET_STOPPED,
                    terminal_event=event,
                )
            )

    if observed == state.event_budget:
        return _budget_exhausted(state, batch.next_cursor, observed)
    continuation_effects = (
        (NavigationEffect.RESUME,)
        if any(event.kind in _CONTINUATION_PAUSE_EVENTS for event in batch.events)
        else ()
    )
    return NavigationTransition(
        state=replace(
            state,
            cursor=batch.next_cursor,
            observed_events=observed,
        ),
        effects=continuation_effects,
    )


def _budget_exhausted(
    state: NavigationState,
    cursor: int,
    observed: int,
) -> NavigationTransition:
    return NavigationTransition(
        state=replace(
            state,
            cursor=cursor,
            observed_events=observed,
            status=NavigationStatus.BUDGET_EXHAUSTED,
        ),
        effects=(NavigationEffect.ENSURE_PAUSED,),
    )