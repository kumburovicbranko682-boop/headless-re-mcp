"""Guard-path coverage for the strict debug-event batch parser.

``test_events.py`` exercises the common rejections and the happy replay paths.
This file pins the individual invariant branches that the broad parametrized
tests happen not to reach: a non-object batch/event, a cursor ahead of latest, a
batch whose event count does not fill the requested window, and the per-field
type checks inside ``_parse_event_data`` (a bad integer, a non-string text
field, and the accepted-boolean path). Each payload is built to pass every
earlier check so it lands on exactly the guard under test.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.core.events import (
    DEBUG_EVENT_CAPACITY,
    MAX_DEBUG_EVENT_BATCH,
    DebugEventProtocolError,
    parse_debug_event_batch,
)

JsonObject = dict[str, Any]


def _event(
    sequence: int,
    kind: str = "debug.paused",
    data: JsonObject | None = None,
) -> JsonObject:
    return {
        "sequence": sequence,
        "timestamp_unix_ms": 1_700_000_000_000 + sequence,
        "source": "x64dbg.plugin_callback",
        "kind": kind,
        "data": data or {},
    }


def _batch(
    *,
    cursor: int = 0,
    latest: int = 2,
    events: list[JsonObject] | None = None,
    capacity: int = DEBUG_EVENT_CAPACITY,
) -> JsonObject:
    oldest = 0 if latest == 0 else max(1, latest - capacity + 1)
    dropped = max(0, oldest - cursor - 1) if oldest else 0
    if events is None:
        first = max(cursor + 1, oldest) if oldest else 1
        events = [_event(sequence) for sequence in range(first, latest + 1)]
    next_cursor = int(events[-1]["sequence"]) if events else cursor + dropped
    return {
        "events": events,
        "count": len(events),
        "cursor": cursor,
        "next_cursor": next_cursor,
        "oldest_sequence": oldest,
        "latest_sequence": latest,
        "dropped": dropped,
        "dropped_total": max(0, latest - capacity),
        "has_more": next_cursor < latest,
        "capacity": capacity,
    }


def _parse(payload: object, *, cursor: int = 0, limit: int = MAX_DEBUG_EVENT_BATCH) -> Any:
    return parse_debug_event_batch(
        payload,
        requested_cursor=cursor,
        requested_limit=limit,
    )


def test_a_non_object_batch_is_rejected() -> None:
    with pytest.raises(DebugEventProtocolError, match="must be an object"):
        _parse(["not", "an", "object"])


def test_a_cursor_ahead_of_latest_is_rejected() -> None:
    """A stream cannot acknowledge past the newest sequence it has produced."""
    payload = _batch(cursor=5, latest=2, events=[])
    with pytest.raises(DebugEventProtocolError, match="ahead of latest_sequence"):
        _parse(payload, cursor=5)


def test_a_short_window_that_still_counts_itself_is_rejected() -> None:
    """count matches the array length yet under-fills the requested window.

    cursor 0 to latest 5 with a generous limit should carry five events; a
    batch that reports three self-consistently (count == len, dropped == 0) must
    still be rejected because it does not span the sequence window it claims.
    """
    payload = _batch(cursor=0, latest=5, events=[_event(1), _event(2), _event(3)])
    with pytest.raises(DebugEventProtocolError, match="expected sequence window"):
        _parse(payload)


def test_a_non_object_event_row_is_rejected() -> None:
    payload = _batch(latest=1, events=[_event(1)])
    payload["events"] = [123]
    with pytest.raises(DebugEventProtocolError, match="debug event must be an object"):
        _parse(payload)


def test_a_non_integer_integer_field_is_rejected() -> None:
    payload = _batch(
        latest=1,
        events=[_event(1, "module.loaded", {"base": "0x1000", "size": 0x2000, "name": "a.dll"})],
    )
    with pytest.raises(DebugEventProtocolError, match="must be a non-negative"):
        _parse(payload)


def test_a_non_string_text_field_is_rejected() -> None:
    payload = _batch(
        latest=1,
        events=[_event(1, "module.loaded", {"base": 0x1000, "size": 0x2000, "name": 123})],
    )
    with pytest.raises(DebugEventProtocolError, match="name is invalid"):
        _parse(payload)


def test_a_valid_boolean_field_is_carried_through() -> None:
    """The accepted-boolean arm: a real bool passes the type gate and survives.

    Non-vacuous companion to the rejection tests -- exception.first_chance set
    to a genuine boolean must parse and appear in the event data rather than
    tripping the boolean guard.
    """
    payload = _batch(
        latest=1,
        events=[
            _event(
                1,
                "exception",
                {"code": 0xC0000005, "address": 0x1000, "first_chance": True},
            )
        ],
    )
    batch = _parse(payload)
    assert batch.events[0].data["first_chance"] is True
    assert batch.events[0].data["code"] == 0xC0000005
